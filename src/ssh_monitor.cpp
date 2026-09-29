#include "ssh_monitor.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <thread>
#include <filesystem>
#include <cstdio>
#include <array>
#include <stdexcept>

namespace ssh {

// ─── parse_line ────────────────────────────────────────────────────────────

std::optional<AuthEvent> SshMonitor::parse_line(const std::string& line) {
    AuthEvent e;

    // Try to extract timestamp from syslog format:
    // "Sep 29 13:05:47 host sshd[pid]: ..."
    // We just use system_clock::now() as a fallback if parsing fails
    e.timestamp  = std::chrono::system_clock::now();
    e.raw_line   = line;

    // Failed password:  "Failed password for USERNAME from IP port PORT ssh2"
    {
        static const std::regex re_fail(
            R"(Failed password for (?:invalid user )?(\S+) from (\S+) port \d+)");
        std::smatch m;
        if (std::regex_search(line, m, re_fail)) {
            e.type       = AuthEvent::Type::FAIL;
            e.username   = m[1].str();
            e.source_ip  = m[2].str();
            return e;
        }
    }

    // Invalid user: "Invalid user USERNAME from IP"
    {
        static const std::regex re_inv(R"(Invalid user (\S+) from (\S+))");
        std::smatch m;
        if (std::regex_search(line, m, re_inv)) {
            e.type      = AuthEvent::Type::INVALID_USER;
            e.username  = m[1].str();
            e.source_ip = m[2].str();
            return e;
        }
    }

    // Accepted: "Accepted password/publickey for USERNAME from IP"
    {
        static const std::regex re_ok(
            R"(Accepted (?:password|publickey) for (\S+) from (\S+))");
        std::smatch m;
        if (std::regex_search(line, m, re_ok)) {
            e.type      = AuthEvent::Type::SUCCESS;
            e.username  = m[1].str();
            e.source_ip = m[2].str();
            return e;
        }
    }

    return std::nullopt;
}

std::string AuthEvent::type_str() const {
    switch (type) {
        case Type::FAIL:         return "FAIL";
        case Type::SUCCESS:      return "SUCCESS";
        case Type::INVALID_USER: return "INVALID_USER";
        case Type::DISCONNECT:   return "DISCONNECT";
    }
    return "?";
}

// ─── SshMonitor ────────────────────────────────────────────────────────────

SshMonitor::SshMonitor(std::shared_ptr<events::EventLog> log,
                       int threshold, int window_secs)
    : event_log_(std::move(log))
    , threshold_(threshold)
    , window_secs_(window_secs)
{}

SshMonitor::~SshMonitor() { stop(); }

void SshMonitor::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&SshMonitor::tail_loop, this);
}

void SshMonitor::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
}

std::string SshMonitor::find_auth_log() {
    // Try common locations
    for (const auto& p : {"/var/log/auth.log", "/var/log/secure"}) {
        if (std::filesystem::exists(p)) return p;
    }
    return ""; // Will fall back to journalctl
}

void SshMonitor::emit_event(events::Severity sev, const std::string& title,
                             const std::string& details)
{
    event_log_->push({
        std::chrono::system_clock::now(),
        events::Category::AUTH,
        sev,
        "ssh_monitor",
        title,
        details
    });
}

void SshMonitor::check_brute_force(const std::string& ip) {
    auto it = ip_stats_.find(ip);
    if (it == ip_stats_.end()) return;
    auto& stats = it->second;
    if (stats.alert_fired) return;

    auto now  = std::chrono::system_clock::now();
    auto window = std::chrono::seconds(window_secs_);

    // Count recent failures in the window
    int recent = 0;
    for (const auto& ev : events_) {
        if (ev.type != AuthEvent::Type::FAIL && ev.type != AuthEvent::Type::INVALID_USER)
            continue;
        if (ev.source_ip != ip) continue;
        if (now - ev.timestamp < window) recent++;
    }

    if (recent >= threshold_) {
        stats.alert_fired = true;
        emit_event(
            events::Severity::HIGH,
            "SSH brute force detected",
            ip + " made " + std::to_string(recent) + " failed attempts in " +
            std::to_string(window_secs_) + "s"
        );
    }
}

void SshMonitor::process_line(const std::string& line) {
    auto ev = parse_line(line);
    if (!ev) return;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(*ev);
        if (events_.size() > 2000) events_.erase(events_.begin());

        auto& stats = ip_stats_[ev->source_ip];
        stats.ip        = ev->source_ip;
        stats.last_seen = ev->timestamp;

        std::string title, details;
        events::Severity sev;

        if (ev->type == AuthEvent::Type::FAIL ||
            ev->type == AuthEvent::Type::INVALID_USER) {
            stats.fail_count++;
            if (std::find(stats.usernames_tried.begin(),
                          stats.usernames_tried.end(),
                          ev->username) == stats.usernames_tried.end())
                stats.usernames_tried.push_back(ev->username);
            sev     = events::Severity::MEDIUM;
            title   = "SSH authentication failure";
            details = "User: " + ev->username + "  from: " + ev->source_ip;
        } else if (ev->type == AuthEvent::Type::SUCCESS) {
            stats.success_count++;
            sev     = events::Severity::LOW;
            title   = "SSH login successful";
            details = "User: " + ev->username + "  from: " + ev->source_ip;
        } else return;

        emit_event(sev, title, details);
        check_brute_force(ev->source_ip);
    }
}

void SshMonitor::tail_loop() {
    std::string log_path = find_auth_log();

    if (!log_path.empty()) {
        // Tail the file
        std::ifstream f(log_path);
        if (f) f.seekg(0, std::ios::end); // Start at end

        while (running_) {
            if (f) {
                std::string line;
                while (std::getline(f, line))
                    process_line(line);
                // Reset eof so we keep reading
                f.clear();
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } else {
        // Fallback: poll journalctl
        while (running_) {
            FILE* pipe = popen(
                "journalctl -u ssh -u sshd -n 50 --no-pager --output=short 2>/dev/null",
                "r");
            if (pipe) {
                char buf[512];
                while (fgets(buf, sizeof(buf), pipe))
                    process_line(std::string(buf));
                pclose(pipe);
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}

} // namespace ssh
