#include "ssh_monitor.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <set>
#include <chrono>
#include <thread>
#include <filesystem>
#include <cstdio>
#include <array>
#include <stdexcept>
#include <algorithm>
#include <sys/stat.h>
#include <unistd.h>

namespace ssh {

std::optional<AuthEvent> SshMonitor::parse_line(const std::string& line) {
    AuthEvent e;
    e.timestamp  = std::chrono::system_clock::now();
    e.raw_line   = line;

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

std::vector<AuthFinding> analyze_auth(const AuthEvent& latest,
                                      const std::vector<AuthEvent>& history,
                                      const IpStats& stats,
                                      const std::set<std::string>& known_success_ips,
                                      const AuthThresholds& thr)
{
    std::vector<AuthFinding> out;
    const std::string& ip = latest.source_ip;
    auto window = std::chrono::seconds(thr.fail_window_secs);

    int recent_fails = 0;
    int recent_fails_same_user = 0;
    std::set<std::string> users_in_window;
    for (const auto& ev : history) {
        if (ev.source_ip != ip) continue;
        if (latest.timestamp - ev.timestamp > window) continue;
        if (ev.type == AuthEvent::Type::FAIL || ev.type == AuthEvent::Type::INVALID_USER) {
            recent_fails++;
            users_in_window.insert(ev.username);
            if (ev.username == latest.username) recent_fails_same_user++;
        }
    }

    auto fill = [&](AuthFinding& f) {
        f.ip = ip;
        f.username = latest.username;
        f.grouping_key = "auth:" + ip;
    };

    if (!stats.burst_alerted && recent_fails >= thr.fail_count) {
        AuthFinding f;
        f.severity = events::Severity::HIGH;
        f.title = "SSH failed-login burst";
        f.why = "One source IP produced a burst of failed authentications inside the configured window.";
        f.evidence = "ip=" + ip + " recent_fails=" + std::to_string(recent_fails) +
                     " window_s=" + std::to_string(thr.fail_window_secs) +
                     " last_user=" + latest.username;
        f.next_steps = "Inspect the IP timeline; confirm whether this is a known scanner; consider firewall or fail2ban policy.";
        fill(f);
        out.push_back(std::move(f));
    }

    if (!stats.spray_alerted &&
        static_cast<int>(stats.usernames_tried.size()) >= thr.spray_usernames) {
        AuthFinding f;
        f.severity = events::Severity::HIGH;
        f.title = "SSH username spray";
        f.why = "The same source tried many distinct usernames, which is typical of credential spraying rather than a mistyped password.";
        f.evidence = "ip=" + ip + " usernames=" + std::to_string(stats.usernames_tried.size()) +
                     " threshold=" + std::to_string(thr.spray_usernames);
        f.next_steps = "Review the username list in the IP view; lock targeted accounts if they exist.";
        fill(f);
        out.push_back(std::move(f));
    }

    if (latest.type == AuthEvent::Type::SUCCESS &&
        !stats.success_alerted &&
        recent_fails_same_user >= thr.success_after_fails) {
        AuthFinding f;
        f.severity = events::Severity::CRITICAL;
        f.title = "SSH success after repeated failures";
        f.why = "A login succeeded from an IP that had just failed multiple times for the same account.";
        f.evidence = "ip=" + ip + " user=" + latest.username +
                     " recent_fails_user=" + std::to_string(recent_fails_same_user);
        f.next_steps = "Verify the user initiated this login; review session source and consider rotating credentials.";
        fill(f);
        out.push_back(std::move(f));
    }

    if (latest.type == AuthEvent::Type::SUCCESS &&
        static_cast<int>(known_success_ips.size()) >= thr.unusual_min_history &&
        known_success_ips.find(ip) == known_success_ips.end()) {
        AuthFinding f;
        f.severity = events::Severity::MEDIUM;
        f.title = "SSH login from new source";
        f.why = "Enough successful-login history exists to treat this IP as unusual.";
        f.evidence = "ip=" + ip + " user=" + latest.username +
                     " known_success_ips=" + std::to_string(known_success_ips.size());
        f.next_steps = "Confirm the user is travelling or on a new network; add to expected sources if legitimate.";
        fill(f);
        out.push_back(std::move(f));
    }

    return out;
}

SshMonitor::SshMonitor(std::shared_ptr<events::EventLog> log,
                       AuthThresholds thresholds,
                       std::filesystem::path known_ips_path)
    : event_log_(std::move(log))
    , thresholds_(thresholds)
    , known_ips_path_(std::move(known_ips_path))
{
    load_known_ips();
}

SshMonitor::SshMonitor(std::shared_ptr<events::EventLog> log,
                       int threshold, int window_secs)
    : SshMonitor(std::move(log), AuthThresholds{threshold, window_secs, 8, 3, 10}, {})
{}

SshMonitor::~SshMonitor() { stop(); }

void SshMonitor::start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread(&SshMonitor::tail_loop, this);
}

void SshMonitor::stop() {
    running_ = false;
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

std::vector<AuthEvent> SshMonitor::recent_events() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return events_;
}

std::map<std::string, IpStats> SshMonitor::ip_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ip_stats_;
}

void SshMonitor::ingest_line(const std::string& line, bool emit) {
    process_line(line, emit);
}

std::string SshMonitor::find_auth_log() {
    for (const auto& p : {"/var/log/auth.log", "/var/log/secure"}) {
        if (std::filesystem::exists(p) && access(p, R_OK) == 0) return p;
    }
    return "";
}

void SshMonitor::load_known_ips() {
    if (known_ips_path_.empty()) return;
    std::ifstream f(known_ips_path_);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line[0] != '#') known_success_ips_.insert(line);
    }
}

void SshMonitor::save_known_ips() const {
    if (known_ips_path_.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(known_ips_path_.parent_path(), ec);
    std::ofstream f(known_ips_path_, std::ios::trunc);
    if (!f) return;
    for (const auto& ip : known_success_ips_) f << ip << "\n";
}

void SshMonitor::emit_auth(const AuthEvent& ev, events::Severity sev,
                           const std::string& title, const std::string& details,
                           const AuthFinding* finding)
{
    events::Event e;
    e.timestamp = ev.timestamp;
    e.category  = events::Category::AUTH;
    e.severity  = sev;
    e.source    = "ssh_monitor";
    e.title     = title;
    e.details   = details;
    e.grouping_key = "auth:" + ev.source_ip;
    e.username  = ev.username;
    e.extra     = ev.source_ip;
    if (finding) {
        e.why_suspicious = finding->why;
        e.evidence       = finding->evidence;
        e.next_steps     = finding->next_steps;
        if (!finding->grouping_key.empty()) e.grouping_key = finding->grouping_key;
    } else {
        e.why_suspicious = "Authentication outcome recorded for investigation.";
        e.evidence = "ip=" + ev.source_ip + " user=" + ev.username + " result=" + ev.type_str();
        e.next_steps = "Open the Auth panel and inspect this source IP timeline.";
    }
    if (e.details.find("What:") == std::string::npos) {
        e.details = "What: " + title + "\nWhy: " + e.why_suspicious +
                    "\nEvidence: " + e.evidence + "\nNext: " + e.next_steps +
                    "\n" + details;
    }
    event_log_->push(std::move(e));
}

void SshMonitor::process_line(const std::string& line, bool emit) {
    auto ev = parse_line(line);
    if (!ev) return;

    std::vector<AuthFinding> findings;
    std::string title, details;
    events::Severity sev = events::Severity::LOW;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        events_.push_back(*ev);
        if (events_.size() > 4000) events_.erase(events_.begin(), events_.begin() + 500);

        auto& stats = ip_stats_[ev->source_ip];
        stats.ip = ev->source_ip;
        stats.last_seen = ev->timestamp;
        if (stats.first_seen.time_since_epoch().count() == 0)
            stats.first_seen = ev->timestamp;

        if (ev->type == AuthEvent::Type::FAIL ||
            ev->type == AuthEvent::Type::INVALID_USER) {
            stats.fail_count++;
            if (ev->type == AuthEvent::Type::INVALID_USER) stats.invalid_count++;
            if (std::find(stats.usernames_tried.begin(),
                          stats.usernames_tried.end(),
                          ev->username) == stats.usernames_tried.end())
                stats.usernames_tried.push_back(ev->username);
        } else if (ev->type == AuthEvent::Type::SUCCESS) {
            stats.success_count++;
        }

        findings = analyze_auth(*ev, events_, stats, known_success_ips_, thresholds_);
        if (ev->type == AuthEvent::Type::SUCCESS) {
            known_success_ips_.insert(ev->source_ip);
            save_known_ips();
        }

        for (const auto& f : findings) {
            if (f.title.find("burst") != std::string::npos) stats.burst_alerted = true;
            if (f.title.find("spray") != std::string::npos) stats.spray_alerted = true;
            if (f.title.find("success after") != std::string::npos) stats.success_alerted = true;
        }

        if (ev->type == AuthEvent::Type::FAIL || ev->type == AuthEvent::Type::INVALID_USER) {
            title = "SSH authentication failure";
            details = "User: " + ev->username + "  from: " + ev->source_ip +
                      "  result: " + ev->type_str();
        } else if (ev->type == AuthEvent::Type::SUCCESS) {
            title = "SSH login successful";
            details = "User: " + ev->username + "  from: " + ev->source_ip;
        }
    }

    if (!emit) return;
    emit_auth(*ev, sev, title, details, nullptr);
    for (const auto& f : findings) {
        emit_auth(*ev, f.severity, f.title,
                  "What: " + f.title + "\nWhy: " + f.why +
                  "\nEvidence: " + f.evidence + "\nNext: " + f.next_steps, &f);
    }
}

void SshMonitor::seed_history_from_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return;
    // Read last ~2000 lines for history without alerting
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) lines.push_back(std::move(line));
    size_t start = lines.size() > 2000 ? lines.size() - 2000 : 0;
    for (size_t i = start; i < lines.size(); ++i)
        process_line(lines[i], false);
}

void SshMonitor::seed_history_from_journal() {
    FILE* pipe = popen(
        "journalctl -u ssh -u sshd -t sshd -n 500 --no-pager -o short-iso 2>/dev/null",
        "r");
    if (!pipe) return;
    char buf[1024];
    while (fgets(buf, sizeof(buf), pipe))
        process_line(buf, false);
    pclose(pipe);
}

void SshMonitor::tail_loop() {
    std::string log_path = find_auth_log();

    if (!log_path.empty()) {
        seed_history_from_file(log_path);

        std::ifstream f(log_path);
        ino_t inode = 0;
        struct stat st{};
        if (::stat(log_path.c_str(), &st) == 0) inode = st.st_ino;
        if (f) f.seekg(0, std::ios::end);

        while (running_) {
            struct stat st2{};
            if (::stat(log_path.c_str(), &st2) == 0 && st2.st_ino != inode) {
                inode = st2.st_ino;
                f.close();
                f.open(log_path);
            }
            if (f) {
                std::string line;
                while (std::getline(f, line))
                    process_line(line, true);
                f.clear();
            }
            std::unique_lock<std::mutex> lock(cv_mutex_);
            cv_.wait_for(lock, std::chrono::seconds(1), [this] { return !running_.load(); });
        }
        return;
    }

    // systemd journal fallback
    seed_history_from_journal();
    std::string since = events::format_time(std::chrono::system_clock::now());
    std::set<std::string> seen;

    while (running_) {
        {
            std::unique_lock<std::mutex> lock(cv_mutex_);
            if (cv_.wait_for(lock, std::chrono::seconds(2), [this] { return !running_.load(); }))
                break;
        }
        std::string cmd = "journalctl -u ssh -u sshd -t sshd --since \"" + since +
                          "\" --no-pager -o short-iso 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) continue;
        char buf[1024];
        std::string last_ts = since;
        while (fgets(buf, sizeof(buf), pipe)) {
            std::string s(buf);
            if (!seen.insert(s).second) continue;
            process_line(s, true);
            // short-iso starts with 2026-10-26T22:00:00
            if (s.size() >= 19) last_ts = s.substr(0, 19);
            std::replace(last_ts.begin(), last_ts.end(), 'T', ' ');
        }
        pclose(pipe);
        if (!last_ts.empty()) since = last_ts;
        if (seen.size() > 2000) {
            auto it = seen.begin();
            std::advance(it, static_cast<long>(seen.size() - 500));
            seen.erase(seen.begin(), it);
        }
    }
}

} // namespace ssh
