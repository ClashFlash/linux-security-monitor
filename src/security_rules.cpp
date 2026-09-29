#include "security_rules.hpp"
#include <sys/stat.h>
#include <sstream>

namespace rules {

// ─── Suspicious path helpers ───────────────────────────────────────────────

static bool is_tmp_path(const std::string& path) {
    return path.rfind("/tmp",     0) == 0 ||
           path.rfind("/dev/shm", 0) == 0 ||
           path.rfind("/run/user",0) == 0 ||
           path.rfind("/var/tmp", 0) == 0;
}

static bool is_world_writable(const std::string& path) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return false;
    return (st.st_mode & S_IWOTH) != 0;
}

// ─── Individual rules ──────────────────────────────────────────────────────

RuleResult check_tmp_process(const proc::ProcessInfo& p) {
    RuleResult r;
    r.rule_name = "tmp_process";
    r.pid       = p.pid;
    if (!p.exe_path.empty() && is_tmp_path(p.exe_path)) {
        r.triggered = true;
        r.severity  = events::Severity::HIGH;
        r.title     = "Process executing from temp directory";
        r.details   = "PID " + std::to_string(p.pid) + " (" + p.name +
                      ") running from " + p.exe_path;
    }
    return r;
}

RuleResult check_writable_path(const proc::ProcessInfo& p) {
    RuleResult r;
    r.rule_name = "writable_path";
    r.pid       = p.pid;
    if (!p.exe_path.empty() && !is_tmp_path(p.exe_path) &&
        is_world_writable(p.exe_path))
    {
        r.triggered = true;
        r.severity  = events::Severity::MEDIUM;
        r.title     = "Process in world-writable location";
        r.details   = "PID " + std::to_string(p.pid) + " (" + p.name +
                      ") exe is world-writable: " + p.exe_path;
    }
    return r;
}

RuleResult check_deleted_exe(const proc::ProcessInfo& p) {
    RuleResult r;
    r.rule_name = "deleted_exe";
    r.pid       = p.pid;
    static const std::string DELETED_SUFFIX = " (deleted)";
    if (p.exe_path.size() >= DELETED_SUFFIX.size() &&
        p.exe_path.substr(p.exe_path.size() - DELETED_SUFFIX.size()) == DELETED_SUFFIX)
    {
        r.triggered = true;
        r.severity  = events::Severity::HIGH;
        r.title     = "Running process with deleted executable";
        r.details   = "PID " + std::to_string(p.pid) + " (" + p.name +
                      "): " + p.exe_path;
    }
    return r;
}

RuleResult check_root_suspicious(const proc::ProcessInfo& p) {
    RuleResult r;
    r.rule_name = "root_suspicious";
    r.pid       = p.pid;
    if (p.uid == 0 && !p.exe_path.empty() &&
        (is_tmp_path(p.exe_path) || is_world_writable(p.exe_path)))
    {
        r.triggered = true;
        r.severity  = events::Severity::CRITICAL;
        r.title     = "Root process from suspicious location";
        r.details   = "UID=0 PID " + std::to_string(p.pid) +
                      " (" + p.name + "): " + p.exe_path;
    }
    return r;
}

RuleResult check_new_listening_port(const proc::ProcessInfo& p,
                                     const std::vector<net::Connection>& new_ports)
{
    RuleResult r;
    r.rule_name = "new_listen_port";
    r.pid       = p.pid;
    for (const auto& c : new_ports) {
        if (c.pid == p.pid) {
            r.triggered = true;
            r.severity  = events::Severity::MEDIUM;
            r.title     = "Process opened new listening port";
            r.details   = "PID " + std::to_string(p.pid) + " (" + p.name +
                          ") listening on :" + std::to_string(c.local_port);
            break;
        }
    }
    return r;
}

RuleResult check_suspicious_outbound(const proc::ProcessInfo& p,
                                      const std::vector<net::Connection>& conns)
{
    RuleResult r;
    r.rule_name = "suspicious_outbound";
    r.pid       = p.pid;
    if (p.exe_path.empty() || !is_tmp_path(p.exe_path)) return r;

    for (const auto& c : conns) {
        if (c.pid == p.pid && c.state == net::ConnState::ESTABLISHED) {
            r.triggered = true;
            r.severity  = events::Severity::HIGH;
            r.title     = "Suspicious outbound connection";
            r.details   = "PID " + std::to_string(p.pid) + " (" + p.name +
                          ") from tmp -> " + c.remote_addr + ":" +
                          std::to_string(c.remote_port);
            break;
        }
    }
    return r;
}

// ─── SecurityEngine ────────────────────────────────────────────────────────

SecurityEngine::SecurityEngine(std::shared_ptr<events::EventLog> log)
    : log_(std::move(log)) {}

void SecurityEngine::evaluate(const std::vector<proc::ProcessInfo>&  procs,
                               const std::vector<net::Connection>&    new_ports,
                               const std::vector<net::Connection>&    conns)
{
    for (const auto& p : procs) {
        auto fire = [&](RuleResult r) {
            if (!r.triggered) return;
            // De-duplicate per (pid, rule)
            auto key = p.pid * 1000 + std::hash<std::string>{}(r.rule_name) % 1000;
            if (alerted_pids_.count(static_cast<int>(key))) return;
            alerted_pids_.insert(static_cast<int>(key));

            log_->push({
                std::chrono::system_clock::now(),
                events::Category::PROCESS,
                r.severity,
                "security_rules",
                r.title,
                r.details
            });
        };

        fire(check_tmp_process(p));
        fire(check_writable_path(p));
        fire(check_deleted_exe(p));
        fire(check_root_suspicious(p));
        fire(check_new_listening_port(p, new_ports));
        fire(check_suspicious_outbound(p, conns));
    }
}

} // namespace rules
