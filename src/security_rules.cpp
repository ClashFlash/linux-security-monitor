#include "security_rules.hpp"
#include <sys/stat.h>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace rules {

bool is_tmp_path(const std::string& path) {
    return path.rfind("/tmp",      0) == 0 ||
           path.rfind("/dev/shm",  0) == 0 ||
           path.rfind("/run/user", 0) == 0 ||
           path.rfind("/var/tmp",  0) == 0;
}

bool is_system_exe_prefix(const std::string& path) {
    static const char* prefixes[] = {
        "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        "/usr/lib/", "/usr/libexec/", "/lib/", "/lib64/",
        "/usr/local/bin/", "/usr/local/sbin/",
        "/opt/", "/snap/", "/nix/", "/usr/lib64/"
    };
    for (const char* p : prefixes) {
        if (path.rfind(p, 0) == 0) return true;
    }
    return path == "/usr/bin" || path == "/bin" || path == "/sbin";
}

bool is_user_writable_location(const std::string& path) {
    if (path.empty()) return false;
    if (is_tmp_path(path)) return true;
    if (path.rfind("/home/", 0) == 0) return true;
    if (path.rfind("/root/", 0) == 0) return true;

    auto writable = [](const std::string& p) {
        struct stat st{};
        if (::stat(p.c_str(), &st) != 0) return false;
        return (st.st_mode & (S_IWOTH | S_IWGRP)) != 0;
    };
    if (writable(path)) return true;
    auto slash = path.rfind('/');
    if (slash != std::string::npos && slash > 0)
        return writable(path.substr(0, slash));
    return false;
}

bool is_shell_name(const std::string& name) {
    return name == "sh" || name == "bash" || name == "dash" || name == "zsh" ||
           name == "ash" || name == "csh" || name == "tcsh" || name == "ksh" ||
           name == "fish" || name == "python" || name == "python3" ||
           name == "perl" || name == "ruby" || name == "nc" || name == "ncat" ||
           name == "netcat" || name == "socat";
}

bool is_service_like_name(const std::string& name) {
    static const char* names[] = {
        "nginx", "apache2", "httpd", "mysqld", "postgres", "redis-server",
        "redis", "php-fpm", "php-fpm7", "php-fpm8", "tomcat", "dockerd",
        "containerd", "sshd", "cron", "crond", "systemd", "httpd-prefork"
    };
    for (const char* n : names)
        if (name == n) return true;
    return false;
}

static std::string connections_for(int pid, const std::vector<net::Connection>& conns) {
    std::ostringstream ss;
    int n = 0;
    for (const auto& c : conns) {
        if (c.pid != pid) continue;
        ++n;
        ss << c.proto_str() << " " << c.state_str() << " "
           << c.local_addr << ":" << c.local_port << " -> "
           << c.remote_addr << ":" << c.remote_port;
        if (!c.owner_known()) ss << " [owner unknown]";
        ss << "; ";
    }
    if (n == 0) return "none observed this cycle";
    return ss.str();
}

static void fill_process_result(RuleResult& r, const proc::ProcessInfo& p,
                                const proc::ProcessInfo* parent,
                                const std::vector<net::Connection>& conns,
                                const std::string& why,
                                const std::string& next)
{
    r.pid          = p.pid;
    r.ppid         = p.ppid;
    r.exe_path     = p.exe_path;
    r.username     = p.username;
    r.grouping_key = "proc:" + std::to_string(p.pid);
    r.why_suspicious = why;
    r.next_steps   = next;
    std::ostringstream ev;
    ev << "PID=" << p.pid << " PPID=" << p.ppid;
    if (parent) ev << " parent=" << parent->name << " parent_exe=" << parent->exe_path;
    ev << " user=" << p.username << " uid=" << p.uid
       << " exe=" << p.exe_path
       << " started=" << p.start_time_str
       << " cmd=" << p.cmdline
       << " conns=[" << connections_for(p.pid, conns) << "]";
    r.evidence = ev.str();

    std::ostringstream d;
    d << "What: " << r.title << "\n"
      << "Why: " << why << " (indicator, not proof of malware)\n"
      << "PID: " << p.pid << "  PPID: " << p.ppid;
    if (parent) d << " (" << parent->name << ")";
    d << "\nUser: " << (p.username.empty() ? std::to_string(p.uid) : p.username)
      << " (uid=" << p.uid << ")\n"
      << "Exe: " << p.exe_path << "\n"
      << "Started: " << p.start_time_str << "\n"
      << "Cmd: " << p.cmdline << "\n"
      << "Connections: " << connections_for(p.pid, conns) << "\n"
      << "Next: " << next;
    r.details = d.str();
}

RuleResult check_tmp_process(const proc::ProcessInfo& p,
                             const proc::ProcessInfo* parent,
                             const std::vector<net::Connection>& conns)
{
    RuleResult r;
    r.rule_name = "tmp_process";
    r.pid       = p.pid;
    if (!p.exe_path.empty() && is_tmp_path(p.exe_path)) {
        r.triggered = true;
        r.severity  = events::Severity::HIGH;
        r.title     = "Process executing from temp directory";
        fill_process_result(r, p, parent, conns,
            "Executables launched from /tmp, /var/tmp, /dev/shm, or /run/user are unusual for long-lived software and are a common persistence drop location.",
            "Confirm whether this binary was installed by an admin; inspect parent PID and open sockets; do not treat a temp path alone as malware.");
    }
    return r;
}

RuleResult check_writable_path(const proc::ProcessInfo& p,
                               const proc::ProcessInfo* parent,
                               const std::vector<net::Connection>& conns)
{
    RuleResult r;
    r.rule_name = "writable_path";
    r.pid       = p.pid;
    if (!p.exe_path.empty() && !is_tmp_path(p.exe_path) &&
        is_user_writable_location(p.exe_path))
    {
        r.triggered = true;
        r.severity  = events::Severity::MEDIUM;
        r.title     = "Process launched from user-writable location";
        fill_process_result(r, p, parent, conns,
            "The executable lives in a home directory or a group/world-writable path, so another user or process could have replaced it.",
            "Check file owner and mode, parent process, and whether this is an expected user-installed tool.");
    }
    return r;
}

RuleResult check_deleted_exe(const proc::ProcessInfo& p,
                             const proc::ProcessInfo* parent,
                             const std::vector<net::Connection>& conns)
{
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
        fill_process_result(r, p, parent, conns,
            "The on-disk binary was unlinked while the process still runs. That happens after package upgrades, and also when malware hides its file.",
            "Compare with recent package updates; inspect /proc/<pid>/exe and open sockets; restart only after confirming origin.");
    }
    return r;
}

RuleResult check_root_suspicious(const proc::ProcessInfo& p,
                                 const proc::ProcessInfo* parent,
                                 const std::vector<net::Connection>& conns)
{
    RuleResult r;
    r.rule_name = "root_suspicious";
    r.pid       = p.pid;
    if (p.uid == 0 && !p.exe_path.empty() &&
        (is_tmp_path(p.exe_path) || is_user_writable_location(p.exe_path)))
    {
        r.triggered = true;
        r.severity  = events::Severity::CRITICAL;
        r.title     = "Root process from suspicious location";
        fill_process_result(r, p, parent, conns,
            "A UID 0 process running from a temp or user-writable path can change anything on the host.",
            "Inspect the parent chain immediately, review listening/outbound sockets, and confirm no unexpected unit or cron installed it.");
    }
    return r;
}

RuleResult check_unexpected_root(const proc::ProcessInfo& p,
                                 const proc::ProcessInfo* parent,
                                 const std::vector<net::Connection>& conns)
{
    RuleResult r;
    r.rule_name = "unexpected_root";
    r.pid       = p.pid;
    if (p.uid != 0 || p.exe_path.empty()) return r;
    if (is_tmp_path(p.exe_path) || is_user_writable_location(p.exe_path))
        return r; // covered by check_root_suspicious
    if (is_system_exe_prefix(p.exe_path)) return r;
    r.triggered = true;
    r.severity  = events::Severity::MEDIUM;
    r.title     = "Unexpected root-owned process";
    fill_process_result(r, p, parent, conns,
        "UID 0 process whose executable is outside common system prefixes (/usr, /bin, /sbin, /lib). Many are legitimate custom services; they still deserve review.",
        "Verify the binary path, package or unit that started it, and whether root is required.");
    return r;
}

RuleResult check_new_listening_port(const proc::ProcessInfo& p,
                                     const std::vector<net::Connection>& new_ports,
                                     const std::set<uint16_t>& trusted_ports)
{
    RuleResult r;
    r.rule_name = "new_listen_port";
    r.pid       = p.pid;
    for (const auto& c : new_ports) {
        if (c.pid != p.pid) continue;
        if (trusted_ports.count(c.local_port)) continue;
        r.triggered = true;
        r.severity  = events::Severity::MEDIUM;
        r.title     = "Suspicious process opened a listening port";
        std::ostringstream why;
        why << "This process began listening on port " << c.local_port
            << " after the network baseline was taken.";
        fill_process_result(r, p, nullptr, new_ports, why.str(),
            "If this service is expected, mark the port trusted. Otherwise identify the parent and whether the bind is reachable externally.");
        break;
    }
    return r;
}

RuleResult check_suspicious_outbound(const proc::ProcessInfo& p,
                                      const std::vector<net::Connection>& conns)
{
    RuleResult r;
    r.rule_name = "suspicious_outbound";
    r.pid       = p.pid;
    if (p.exe_path.empty()) return r;
    bool suspicious_proc = is_tmp_path(p.exe_path) || is_user_writable_location(p.exe_path);
    if (!suspicious_proc) return r;

    for (const auto& c : conns) {
        if (c.pid != p.pid) continue;
        if (c.state != net::ConnState::ESTABLISHED && c.state != net::ConnState::SYN_SENT)
            continue;
        bool loopback = c.remote_addr == "127.0.0.1" || c.remote_addr == "::1" ||
                        c.remote_addr == "0.0.0.0" || c.remote_addr.empty();
        if (loopback) continue;
        r.triggered = true;
        r.severity  = events::Severity::HIGH;
        r.title     = "Suspicious process connected to a remote host";
        fill_process_result(r, p, nullptr, conns,
            "A process from a temp or user-writable path established (or is attempting) an outbound connection.",
            "Identify the remote host, capture the parent chain, and decide whether the process should keep running.");
        break;
    }
    return r;
}

RuleResult check_service_shell(const proc::ProcessInfo& p,
                               const proc::ProcessInfo* parent,
                               const std::vector<net::Connection>& conns)
{
    RuleResult r;
    r.rule_name = "service_shell";
    r.pid       = p.pid;
    if (!parent) return r;
    if (!is_shell_name(p.name)) return r;
    if (!is_service_like_name(parent->name)) return r;
    // systemd spawning a shell during service start can be noisy; still useful
    r.triggered = true;
    r.severity  = parent->name == "systemd" ? events::Severity::LOW : events::Severity::HIGH;
    r.title     = "Unusual shell spawned by a service";
    fill_process_result(r, p, parent, conns,
        "A shell or scripting interpreter was spawned by a service-like parent. That is expected for some admin units and a common post-exploitation pattern for others.",
        "Review the parent unit, the shell command line, and whether this service normally launches a shell.");
    return r;
}

SecurityEngine::SecurityEngine(std::shared_ptr<events::EventLog> log)
    : log_(std::move(log)) {}

void SecurityEngine::evaluate(const std::vector<proc::ProcessInfo>&  procs,
                               const std::vector<net::Connection>&    new_ports,
                               const std::vector<net::Connection>&    conns,
                               const std::set<uint16_t>&              trusted_ports)
{
    std::unordered_map<int, const proc::ProcessInfo*> by_pid;
    by_pid.reserve(procs.size());
    for (const auto& p : procs) by_pid[p.pid] = &p;

    for (const auto& p : procs) {
        const proc::ProcessInfo* parent = nullptr;
        auto it = by_pid.find(p.ppid);
        if (it != by_pid.end()) parent = it->second;

        auto fire = [&](RuleResult r) {
            if (!r.triggered) return;
            auto key = std::make_pair(p.pid, r.rule_name);
            if (alerted_rules_.count(key)) return;
            alerted_rules_.insert(key);

            events::Event e;
            e.timestamp      = std::chrono::system_clock::now();
            e.category       = events::Category::PROCESS;
            e.severity       = r.severity;
            e.source         = "security_rules";
            e.title          = r.title;
            e.details        = r.details;
            e.grouping_key   = r.grouping_key;
            e.why_suspicious = r.why_suspicious;
            e.evidence       = r.evidence;
            e.next_steps     = r.next_steps;
            e.pid            = r.pid;
            e.ppid           = r.ppid;
            e.exe_path       = r.exe_path;
            e.username       = r.username;
            e.extra          = std::to_string(p.pid);
            log_->push(std::move(e));
        };

        fire(check_tmp_process(p, parent, conns));
        fire(check_writable_path(p, parent, conns));
        fire(check_deleted_exe(p, parent, conns));
        fire(check_root_suspicious(p, parent, conns));
        fire(check_unexpected_root(p, parent, conns));
        fire(check_new_listening_port(p, new_ports, trusted_ports));
        fire(check_suspicious_outbound(p, conns));
        fire(check_service_shell(p, parent, conns));
    }

    // Listening ports whose owner could not be attributed
    for (const auto& c : new_ports) {
        if (c.owner_known()) continue;
        if (trusted_ports.count(c.local_port)) continue;
        auto key = std::make_pair(-static_cast<int>(c.local_port), std::string("unattributed_listen"));
        if (!alerted_rules_.insert(key).second) continue;
        events::Event e;
        e.timestamp = std::chrono::system_clock::now();
        e.category  = events::Category::NETWORK;
        e.severity  = events::Severity::MEDIUM;
        e.source    = "security_rules";
        e.title     = "New listening port with unknown process owner";
        e.grouping_key = "net:listen:" + std::to_string(c.local_port);
        e.why_suspicious = "A new listening socket appeared but /proc/*/fd did not map the inode to a PID. Attribution is unknown, not invented.";
        e.evidence = "port=" + std::to_string(c.local_port) + " proto=" + c.proto_str() +
                     " local=" + c.local_addr + " pid=-1";
        e.next_steps = "Re-run the monitor with sufficient privileges to read other users' /proc/<pid>/fd, or inspect ss -lptn.";
        e.details = e.why_suspicious + "\n" + e.evidence + "\nNext: " + e.next_steps;
        e.extra = std::to_string(c.local_port);
        log_->push(std::move(e));
    }
}

} // namespace rules
