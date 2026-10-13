#pragma once
#include "event_system.hpp"
#include "process.hpp"
#include "network.hpp"
#include <vector>
#include <set>
#include <memory>

namespace rules {

struct RuleResult {
    bool                triggered = false;
    std::string         rule_name;
    events::Severity    severity;
    std::string         title;
    std::string         details;
    int                 pid = -1;
};

// Pure evaluation functions — no side effects, easy to unit-test

// 1. Process from /tmp, /dev/shm, /run/user, /var/tmp
RuleResult check_tmp_process(const proc::ProcessInfo& p);

// 2. Process from user-writable location (mode has group/world write)
RuleResult check_writable_path(const proc::ProcessInfo& p);

// 3. Deleted executable still running
RuleResult check_deleted_exe(const proc::ProcessInfo& p);

// 4. Root process from suspicious location
RuleResult check_root_suspicious(const proc::ProcessInfo& p);

// 5. Process opened a new listening port
RuleResult check_new_listening_port(const proc::ProcessInfo& p,
                                    const std::vector<net::Connection>& new_ports);

// 6. Process from suspicious path making outbound connection
RuleResult check_suspicious_outbound(const proc::ProcessInfo& p,
                                     const std::vector<net::Connection>& conns);

// Run all rules on all processes, emit events
class SecurityEngine {
public:
    explicit SecurityEngine(std::shared_ptr<events::EventLog> log);

    void evaluate(const std::vector<proc::ProcessInfo>&  procs,
                  const std::vector<net::Connection>&    new_ports,
                  const std::vector<net::Connection>&    conns);

private:
    std::shared_ptr<events::EventLog>       log_;
    std::set<std::pair<int, std::string>>   alerted_rules_;  // avoid duplicate alerts
};

} // namespace rules
