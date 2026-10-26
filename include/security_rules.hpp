#pragma once
#include "event_system.hpp"
#include "process.hpp"
#include "network.hpp"
#include <vector>
#include <set>
#include <memory>
#include <unordered_map>

namespace rules {

struct RuleResult {
    bool                triggered = false;
    std::string         rule_name;
    events::Severity    severity = events::Severity::LOW;
    std::string         title;
    std::string         details;
    std::string         why_suspicious;
    std::string         evidence;
    std::string         next_steps;
    int                 pid = -1;
    int                 ppid = -1;
    std::string         exe_path;
    std::string         username;
    std::string         grouping_key;
};

// Pure evaluation functions — no side effects, easy to unit-test

RuleResult check_tmp_process(const proc::ProcessInfo& p,
                             const proc::ProcessInfo* parent = nullptr,
                             const std::vector<net::Connection>& conns = {});

RuleResult check_writable_path(const proc::ProcessInfo& p,
                               const proc::ProcessInfo* parent = nullptr,
                               const std::vector<net::Connection>& conns = {});

RuleResult check_deleted_exe(const proc::ProcessInfo& p,
                             const proc::ProcessInfo* parent = nullptr,
                             const std::vector<net::Connection>& conns = {});

RuleResult check_root_suspicious(const proc::ProcessInfo& p,
                                 const proc::ProcessInfo* parent = nullptr,
                                 const std::vector<net::Connection>& conns = {});

RuleResult check_unexpected_root(const proc::ProcessInfo& p,
                                 const proc::ProcessInfo* parent = nullptr,
                                 const std::vector<net::Connection>& conns = {});

RuleResult check_new_listening_port(const proc::ProcessInfo& p,
                                    const std::vector<net::Connection>& new_ports,
                                    const std::set<uint16_t>& trusted_ports = {});

RuleResult check_suspicious_outbound(const proc::ProcessInfo& p,
                                     const std::vector<net::Connection>& conns);

RuleResult check_service_shell(const proc::ProcessInfo& p,
                               const proc::ProcessInfo* parent,
                               const std::vector<net::Connection>& conns = {});

bool is_tmp_path(const std::string& path);
bool is_user_writable_location(const std::string& path);
bool is_system_exe_prefix(const std::string& path);
bool is_shell_name(const std::string& name);
bool is_service_like_name(const std::string& name);

class SecurityEngine {
public:
    explicit SecurityEngine(std::shared_ptr<events::EventLog> log);

    void evaluate(const std::vector<proc::ProcessInfo>&  procs,
                  const std::vector<net::Connection>&    new_ports,
                  const std::vector<net::Connection>&    conns,
                  const std::set<uint16_t>&              trusted_ports = {});

private:
    std::shared_ptr<events::EventLog>       log_;
    std::set<std::pair<int, std::string>>   alerted_rules_;
};

} // namespace rules
