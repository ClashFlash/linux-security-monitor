#pragma once
#include "event_system.hpp"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <atomic>
#include <thread>
#include <functional>
#include <optional>
#include <mutex>
#include <memory>

namespace ssh {

struct AuthEvent {
    enum class Type { FAIL, SUCCESS, INVALID_USER, DISCONNECT };
    Type        type;
    std::string username;
    std::string source_ip;
    std::chrono::system_clock::time_point timestamp;
    std::string raw_line;

    std::string type_str() const;
};

struct IpStats {
    std::string                           ip;
    int                                   fail_count   = 0;
    int                                   success_count = 0;
    std::chrono::system_clock::time_point last_seen;
    std::vector<std::string>              usernames_tried;
    bool                                  alert_fired  = false;
};

class SshMonitor {
public:
    // threshold: number of failures in window_secs before a HIGH event
    SshMonitor(std::shared_ptr<events::EventLog> log,
               int threshold    = 5,
               int window_secs  = 60);
    ~SshMonitor();

    void start();
    void stop();

    const std::vector<AuthEvent>& recent_events() const { return events_; }
    const std::map<std::string, IpStats>& ip_stats() const { return ip_stats_; }

    // Parse a single auth.log line (public for unit testing)
    static std::optional<AuthEvent> parse_line(const std::string& line);

private:
    std::shared_ptr<events::EventLog> event_log_;
    int                               threshold_;
    int                               window_secs_;
    std::thread                       thread_;
    std::atomic<bool>                 running_{false};

    std::vector<AuthEvent>            events_;
    std::map<std::string, IpStats>    ip_stats_;
    mutable std::mutex                mutex_;

    void tail_loop();
    std::string find_auth_log();
    void process_line(const std::string& line);
    void check_brute_force(const std::string& ip);
    void emit_event(events::Severity sev, const std::string& title,
                    const std::string& details);
};

} // namespace ssh
