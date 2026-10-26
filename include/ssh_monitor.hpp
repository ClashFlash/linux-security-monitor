#pragma once
#include "event_system.hpp"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <atomic>
#include <thread>
#include <functional>
#include <optional>
#include <mutex>
#include <memory>
#include <filesystem>
#include <condition_variable>

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
    int                                   fail_count    = 0;
    int                                   success_count = 0;
    int                                   invalid_count = 0;
    std::chrono::system_clock::time_point last_seen;
    std::chrono::system_clock::time_point first_seen;
    std::vector<std::string>              usernames_tried;
    bool                                  burst_alerted   = false;
    bool                                  spray_alerted   = false;
    bool                                  success_alerted = false;
};

struct AuthThresholds {
    int fail_count            = 5;
    int fail_window_secs      = 60;
    int spray_usernames       = 8;
    int success_after_fails   = 3;
    int unusual_min_history   = 10;
};

struct AuthFinding {
    events::Severity severity = events::Severity::MEDIUM;
    std::string title;
    std::string why;
    std::string evidence;
    std::string next_steps;
    std::string grouping_key;
    std::string ip;
    std::string username;
};

// Pure analysis used by the monitor and unit tests.
std::vector<AuthFinding> analyze_auth(const AuthEvent& latest,
                                      const std::vector<AuthEvent>& history,
                                      const IpStats& stats,
                                      const std::set<std::string>& known_success_ips,
                                      const AuthThresholds& thr);

class SshMonitor {
public:
    SshMonitor(std::shared_ptr<events::EventLog> log,
               AuthThresholds thresholds = {},
               std::filesystem::path known_ips_path = {});
    SshMonitor(std::shared_ptr<events::EventLog> log,
               int threshold,
               int window_secs);
    ~SshMonitor();

    void start();
    void stop();

    std::vector<AuthEvent> recent_events() const;
    std::map<std::string, IpStats> ip_stats() const;
    AuthThresholds thresholds() const { return thresholds_; }

    // Parse a single auth.log / journal line (public for unit testing)
    static std::optional<AuthEvent> parse_line(const std::string& line);

    // Ingest a line (tests). emit=false seeds history without alerts.
    void ingest_line(const std::string& line, bool emit = true);

private:
    std::shared_ptr<events::EventLog> event_log_;
    AuthThresholds                    thresholds_;
    std::filesystem::path             known_ips_path_;
    std::thread                       thread_;
    std::atomic<bool>                 running_{false};
    std::condition_variable           cv_;
    std::mutex                        cv_mutex_;

    std::vector<AuthEvent>            events_;
    std::map<std::string, IpStats>    ip_stats_;
    std::set<std::string>             known_success_ips_;
    mutable std::mutex                mutex_;

    void tail_loop();
    std::string find_auth_log();
    void process_line(const std::string& line, bool emit);
    void emit_auth(const AuthEvent& ev, events::Severity sev,
                   const std::string& title, const std::string& details,
                   const AuthFinding* finding = nullptr);
    void load_known_ips();
    void save_known_ips() const;
    void seed_history_from_file(const std::string& path);
    void seed_history_from_journal();
};

} // namespace ssh
