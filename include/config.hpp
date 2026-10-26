#pragma once
#include <string>
#include <vector>
#include <filesystem>

#include "event_system.hpp"
#include "ssh_monitor.hpp"

namespace config {

struct AppConfig {
    std::vector<std::filesystem::path> monitored_paths;

    events::Severity terminal_bell   = events::Severity::HIGH;
    events::Severity desktop_notify  = events::Severity::HIGH;
    int  ssh_fail_threshold    = 5;
    int  ssh_fail_window_secs  = 60;
    int  ssh_spray_usernames   = 8;
    int  ssh_success_after_fails = 3;
    int  ssh_unusual_min_history = 10;
    int  conn_burst_count      = 12;
    int  conn_burst_window     = 10;
    bool sound_enabled         = true;
    bool notify_send_enabled   = true;

    std::filesystem::path event_log_path;
    std::filesystem::path data_dir;
    std::filesystem::path file_baseline_path;
    std::filesystem::path trusted_ports_path;
    std::filesystem::path known_auth_ips_path;
    std::filesystem::path incidents_path;
    std::filesystem::path reports_dir;

    ssh::AuthThresholds ssh_thresholds() const {
        return {ssh_fail_threshold, ssh_fail_window_secs, ssh_spray_usernames,
                ssh_success_after_fails, ssh_unusual_min_history};
    }

    static AppConfig load(const std::filesystem::path& config_dir);
    static AppConfig defaults();
};

std::vector<std::filesystem::path> load_monitored_files(const std::filesystem::path& path);

} // namespace config
