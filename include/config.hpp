#pragma once
#include <string>
#include <vector>
#include <filesystem>

#include "event_system.hpp"

namespace config {

struct AppConfig {
    // File integrity
    std::vector<std::filesystem::path> monitored_paths;

    // Thresholds
    events::Severity terminal_bell   = events::Severity::HIGH;
    events::Severity desktop_notify  = events::Severity::HIGH;
    int  ssh_fail_threshold    = 5;
    int  ssh_fail_window_secs  = 60;
    bool sound_enabled         = true;
    bool notify_send_enabled   = true;

    // Event log
    std::filesystem::path event_log_path;

    static AppConfig load(const std::filesystem::path& config_dir);
    static AppConfig defaults();
};

// Loads monitored_files.conf — one path per line, # comments allowed
std::vector<std::filesystem::path> load_monitored_files(const std::filesystem::path& path);

} // namespace config
