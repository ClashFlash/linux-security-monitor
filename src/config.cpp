#include "config.hpp"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <filesystem>

namespace config {

static std::filesystem::path default_data_dir() {
    const char* xdg = std::getenv("XDG_DATA_HOME");
    std::filesystem::path data_home = xdg ? xdg
        : (std::filesystem::path(std::getenv("HOME") ? std::getenv("HOME") : "/tmp")
           / ".local/share");
    return data_home / "linux-security-monitor";
}

AppConfig AppConfig::defaults() {
    AppConfig c;
    c.monitored_paths = {
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d",
        "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
        "/etc/hosts", "/etc/crontab", "/etc/cron.d", "/etc/pam.d",
        "/etc/systemd/system", "/etc/systemd/user"
    };
    c.data_dir = default_data_dir();
    c.event_log_path = c.data_dir / "events.log";
    c.file_baseline_path = c.data_dir / "file_baseline.tsv";
    c.trusted_ports_path = c.data_dir / "trusted_ports.conf";
    c.known_auth_ips_path = c.data_dir / "known_auth_ips.txt";
    c.incidents_path = c.data_dir / "incidents.store";
    c.reports_dir = c.data_dir / "reports";
    return c;
}

AppConfig AppConfig::load(const std::filesystem::path& config_dir) {
    AppConfig c = defaults();

    auto mf = config_dir / "monitored_files.conf";
    if (std::filesystem::exists(mf)) {
        auto paths = load_monitored_files(mf);
        if (!paths.empty()) c.monitored_paths = paths;
    }

    auto tf = config_dir / "thresholds.conf";
    std::ifstream f(tf);
    if (f) {
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
            while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) key.erase(key.begin());
            while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r')) val.pop_back();
            while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
            try {
                if (key == "ssh_fail_threshold" || key == "ssh_fail_count")
                    c.ssh_fail_threshold = std::stoi(val);
                else if (key == "ssh_fail_window_secs" || key == "ssh_fail_window")
                    c.ssh_fail_window_secs = std::stoi(val);
                else if (key == "ssh_spray_usernames")
                    c.ssh_spray_usernames = std::stoi(val);
                else if (key == "ssh_success_after_fails")
                    c.ssh_success_after_fails = std::stoi(val);
                else if (key == "ssh_unusual_min_history")
                    c.ssh_unusual_min_history = std::stoi(val);
                else if (key == "conn_burst_count")
                    c.conn_burst_count = std::stoi(val);
                else if (key == "conn_burst_window")
                    c.conn_burst_window = std::stoi(val);
                else if (key == "sound_enabled")
                    c.sound_enabled = (val == "true" || val == "1");
                else if (key == "notify_send_enabled" || key == "notify_enabled")
                    c.notify_send_enabled = (val == "true" || val == "1");
                else if (key == "terminal_bell")
                    c.terminal_bell = events::str_to_severity(val);
                else if (key == "desktop_notify")
                    c.desktop_notify = events::str_to_severity(val);
            } catch (...) {}
        }
    }
    return c;
}

std::vector<std::filesystem::path> load_monitored_files(const std::filesystem::path& path) {
    std::vector<std::filesystem::path> result;
    std::ifstream f(path);
    if (!f) return result;
    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find('#');
        if (pos != std::string::npos) line = line.substr(0, pos);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
            line.pop_back();
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.erase(line.begin());
        if (!line.empty())
            result.push_back(line);
    }
    return result;
}

} // namespace config
