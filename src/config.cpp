#include "config.hpp"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <filesystem>

namespace config {

AppConfig AppConfig::defaults() {
    AppConfig c;
    // Default monitored paths
    c.monitored_paths = {
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/etc/hosts",
        "/bin", "/sbin", "/usr/bin", "/usr/sbin"
    };
    // Event log in XDG data home
    const char* xdg = std::getenv("XDG_DATA_HOME");
    std::filesystem::path data_home = xdg ? xdg
        : (std::filesystem::path(std::getenv("HOME") ? std::getenv("HOME") : "/tmp")
           / ".local/share");
    c.event_log_path = data_home / "linux-security-monitor" / "events.log";
    return c;
}

AppConfig AppConfig::load(const std::filesystem::path& config_dir) {
    AppConfig c = defaults();

    // Load monitored_files.conf
    auto mf = config_dir / "monitored_files.conf";
    if (std::filesystem::exists(mf)) {
        auto paths = load_monitored_files(mf);
        if (!paths.empty()) c.monitored_paths = paths;
    }

    // Load thresholds.conf
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
            try {
                if (key == "ssh_fail_threshold")   c.ssh_fail_threshold   = std::stoi(val);
                if (key == "ssh_fail_window_secs") c.ssh_fail_window_secs = std::stoi(val);
                if (key == "sound_enabled")        c.sound_enabled   = (val == "true" || val == "1");
                if (key == "notify_send_enabled")  c.notify_send_enabled = (val == "true" || val == "1");
            } catch (...) { /* ignore parse errors */ }
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
        // Strip comments and whitespace
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
