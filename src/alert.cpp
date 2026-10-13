#include "alert.hpp"
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/wait.h>
#include <fstream>
#include <sstream>

namespace alert {

// ─── Thresholds::load ──────────────────────────────────────────────────────

Thresholds Thresholds::load(const std::string& path) {
    Thresholds t;
    std::ifstream f(path);
    if (!f) return t;
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
            if (key == "terminal_bell")    t.terminal_bell  = events::str_to_severity(val);
            else if (key == "desktop_notify")   t.desktop_notify = events::str_to_severity(val);
            else if (key == "ssh_fail_count" || key == "ssh_fail_threshold")   t.ssh_fail_count = std::stoi(val);
            else if (key == "ssh_fail_window" || key == "ssh_fail_window_secs")  t.ssh_fail_window_secs = std::stoi(val);
            else if (key == "sound_enabled")    t.sound_enabled = (val == "true" || val == "1");
            else if (key == "notify_enabled" || key == "notify_send_enabled")   t.notify_send_enabled = (val == "true" || val == "1");
        } catch (...) { /* ignore parse errors */ }
    }
    return t;
}

// ─── Alerter ───────────────────────────────────────────────────────────────

Alerter::Alerter(Thresholds t)
    : thresholds_(t), notify_send_available_(false)
{
    // Check if notify-send exists
    if (t.notify_send_enabled) {
        notify_send_available_ = (system("which notify-send >/dev/null 2>&1") == 0);
    }
}

void Alerter::handle(const events::Event& e) {
    if (thresholds_.sound_enabled &&
        static_cast<int>(e.severity) >= static_cast<int>(thresholds_.terminal_bell))
        ring_bell();

    if (notify_send_available_ &&
        static_cast<int>(e.severity) >= static_cast<int>(thresholds_.desktop_notify))
        desktop_notify(e);
}

void Alerter::ring_bell() const {
    // Write BEL character to stderr (visible terminal)
    ssize_t ret = write(STDERR_FILENO, "\a", 1);
    (void)ret;
}

void Alerter::desktop_notify(const events::Event& e) const {
    // Prepare string arguments before fork to avoid heap allocation after fork
    std::string urgency = "normal";
    if (e.severity == events::Severity::CRITICAL || e.severity == events::Severity::HIGH)
        urgency = "critical";

    std::string title = "[" + e.severity_str() + "] " + e.title;
    std::string body  = e.details.substr(0, 200);

    // Double-fork idiom:
    // First child forks the grandchild and exits immediately.
    // Parent synchronously reaps the first child (< 1ms).
    // Grandchild is adopted by init/systemd (PID 1) and reaped automatically.
    // This avoids zombies, avoids signal races, and does not interfere with pclose().
    pid_t pid = fork();
    if (pid == 0) {
        pid_t gpid = fork();
        if (gpid == 0) {
            execlp("notify-send", "notify-send",
                   "-u", urgency.c_str(),
                   "-t", "5000",
                   title.c_str(),
                   body.c_str(),
                   nullptr);
            _exit(1); // exec failed
        }
        _exit(0); // first child exits immediately
    }
    if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0); // Reaps first child immediately
    }
}

} // namespace alert
