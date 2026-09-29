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
        if (key == "terminal_bell")    t.terminal_bell  = events::str_to_severity(val);
        if (key == "desktop_notify")   t.desktop_notify = events::str_to_severity(val);
        if (key == "ssh_fail_count")   t.ssh_fail_count = std::stoi(val);
        if (key == "ssh_fail_window")  t.ssh_fail_window_secs = std::stoi(val);
        if (key == "sound_enabled")    t.sound_enabled = (val == "true" || val == "1");
        if (key == "notify_enabled")   t.notify_send_enabled = (val == "true" || val == "1");
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
    write(STDERR_FILENO, "\a", 1);
}

void Alerter::desktop_notify(const events::Event& e) const {
    // Non-blocking fork+exec
    pid_t pid = fork();
    if (pid == 0) {
        // Child
        std::string urgency = "normal";
        if (e.severity == events::Severity::CRITICAL) urgency = "critical";
        if (e.severity == events::Severity::HIGH)     urgency = "critical";

        std::string title   = "[" + e.severity_str() + "] " + e.title;
        std::string body    = e.details.substr(0, 200);

        execlp("notify-send", "notify-send",
               "-u", urgency.c_str(),
               "-t", "5000",
               title.c_str(),
               body.c_str(),
               nullptr);
        _exit(1); // exec failed
    }
    // Parent doesn't wait — fire and forget
    if (pid > 0) {
        // Reap async to avoid zombies
        struct sigaction sa{};
        sa.sa_handler = SIG_DFL;
        sa.sa_flags   = SA_NOCLDWAIT;
        sigaction(SIGCHLD, &sa, nullptr);
    }
}

} // namespace alert
