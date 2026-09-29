#pragma once
#include "event_system.hpp"
#include <string>
#include <map>

namespace alert {

struct Thresholds {
    events::Severity terminal_bell    = events::Severity::HIGH;
    events::Severity desktop_notify   = events::Severity::HIGH;
    int ssh_fail_count                = 5;   // attempts before alert
    int ssh_fail_window_secs          = 60;
    bool sound_enabled                = true;
    bool notify_send_enabled          = true;

    static Thresholds load(const std::string& path);
};

class Alerter {
public:
    explicit Alerter(Thresholds t = {});

    // Called by EventLog callback — sends bell/notify if severity >= threshold
    void handle(const events::Event& e);

private:
    Thresholds thresholds_;
    bool       notify_send_available_;

    void ring_bell() const;
    void desktop_notify(const events::Event& e) const;
};

} // namespace alert
