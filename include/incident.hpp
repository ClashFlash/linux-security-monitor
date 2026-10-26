#pragma once
#include "event_system.hpp"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <filesystem>
#include <optional>

namespace incidents {

enum class Status {
    OPEN,
    ACKNOWLEDGED,
    INVESTIGATING,
    RESOLVED
};

std::string status_to_str(Status s);
Status      str_to_status(const std::string& s);

struct Incident {
    std::string id;
    Status      status = Status::OPEN;
    events::Category category = events::Category::SYSTEM;
    events::Severity max_severity = events::Severity::LOW;
    std::string title;
    std::string grouping_key;
    std::string explanation;
    std::string next_steps;
    std::vector<events::Event> evidence_events;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    int related_pid = -1;
    std::string related_user;
    std::string related_path;
    std::string extra; // IP, port, etc.

    std::string status_str() const { return status_to_str(status); }
    std::string to_report() const;
};

class IncidentStore {
public:
    explicit IncidentStore(std::filesystem::path store_path);

    // Group related alerts. LOW/SYSTEM events are ignored unless they carry a grouping key.
    void ingest(const events::Event& e);

    std::vector<Incident> snapshot() const;
    std::optional<Incident> get(const std::string& id) const;

    bool set_status(const std::string& id, Status s);
    std::filesystem::path export_report(const std::string& id,
                                        const std::filesystem::path& dest_dir) const;

    size_t count_open() const;

private:
    std::filesystem::path store_path_;
    mutable std::mutex mutex_;
    std::vector<Incident> incidents_;
    uint64_t next_id_ = 1;

    void persist_unlocked() const;
    void load();
    Incident* find_open_group(const std::string& key);
};

} // namespace incidents
