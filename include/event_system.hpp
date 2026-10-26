#pragma once
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <functional>
#include <chrono>
#include <atomic>
#include <filesystem>

namespace events {

enum class Category {
    AUTH,
    PROCESS,
    NETWORK,
    FILE,
    SYSTEM
};

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct Event {
    std::chrono::system_clock::time_point timestamp;
    Category    category;
    Severity    severity;
    std::string source;      // module name
    std::string title;       // short one-liner
    std::string details;     // full description

    std::string id;
    std::string grouping_key;
    std::string why_suspicious;
    std::string evidence;
    std::string next_steps;
    int         pid      = -1;
    int         ppid     = -1;
    std::string exe_path;
    std::string username;
    std::string extra;       // free-form (IP, path, port)

    std::string category_str() const;
    std::string severity_str() const;
    std::string timestamp_str() const;
    std::string to_json() const;

    static Event from_json(const std::string& line);
};

// Thread-safe ring buffer + persistent log
class EventLog {
public:
    static constexpr size_t MAX_IN_MEMORY = 1000;

    explicit EventLog(const std::filesystem::path& log_path);
    ~EventLog();

    void push(Event e);

    // Returns a snapshot copy — safe to call from any thread
    std::vector<Event> snapshot() const;

    // Filtered snapshot
    std::vector<Event> snapshot(Category cat) const;
    std::vector<Event> search(const std::string& keyword) const;

    size_t count() const;

    // Register a callback fired (from the pushing thread) on new events
    using Callback = std::function<void(const Event&)>;
    void on_event(Callback cb);

private:
    mutable std::mutex     mutex_;
    mutable std::mutex     cb_mutex_;
    std::deque<Event>      ring_;
    std::vector<Callback>  callbacks_;
    std::filesystem::path  log_path_;
    std::atomic<uint64_t>  next_id_{1};

    void write_to_log(const Event& e);
    void load_from_disk();
};

// Convenience helpers
std::string category_to_str(Category c);
std::string severity_to_str(Severity s);
Category    str_to_category(const std::string& s);
Severity    str_to_severity(const std::string& s);

std::string json_escape(const std::string& in);
std::string json_unescape(const std::string& in);
std::string json_get(const std::string& obj, const std::string& key);
std::string format_time(std::chrono::system_clock::time_point tp);
std::chrono::system_clock::time_point parse_time(const std::string& s);

} // namespace events
