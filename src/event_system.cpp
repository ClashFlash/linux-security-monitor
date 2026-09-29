#include "event_system.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <filesystem>

namespace events {

// ─── helpers ───────────────────────────────────────────────────────────────

std::string category_to_str(Category c) {
    switch (c) {
        case Category::AUTH:    return "AUTH";
        case Category::PROCESS: return "PROCESS";
        case Category::NETWORK: return "NETWORK";
        case Category::FILE:    return "FILE";
        case Category::SYSTEM:  return "SYSTEM";
    }
    return "UNKNOWN";
}

std::string severity_to_str(Severity s) {
    switch (s) {
        case Severity::LOW:      return "LOW";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::HIGH:     return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

Category str_to_category(const std::string& s) {
    if (s == "AUTH")    return Category::AUTH;
    if (s == "PROCESS") return Category::PROCESS;
    if (s == "NETWORK") return Category::NETWORK;
    if (s == "FILE")    return Category::FILE;
    return Category::SYSTEM;
}

Severity str_to_severity(const std::string& s) {
    if (s == "LOW")      return Severity::LOW;
    if (s == "MEDIUM")   return Severity::MEDIUM;
    if (s == "HIGH")     return Severity::HIGH;
    if (s == "CRITICAL") return Severity::CRITICAL;
    return Severity::LOW;
}

// ─── Event methods ─────────────────────────────────────────────────────────

std::string Event::category_str() const  { return category_to_str(category); }
std::string Event::severity_str() const  { return severity_to_str(severity); }

std::string Event::timestamp_str() const {
    auto t = std::chrono::system_clock::to_time_t(timestamp);
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string Event::to_json() const {
    // Simple hand-rolled JSON — avoids a dependency
    auto escape = [](const std::string& in) {
        std::string out;
        for (char c : in) {
            if      (c == '"')  out += "\\\"";
            else if (c == '\\') out += "\\\\";
            else if (c == '\n') out += "\\n";
            else                out += c;
        }
        return out;
    };
    std::ostringstream ss;
    ss << "{\"ts\":\"" << escape(timestamp_str())
       << "\",\"cat\":\"" << escape(category_str())
       << "\",\"sev\":\"" << escape(severity_str())
       << "\",\"src\":\"" << escape(source)
       << "\",\"title\":\"" << escape(title)
       << "\",\"details\":\"" << escape(details) << "\"}";
    return ss.str();
}

// ─── EventLog ──────────────────────────────────────────────────────────────

EventLog::EventLog(const std::filesystem::path& log_path)
    : log_path_(log_path)
{
    // Ensure parent directory exists
    if (!log_path_.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(log_path_.parent_path(), ec);
        // Non-fatal if we can't create the dir
    }
}

EventLog::~EventLog() = default;

void EventLog::push(Event e) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ring_.push_back(e);
        if (ring_.size() > MAX_IN_MEMORY)
            ring_.pop_front();
        write_to_log(e);
    }
    // Fire callbacks outside the lock to avoid deadlock
    for (auto& cb : callbacks_)
        cb(e);
}

std::vector<Event> EventLog::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {ring_.begin(), ring_.end()};
}

std::vector<Event> EventLog::snapshot(Category cat) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Event> out;
    for (const auto& e : ring_)
        if (e.category == cat) out.push_back(e);
    return out;
}

std::vector<Event> EventLog::search(const std::string& kw) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Event> out;
    for (const auto& e : ring_) {
        if (e.title.find(kw) != std::string::npos ||
            e.details.find(kw) != std::string::npos ||
            e.source.find(kw) != std::string::npos)
            out.push_back(e);
    }
    return out;
}

size_t EventLog::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ring_.size();
}

void EventLog::on_event(Callback cb) {
    callbacks_.push_back(std::move(cb));
}

void EventLog::write_to_log(const Event& e) {
    if (log_path_.empty()) return;
    try {
        std::ofstream f(log_path_, std::ios::app);
        if (f) f << e.to_json() << "\n";
    } catch (...) {
        // Non-fatal: we never crash because logging failed
    }
}

} // namespace events
