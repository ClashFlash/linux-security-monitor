#include "event_system.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <filesystem>
#include <algorithm>
#include <cctype>

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

std::string json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    return out;
}

std::string json_unescape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 1 < in.size()) {
            char n = in[++i];
            if      (n == 'n') out += '\n';
            else if (n == 'r') out += '\r';
            else if (n == 't') out += '\t';
            else               out += n;
        } else {
            out += in[i];
        }
    }
    return out;
}

std::string json_get(const std::string& obj, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    auto pos = obj.find(pat);
    if (pos == std::string::npos) {
        // numeric / unquoted
        pat = "\"" + key + "\":";
        pos = obj.find(pat);
        if (pos == std::string::npos) return "";
        pos += pat.size();
        while (pos < obj.size() && std::isspace(static_cast<unsigned char>(obj[pos]))) pos++;
        if (pos < obj.size() && obj[pos] == '"') {
            ++pos;
            std::string raw;
            for (; pos < obj.size(); ++pos) {
                if (obj[pos] == '\\' && pos + 1 < obj.size()) { raw += obj[pos]; raw += obj[++pos]; continue; }
                if (obj[pos] == '"') break;
                raw += obj[pos];
            }
            return json_unescape(raw);
        }
        std::string raw;
        while (pos < obj.size() && obj[pos] != ',' && obj[pos] != '}') {
            raw += obj[pos++];
        }
        while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.back()))) raw.pop_back();
        return raw;
    }
    pos += pat.size();
    std::string raw;
    for (; pos < obj.size(); ++pos) {
        if (obj[pos] == '\\' && pos + 1 < obj.size()) { raw += obj[pos]; raw += obj[++pos]; continue; }
        if (obj[pos] == '"') break;
        raw += obj[pos];
    }
    return json_unescape(raw);
}

std::string format_time(std::chrono::system_clock::time_point tp) {
    auto t = std::chrono::system_clock::to_time_t(tp);
    struct tm tm_buf{};
    localtime_r(&t, &tm_buf);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}

std::chrono::system_clock::time_point parse_time(const std::string& s) {
    struct tm tm_buf{};
    if (strptime(s.c_str(), "%Y-%m-%d %H:%M:%S", &tm_buf) == nullptr)
        return std::chrono::system_clock::now();
    tm_buf.tm_isdst = -1;
    auto t = mktime(&tm_buf);
    return std::chrono::system_clock::from_time_t(t);
}

// ─── Event methods ─────────────────────────────────────────────────────────

std::string Event::category_str() const  { return category_to_str(category); }
std::string Event::severity_str() const  { return severity_to_str(severity); }

std::string Event::timestamp_str() const {
    return format_time(timestamp);
}

std::string Event::to_json() const {
    std::ostringstream ss;
    ss << "{\"ts\":\"" << json_escape(timestamp_str())
       << "\",\"cat\":\"" << json_escape(category_str())
       << "\",\"sev\":\"" << json_escape(severity_str())
       << "\",\"src\":\"" << json_escape(source)
       << "\",\"title\":\"" << json_escape(title)
       << "\",\"details\":\"" << json_escape(details)
       << "\",\"id\":\"" << json_escape(id)
       << "\",\"gkey\":\"" << json_escape(grouping_key)
       << "\",\"why\":\"" << json_escape(why_suspicious)
       << "\",\"evidence\":\"" << json_escape(evidence)
       << "\",\"next\":\"" << json_escape(next_steps)
       << "\",\"pid\":" << pid
       << ",\"ppid\":" << ppid
       << ",\"exe\":\"" << json_escape(exe_path)
       << "\",\"user\":\"" << json_escape(username)
       << "\",\"extra\":\"" << json_escape(extra) << "\"}";
    return ss.str();
}

Event Event::from_json(const std::string& line) {
    Event e;
    e.timestamp       = parse_time(json_get(line, "ts"));
    e.category        = str_to_category(json_get(line, "cat"));
    e.severity        = str_to_severity(json_get(line, "sev"));
    e.source          = json_get(line, "src");
    e.title           = json_get(line, "title");
    e.details         = json_get(line, "details");
    e.id              = json_get(line, "id");
    e.grouping_key    = json_get(line, "gkey");
    e.why_suspicious  = json_get(line, "why");
    e.evidence        = json_get(line, "evidence");
    e.next_steps      = json_get(line, "next");
    e.exe_path        = json_get(line, "exe");
    e.username        = json_get(line, "user");
    e.extra           = json_get(line, "extra");
    try { e.pid  = std::stoi(json_get(line, "pid")); } catch (...) {}
    try { e.ppid = std::stoi(json_get(line, "ppid")); } catch (...) {}
    return e;
}

// ─── EventLog ──────────────────────────────────────────────────────────────

EventLog::EventLog(const std::filesystem::path& log_path)
    : log_path_(log_path)
{
    if (!log_path_.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(log_path_.parent_path(), ec);
    }
    load_from_disk();
}

EventLog::~EventLog() = default;

void EventLog::load_from_disk() {
    if (log_path_.empty()) return;
    std::ifstream f(log_path_);
    if (!f) return;
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) lines.push_back(std::move(line));
    }
    size_t start = lines.size() > MAX_IN_MEMORY ? lines.size() - MAX_IN_MEMORY : 0;
    uint64_t max_id = 0;
    for (size_t i = start; i < lines.size(); ++i) {
        Event e = Event::from_json(lines[i]);
        if (e.title.empty() && e.details.empty()) continue;
        if (!e.id.empty() && e.id.rfind("ev-", 0) == 0) {
            try {
                uint64_t n = std::stoull(e.id.substr(3));
                if (n > max_id) max_id = n;
            } catch (...) {}
        }
        ring_.push_back(std::move(e));
    }
    next_id_ = max_id + 1;
}

void EventLog::push(Event e) {
    if (e.id.empty()) {
        uint64_t n = next_id_.fetch_add(1);
        std::ostringstream ss;
        ss << "ev-" << std::setw(6) << std::setfill('0') << n;
        e.id = ss.str();
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ring_.push_back(e);
        if (ring_.size() > MAX_IN_MEMORY)
            ring_.pop_front();
        write_to_log(e);
    }
    std::vector<Callback> cbs;
    {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        cbs = callbacks_;
    }
    for (auto& cb : cbs)
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
            e.source.find(kw) != std::string::npos ||
            e.evidence.find(kw) != std::string::npos ||
            e.extra.find(kw) != std::string::npos)
            out.push_back(e);
    }
    return out;
}

size_t EventLog::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ring_.size();
}

void EventLog::on_event(Callback cb) {
    std::lock_guard<std::mutex> lock(cb_mutex_);
    callbacks_.push_back(std::move(cb));
}

void EventLog::write_to_log(const Event& e) {
    if (log_path_.empty()) return;
    try {
        std::ofstream f(log_path_, std::ios::app);
        if (f) f << e.to_json() << "\n";
    } catch (...) {
    }
}

} // namespace events
