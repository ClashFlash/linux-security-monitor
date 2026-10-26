#include "incident.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace incidents {

std::string status_to_str(Status s) {
    switch (s) {
        case Status::OPEN:           return "OPEN";
        case Status::ACKNOWLEDGED:   return "ACKNOWLEDGED";
        case Status::INVESTIGATING:  return "INVESTIGATING";
        case Status::RESOLVED:       return "RESOLVED";
    }
    return "OPEN";
}

Status str_to_status(const std::string& s) {
    if (s == "ACKNOWLEDGED")  return Status::ACKNOWLEDGED;
    if (s == "INVESTIGATING") return Status::INVESTIGATING;
    if (s == "RESOLVED")      return Status::RESOLVED;
    return Status::OPEN;
}

static std::string join_unique_titles(const std::vector<events::Event>& evs) {
    std::string out;
    for (const auto& e : evs) {
        if (out.find(e.title) != std::string::npos) continue;
        if (!out.empty()) out += "; ";
        out += e.title;
    }
    return out;
}

std::string Incident::to_report() const {
    std::ostringstream ss;
    ss << "Linux Security Monitor — Incident Report\n";
    ss << "========================================\n\n";
    ss << "ID:          " << id << "\n";
    ss << "Status:      " << status_str() << "\n";
    ss << "Category:    " << events::category_to_str(category) << "\n";
    ss << "Severity:    " << events::severity_to_str(max_severity) << "\n";
    ss << "First seen:  " << events::format_time(first_seen) << "\n";
    ss << "Last seen:   " << events::format_time(last_seen) << "\n";
    ss << "Title:       " << title << "\n";
    if (related_pid > 0) ss << "Related PID: " << related_pid << "\n";
    if (!related_user.empty()) ss << "User:        " << related_user << "\n";
    if (!related_path.empty()) ss << "Path:        " << related_path << "\n";
    if (!extra.empty()) ss << "Key:         " << extra << "\n";
    ss << "\nWhat happened\n-------------\n" << title << "\n";
    if (!explanation.empty()) ss << explanation << "\n";
    ss << "\nWhy it is suspicious\n--------------------\n";
    ss << (explanation.empty() ? "Related alerts were grouped because they share a subject (process, IP, file, or port).\n"
                               : explanation + "\n");
    ss << "These are indicators, not automatic proof of malware or compromise.\n";
    ss << "\nWhat to check next\n-------------------\n";
    ss << (next_steps.empty()
               ? "Review evidence below, confirm whether the change is expected, and only then consider response.\n"
               : next_steps + "\n");
    ss << "\nEvidence (" << evidence_events.size() << " event(s))\n";
    ss << "--------\n";
    for (const auto& e : evidence_events) {
        ss << "\n[" << e.timestamp_str() << "] " << e.severity_str()
           << " " << e.category_str() << " — " << e.title << " (" << e.id << ")\n";
        if (!e.why_suspicious.empty()) ss << "  Why: " << e.why_suspicious << "\n";
        if (!e.evidence.empty())       ss << "  Evidence: " << e.evidence << "\n";
        if (!e.details.empty())        ss << "  Details: " << e.details << "\n";
        if (!e.next_steps.empty())     ss << "  Next: " << e.next_steps << "\n";
    }
    return ss.str();
}

IncidentStore::IncidentStore(std::filesystem::path store_path)
    : store_path_(std::move(store_path))
{
    if (!store_path_.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(store_path_.parent_path(), ec);
    }
    load();
}

Incident* IncidentStore::find_open_group(const std::string& key) {
    for (auto& inc : incidents_) {
        if (inc.grouping_key == key && inc.status != Status::RESOLVED)
            return &inc;
    }
    return nullptr;
}

void IncidentStore::ingest(const events::Event& e) {
    if (e.grouping_key.empty()) return;
    if (e.severity == events::Severity::LOW && e.category == events::Category::SYSTEM)
        return;

    std::lock_guard<std::mutex> lock(mutex_);
    if (auto* existing = find_open_group(e.grouping_key)) {
        existing->evidence_events.push_back(e);
        if (existing->evidence_events.size() > 200)
            existing->evidence_events.erase(existing->evidence_events.begin());
        existing->last_seen = e.timestamp;
        if (static_cast<int>(e.severity) > static_cast<int>(existing->max_severity))
            existing->max_severity = e.severity;
        if (e.pid > 0) existing->related_pid = e.pid;
        if (!e.username.empty()) existing->related_user = e.username;
        if (!e.exe_path.empty()) existing->related_path = e.exe_path;
        if (!e.extra.empty()) existing->extra = e.extra;
        if (!e.why_suspicious.empty()) existing->explanation = e.why_suspicious;
        if (!e.next_steps.empty()) existing->next_steps = e.next_steps;
        existing->title = join_unique_titles(existing->evidence_events);
        persist_unlocked();
        return;
    }

    Incident inc;
    std::ostringstream idss;
    idss << "inc-" << std::setw(5) << std::setfill('0') << next_id_++;
    inc.id            = idss.str();
    inc.status        = Status::OPEN;
    inc.category      = e.category;
    inc.max_severity  = e.severity;
    inc.title         = e.title;
    inc.grouping_key  = e.grouping_key;
    inc.explanation   = e.why_suspicious.empty() ? e.details : e.why_suspicious;
    inc.next_steps    = e.next_steps;
    inc.evidence_events.push_back(e);
    inc.first_seen    = e.timestamp;
    inc.last_seen     = e.timestamp;
    inc.related_pid   = e.pid;
    inc.related_user  = e.username;
    inc.related_path  = e.exe_path.empty() ? e.extra : e.exe_path;
    inc.extra         = e.extra.empty() ? e.grouping_key : e.extra;
    incidents_.push_back(std::move(inc));
    persist_unlocked();
}

std::vector<Incident> IncidentStore::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return incidents_;
}

std::optional<Incident> IncidentStore::get(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& inc : incidents_)
        if (inc.id == id) return inc;
    return std::nullopt;
}

bool IncidentStore::set_status(const std::string& id, Status s) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& inc : incidents_) {
        if (inc.id == id) {
            inc.status = s;
            persist_unlocked();
            return true;
        }
    }
    return false;
}

std::filesystem::path IncidentStore::export_report(const std::string& id,
                                                   const std::filesystem::path& dest_dir) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    const Incident* found = nullptr;
    for (const auto& inc : incidents_)
        if (inc.id == id) { found = &inc; break; }
    if (!found) return {};

    std::error_code ec;
    std::filesystem::create_directories(dest_dir, ec);
    auto path = dest_dir / (found->id + ".txt");
    std::ofstream f(path);
    if (!f) return {};
    f << found->to_report();
    return path;
}

size_t IncidentStore::count_open() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t n = 0;
    for (const auto& inc : incidents_)
        if (inc.status != Status::RESOLVED) ++n;
    return n;
}

void IncidentStore::persist_unlocked() const {
    if (store_path_.empty()) return;
    try {
        std::ofstream f(store_path_, std::ios::trunc);
        if (!f) return;
        for (const auto& inc : incidents_) {
            f << "{\"id\":\"" << events::json_escape(inc.id)
              << "\",\"status\":\"" << events::json_escape(inc.status_str())
              << "\",\"cat\":\"" << events::json_escape(events::category_to_str(inc.category))
              << "\",\"sev\":\"" << events::json_escape(events::severity_to_str(inc.max_severity))
              << "\",\"title\":\"" << events::json_escape(inc.title)
              << "\",\"gkey\":\"" << events::json_escape(inc.grouping_key)
              << "\",\"expl\":\"" << events::json_escape(inc.explanation)
              << "\",\"next\":\"" << events::json_escape(inc.next_steps)
              << "\",\"first\":\"" << events::json_escape(events::format_time(inc.first_seen))
              << "\",\"last\":\"" << events::json_escape(events::format_time(inc.last_seen))
              << "\",\"pid\":" << inc.related_pid
              << ",\"user\":\"" << events::json_escape(inc.related_user)
              << "\",\"path\":\"" << events::json_escape(inc.related_path)
              << "\",\"extra\":\"" << events::json_escape(inc.extra)
              << "\",\"n_ev\":" << inc.evidence_events.size()
              << "}\n";
            for (const auto& e : inc.evidence_events)
                f << "E" << e.to_json() << "\n";
        }
    } catch (...) {}
}

void IncidentStore::load() {
    if (store_path_.empty()) return;
    std::ifstream f(store_path_);
    if (!f) return;
    std::string line;
    Incident* current = nullptr;
    uint64_t max_id = 0;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        if (line[0] == 'E') {
            if (current)
                current->evidence_events.push_back(events::Event::from_json(line.substr(1)));
            continue;
        }
        Incident inc;
        inc.id           = events::json_get(line, "id");
        inc.status       = str_to_status(events::json_get(line, "status"));
        inc.category     = events::str_to_category(events::json_get(line, "cat"));
        inc.max_severity = events::str_to_severity(events::json_get(line, "sev"));
        inc.title        = events::json_get(line, "title");
        inc.grouping_key = events::json_get(line, "gkey");
        inc.explanation  = events::json_get(line, "expl");
        inc.next_steps   = events::json_get(line, "next");
        inc.first_seen   = events::parse_time(events::json_get(line, "first"));
        inc.last_seen    = events::parse_time(events::json_get(line, "last"));
        inc.related_user = events::json_get(line, "user");
        inc.related_path = events::json_get(line, "path");
        inc.extra        = events::json_get(line, "extra");
        try { inc.related_pid = std::stoi(events::json_get(line, "pid")); } catch (...) {}
        if (inc.id.rfind("inc-", 0) == 0) {
            try {
                uint64_t n = std::stoull(inc.id.substr(4));
                if (n > max_id) max_id = n;
            } catch (...) {}
        }
        incidents_.push_back(std::move(inc));
        current = &incidents_.back();
    }
    next_id_ = max_id + 1;
}

} // namespace incidents
