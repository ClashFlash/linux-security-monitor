#pragma once
#include "event_system.hpp"
#include <string>
#include <map>
#include <vector>
#include <filesystem>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <chrono>
#include <condition_variable>

namespace integrity {

// SHA-256 digest as hex string
std::string sha256_file(const std::filesystem::path& path);

struct FileRecord {
    std::filesystem::path path;
    std::string           hash;
    uintmax_t             size    = 0;
    std::filesystem::file_time_type mtime;
    bool                  exists  = true;
};

enum class ChangeType { MODIFIED, CREATED, DELETED };

struct FileChange {
    ChangeType              type;
    std::filesystem::path   path;
    std::string             old_hash;
    std::string             new_hash;
    std::chrono::system_clock::time_point timestamp;

    std::string type_str() const;
};

class FileIntegrityMonitor {
public:
    FileIntegrityMonitor(std::shared_ptr<events::EventLog> log,
                         std::vector<std::filesystem::path> watched);
    ~FileIntegrityMonitor();

    void start();
    void stop();

    // Take baseline (hash everything now) — also called in start()
    void baseline();

    // Manual scan — returns changes found
    std::vector<FileChange> scan();

    std::vector<FileChange> history() const;
    std::map<std::filesystem::path, FileRecord> baseline_map() const;

private:
    std::shared_ptr<events::EventLog>          event_log_;
    std::vector<std::filesystem::path>         watched_;
    std::map<std::filesystem::path, FileRecord> baseline_;
    std::vector<FileChange>                    history_;
    mutable std::mutex                         mutex_;
    std::thread                                thread_;
    std::atomic<bool>                          running_{false};
    std::condition_variable                    cv_;
    std::mutex                                 cv_mutex_;

    void watch_loop();
    void collect_paths(const std::filesystem::path& root,
                       std::vector<std::filesystem::path>& out) const;
    void emit_change(const FileChange& fc);
    FileRecord make_record(const std::filesystem::path& p) const;
};

} // namespace integrity
