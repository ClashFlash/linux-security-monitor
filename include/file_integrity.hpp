#pragma once
#include "event_system.hpp"
#include <string>
#include <map>
#include <vector>
#include <set>
#include <filesystem>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <chrono>
#include <condition_variable>
#include <sys/types.h>

namespace integrity {

std::string sha256_file(const std::filesystem::path& path);
bool is_persistence_path(const std::filesystem::path& path);

struct FileRecord {
    std::filesystem::path path;
    std::string           hash;
    uintmax_t             size    = 0;
    int64_t               mtime_count = 0;
    mode_t                mode    = 0;
    uid_t                 uid     = 0;
    gid_t                 gid     = 0;
    bool                  exists  = true;
};

enum class ChangeType { MODIFIED, CREATED, DELETED, PERM_CHANGED, NEW_STARTUP };

struct FileChange {
    ChangeType              type;
    std::filesystem::path   path;
    std::string             old_hash;
    std::string             new_hash;
    mode_t                  old_mode = 0;
    mode_t                  new_mode = 0;
    uid_t                   old_uid = 0;
    uid_t                   new_uid = 0;
    gid_t                   old_gid = 0;
    gid_t                   new_gid = 0;
    uintmax_t               old_size = 0;
    uintmax_t               new_size = 0;
    std::chrono::system_clock::time_point timestamp;

    std::string type_str() const;
};

class FileIntegrityMonitor {
public:
    FileIntegrityMonitor(std::shared_ptr<events::EventLog> log,
                         std::vector<std::filesystem::path> watched,
                         std::filesystem::path baseline_path = {});
    ~FileIntegrityMonitor();

    void start();
    void stop();

    // Deliberately (re)establish the approved baseline from disk and persist it.
    void baseline();

    std::vector<FileChange> scan();

    std::vector<FileChange> history() const;
    std::map<std::filesystem::path, FileRecord> baseline_map() const;
    bool has_persisted_baseline() const;
    std::chrono::system_clock::time_point baseline_established_at() const;

private:
    std::shared_ptr<events::EventLog>          event_log_;
    std::vector<std::filesystem::path>         watched_;
    std::filesystem::path                      baseline_path_;
    std::map<std::filesystem::path, FileRecord> approved_;
    std::map<std::filesystem::path, FileRecord> last_scan_;
    std::vector<FileChange>                    history_;
    std::set<std::string>                      alerted_keys_;
    std::chrono::system_clock::time_point      baseline_at_{};
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
    bool load_persisted();
    void save_persisted() const;
};

} // namespace integrity
