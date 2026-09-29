#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace proc {

enum class ProcState : char {
    Running  = 'R',
    Sleeping = 'S',
    Waiting  = 'D',
    Zombie   = 'Z',
    Stopped  = 'T',
    Unknown  = '?'
};

struct ProcessInfo {
    int         pid       = 0;
    int         ppid      = 0;
    std::string name;
    std::string cmdline;
    std::string exe_path;        // readlink /proc/pid/exe
    std::string username;
    uid_t       uid       = 0;
    ProcState   state     = ProcState::Unknown;
    float       cpu_pct   = 0.f;
    float       mem_pct   = 0.f;
    uint64_t    rss_kb    = 0;
    uint64_t    start_time_epoch = 0; // seconds since boot -> wall clock
    std::string start_time_str;

    // Anomaly flags (set by security_rules)
    bool exe_deleted          = false;  // exe_path ends with " (deleted)"
    bool from_tmp             = false;  // exe in /tmp /dev/shm /run/user
    bool from_writable_path   = false;
    bool root_from_suspicious = false;  // uid==0 && from_tmp/writable

    int fd_count = 0; // number of open file descriptors
};

enum class SortField { CPU, MEM, PID };

class ProcessMonitor {
public:
    ProcessMonitor();

    // Refresh the process list; call twice ~2s apart for accurate CPU%
    void refresh();

    const std::vector<ProcessInfo>& processes() const { return procs_; }

    // Sorted view (does not modify procs_)
    std::vector<const ProcessInfo*> sorted(SortField f = SortField::CPU) const;

    // Filter by name/cmdline substring
    std::vector<const ProcessInfo*> filter(const std::string& query) const;

    // Full detail for one PID (includes fd_count)
    ProcessInfo detail(int pid) const;

private:
    std::vector<ProcessInfo> procs_;
    // Previous tick data for CPU delta
    struct Snapshot {
        uint64_t utime = 0, stime = 0;
        uint64_t total_cpu_time = 0;
    };
    std::unordered_map<int, Snapshot> prev_;
    uint64_t                          prev_total_cpu_ = 0;
    double                            tick_hz_        = 100.0;
    uint64_t                          boot_time_      = 0; // epoch seconds

    void read_stat(ProcessInfo& p, const Snapshot* prev, uint64_t cpu_delta) const;
    void read_cmdline(ProcessInfo& p) const;
    void read_exe(ProcessInfo& p) const;
    void read_username(ProcessInfo& p) const;
    uint64_t total_cpu_jiffies() const;
};

} // namespace proc
