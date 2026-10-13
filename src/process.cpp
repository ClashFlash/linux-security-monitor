#include "process.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <pwd.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <fcntl.h>

namespace proc {

ProcessMonitor::ProcessMonitor() {
    tick_hz_ = static_cast<double>(sysconf(_SC_CLK_TCK));
    if (tick_hz_ <= 0) tick_hz_ = 100.0;

    // Read boot time from /proc/stat
    std::ifstream f("/proc/stat");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("btime", 0) == 0) {
            std::istringstream ss(line);
            std::string k;
            ss >> k >> boot_time_;
            break;
        }
    }
}

uint64_t ProcessMonitor::total_cpu_jiffies() const {
    std::ifstream f("/proc/stat");
    if (!f) return 0;
    std::string label;
    uint64_t u, n, s, i, w, r, x, st;
    f >> label >> u >> n >> s >> i >> w >> r >> x >> st;
    return u + n + s + i + w + r + x + st;
}

uint64_t ProcessMonitor::read_mem_total_kb() {
    std::ifstream memf("/proc/meminfo");
    if (!memf) return 0;
    std::string k;
    uint64_t v = 0;
    memf >> k >> v;
    return v;
}

void ProcessMonitor::refresh() {
    std::vector<ProcessInfo> new_procs;
    std::unordered_map<int, Snapshot> new_prev;
    uint64_t total_now = total_cpu_jiffies();
    uint64_t total_delta = (total_now > prev_total_cpu_) ? total_now - prev_total_cpu_ : 1;
    uint64_t mem_total_kb = read_mem_total_kb();

    DIR* dir = opendir("/proc");
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
        char* end = nullptr;
        long pid_l = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid_l <= 0) continue;
        int pid = static_cast<int>(pid_l);

        ProcessInfo p;
        p.pid = pid;

        // Find previous snapshot
        const Snapshot* prev_snap = nullptr;
        auto it = prev_.find(pid);
        if (it != prev_.end()) prev_snap = &it->second;

        Snapshot sn{};
        read_stat(p, prev_snap, total_delta, mem_total_kb, sn);
        if (p.name.empty()) continue; // Process died or unreadable

        sn.total_cpu_time = total_now;
        new_prev[pid] = sn;

        read_cmdline(p);
        read_exe(p);
        read_username(p);

        // Check anomaly flags
        if (!p.exe_path.empty()) {
            p.exe_deleted = (p.exe_path.size() >= 9 &&
                p.exe_path.substr(p.exe_path.size() - 9) == " (deleted)");
            p.from_tmp =
                p.exe_path.rfind("/tmp",     0) == 0 ||
                p.exe_path.rfind("/dev/shm", 0) == 0 ||
                p.exe_path.rfind("/run/user",0) == 0 ||
                p.exe_path.rfind("/var/tmp", 0) == 0;
            // World-writable check (lightweight stat)
            struct stat st{};
            if (!p.from_tmp && ::stat(p.exe_path.c_str(), &st) == 0)
                p.from_writable_path = (st.st_mode & S_IWOTH) != 0;
            p.root_from_suspicious = (p.uid == 0) &&
                (p.from_tmp || p.from_writable_path);
        }

        new_procs.push_back(std::move(p));
    }
    closedir(dir);

    std::lock_guard<std::mutex> lock(mutex_);
    prev_total_cpu_ = total_now;
    prev_ = std::move(new_prev);
    procs_ = std::move(new_procs);
}

void ProcessMonitor::read_stat(ProcessInfo& p, const Snapshot* prev,
                               uint64_t cpu_delta, uint64_t mem_total_kb,
                               Snapshot& out_snap) const
{
    std::string path = "/proc/" + std::to_string(p.pid) + "/stat";

    // Read UID directly via stat on /proc/<pid>/stat
    struct stat pst{};
    if (::stat(path.c_str(), &pst) == 0) {
        p.uid = pst.st_uid;
    } else {
        p.uid = 65534;
    }

    std::ifstream f(path);
    if (!f) return;
    std::string line;
    if (!std::getline(f, line)) return;

    // Format: pid (name) state ppid pgroup session tty_nr ...
    // Name can contain spaces/parens: find last ')'
    auto lp = line.find('(');
    auto rp = line.rfind(')');
    if (lp == std::string::npos || rp == std::string::npos || rp <= lp) return;

    p.name = line.substr(lp + 1, rp - lp - 1);

    std::istringstream ss(line.substr(rp + 2));
    char state_c = '?';
    int ppid = 0;
    uint64_t skip = 0, utime = 0, stime = 0, starttime = 0;
    uint64_t rss = 0;

    ss >> state_c >> ppid;
    for (int i = 0; i < 11; ++i) ss >> skip; // fields 5-15
    ss >> utime >> stime;                    // fields 14,15
    for (int i = 0; i < 6; ++i) ss >> skip;  // skip to starttime(22)
    ss >> starttime;                         // field 22
    ss >> skip >> rss;                       // vsize(23), rss(24)

    out_snap.utime = utime;
    out_snap.stime = stime;

    p.ppid  = ppid;
    p.state = static_cast<ProcState>(state_c);
    p.rss_kb = rss * 4; // pages -> KB (assume 4K pages)

    // CPU%
    if (prev && cpu_delta > 0) {
        uint64_t prev_proc = prev->utime + prev->stime;
        uint64_t curr_proc = utime + stime;
        if (curr_proc > prev_proc) {
            uint64_t proc_delta = curr_proc - prev_proc;
            p.cpu_pct = static_cast<float>(proc_delta) /
                        static_cast<float>(cpu_delta) * 100.f;
        }
    }

    // Memory%
    if (mem_total_kb > 0)
        p.mem_pct = static_cast<float>(p.rss_kb) / static_cast<float>(mem_total_kb) * 100.f;

    // Start time -> epoch
    p.start_time_epoch = boot_time_ + starttime / static_cast<uint64_t>(tick_hz_);
    time_t t = static_cast<time_t>(p.start_time_epoch);
    char buf[32];
    struct tm tm_info{};
    if (localtime_r(&t, &tm_info)) {
        strftime(buf, sizeof(buf), "%b%d %H:%M", &tm_info);
        p.start_time_str = buf;
    }
}

void ProcessMonitor::read_cmdline(ProcessInfo& p) const {
    std::string path = "/proc/" + std::to_string(p.pid) + "/cmdline";
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return;

    char buf[2048];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);

    if (n > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            if (buf[i] == '\0') buf[i] = ' ';
        }
        while (n > 0 && buf[n - 1] == ' ') n--;
        p.cmdline.assign(buf, static_cast<size_t>(n));
    }
    if (p.cmdline.empty()) {
        p.cmdline = "[" + p.name + "]";
    }
}

void ProcessMonitor::read_exe(ProcessInfo& p) const {
    std::string link = "/proc/" + std::to_string(p.pid) + "/exe";
    char buf[4096] = {};
    ssize_t len = readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        p.exe_path = buf;
    }
}

void ProcessMonitor::read_username(ProcessInfo& p) const {
    auto it = username_cache_.find(p.uid);
    if (it != username_cache_.end()) {
        p.username = it->second;
        return;
    }

    struct passwd* pw = getpwuid(p.uid);
    std::string uname = pw ? pw->pw_name : std::to_string(p.uid);
    username_cache_[p.uid] = uname;
    p.username = std::move(uname);
}

std::vector<ProcessInfo> ProcessMonitor::processes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return procs_;
}

std::vector<const ProcessInfo*> ProcessMonitor::sorted(SortField f) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<const ProcessInfo*> v;
    v.reserve(procs_.size());
    for (const auto& p : procs_) v.push_back(&p);
    std::sort(v.begin(), v.end(), [f](const ProcessInfo* a, const ProcessInfo* b) {
        if (f == SortField::CPU) return a->cpu_pct  > b->cpu_pct;
        if (f == SortField::MEM) return a->mem_pct  > b->mem_pct;
        return a->pid < b->pid;
    });
    return v;
}

std::vector<const ProcessInfo*> ProcessMonitor::filter(const std::string& query) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<const ProcessInfo*> v;
    for (const auto& p : procs_) {
        if (p.name.find(query)    != std::string::npos ||
            p.cmdline.find(query) != std::string::npos)
            v.push_back(&p);
    }
    return v;
}

ProcessInfo ProcessMonitor::detail(int pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& p : procs_) {
        if (p.pid == pid) {
            ProcessInfo d = p;
            std::string fd_path = "/proc/" + std::to_string(pid) + "/fd";
            try {
                d.fd_count = static_cast<int>(
                    std::distance(std::filesystem::directory_iterator(fd_path),
                                  std::filesystem::directory_iterator{}));
            } catch (...) { d.fd_count = -1; }
            return d;
        }
    }
    return {};
}

} // namespace proc
