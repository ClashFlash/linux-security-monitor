#pragma once
#include <vector>
#include <string>
#include <cstdint>

#include <mutex>

namespace cpu {

struct CoreStats {
    int     core_id   = 0;
    float   usage_pct = 0.f;
};

struct CpuSnapshot {
    uint64_t user = 0, nice = 0, system = 0, idle = 0,
             iowait = 0, irq = 0, softirq = 0, steal = 0;

    uint64_t total() const { return user+nice+system+idle+iowait+irq+softirq+steal; }
    uint64_t busy()  const { return total() - idle - iowait; }
};

class CpuMonitor {
public:
    CpuMonitor();

    // Read /proc/stat and compute delta since last call
    void refresh();

    float overall_pct() const;
    std::vector<CoreStats> cores() const;

    // For unit-testing: compute pct from two raw snapshots
    static float compute_pct(const CpuSnapshot& prev, const CpuSnapshot& curr);

    // Read one snapshot from /proc/stat (public for tests)
    static std::vector<CpuSnapshot> read_proc_stat();

private:
    mutable std::mutex       mutex_;
    float                    overall_ = 0.f;
    std::vector<CoreStats>   cores_;
    std::vector<CpuSnapshot> prev_;
};

} // namespace cpu
