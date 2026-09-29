#include "cpu.hpp"
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace cpu {

CpuMonitor::CpuMonitor() {
    prev_ = read_proc_stat(); // Initial snapshot
}

void CpuMonitor::refresh() {
    auto curr = read_proc_stat();
    if (curr.empty()) return;

    // Overall (index 0 = aggregate "cpu" line)
    if (!prev_.empty()) {
        overall_ = compute_pct(prev_[0], curr[0]);
    }

    // Per-core (indices 1+)
    cores_.clear();
    for (size_t i = 1; i < curr.size(); ++i) {
        CoreStats cs;
        cs.core_id   = static_cast<int>(i) - 1;
        cs.usage_pct = (i < prev_.size()) ? compute_pct(prev_[i], curr[i]) : 0.f;
        cores_.push_back(cs);
    }

    prev_ = curr;
}

float CpuMonitor::compute_pct(const CpuSnapshot& prev, const CpuSnapshot& curr) {
    // Guard against the total going backwards (counter reset or first sample)
    if (curr.total() <= prev.total()) return 0.f;
    uint64_t total_delta = curr.total() - prev.total();
    if (total_delta == 0) return 0.f;
    // busy can also only go forward; clamp underflow
    uint64_t prev_busy = prev.busy();
    uint64_t curr_busy = curr.busy();
    if (curr_busy <= prev_busy) return 0.f;
    uint64_t busy_delta = curr_busy - prev_busy;
    return static_cast<float>(busy_delta) / static_cast<float>(total_delta) * 100.f;
}

std::vector<CpuSnapshot> CpuMonitor::read_proc_stat() {
    std::ifstream f("/proc/stat");
    if (!f) return {};

    std::vector<CpuSnapshot> snaps;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("cpu", 0) != 0) break; // cpu lines are always first
        std::istringstream ss(line);
        std::string label;
        CpuSnapshot s;
        ss >> label >> s.user >> s.nice >> s.system >> s.idle
           >> s.iowait >> s.irq >> s.softirq >> s.steal;
        snaps.push_back(s);
    }
    return snaps;
}

} // namespace cpu
