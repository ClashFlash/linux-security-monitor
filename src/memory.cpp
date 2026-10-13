#include "memory.hpp"
#include <fstream>
#include <string>
#include <sstream>
#include <cstring>

namespace mem {

float MemInfo::used_pct() const {
    if (total_kb == 0) return 0.f;
    return static_cast<float>(used_kb) / static_cast<float>(total_kb) * 100.f;
}

float MemInfo::swap_used_pct() const {
    if (swap_total_kb == 0) return 0.f;
    return static_cast<float>(swap_used_kb) / static_cast<float>(swap_total_kb) * 100.f;
}

void MemoryMonitor::refresh() {
    std::ifstream f("/proc/meminfo");
    if (!f) return;

    MemInfo m{};
    uint64_t mem_free_kb = 0;
    uint64_t swap_free_kb = 0;
    bool has_available = false;

    char key[64];
    uint64_t val = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (sscanf(line.c_str(), "%63s %lu", key, &val) != 2) continue;
        if      (strcmp(key, "MemTotal:") == 0)     m.total_kb      = val;
        else if (strcmp(key, "MemAvailable:") == 0) { m.available_kb = val; has_available = true; }
        else if (strcmp(key, "MemFree:") == 0)      mem_free_kb     = val;
        else if (strcmp(key, "Buffers:") == 0)      m.buffers_kb    = val;
        else if (strcmp(key, "Cached:") == 0)       m.cached_kb     = val;
        else if (strcmp(key, "SwapTotal:") == 0)    m.swap_total_kb = val;
        else if (strcmp(key, "SwapFree:") == 0)     swap_free_kb    = val;
    }

    if (!has_available) {
        m.available_kb = mem_free_kb + m.buffers_kb + m.cached_kb;
        if (m.available_kb > m.total_kb) m.available_kb = m.total_kb;
    }

    m.used_kb = (m.total_kb > m.available_kb) ? m.total_kb - m.available_kb : 0;
    m.swap_used_kb = (m.swap_total_kb > swap_free_kb) ? m.swap_total_kb - swap_free_kb : 0;

    std::lock_guard<std::mutex> lock(mutex_);
    info_ = m;
}

MemInfo MemoryMonitor::info() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return info_;
}

} // namespace mem
