#include "memory.hpp"
#include <fstream>
#include <string>
#include <sstream>

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

    std::string key;
    uint64_t val;
    std::string unit;

    MemInfo m{};

    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        ss >> key >> val;
        // key ends with ':'
        if      (key == "MemTotal:")     m.total_kb     = val;
        else if (key == "MemAvailable:") m.available_kb = val;
        else if (key == "Buffers:")      m.buffers_kb   = val;
        else if (key == "Cached:")       m.cached_kb    = val;
        else if (key == "SwapTotal:")    m.swap_total_kb = val;
        else if (key == "SwapFree:") {
            m.swap_used_kb = m.swap_total_kb - val;
        }
    }

    m.used_kb = (m.total_kb > m.available_kb) ? m.total_kb - m.available_kb : 0;
    info_ = m;
}

} // namespace mem
