#pragma once
#include <cstdint>

namespace mem {

struct MemInfo {
    uint64_t total_kb    = 0;
    uint64_t available_kb = 0;
    uint64_t used_kb     = 0;  // total - available
    uint64_t buffers_kb  = 0;
    uint64_t cached_kb   = 0;
    uint64_t swap_total_kb = 0;
    uint64_t swap_used_kb  = 0;

    float used_pct()      const;
    float swap_used_pct() const;

    // Convenience: MB values
    uint64_t total_mb()    const { return total_kb    / 1024; }
    uint64_t used_mb()     const { return used_kb     / 1024; }
    uint64_t available_mb()const { return available_kb/ 1024; }
    uint64_t swap_total_mb()const{ return swap_total_kb/1024; }
    uint64_t swap_used_mb() const{ return swap_used_kb /1024; }
};

class MemoryMonitor {
public:
    void refresh();
    const MemInfo& info() const { return info_; }

private:
    MemInfo info_;
};

} // namespace mem
