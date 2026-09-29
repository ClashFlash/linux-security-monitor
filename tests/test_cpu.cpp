#include <gtest/gtest.h>
#include "cpu.hpp"

using namespace cpu;

TEST(CpuTest, ComputePctZeroWhenNoChange) {
    CpuSnapshot s{100, 0, 50, 200, 0, 0, 0, 0};
    EXPECT_FLOAT_EQ(0.f, CpuMonitor::compute_pct(s, s));
}

TEST(CpuTest, ComputePct100PercentBusy) {
    CpuSnapshot prev{0, 0, 0, 0, 0, 0, 0, 0};
    CpuSnapshot curr{100, 0, 0, 0, 0, 0, 0, 0}; // 100 user, 0 idle
    // busy_delta = 100, total_delta = 100 → 100%
    EXPECT_FLOAT_EQ(100.f, CpuMonitor::compute_pct(prev, curr));
}

TEST(CpuTest, ComputePct50PercentBusy) {
    CpuSnapshot prev{0, 0, 0, 0, 0, 0, 0, 0};
    CpuSnapshot curr{50, 0, 0, 50, 0, 0, 0, 0}; // 50 user, 50 idle
    EXPECT_FLOAT_EQ(50.f, CpuMonitor::compute_pct(prev, curr));
}

TEST(CpuTest, ComputePctDeltaAcrossSnapshots) {
    // Simulate two consecutive reads
    CpuSnapshot prev{1000, 0, 200, 8000, 100, 0, 0, 0};
    CpuSnapshot curr{1100, 0, 250, 8200, 100, 0, 0, 0};
    // busy_delta = (1100+250)-(1000+200) = 150; total_delta = 9650-9300 = 350
    float expected = 150.f / 350.f * 100.f;
    EXPECT_NEAR(expected, CpuMonitor::compute_pct(prev, curr), 0.1f);
}

TEST(CpuTest, ComputePctHandlesOverflow) {
    // When curr total < prev total (counter reset), guard returns 0
    CpuSnapshot prev{1000, 0, 200, 8000, 0, 0, 0, 0};
    CpuSnapshot curr{0,    0,   0,    0, 0, 0, 0, 0};
    EXPECT_FLOAT_EQ(0.f, CpuMonitor::compute_pct(prev, curr));
}

TEST(CpuTest, ReadProcStatReturnsAtLeastOne) {
    auto snaps = CpuMonitor::read_proc_stat();
    ASSERT_FALSE(snaps.empty()) << "/proc/stat must be readable";
    // First entry is aggregate "cpu"
    EXPECT_GT(snaps[0].total(), 0ULL);
}

TEST(CpuTest, RefreshDoesNotCrash) {
    CpuMonitor mon;
    EXPECT_NO_THROW(mon.refresh());
    EXPECT_GE(mon.overall_pct(), 0.f);
    EXPECT_LE(mon.overall_pct(), 100.f);
}
