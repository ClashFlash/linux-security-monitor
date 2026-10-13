#include <gtest/gtest.h>
#include "process.hpp"
#include <unistd.h>

using namespace proc;

TEST(ProcessTest, RefreshPopulatesProcesses) {
    ProcessMonitor mon;
    mon.refresh();
    auto procs = mon.processes();
    EXPECT_FALSE(procs.empty()) << "/proc should contain processes";

    // Own PID must be present
    int my_pid = getpid();
    bool found_self = false;
    for (const auto& p : procs) {
        if (p.pid == my_pid) {
            found_self = true;
            EXPECT_FALSE(p.name.empty());
            EXPECT_FALSE(p.username.empty());
            break;
        }
    }
    EXPECT_TRUE(found_self) << "Process list must include the current test process";
}

TEST(ProcessTest, SortByPid) {
    ProcessMonitor mon;
    mon.refresh();
    auto sorted = mon.sorted(SortField::PID);
    ASSERT_GT(sorted.size(), 1u);
    for (size_t i = 1; i < sorted.size(); ++i) {
        EXPECT_LE(sorted[i - 1]->pid, sorted[i]->pid);
    }
}

TEST(ProcessTest, SortByCpu) {
    ProcessMonitor mon;
    mon.refresh();
    auto sorted = mon.sorted(SortField::CPU);
    ASSERT_GT(sorted.size(), 1u);
    for (size_t i = 1; i < sorted.size(); ++i) {
        EXPECT_GE(sorted[i - 1]->cpu_pct, sorted[i]->cpu_pct);
    }
}

TEST(ProcessTest, SortByMem) {
    ProcessMonitor mon;
    mon.refresh();
    auto sorted = mon.sorted(SortField::MEM);
    ASSERT_GT(sorted.size(), 1u);
    for (size_t i = 1; i < sorted.size(); ++i) {
        EXPECT_GE(sorted[i - 1]->mem_pct, sorted[i]->mem_pct);
    }
}

TEST(ProcessTest, FilterByName) {
    ProcessMonitor mon;
    mon.refresh();
    int my_pid = getpid();
    auto self_detail = mon.detail(my_pid);
    ASSERT_FALSE(self_detail.name.empty());

    auto filtered = mon.filter(self_detail.name);
    EXPECT_FALSE(filtered.empty());
    bool found_self = false;
    for (const auto* p : filtered) {
        if (p->pid == my_pid) {
            found_self = true;
            break;
        }
    }
    EXPECT_TRUE(found_self);
}

TEST(ProcessTest, DetailReturnsValidInfo) {
    ProcessMonitor mon;
    mon.refresh();
    int my_pid = getpid();
    auto d = mon.detail(my_pid);
    EXPECT_EQ(d.pid, my_pid);
    EXPECT_GE(d.fd_count, 0) << "Current process must have non-negative open FDs";
}
