#include <gtest/gtest.h>
#include "security_rules.hpp"
#include "process.hpp"
#include "network.hpp"
#include "event_system.hpp"

using namespace rules;
using proc::ProcessInfo;
using proc::ProcState;
using net::Connection;
using net::ConnState;
using net::Proto;

// Helper to make a ProcessInfo
static ProcessInfo make_proc(int pid, uid_t uid, const std::string& exe) {
    ProcessInfo p;
    p.pid      = pid;
    p.uid      = uid;
    p.name     = "test";
    p.exe_path = exe;
    p.state    = ProcState::Running;
    return p;
}

// Helper to make a listening Connection
static Connection make_listen(uint16_t port, int pid) {
    Connection c;
    c.proto      = Proto::TCP;
    c.local_port = port;
    c.remote_port = 0;
    c.state      = ConnState::LISTEN;
    c.pid        = pid;
    return c;
}

// Helper to make an ESTABLISHED Connection
static Connection make_established(int pid, const std::string& remote_addr, uint16_t remote_port) {
    Connection c;
    c.proto       = Proto::TCP;
    c.local_port  = 12345;
    c.remote_addr = remote_addr;
    c.remote_port = remote_port;
    c.state       = ConnState::ESTABLISHED;
    c.pid         = pid;
    return c;
}

// ── check_tmp_process ───────────────────────────────────────────────────────

TEST(SecurityRules, TmpProcessTriggers) {
    auto p = make_proc(1234, 1000, "/tmp/evil");
    auto r = check_tmp_process(p);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::HIGH);
}

TEST(SecurityRules, TmpProcessDevShm) {
    auto p = make_proc(1234, 1000, "/dev/shm/payload");
    EXPECT_TRUE(check_tmp_process(p).triggered);
}

TEST(SecurityRules, TmpProcessRunUser) {
    auto p = make_proc(1234, 1000, "/run/user/1000/prog");
    EXPECT_TRUE(check_tmp_process(p).triggered);
}

TEST(SecurityRules, NormalProcessNoTrigger) {
    auto p = make_proc(1234, 1000, "/usr/bin/bash");
    EXPECT_FALSE(check_tmp_process(p).triggered);
}

// ── check_deleted_exe ───────────────────────────────────────────────────────

TEST(SecurityRules, DeletedExeTriggers) {
    auto p = make_proc(9999, 1000, "/usr/bin/something (deleted)");
    auto r = check_deleted_exe(p);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::HIGH);
}

TEST(SecurityRules, DeletedExeWordInMiddleNoTrigger) {
    auto p = make_proc(9999, 1000, "/usr/bin/deleted_old_tool");
    EXPECT_FALSE(check_deleted_exe(p).triggered);
}

// ── check_root_suspicious ───────────────────────────────────────────────────

TEST(SecurityRules, RootFromTmpIsCritical) {
    auto p = make_proc(1, 0, "/tmp/rootkit");
    auto r = check_root_suspicious(p);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::CRITICAL);
}

TEST(SecurityRules, NonRootFromTmpNotCritical) {
    auto p = make_proc(1, 1000, "/tmp/notroot");
    EXPECT_FALSE(check_root_suspicious(p).triggered);
}

TEST(SecurityRules, RootFromNormalPathOk) {
    auto p = make_proc(1, 0, "/sbin/init");
    EXPECT_FALSE(check_root_suspicious(p).triggered);
}

// ── check_new_listening_port ────────────────────────────────────────────────

TEST(SecurityRules, NewListenPortMatchesPid) {
    auto p = make_proc(5555, 1000, "/usr/bin/nginx");
    std::vector<Connection> new_ports = {make_listen(8080, 5555)};
    auto r = check_new_listening_port(p, new_ports);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::MEDIUM);
}

TEST(SecurityRules, NewListenPortDifferentPidNoTrigger) {
    auto p = make_proc(5555, 1000, "/usr/bin/nginx");
    std::vector<Connection> new_ports = {make_listen(8080, 9999)};
    EXPECT_FALSE(check_new_listening_port(p, new_ports).triggered);
}

// ── check_suspicious_outbound ───────────────────────────────────────────────

TEST(SecurityRules, TmpProcessOutboundTriggers) {
    auto p = make_proc(7777, 1000, "/tmp/backdoor");
    std::vector<Connection> conns = {make_established(7777, "1.2.3.4", 4444)};
    auto r = check_suspicious_outbound(p, conns);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::HIGH);
}

TEST(SecurityRules, NormalProcessOutboundOk) {
    auto p = make_proc(7777, 1000, "/usr/bin/curl");
    std::vector<Connection> conns = {make_established(7777, "1.2.3.4", 443)};
    EXPECT_FALSE(check_suspicious_outbound(p, conns).triggered);
}

// ── SecurityEngine integration ──────────────────────────────────────────────

TEST(SecurityRules, EngineEmitsEventForTmpProcess) {
    auto log = std::make_shared<events::EventLog>("");
    SecurityEngine engine(log);

    auto p = make_proc(1234, 1000, "/tmp/evil");
    engine.evaluate({p}, {}, {});

    auto events = log->snapshot();
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events[0].category, events::Category::PROCESS);
    EXPECT_EQ(events[0].severity, events::Severity::HIGH);
}

TEST(SecurityRules, EngineDeduplicate) {
    auto log = std::make_shared<events::EventLog>("");
    SecurityEngine engine(log);

    auto p = make_proc(1234, 1000, "/tmp/evil");
    engine.evaluate({p}, {}, {});
    size_t count_first = log->count();

    engine.evaluate({p}, {}, {});
    size_t count_second = log->count();

    // Should not re-fire the same PID for the same rule
    EXPECT_EQ(count_first, count_second);
}
