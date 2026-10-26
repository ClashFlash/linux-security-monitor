#include <gtest/gtest.h>
#include "security_rules.hpp"
#include "process.hpp"
#include "network.hpp"
#include "event_system.hpp"
#include <thread>
#include <chrono>

using namespace rules;
using proc::ProcessInfo;
using proc::ProcState;
using net::Connection;
using net::ConnState;
using net::Proto;

// ── Helpers ──────────────────────────────────────────────────────────────────

static ProcessInfo make_proc(int pid, uid_t uid, const std::string& exe,
                             const std::string& name = "test", int ppid = 1)
{
    ProcessInfo p;
    p.pid      = pid;
    p.ppid     = ppid;
    p.uid      = uid;
    p.name     = name;
    p.exe_path = exe;
    p.state    = ProcState::Running;
    p.username = (uid == 0) ? "root" : "user";
    return p;
}

static Connection make_listen(uint16_t port, int pid) {
    Connection c;
    c.proto      = Proto::TCP;
    c.local_addr = "0.0.0.0";
    c.local_port = port;
    c.remote_port = 0;
    c.state      = ConnState::LISTEN;
    c.pid        = pid;
    return c;
}

static Connection make_established(int pid, const std::string& remote, uint16_t rport) {
    Connection c;
    c.proto       = Proto::TCP;
    c.local_addr  = "192.168.1.10";
    c.local_port  = 54321;
    c.remote_addr = remote;
    c.remote_port = rport;
    c.state       = ConnState::ESTABLISHED;
    c.pid         = pid;
    return c;
}

// ── check_service_shell (parent-child chain) ─────────────────────────────────

TEST(ProcessParentChain, ServiceShellTriggers) {
    auto parent = make_proc(100, 0, "/usr/sbin/nginx", "nginx");
    auto child  = make_proc(200, 0, "/bin/bash", "bash", 100);
    auto r = check_service_shell(child, &parent);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::HIGH);
}

TEST(ProcessParentChain, SystemdShellIsLow) {
    auto parent = make_proc(1, 0, "/lib/systemd/systemd", "systemd");
    auto child  = make_proc(200, 1000, "/bin/sh", "sh", 1);
    auto r = check_service_shell(child, &parent);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::LOW); // systemd spawning shells during service start
}

TEST(ProcessParentChain, NonServiceParentNoTrigger) {
    auto parent = make_proc(100, 1000, "/usr/bin/bash", "bash");
    auto child  = make_proc(200, 1000, "/bin/sh", "sh", 100);
    // bash is not a service-like name
    auto r = check_service_shell(child, &parent);
    EXPECT_FALSE(r.triggered);
}

TEST(ProcessParentChain, NoParentNoTrigger) {
    auto child = make_proc(200, 1000, "/bin/bash", "bash");
    auto r = check_service_shell(child, nullptr);
    EXPECT_FALSE(r.triggered);
}

TEST(ProcessParentChain, SshdSpawnsBashIsHigh) {
    auto parent = make_proc(100, 0, "/usr/sbin/sshd", "sshd");
    auto child  = make_proc(200, 1000, "/bin/bash", "bash", 100);
    auto r = check_service_shell(child, &parent);
    EXPECT_TRUE(r.triggered);
    // sshd is not "systemd", so HIGH
    EXPECT_EQ(r.severity, events::Severity::HIGH);
}

// ── check_new_listening_port (process opens a port) ──────────────────────────

TEST(ProcessNetworkLink, SuspiciousProcessOpensPort) {
    auto p = make_proc(555, 1000, "/tmp/malware");
    std::vector<Connection> new_ports = {make_listen(4444, 555)};
    std::set<uint16_t> trusted;
    auto r = check_new_listening_port(p, new_ports, trusted);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::MEDIUM);
}

TEST(ProcessNetworkLink, TrustedPortNotFlagged) {
    auto p = make_proc(555, 1000, "/usr/bin/nginx");
    std::vector<Connection> new_ports = {make_listen(80, 555)};
    std::set<uint16_t> trusted = {80};
    EXPECT_FALSE(check_new_listening_port(p, new_ports, trusted).triggered);
}

TEST(ProcessNetworkLink, PortBelongingToOtherPidNoTrigger) {
    auto p = make_proc(555, 1000, "/tmp/evil");
    std::vector<Connection> new_ports = {make_listen(4444, 999)}; // different PID
    EXPECT_FALSE(check_new_listening_port(p, new_ports).triggered);
}

// ── check_suspicious_outbound (from temp/writable path) ──────────────────────

TEST(ProcessOutbound, TmpOutboundToPublicTriggers) {
    auto p = make_proc(777, 1000, "/tmp/backdoor");
    std::vector<Connection> conns = {make_established(777, "8.8.8.8", 443)};
    auto r = check_suspicious_outbound(p, conns);
    EXPECT_TRUE(r.triggered);
    EXPECT_EQ(r.severity, events::Severity::HIGH);
}

TEST(ProcessOutbound, TmpOutboundToLoopbackOk) {
    auto p = make_proc(777, 1000, "/tmp/tool");
    std::vector<Connection> conns = {make_established(777, "127.0.0.1", 8080)};
    EXPECT_FALSE(check_suspicious_outbound(p, conns).triggered);
}

TEST(ProcessOutbound, SystemBinaryOutboundOk) {
    auto p = make_proc(777, 0, "/usr/bin/curl");
    std::vector<Connection> conns = {make_established(777, "1.2.3.4", 443)};
    EXPECT_FALSE(check_suspicious_outbound(p, conns).triggered);
}

// ── SecurityEngine deduplication across refresh cycles ───────────────────────

TEST(SecurityEngine, SameRuleDoesNotFireTwiceForSamePid) {
    auto log = std::make_shared<events::EventLog>("");
    SecurityEngine engine(log);
    auto p = make_proc(1234, 1000, "/tmp/evil");
    engine.evaluate({p}, {}, {});
    size_t after_first = log->count();
    engine.evaluate({p}, {}, {});
    EXPECT_EQ(log->count(), after_first);
}

TEST(SecurityEngine, DifferentPidsFireSeparately) {
    auto log = std::make_shared<events::EventLog>("");
    SecurityEngine engine(log);
    auto p1 = make_proc(1000, 1000, "/tmp/evil1");
    auto p2 = make_proc(1001, 1000, "/tmp/evil2");
    engine.evaluate({p1}, {}, {});
    size_t after_first = log->count();
    engine.evaluate({p2}, {}, {});
    EXPECT_GT(log->count(), after_first);
}

TEST(SecurityEngine, AllRulesFireForRootTmpProcess) {
    auto log = std::make_shared<events::EventLog>("");
    SecurityEngine engine(log);
    // UID 0 + /tmp => triggers check_tmp_process, check_root_suspicious
    auto p = make_proc(9999, 0, "/tmp/rootkit");
    engine.evaluate({p}, {}, {});
    auto evs = log->snapshot();
    // At minimum tmp_process + root_suspicious
    EXPECT_GE(evs.size(), 2u);
    bool has_critical = false;
    for (const auto& e : evs)
        if (e.severity == events::Severity::CRITICAL) has_critical = true;
    EXPECT_TRUE(has_critical);
}

// ── Evidence content validation ───────────────────────────────────────────────

TEST(RuleResult, TmpProcessEvidenceContainsPid) {
    auto p = make_proc(42, 1000, "/dev/shm/implant");
    p.username = "flashy";
    auto r = check_tmp_process(p);
    EXPECT_TRUE(r.triggered);
    EXPECT_NE(r.evidence.find("PID=42"), std::string::npos);
    EXPECT_NE(r.details.find("flashy"), std::string::npos);
}

TEST(RuleResult, DeletedExeEvidenceContainsPath) {
    auto p = make_proc(77, 1000, "/usr/bin/legit (deleted)");
    auto r = check_deleted_exe(p);
    EXPECT_TRUE(r.triggered);
    EXPECT_NE(r.evidence.find("/usr/bin/legit"), std::string::npos);
}
