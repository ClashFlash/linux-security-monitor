#include <gtest/gtest.h>
#include "incident.hpp"
#include "event_system.hpp"
#include <filesystem>
#include <fstream>
#include <cstdio>

using namespace incidents;
using namespace events;

// Helper: build a minimal event with a grouping key
static Event make_event(Category cat, Severity sev,
                        const std::string& title,
                        const std::string& gkey,
                        int pid = -1,
                        const std::string& user = "",
                        const std::string& why = "test-why",
                        const std::string& next = "test-next")
{
    Event e;
    e.timestamp    = std::chrono::system_clock::now();
    e.category     = cat;
    e.severity     = sev;
    e.source       = "test";
    e.title        = title;
    e.grouping_key = gkey;
    e.pid          = pid;
    e.username     = user;
    e.why_suspicious = why;
    e.next_steps   = next;
    return e;
}

// ── IncidentStore basic ingestion ────────────────────────────────────────────

TEST(IncidentStore, IngestsEventCreatesIncident) {
    IncidentStore store("");
    auto ev = make_event(Category::PROCESS, Severity::HIGH, "Test alert", "proc:1234");
    store.ingest(ev);
    EXPECT_EQ(store.count_open(), 1u);
    auto list = store.snapshot();
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].grouping_key, "proc:1234");
    EXPECT_EQ(list[0].status, Status::OPEN);
    EXPECT_EQ(list[0].max_severity, Severity::HIGH);
}

TEST(IncidentStore, SameKeyGroupsIntoOne) {
    IncidentStore store("");
    store.ingest(make_event(Category::AUTH, Severity::MEDIUM, "Fail 1", "auth:1.2.3.4"));
    store.ingest(make_event(Category::AUTH, Severity::HIGH,   "Fail 2", "auth:1.2.3.4"));
    EXPECT_EQ(store.count_open(), 1u);
    auto list = store.snapshot();
    ASSERT_EQ(list.size(), 1u);
    // Max severity should be escalated
    EXPECT_EQ(list[0].max_severity, Severity::HIGH);
    EXPECT_EQ(list[0].evidence_events.size(), 2u);
}

TEST(IncidentStore, DifferentKeysCreateSeparateIncidents) {
    IncidentStore store("");
    store.ingest(make_event(Category::PROCESS, Severity::HIGH, "A", "proc:100"));
    store.ingest(make_event(Category::NETWORK, Severity::MEDIUM, "B", "net:200"));
    EXPECT_EQ(store.count_open(), 2u);
}

TEST(IncidentStore, EmptyKeyIsIgnored) {
    IncidentStore store("");
    Event e = make_event(Category::SYSTEM, Severity::LOW, "System start", "");
    store.ingest(e);
    EXPECT_EQ(store.count_open(), 0u);
}

TEST(IncidentStore, LowSystemEventsWithoutKeyIgnored) {
    IncidentStore store("");
    // LOW + SYSTEM + empty gkey: should not create incident
    store.ingest(make_event(Category::SYSTEM, Severity::LOW, "Startup", ""));
    EXPECT_EQ(store.count_open(), 0u);
}

// ── Status transitions ───────────────────────────────────────────────────────

TEST(IncidentStore, StatusTransitionWorks) {
    IncidentStore store("");
    store.ingest(make_event(Category::FILE, Severity::HIGH, "Shadow modified", "file:/etc/shadow"));
    auto list = store.snapshot();
    ASSERT_FALSE(list.empty());
    std::string id = list[0].id;

    EXPECT_TRUE(store.set_status(id, Status::ACKNOWLEDGED));
    auto after = store.get(id);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->status, Status::ACKNOWLEDGED);
}

TEST(IncidentStore, ResolvedIncidentIsNotOpen) {
    IncidentStore store("");
    store.ingest(make_event(Category::PROCESS, Severity::CRITICAL, "Rootkit", "proc:9999", 9999));
    auto id = store.snapshot()[0].id;
    store.set_status(id, Status::RESOLVED);
    EXPECT_EQ(store.count_open(), 0u);
}

TEST(IncidentStore, ResolvedIncidentGetsNewGroupOnNextEvent) {
    IncidentStore store("");
    store.ingest(make_event(Category::AUTH, Severity::HIGH, "Burst 1", "auth:5.5.5.5"));
    auto id = store.snapshot()[0].id;
    store.set_status(id, Status::RESOLVED);

    // New event with same key should open a new incident
    store.ingest(make_event(Category::AUTH, Severity::HIGH, "Burst 2", "auth:5.5.5.5"));
    EXPECT_EQ(store.count_open(), 1u);
    auto list = store.snapshot();
    EXPECT_NE(list.back().id, id); // new incident
}

// ── Persistence ──────────────────────────────────────────────────────────────

TEST(IncidentStore, PersistAndReload) {
    // Use a temp file
    auto tmp = std::filesystem::temp_directory_path() / "lsm_test_incidents.store";
    std::filesystem::remove(tmp); // ensure clean state
    {
        IncidentStore store(tmp);
        store.ingest(make_event(Category::PROCESS, Severity::HIGH, "Persistent alert",
                                "proc:777", 777, "root", "suspicious exec", "check it"));
        store.set_status(store.snapshot()[0].id, Status::INVESTIGATING);
    }
    // Reload from disk
    {
        IncidentStore store(tmp);
        auto list = store.snapshot();
        ASSERT_EQ(list.size(), 1u);
        EXPECT_EQ(list[0].status, Status::INVESTIGATING);
        EXPECT_EQ(list[0].related_pid, 777);
    }
    std::filesystem::remove(tmp);
}

// ── Export ───────────────────────────────────────────────────────────────────

TEST(IncidentStore, ExportReportWritesFile) {
    auto tmp_dir = std::filesystem::temp_directory_path() / "lsm_report_test";
    std::filesystem::create_directories(tmp_dir);

    IncidentStore store("");
    store.ingest(make_event(Category::FILE, Severity::CRITICAL, "SSH config changed",
                            "file:/etc/ssh/sshd_config", -1, "",
                            "/etc/ssh/sshd_config was modified", "Review the diff"));
    auto id = store.snapshot()[0].id;

    auto path = store.export_report(id, tmp_dir);
    EXPECT_FALSE(path.empty());
    EXPECT_TRUE(std::filesystem::exists(path));

    // Report should contain meaningful fields
    std::ifstream f(path);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    EXPECT_TRUE(content.find("SSH config changed") != std::string::npos);
    EXPECT_TRUE(content.find("Incident Report") != std::string::npos);

    std::filesystem::remove_all(tmp_dir);
}

// ── EventLog -> IncidentStore callback chain ─────────────────────────────────

TEST(IncidentStore, EventLogCallbackFeeds) {
    auto log = std::make_shared<events::EventLog>("");
    IncidentStore store("");
    log->on_event([&](const events::Event& e) { store.ingest(e); });

    Event e = make_event(Category::NETWORK, Severity::HIGH,
                         "New port opened", "net:listen:8888");
    e.extra = "8888";
    log->push(e);

    EXPECT_EQ(store.count_open(), 1u);
}
