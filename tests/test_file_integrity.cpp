#include <gtest/gtest.h>
#include "file_integrity.hpp"
#include "event_system.hpp"
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;
using namespace integrity;

class FileIntegrityTest : public ::testing::Test {
protected:
    fs::path tmpdir;

    void SetUp() override {
        tmpdir = fs::temp_directory_path() / ("lsm_test_" + std::to_string(getpid()));
        fs::create_directories(tmpdir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmpdir, ec);
    }

    fs::path make_file(const std::string& name, const std::string& content) {
        auto path = tmpdir / name;
        std::ofstream f(path);
        f << content;
        return path;
    }
};

TEST_F(FileIntegrityTest, Sha256SameContentSameHash) {
    auto p = make_file("a.txt", "hello world");
    auto q = make_file("b.txt", "hello world");
    EXPECT_EQ(sha256_file(p), sha256_file(q));
}

TEST_F(FileIntegrityTest, Sha256DifferentContentDifferentHash) {
    auto p = make_file("a.txt", "hello");
    auto q = make_file("b.txt", "world");
    EXPECT_NE(sha256_file(p), sha256_file(q));
}

TEST_F(FileIntegrityTest, Sha256KnownVector) {
    // SHA-256 of empty string is well-known
    auto p = make_file("empty.txt", "");
    EXPECT_EQ(sha256_file(p),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_F(FileIntegrityTest, Sha256NonexistentReturnsEmpty) {
    EXPECT_EQ(sha256_file(tmpdir / "no_such_file.txt"), "");
}

TEST_F(FileIntegrityTest, DetectsModification) {
    auto p = make_file("watched.txt", "original content");

    auto log = std::make_shared<events::EventLog>("");
    FileIntegrityMonitor mon(log, {tmpdir});
    mon.baseline();

    // Modify the file
    {
        std::ofstream f(p, std::ios::trunc);
        f << "modified content";
    }

    auto changes = mon.scan();
    ASSERT_FALSE(changes.empty());
    bool found = false;
    for (const auto& c : changes) {
        if (c.path == p && c.type == ChangeType::MODIFIED) { found = true; break; }
    }
    EXPECT_TRUE(found) << "Should detect file modification";
}

TEST_F(FileIntegrityTest, DetectsCreation) {
    auto log = std::make_shared<events::EventLog>("");
    FileIntegrityMonitor mon(log, {tmpdir});
    mon.baseline();

    // Create a new file
    make_file("new_file.txt", "brand new");

    auto changes = mon.scan();
    bool found = false;
    for (const auto& c : changes) {
        if (c.type == ChangeType::CREATED) { found = true; break; }
    }
    EXPECT_TRUE(found) << "Should detect file creation";
}

TEST_F(FileIntegrityTest, DetectsDeletion) {
    auto p = make_file("to_delete.txt", "bye");

    auto log = std::make_shared<events::EventLog>("");
    FileIntegrityMonitor mon(log, {tmpdir});
    mon.baseline();

    fs::remove(p);

    auto changes = mon.scan();
    bool found = false;
    for (const auto& c : changes) {
        if (c.path == p && c.type == ChangeType::DELETED) { found = true; break; }
    }
    EXPECT_TRUE(found) << "Should detect file deletion";
}

TEST_F(FileIntegrityTest, NoChangeWhenFileUnchanged) {
    make_file("stable.txt", "no change here");

    auto log = std::make_shared<events::EventLog>("");
    FileIntegrityMonitor mon(log, {tmpdir});
    mon.baseline();

    auto changes = mon.scan();
    EXPECT_TRUE(changes.empty()) << "Should not report spurious changes";
}

TEST_F(FileIntegrityTest, EmitsEventOnModification) {
    auto p = make_file("watched2.txt", "original");

    auto log = std::make_shared<events::EventLog>("");
    FileIntegrityMonitor mon(log, {tmpdir});
    mon.baseline();

    {
        std::ofstream f(p, std::ios::trunc);
        f << "changed";
    }
    mon.scan();

    auto events = log->snapshot();
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events[0].category, events::Category::FILE);
    EXPECT_EQ(events[0].severity, events::Severity::HIGH);
}
