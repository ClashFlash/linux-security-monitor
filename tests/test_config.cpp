#include <gtest/gtest.h>
#include "config.hpp"
#include <fstream>
#include <filesystem>
#include <unistd.h>

namespace fs = std::filesystem;

class ConfigTest : public ::testing::Test {
protected:
    fs::path tmpdir;

    void SetUp() override {
        tmpdir = fs::temp_directory_path() / ("lsm_cfg_test_" + std::to_string(getpid()));
        fs::create_directories(tmpdir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmpdir, ec);
    }
};

TEST_F(ConfigTest, DefaultsAreSensible) {
    auto cfg = config::AppConfig::defaults();
    EXPECT_GT(cfg.monitored_paths.size(), 0u);
    EXPECT_EQ(cfg.ssh_fail_threshold, 5);
    EXPECT_EQ(cfg.ssh_fail_window_secs, 60);
    EXPECT_TRUE(cfg.sound_enabled);
    EXPECT_TRUE(cfg.notify_send_enabled);
    EXPECT_FALSE(cfg.event_log_path.empty());
}

TEST_F(ConfigTest, LoadThresholdsWithAliasesAndWhitespace) {
    fs::path tf = tmpdir / "thresholds.conf";
    {
        std::ofstream f(tf);
        f << "# Comment line\n";
        f << "terminal_bell = CRITICAL \n";
        f << "desktop_notify = HIGH\n";
        f << "ssh_fail_count = 10\n";
        f << "ssh_fail_window = 120\n";
        f << "sound_enabled = false\n";
        f << "notify_enabled = true\n";
    }

    auto cfg = config::AppConfig::load(tmpdir);
    EXPECT_EQ(cfg.terminal_bell, events::Severity::CRITICAL);
    EXPECT_EQ(cfg.desktop_notify, events::Severity::HIGH);
    EXPECT_EQ(cfg.ssh_fail_threshold, 10);
    EXPECT_EQ(cfg.ssh_fail_window_secs, 120);
    EXPECT_FALSE(cfg.sound_enabled);
    EXPECT_TRUE(cfg.notify_send_enabled);
}

TEST_F(ConfigTest, LoadMonitoredFilesStripsComments) {
    fs::path mf = tmpdir / "monitored_files.conf";
    {
        std::ofstream f(mf);
        f << "# Some comment\n";
        f << "  /etc/passwd  # user accounts\n";
        f << "/etc/shadow\n";
        f << "\n";
        f << "   /usr/bin   \n";
    }

    auto paths = config::load_monitored_files(mf);
    ASSERT_EQ(paths.size(), 3u);
    EXPECT_EQ(paths[0], "/etc/passwd");
    EXPECT_EQ(paths[1], "/etc/shadow");
    EXPECT_EQ(paths[2], "/usr/bin");
}
