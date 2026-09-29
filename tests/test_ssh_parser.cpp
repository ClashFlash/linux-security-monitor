#include <gtest/gtest.h>
#include "ssh_monitor.hpp"

using namespace ssh;

TEST(SshParserTest, ParseFailedPassword) {
    auto line = "Sep 29 13:05:47 host sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2";
    auto ev = SshMonitor::parse_line(line);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->type, AuthEvent::Type::FAIL);
    EXPECT_EQ(ev->username, "root");
    EXPECT_EQ(ev->source_ip, "192.168.1.100");
}

TEST(SshParserTest, ParseInvalidUser) {
    auto line = "Sep 29 13:05:47 host sshd[1234]: Invalid user attacker from 10.0.0.1 port 4444";
    auto ev = SshMonitor::parse_line(line);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->type, AuthEvent::Type::INVALID_USER);
    EXPECT_EQ(ev->username, "attacker");
    EXPECT_EQ(ev->source_ip, "10.0.0.1");
}

TEST(SshParserTest, ParseFailedPasswordInvalidUser) {
    // Some systems emit "Failed password for invalid user foo from ..."
    auto line = "Sep 29 13:05:47 host sshd[1234]: Failed password for invalid user foo from 172.16.0.5 port 2222 ssh2";
    auto ev = SshMonitor::parse_line(line);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->type, AuthEvent::Type::FAIL);
    EXPECT_EQ(ev->username, "foo");
    EXPECT_EQ(ev->source_ip, "172.16.0.5");
}

TEST(SshParserTest, ParseAcceptedPassword) {
    auto line = "Sep 29 13:05:47 host sshd[1234]: Accepted password for alice from 192.168.1.50 port 8888 ssh2";
    auto ev = SshMonitor::parse_line(line);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->type, AuthEvent::Type::SUCCESS);
    EXPECT_EQ(ev->username, "alice");
    EXPECT_EQ(ev->source_ip, "192.168.1.50");
}

TEST(SshParserTest, ParseAcceptedPublicKey) {
    auto line = "Sep 29 13:05:47 host sshd[1234]: Accepted publickey for bob from 10.10.10.10 port 54321 ssh2";
    auto ev = SshMonitor::parse_line(line);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->type, AuthEvent::Type::SUCCESS);
    EXPECT_EQ(ev->username, "bob");
    EXPECT_EQ(ev->source_ip, "10.10.10.10");
}

TEST(SshParserTest, IgnoresUnrelatedLine) {
    auto line = "Sep 29 13:05:47 host systemd[1]: Started Daily apt upgrade and clean activities.";
    auto ev = SshMonitor::parse_line(line);
    EXPECT_FALSE(ev.has_value());
}

TEST(SshParserTest, IgnoresEmptyLine) {
    auto ev = SshMonitor::parse_line("");
    EXPECT_FALSE(ev.has_value());
}

TEST(SshParserTest, ParseIPv6Source) {
    auto line = "Sep 29 13:05:47 host sshd[1234]: Failed password for user from ::1 port 22 ssh2";
    auto ev = SshMonitor::parse_line(line);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->type, AuthEvent::Type::FAIL);
    EXPECT_EQ(ev->source_ip, "::1");
}
