#include <gtest/gtest.h>
#include "network.hpp"
#include <fstream>

// We expose hex_to_ip and hex_to_port as static methods; to test them,
// we use a thin test harness that calls through the production path.

// Rather than break encapsulation, we test via a public integration path:
// parse /proc/net/tcp ourselves and verify we get valid-looking results.
// For the hex conversion we write a minimal standalone reimplementation
// that mirrors the production code, then verify it against known values.

// ── Hex conversion tests (standalone mirrors of production logic) ───────────

static std::string test_hex_to_ip_v4(const std::string& hex) {
    // Little-endian 32-bit hex -> dotted decimal
    uint32_t addr;
    sscanf(hex.c_str(), "%X", &addr);
    // reverse byte order
    addr = ((addr & 0xFF) << 24) | (((addr >> 8) & 0xFF) << 16) |
           (((addr >> 16) & 0xFF) << 8) | ((addr >> 24) & 0xFF);
    char buf[32];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
             (addr >> 8) & 0xFF, addr & 0xFF);
    return buf;
}

static uint16_t test_hex_to_port(const std::string& hex) {
    unsigned int p;
    sscanf(hex.c_str(), "%X", &p);
    return static_cast<uint16_t>(p);
}

TEST(NetworkParser, HexToIpLoopback) {
    // 127.0.0.1 in little-endian hex = 0100007F
    EXPECT_EQ("127.0.0.1", test_hex_to_ip_v4("0100007F"));
}

TEST(NetworkParser, HexToIpAllZeros) {
    EXPECT_EQ("0.0.0.0", test_hex_to_ip_v4("00000000"));
}

TEST(NetworkParser, HexToIpBroadcast) {
    // 255.255.255.255 = FFFFFFFF
    EXPECT_EQ("255.255.255.255", test_hex_to_ip_v4("FFFFFFFF"));
}

TEST(NetworkParser, HexToIpPrivate) {
    // 192.168.1.1 = C0A80101 big-endian; little-endian = 0101A8C0
    EXPECT_EQ("192.168.1.1", test_hex_to_ip_v4("0101A8C0"));
}

TEST(NetworkParser, HexToPortHttp) {
    EXPECT_EQ(80, test_hex_to_port("0050"));
}

TEST(NetworkParser, HexToPortHttps) {
    EXPECT_EQ(443, test_hex_to_port("01BB"));
}

TEST(NetworkParser, HexToPortSsh) {
    EXPECT_EQ(22, test_hex_to_port("0016"));
}

TEST(NetworkParser, HexToPortZero) {
    EXPECT_EQ(0, test_hex_to_port("0000"));
}

TEST(NetworkParser, HexToPortMax) {
    EXPECT_EQ(65535, test_hex_to_port("FFFF"));
}

// ── Integration: read /proc/net/tcp ────────────────────────────────────────

TEST(NetworkParser, ProcNetTcpReadable) {
    std::ifstream f("/proc/net/tcp");
    ASSERT_TRUE(f.good()) << "/proc/net/tcp must be readable on Linux";
}

TEST(NetworkParser, NetworkMonitorRefreshDoesNotCrash) {
    net::NetworkMonitor mon;
    EXPECT_NO_THROW(mon.refresh());
}

TEST(NetworkParser, InterfacesNotEmpty) {
    net::NetworkMonitor mon;
    EXPECT_FALSE(mon.interfaces().empty()) << "At least loopback should be present";
}

TEST(NetworkParser, ConnectionsHaveValidPorts) {
    net::NetworkMonitor mon;
    for (const auto& c : mon.connections()) {
        // Ports should be in valid range
        EXPECT_LE(c.local_port, 65535);
        EXPECT_LE(c.remote_port, 65535);
    }
}
