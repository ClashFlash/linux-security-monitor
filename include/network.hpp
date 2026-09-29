#pragma once
#include <string>
#include <vector>
#include <set>
#include <map>
#include <cstdint>
#include <chrono>

namespace net {

enum class Proto { TCP, TCP6, UDP, UDP6 };
enum class ConnState { LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, SYN_SENT, OTHER };

struct Connection {
    Proto       proto;
    std::string local_addr;
    uint16_t    local_port  = 0;
    std::string remote_addr;
    uint16_t    remote_port = 0;
    ConnState   state;
    int         pid         = -1;  // -1 = unknown
    std::string process_name;

    std::string state_str() const;
    std::string proto_str() const;
};

struct Interface {
    std::string name;
    uint64_t    rx_bytes   = 0;
    uint64_t    rx_packets = 0;
    uint64_t    rx_errors  = 0;
    uint64_t    tx_bytes   = 0;
    uint64_t    tx_packets = 0;
    uint64_t    tx_errors  = 0;

    // Rates (bytes/s), computed between two snapshots
    double      rx_rate    = 0.0;
    double      tx_rate    = 0.0;
};

class NetworkMonitor {
public:
    NetworkMonitor();

    void refresh();

    const std::vector<Interface>&  interfaces()  const { return ifaces_; }
    const std::vector<Connection>& connections() const { return conns_; }

    // Only LISTEN state
    std::vector<Connection> listening_ports() const;

    // New listening ports since baseline (set at construction)
    std::vector<Connection> new_listening_ports() const;

    // Connections that disappeared since last refresh (closed connections)
    std::vector<Connection> closed_connections() const;

private:
    std::vector<Interface>  ifaces_;
    std::vector<Connection> conns_;
    std::vector<Connection> prev_conns_;

    // Baseline listening ports (captured at startup)
    std::set<uint16_t> baseline_listen_ports_;
    bool               baseline_set_ = false;

    // PID → process name map (built from /proc/PID/fd symlinks)
    std::map<uint64_t, int> inode_to_pid_;  // socket inode → pid
    std::map<int, std::string> pid_to_name_;

    void parse_interfaces();
    void parse_connections(const std::string& path, Proto proto);
    void build_inode_map();
    static std::string hex_to_ip(const std::string& hex, bool ipv6 = false);
    static uint16_t    hex_to_port(const std::string& hex);
    static ConnState   hex_to_state(const std::string& hex);

    // Previous interface snapshot for rate calculation
    std::vector<Interface>                         prev_ifaces_;
    std::chrono::steady_clock::time_point          last_refresh_;
};

} // namespace net
