#pragma once
#include <string>
#include <vector>
#include <set>
#include <map>
#include <cstdint>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <filesystem>

namespace net {

enum class Proto { TCP, TCP6, UDP, UDP6 };
enum class ConnState { LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, SYN_SENT, OTHER };

struct Connection {
    Proto       proto = Proto::TCP;
    std::string local_addr;
    uint16_t    local_port  = 0;
    std::string remote_addr;
    uint16_t    remote_port = 0;
    ConnState   state = ConnState::OTHER;
    int         pid         = -1;  // -1 = unknown; never invent an owner
    std::string process_name;
    uint64_t    inode       = 0;

    std::string state_str() const;
    std::string proto_str() const;
    bool owner_known() const { return pid > 0; }
    std::string owner_label() const {
        if (pid > 0) {
            if (!process_name.empty()) return process_name + " (" + std::to_string(pid) + ")";
            return std::to_string(pid);
        }
        return "unknown";
    }
};

enum class ConnChangeType { NEW_LISTEN, CLOSED_LISTEN, NEW_ESTABLISHED, CLOSED, BURST };

struct ConnChange {
    std::chrono::system_clock::time_point timestamp;
    ConnChangeType type = ConnChangeType::NEW_ESTABLISHED;
    Connection     conn;
    std::string    note;

    std::string type_str() const;
};

struct BurstAlert {
    std::string remote_addr;
    uint16_t    remote_port = 0;
    int         count = 0;
    int         window_secs = 0;
    int         pid = -1;
    std::string process_name;
    bool        owner_known = false;
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
    explicit NetworkMonitor(std::filesystem::path trusted_path);

    void refresh();

    std::vector<Interface>  interfaces()  const;
    std::vector<Connection> connections() const;

    std::vector<Connection> listening_ports() const;
    std::vector<Connection> new_listening_ports() const;
    std::vector<Connection> closed_connections() const;
    std::vector<ConnChange> timeline() const;
    std::set<uint16_t>      trusted_ports() const;

    void trust_port(uint16_t port);
    void untrust_port(uint16_t port);
    bool is_trusted(uint16_t port) const;

    std::vector<BurstAlert> detect_bursts(int count_threshold, int window_secs) const;

private:
    mutable std::mutex      mutex_;
    std::vector<Interface>  ifaces_;
    std::vector<Connection> conns_;
    std::vector<Connection> prev_conns_;
    std::vector<ConnChange> timeline_;
    std::filesystem::path   trusted_path_;

    std::set<uint16_t> baseline_listen_ports_;
    std::set<uint16_t> trusted_ports_;
    bool               baseline_set_ = false;

    std::unordered_map<uint64_t, int> inode_to_pid_;
    std::unordered_map<int, std::string> pid_to_name_;

    void parse_interfaces();
    void parse_connections(std::vector<Connection>& out, const std::string& path, Proto proto);
    void build_inode_map();
    void load_trusted();
    void save_trusted() const;
    static std::string hex_to_ip(const std::string& hex, bool ipv6 = false);
    static uint16_t    hex_to_port(const std::string& hex);
    static ConnState   hex_to_state(const std::string& hex);

    std::vector<Interface>                         prev_ifaces_;
    std::chrono::steady_clock::time_point          last_refresh_;
};

} // namespace net
