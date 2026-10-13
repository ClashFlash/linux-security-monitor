#include "network.hpp"
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <algorithm>
#include <filesystem>
#include <chrono>

namespace net {

std::string Connection::state_str() const {
    switch (state) {
        case ConnState::LISTEN:      return "LISTEN";
        case ConnState::ESTABLISHED: return "ESTABLISHED";
        case ConnState::TIME_WAIT:   return "TIME_WAIT";
        case ConnState::CLOSE_WAIT:  return "CLOSE_WAIT";
        case ConnState::SYN_SENT:    return "SYN_SENT";
        default:                     return "OTHER";
    }
}

std::string Connection::proto_str() const {
    switch (proto) {
        case Proto::TCP:  return "TCP";
        case Proto::TCP6: return "TCP6";
        case Proto::UDP:  return "UDP";
        case Proto::UDP6: return "UDP6";
    }
    return "?";
}

// ─── NetworkMonitor ────────────────────────────────────────────────────────

NetworkMonitor::NetworkMonitor() {
    last_refresh_ = std::chrono::steady_clock::now();
    refresh(); // Initial snapshot (captures baseline listening ports)
    baseline_listen_ports_.clear();
    for (const auto& c : conns_)
        if (c.state == ConnState::LISTEN)
            baseline_listen_ports_.insert(c.local_port);
    baseline_set_ = true;
}

void NetworkMonitor::refresh() {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - last_refresh_).count();
    if (elapsed < 0.001) elapsed = 1.0;
    last_refresh_ = now;

    build_inode_map();
    parse_interfaces();

    std::vector<Connection> new_conns;
    // Temporarily point conns_ to new_conns or parse into local
    conns_.clear();
    parse_connections("/proc/net/tcp",  Proto::TCP);
    parse_connections("/proc/net/tcp6", Proto::TCP6);
    parse_connections("/proc/net/udp",  Proto::UDP);
    parse_connections("/proc/net/udp6", Proto::UDP6);

    // Compute interface rates
    for (auto& iface : ifaces_) {
        for (const auto& prev : prev_ifaces_) {
            if (prev.name == iface.name) {
                iface.rx_rate = (iface.rx_bytes >= prev.rx_bytes) ? (iface.rx_bytes - prev.rx_bytes) / elapsed : 0.0;
                iface.tx_rate = (iface.tx_bytes >= prev.tx_bytes) ? (iface.tx_bytes - prev.tx_bytes) / elapsed : 0.0;
                break;
            }
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    prev_conns_ = conns_;
    prev_ifaces_ = ifaces_;
}

std::vector<Interface> NetworkMonitor::interfaces() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ifaces_;
}

std::vector<Connection> NetworkMonitor::connections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return conns_;
}

void NetworkMonitor::parse_interfaces() {
    ifaces_.clear();
    std::ifstream f("/proc/net/dev");
    if (!f) return;

    std::string line;
    std::getline(f, line); // header line 1
    std::getline(f, line); // header line 2

    while (std::getline(f, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        Interface iface;
        // Trim leading spaces from name
        iface.name = line.substr(0, colon);
        while (!iface.name.empty() && (iface.name.front() == ' ' || iface.name.front() == '\t'))
            iface.name.erase(iface.name.begin());

        std::istringstream ss(line.substr(colon + 1));
        uint64_t skip;
        ss >> iface.rx_bytes >> iface.rx_packets >> iface.rx_errors >> skip
           >> skip >> skip >> skip >> skip
           >> iface.tx_bytes >> iface.tx_packets >> iface.tx_errors;

        ifaces_.push_back(iface);
    }
}

void NetworkMonitor::build_inode_map() {
    inode_to_pid_.clear();
    pid_to_name_.clear();

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
        char* end = nullptr;
        long pid_l = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid_l <= 0) continue;
        int pid = static_cast<int>(pid_l);

        // Iterate /proc/PID/fd
        std::string fd_path = "/proc/" + std::to_string(pid) + "/fd";
        DIR* fd_dir = opendir(fd_path.c_str());
        if (!fd_dir) continue;

        bool has_socket = false;
        struct dirent* fd_entry;
        while ((fd_entry = readdir(fd_dir)) != nullptr) {
            if (fd_entry->d_type != DT_LNK && fd_entry->d_type != DT_UNKNOWN) continue;
            std::string link_path = fd_path + "/" + fd_entry->d_name;
            char buf[256] = {};
            ssize_t len = readlink(link_path.c_str(), buf, sizeof(buf) - 1);
            if (len <= 9) continue;
            buf[len] = '\0';
            // socket:[12345]
            if (strncmp(buf, "socket:[", 8) == 0 && buf[len - 1] == ']') {
                buf[len - 1] = '\0';
                char* parse_end = nullptr;
                uint64_t inode = strtoull(buf + 8, &parse_end, 10);
                if (inode > 0 && parse_end && *parse_end == '\0') {
                    inode_to_pid_[inode] = pid;
                    has_socket = true;
                }
            }
        }
        closedir(fd_dir);

        // Read process name only if process has socket
        if (has_socket && pid_to_name_.find(pid) == pid_to_name_.end()) {
            std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
            std::ifstream cf(comm_path);
            std::string name;
            if (std::getline(cf, name)) pid_to_name_[pid] = name;
        }
    }
    closedir(proc_dir);
}

std::string NetworkMonitor::hex_to_ip(const std::string& hex, bool ipv6) {
    if (!ipv6) {
        // Little-endian 4-byte hex
        uint32_t addr;
        sscanf(hex.c_str(), "%X", &addr);
        struct in_addr in;
        in.s_addr = htonl(__builtin_bswap32(addr));
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &in, buf, sizeof(buf));
        return buf;
    } else {
        // 32-char hex, 4 groups of 4 bytes, each group little-endian
        if (hex.size() != 32) return "::";
        unsigned char bytes[16];
        for (int i = 0; i < 4; i++) {
            uint32_t word;
            sscanf(hex.c_str() + i * 8, "%8X", &word);
            word = __builtin_bswap32(word);
            memcpy(bytes + i * 4, &word, 4);
        }
        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, bytes, buf, sizeof(buf));
        return buf;
    }
}

uint16_t NetworkMonitor::hex_to_port(const std::string& hex) {
    unsigned int p;
    sscanf(hex.c_str(), "%X", &p);
    return static_cast<uint16_t>(p);
}

ConnState NetworkMonitor::hex_to_state(const std::string& hex) {
    unsigned int s;
    sscanf(hex.c_str(), "%X", &s);
    switch (s) {
        case 0x01: return ConnState::ESTABLISHED;
        case 0x0A: return ConnState::LISTEN;
        case 0x06: return ConnState::TIME_WAIT;
        case 0x08: return ConnState::CLOSE_WAIT;
        case 0x02: return ConnState::SYN_SENT;
        default:   return ConnState::OTHER;
    }
}

void NetworkMonitor::parse_connections(const std::string& path, Proto proto) {
    std::ifstream f(path);
    if (!f) return;

    bool ipv6 = (proto == Proto::TCP6 || proto == Proto::UDP6);
    std::string line;
    std::getline(f, line); // skip header

    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string sl, local, remote, state_hex, skip;
        uint64_t inode_val;
        // Fields: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
        ss >> sl >> local >> remote >> state_hex;
        for (int i = 0; i < 4; ++i) ss >> skip; // tx_queue:... tr:... retrnsmt uid
        ss >> skip; // timeout
        ss >> inode_val;

        auto colon_l = local.find(':');
        auto colon_r = remote.find(':');
        if (colon_l == std::string::npos || colon_r == std::string::npos) continue;

        Connection c;
        c.proto       = proto;
        c.local_addr  = hex_to_ip(local.substr(0, colon_l),  ipv6);
        c.local_port  = hex_to_port(local.substr(colon_l + 1));
        c.remote_addr = hex_to_ip(remote.substr(0, colon_r), ipv6);
        c.remote_port = hex_to_port(remote.substr(colon_r + 1));
        c.state       = hex_to_state(state_hex);

        auto it = inode_to_pid_.find(inode_val);
        if (it != inode_to_pid_.end()) {
            c.pid = it->second;
            auto nit = pid_to_name_.find(c.pid);
            if (nit != pid_to_name_.end()) c.process_name = nit->second;
        }

        conns_.push_back(c);
    }
}

std::vector<Connection> NetworkMonitor::listening_ports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Connection> v;
    for (const auto& c : conns_)
        if (c.state == ConnState::LISTEN) v.push_back(c);
    return v;
}

std::vector<Connection> NetworkMonitor::new_listening_ports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!baseline_set_) return {};
    std::vector<Connection> v;
    for (const auto& c : conns_) {
        if (c.state == ConnState::LISTEN &&
            baseline_listen_ports_.find(c.local_port) == baseline_listen_ports_.end())
            v.push_back(c);
    }
    return v;
}

std::vector<Connection> NetworkMonitor::closed_connections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Find ESTABLISHED connections from prev that are gone now
    std::vector<Connection> v;
    for (const auto& prev : prev_conns_) {
        if (prev.state != ConnState::ESTABLISHED) continue;
        bool found = false;
        for (const auto& curr : conns_) {
            if (curr.local_addr  == prev.local_addr  &&
                curr.local_port  == prev.local_port  &&
                curr.remote_addr == prev.remote_addr &&
                curr.remote_port == prev.remote_port)
            { found = true; break; }
        }
        if (!found) v.push_back(prev);
    }
    return v;
}

} // namespace net
