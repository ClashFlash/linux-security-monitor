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
#include <map>

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

std::string ConnChange::type_str() const {
    switch (type) {
        case ConnChangeType::NEW_LISTEN:      return "NEW_LISTEN";
        case ConnChangeType::CLOSED_LISTEN:   return "CLOSED_LISTEN";
        case ConnChangeType::NEW_ESTABLISHED: return "NEW_ESTABLISHED";
        case ConnChangeType::CLOSED:          return "CLOSED";
        case ConnChangeType::BURST:           return "BURST";
    }
    return "?";
}

// ─── NetworkMonitor ────────────────────────────────────────────────────────

NetworkMonitor::NetworkMonitor() : NetworkMonitor(std::filesystem::path{}) {}

NetworkMonitor::NetworkMonitor(std::filesystem::path trusted_path)
    : trusted_path_(std::move(trusted_path))
{
    last_refresh_ = std::chrono::steady_clock::now();
    load_trusted();
    refresh();
    baseline_listen_ports_.clear();
    for (const auto& c : conns_)
        if (c.state == ConnState::LISTEN)
            baseline_listen_ports_.insert(c.local_port);
    baseline_set_ = true;
    timeline_.clear(); // baseline itself is not a change
}

void NetworkMonitor::load_trusted() {
    if (trusted_path_.empty()) return;
    std::ifstream f(trusted_path_);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        try { trusted_ports_.insert(static_cast<uint16_t>(std::stoi(line))); } catch (...) {}
    }
}

void NetworkMonitor::save_trusted() const {
    if (trusted_path_.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(trusted_path_.parent_path(), ec);
    std::ofstream f(trusted_path_, std::ios::trunc);
    if (!f) return;
    for (uint16_t p : trusted_ports_) f << p << "\n";
}

void NetworkMonitor::trust_port(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    trusted_ports_.insert(port);
    save_trusted();
}

void NetworkMonitor::untrust_port(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    trusted_ports_.erase(port);
    save_trusted();
}

bool NetworkMonitor::is_trusted(uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return trusted_ports_.count(port) != 0;
}

std::set<uint16_t> NetworkMonitor::trusted_ports() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return trusted_ports_;
}

std::vector<ConnChange> NetworkMonitor::timeline() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return timeline_;
}

static bool same_tuple(const Connection& a, const Connection& b) {
    return a.local_addr == b.local_addr && a.local_port == b.local_port &&
           a.remote_addr == b.remote_addr && a.remote_port == b.remote_port &&
           a.proto == b.proto;
}

void NetworkMonitor::refresh() {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - last_refresh_).count();
    if (elapsed < 0.001) elapsed = 1.0;
    last_refresh_ = now;

    build_inode_map();
    parse_interfaces();

    std::vector<Connection> parsed;
    parse_connections(parsed, "/proc/net/tcp",  Proto::TCP);
    parse_connections(parsed, "/proc/net/tcp6", Proto::TCP6);
    parse_connections(parsed, "/proc/net/udp",  Proto::UDP);
    parse_connections(parsed, "/proc/net/udp6", Proto::UDP6);

    for (auto& iface : ifaces_) {
        for (const auto& prev : prev_ifaces_) {
            if (prev.name == iface.name) {
                iface.rx_rate = (iface.rx_bytes >= prev.rx_bytes) ? (iface.rx_bytes - prev.rx_bytes) / elapsed : 0.0;
                iface.tx_rate = (iface.tx_bytes >= prev.tx_bytes) ? (iface.tx_bytes - prev.tx_bytes) / elapsed : 0.0;
                break;
            }
        }
    }

    auto wall = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    auto record = [&](ConnChangeType t, const Connection& c, const std::string& note) {
        ConnChange ch;
        ch.timestamp = wall;
        ch.type = t;
        ch.conn = c;
        ch.note = note;
        timeline_.push_back(std::move(ch));
        if (timeline_.size() > 500) timeline_.erase(timeline_.begin(), timeline_.begin() + 50);
    };

    if (!prev_conns_.empty() || baseline_set_) {
        for (const auto& c : parsed) {
            bool found = false;
            for (const auto& prev : conns_) {
                if (same_tuple(prev, c)) { found = true; break; }
            }
            if (found) continue;
            if (c.state == ConnState::LISTEN) {
                std::string note = "listen " + std::to_string(c.local_port) + " owner=" + c.owner_label();
                if (!c.owner_known()) note += " (attribution uncertain)";
                record(ConnChangeType::NEW_LISTEN, c, note);
            } else if (c.state == ConnState::ESTABLISHED || c.state == ConnState::SYN_SENT) {
                record(ConnChangeType::NEW_ESTABLISHED, c,
                       c.remote_addr + ":" + std::to_string(c.remote_port) + " owner=" + c.owner_label());
            }
        }
        for (const auto& prev : conns_) {
            bool found = false;
            for (const auto& c : parsed) {
                if (same_tuple(prev, c)) { found = true; break; }
            }
            if (found) continue;
            if (prev.state == ConnState::LISTEN)
                record(ConnChangeType::CLOSED_LISTEN, prev, "closed listen " + std::to_string(prev.local_port));
            else if (prev.state == ConnState::ESTABLISHED)
                record(ConnChangeType::CLOSED, prev, "closed " + prev.remote_addr + ":" + std::to_string(prev.remote_port));
        }
    }

    prev_conns_ = std::move(conns_);
    conns_ = std::move(parsed);
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

void NetworkMonitor::parse_connections(std::vector<Connection>& out, const std::string& path, Proto proto) {
    std::ifstream f(path);
    if (!f) return;

    bool ipv6 = (proto == Proto::TCP6 || proto == Proto::UDP6);
    std::string line;
    std::getline(f, line); // skip header

    while (std::getline(f, line)) {
        std::istringstream ss(line);
        std::string sl, local, remote, state_hex, skip;
        uint64_t inode_val = 0;
        ss >> sl >> local >> remote >> state_hex;
        for (int i = 0; i < 4; ++i) ss >> skip;
        ss >> skip;
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
        c.inode       = inode_val;
        c.pid         = -1;

        auto it = inode_to_pid_.find(inode_val);
        if (it != inode_to_pid_.end()) {
            c.pid = it->second;
            auto nit = pid_to_name_.find(c.pid);
            if (nit != pid_to_name_.end()) c.process_name = nit->second;
        }

        out.push_back(c);
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
    std::vector<Connection> v;
    for (const auto& prev : prev_conns_) {
        if (prev.state != ConnState::ESTABLISHED) continue;
        bool found = false;
        for (const auto& curr : conns_) {
            if (same_tuple(curr, prev)) { found = true; break; }
        }
        if (!found) v.push_back(prev);
    }
    return v;
}

std::vector<BurstAlert> NetworkMonitor::detect_bursts(int count_threshold, int window_secs) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<BurstAlert> out;
    if (count_threshold <= 0 || window_secs <= 0) return out;
    auto now = std::chrono::system_clock::now();
    auto window = std::chrono::seconds(window_secs);

    struct Key { std::string addr; uint16_t port; int pid; };
    struct Rec { int count = 0; std::string name; bool known = false; };
    std::map<std::string, Rec> buckets;

    for (const auto& ch : timeline_) {
        if (ch.type != ConnChangeType::NEW_ESTABLISHED) continue;
        if (now - ch.timestamp > window) continue;
        std::string k = ch.conn.remote_addr + "|" + std::to_string(ch.conn.remote_port) +
                        "|" + std::to_string(ch.conn.pid);
        auto& rec = buckets[k];
        rec.count++;
        rec.name = ch.conn.process_name;
        rec.known = ch.conn.owner_known();
    }
    for (const auto& [k, rec] : buckets) {
        if (rec.count < count_threshold) continue;
        BurstAlert b;
        auto c1 = k.rfind('|');
        auto c2 = k.rfind('|', c1 - 1);
        if (c1 == std::string::npos || c2 == std::string::npos) continue;
        try {
            b.pid = std::stoi(k.substr(c1 + 1));
            b.remote_port = static_cast<uint16_t>(std::stoi(k.substr(c2 + 1, c1 - c2 - 1)));
            b.remote_addr = k.substr(0, c2);
        } catch (...) { continue; }
        b.count = rec.count;
        b.window_secs = window_secs;
        b.process_name = rec.name;
        b.owner_known = rec.known;
        out.push_back(b);
    }
    return out;
}

} // namespace net
