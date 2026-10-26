#include "file_integrity.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <stdexcept>
#include <cstring>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

// ─── SHA-256 (header-only implementation, no OpenSSL dep) ─────────────────
// Public domain implementation based on RFC 6234

namespace {

struct SHA256Context {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
};

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define S1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define s0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define s1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256_transform(SHA256Context& ctx, const uint8_t* data) {
    uint32_t W[64], a,b,c,d,e,f,g,h,T1,T2;
    for (int i=0;i<16;i++)
        W[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|
               ((uint32_t)data[i*4+2]<<8)|(uint32_t)data[i*4+3];
    for (int i=16;i<64;i++)
        W[i] = s1(W[i-2])+W[i-7]+s0(W[i-15])+W[i-16];
    a=ctx.state[0]; b=ctx.state[1]; c=ctx.state[2]; d=ctx.state[3];
    e=ctx.state[4]; f=ctx.state[5]; g=ctx.state[6]; h=ctx.state[7];
    for (int i=0;i<64;i++) {
        T1=h+S1(e)+CH(e,f,g)+K[i]+W[i];
        T2=S0(a)+MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    ctx.state[0]+=a; ctx.state[1]+=b; ctx.state[2]+=c; ctx.state[3]+=d;
    ctx.state[4]+=e; ctx.state[5]+=f; ctx.state[6]+=g; ctx.state[7]+=h;
}

static void sha256_init(SHA256Context& ctx) {
    ctx.count=0;
    ctx.state[0]=0x6a09e667; ctx.state[1]=0xbb67ae85;
    ctx.state[2]=0x3c6ef372; ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f; ctx.state[5]=0x9b05688c;
    ctx.state[6]=0x1f83d9ab; ctx.state[7]=0x5be0cd19;
}

static void sha256_update(SHA256Context& ctx, const uint8_t* data, size_t len) {
    size_t i=0;
    uint32_t j = (uint32_t)(ctx.count & 63);
    ctx.count += len;
    if (j + len >= 64) {
        memcpy(&ctx.buffer[j], data, (64-j));
        sha256_transform(ctx, ctx.buffer);
        i = 64-j;
        while (i+63 < len) { sha256_transform(ctx, data+i); i+=64; }
        j = 0;
    }
    memcpy(&ctx.buffer[j], data+i, len-i);
}

static void sha256_final(SHA256Context& ctx, uint8_t digest[32]) {
    uint8_t finalcount[8];
    uint64_t bits = ctx.count * 8;
    for (int i=0;i<8;i++) finalcount[i]=(uint8_t)(bits>>((7-i)*8));
    uint8_t c = 0x80;
    sha256_update(ctx, &c, 1);
    while ((ctx.count & 63) != 56) { c=0; sha256_update(ctx, &c, 1); }
    sha256_update(ctx, finalcount, 8);
    for (int i=0;i<32;i++)
        digest[i]=(uint8_t)(ctx.state[i>>2]>>((3-(i&3))*8));
}

} // anonymous

// ─── Public interface ──────────────────────────────────────────────────────

namespace integrity {

std::string sha256_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";

    SHA256Context ctx;
    sha256_init(ctx);
    uint8_t buf[8192];
    while (f.read(reinterpret_cast<char*>(buf), sizeof(buf)) || f.gcount() > 0) {
        sha256_update(ctx, buf, static_cast<size_t>(f.gcount()));
    }
    uint8_t digest[32];
    sha256_final(ctx, digest);

    std::ostringstream ss;
    for (int i=0;i<32;i++) ss << std::hex << std::setw(2) << std::setfill('0')
                               << static_cast<int>(digest[i]);
    return ss.str();
}

std::string FileChange::type_str() const {
    switch (type) {
        case ChangeType::MODIFIED:     return "MODIFIED";
        case ChangeType::CREATED:      return "CREATED";
        case ChangeType::DELETED:      return "DELETED";
        case ChangeType::PERM_CHANGED: return "PERM_CHANGED";
        case ChangeType::NEW_STARTUP:  return "NEW_STARTUP";
    }
    return "?";
}

bool is_persistence_path(const std::filesystem::path& path) {
    auto s = path.generic_string();
    return s.find("/systemd/") != std::string::npos ||
           s.find("/cron.") != std::string::npos ||
           s.find("/cron/") != std::string::npos ||
           (s.size() >= 12 && s.compare(s.size() - 12, 12, "/etc/crontab") == 0) ||
           s.find("/init.d/") != std::string::npos ||
           s.find("/xdg/autostart") != std::string::npos ||
           s.find("/.config/autostart") != std::string::npos ||
           s.find("/rc.local") != std::string::npos;
}

static std::string mode_str(mode_t m) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%04o", static_cast<unsigned>(m & 07777));
    return buf;
}

static std::string hash_short(const std::string& h) {
    if (h.size() <= 16) return h;
    return h.substr(0, 16) + "...";
}

// ─── FileIntegrityMonitor ──────────────────────────────────────────────────

FileIntegrityMonitor::FileIntegrityMonitor(
    std::shared_ptr<events::EventLog> log,
    std::vector<std::filesystem::path> watched,
    std::filesystem::path baseline_path)
    : event_log_(std::move(log))
    , watched_(std::move(watched))
    , baseline_path_(std::move(baseline_path))
{}

FileIntegrityMonitor::~FileIntegrityMonitor() { stop(); }

void FileIntegrityMonitor::start() {
    if (!load_persisted()) {
        baseline();
        if (event_log_) {
            events::Event e;
            e.timestamp = std::chrono::system_clock::now();
            e.category  = events::Category::SYSTEM;
            e.severity  = events::Severity::LOW;
            e.source    = "file_integrity";
            e.title     = "File integrity baseline established";
            e.details   = "Captured " + std::to_string(approved_.size()) +
                          " files as the approved snapshot. Later create/modify/delete/permission "
                          "events are compared to this snapshot, not to 'whatever was on disk at last start'. "
                          "Press B in the UI to deliberately re-establish the baseline after expected changes.";
            e.next_steps = "Review monitored paths, then treat subsequent FILE alerts as deviations from this snapshot.";
            event_log_->push(std::move(e));
        }
    }
    if (running_.exchange(true)) return;
    thread_ = std::thread(&FileIntegrityMonitor::watch_loop, this);
}

void FileIntegrityMonitor::stop() {
    running_ = false;
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

std::vector<FileChange> FileIntegrityMonitor::history() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

std::map<std::filesystem::path, FileRecord> FileIntegrityMonitor::baseline_map() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return approved_;
}

bool FileIntegrityMonitor::has_persisted_baseline() const {
    return !baseline_path_.empty() && std::filesystem::exists(baseline_path_);
}

std::chrono::system_clock::time_point FileIntegrityMonitor::baseline_established_at() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return baseline_at_;
}

FileRecord FileIntegrityMonitor::make_record(const std::filesystem::path& p) const {
    FileRecord r;
    r.path   = p;
    r.exists = std::filesystem::exists(p);
    if (!r.exists) return r;
    r.hash   = sha256_file(p);
    try {
        r.size = std::filesystem::file_size(p);
        r.mtime_count = std::filesystem::last_write_time(p).time_since_epoch().count();
    } catch (...) {}
    struct stat st{};
    if (::stat(p.c_str(), &st) == 0) {
        r.mode = st.st_mode;
        r.uid  = st.st_uid;
        r.gid  = st.st_gid;
        r.size = static_cast<uintmax_t>(st.st_size);
    }
    return r;
}

void FileIntegrityMonitor::collect_paths(const std::filesystem::path& root,
                                          std::vector<std::filesystem::path>& out) const
{
    std::error_code ec;
    if (std::filesystem::is_regular_file(root, ec)) {
        out.push_back(root);
    } else if (std::filesystem::is_directory(root, ec)) {
        for (const auto& e : std::filesystem::recursive_directory_iterator(
                 root, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (!ec && e.is_regular_file()) out.push_back(e.path());
        }
    }
}

void FileIntegrityMonitor::baseline() {
    std::lock_guard<std::mutex> lock(mutex_);
    approved_.clear();
    alerted_keys_.clear();

    std::vector<std::filesystem::path> all;
    for (const auto& w : watched_) collect_paths(w, all);

    for (const auto& p : all) {
        auto r = make_record(p);
        if (r.exists) approved_[p] = r;
    }
    last_scan_ = approved_;
    baseline_at_ = std::chrono::system_clock::now();
    save_persisted();
}

bool FileIntegrityMonitor::load_persisted() {
    if (baseline_path_.empty()) return false;
    std::ifstream f(baseline_path_);
    if (!f) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    approved_.clear();
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        if (line.rfind("ESTABLISHED=", 0) == 0) {
            baseline_at_ = events::parse_time(line.substr(12));
            continue;
        }
        std::istringstream ss(line);
        std::string path, hash, size_s, mt_s, mode_s, uid_s, gid_s;
        if (!std::getline(ss, path, '\t')) continue;
        if (!std::getline(ss, hash, '\t')) continue;
        std::getline(ss, size_s, '\t');
        std::getline(ss, mt_s, '\t');
        std::getline(ss, mode_s, '\t');
        std::getline(ss, uid_s, '\t');
        std::getline(ss, gid_s, '\t');
        FileRecord r;
        r.path = path;
        r.hash = hash;
        r.exists = true;
        try { r.size = std::stoull(size_s); } catch (...) {}
        try { r.mtime_count = std::stoll(mt_s); } catch (...) {}
        try { r.mode = static_cast<mode_t>(std::stoul(mode_s, nullptr, 8)); } catch (...) {}
        try { r.uid = static_cast<uid_t>(std::stoul(uid_s)); } catch (...) {}
        try { r.gid = static_cast<gid_t>(std::stoul(gid_s)); } catch (...) {}
        approved_[r.path] = r;
    }
    last_scan_ = approved_;
    return !approved_.empty();
}

void FileIntegrityMonitor::save_persisted() const {
    if (baseline_path_.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(baseline_path_.parent_path(), ec);
    std::ofstream f(baseline_path_, std::ios::trunc);
    if (!f) return;
    f << "ESTABLISHED=" << events::format_time(baseline_at_) << "\n";
    for (const auto& [path, r] : approved_) {
        f << path.string() << '\t' << r.hash << '\t' << r.size << '\t'
          << r.mtime_count << '\t' << mode_str(r.mode) << '\t'
          << r.uid << '\t' << r.gid << '\n';
    }
}

std::vector<FileChange> FileIntegrityMonitor::scan() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FileChange> changes;
    auto now = std::chrono::system_clock::now();

    std::vector<std::filesystem::path> all;
    for (const auto& w : watched_) collect_paths(w, all);

    std::map<std::filesystem::path, FileRecord> current;
    for (const auto& p : all) {
        FileRecord r;
        r.path = p;
        struct stat st{};
        if (::stat(p.c_str(), &st) != 0) continue;
        r.exists = true;
        r.size = static_cast<uintmax_t>(st.st_size);
        r.mode = st.st_mode;
        r.uid  = st.st_uid;
        r.gid  = st.st_gid;
        try {
            r.mtime_count = std::filesystem::last_write_time(p).time_since_epoch().count();
        } catch (...) {}

        auto cache_it = last_scan_.find(p);
        auto base_it  = approved_.find(p);
        if (cache_it != last_scan_.end() &&
            cache_it->second.size == r.size &&
            cache_it->second.mtime_count == r.mtime_count &&
            cache_it->second.mode == r.mode &&
            !cache_it->second.hash.empty()) {
            r.hash = cache_it->second.hash;
        } else if (base_it != approved_.end() &&
                   base_it->second.size == r.size &&
                   base_it->second.mtime_count == r.mtime_count &&
                   base_it->second.mode == r.mode &&
                   !base_it->second.hash.empty()) {
            r.hash = base_it->second.hash;
        } else {
            r.hash = sha256_file(p);
        }
        current[p] = std::move(r);
    }

    auto maybe_emit = [&](FileChange fc) {
        std::string key = fc.path.string() + "|" + fc.type_str() + "|" + fc.new_hash + "|" +
                          mode_str(fc.new_mode);
        if (!alerted_keys_.insert(key).second) return;
        changes.push_back(fc);
        history_.push_back(fc);
        emit_change(fc);
    };

    for (const auto& [path, old_rec] : approved_) {
        auto it = current.find(path);
        if (it == current.end()) {
            FileChange fc;
            fc.type = ChangeType::DELETED;
            fc.path = path;
            fc.old_hash = old_rec.hash;
            fc.old_mode = old_rec.mode;
            fc.old_uid = old_rec.uid;
            fc.old_gid = old_rec.gid;
            fc.old_size = old_rec.size;
            fc.timestamp = now;
            maybe_emit(fc);
            continue;
        }
        const auto& cur = it->second;
        if (cur.hash != old_rec.hash) {
            FileChange fc;
            fc.type = ChangeType::MODIFIED;
            fc.path = path;
            fc.old_hash = old_rec.hash;
            fc.new_hash = cur.hash;
            fc.old_mode = old_rec.mode;
            fc.new_mode = cur.mode;
            fc.old_uid = old_rec.uid;
            fc.new_uid = cur.uid;
            fc.old_gid = old_rec.gid;
            fc.new_gid = cur.gid;
            fc.old_size = old_rec.size;
            fc.new_size = cur.size;
            fc.timestamp = now;
            maybe_emit(fc);
        } else if (cur.mode != old_rec.mode || cur.uid != old_rec.uid || cur.gid != old_rec.gid) {
            FileChange fc;
            fc.type = ChangeType::PERM_CHANGED;
            fc.path = path;
            fc.old_hash = old_rec.hash;
            fc.new_hash = cur.hash;
            fc.old_mode = old_rec.mode;
            fc.new_mode = cur.mode;
            fc.old_uid = old_rec.uid;
            fc.new_uid = cur.uid;
            fc.old_gid = old_rec.gid;
            fc.new_gid = cur.gid;
            fc.old_size = old_rec.size;
            fc.new_size = cur.size;
            fc.timestamp = now;
            maybe_emit(fc);
        }
    }

    for (const auto& [path, rec] : current) {
        if (approved_.find(path) != approved_.end()) continue;
        FileChange fc;
        fc.type = is_persistence_path(path) ? ChangeType::NEW_STARTUP : ChangeType::CREATED;
        fc.path = path;
        fc.new_hash = rec.hash;
        fc.new_mode = rec.mode;
        fc.new_uid = rec.uid;
        fc.new_gid = rec.gid;
        fc.new_size = rec.size;
        fc.timestamp = now;
        maybe_emit(fc);
    }

    last_scan_ = std::move(current);
    return changes;
}

void FileIntegrityMonitor::emit_change(const FileChange& fc) {
    events::Severity sev = events::Severity::MEDIUM;
    if (fc.type == ChangeType::MODIFIED || fc.type == ChangeType::DELETED ||
        fc.type == ChangeType::NEW_STARTUP)
        sev = events::Severity::HIGH;
    if (fc.path.filename() == "shadow" || fc.path.filename() == "sudoers" ||
        fc.path.string().find("sshd_config") != std::string::npos)
        sev = events::Severity::CRITICAL;

    events::Event e;
    e.timestamp = fc.timestamp;
    e.category  = events::Category::FILE;
    e.severity  = sev;
    e.source    = "file_integrity";
    e.title     = (fc.type == ChangeType::NEW_STARTUP)
                    ? ("New startup/service entry: " + fc.path.filename().string())
                    : ("File " + fc.type_str() + ": " + fc.path.filename().string());
    e.grouping_key = "file:" + fc.path.string();
    e.extra        = fc.path.string();
    e.exe_path     = fc.path.string();
    e.why_suspicious =
        (fc.type == ChangeType::NEW_STARTUP)
            ? "A new file appeared in a persistence location (systemd, cron, init, autostart)."
            : "The file no longer matches the operator-established integrity baseline.";
    std::ostringstream ev;
    ev << "path=" << fc.path.string()
       << " type=" << fc.type_str()
       << " old_hash=" << hash_short(fc.old_hash)
       << " new_hash=" << hash_short(fc.new_hash)
       << " old_mode=" << mode_str(fc.old_mode)
       << " new_mode=" << mode_str(fc.new_mode)
       << " old_uid=" << fc.old_uid << " new_uid=" << fc.new_uid
       << " old_gid=" << fc.old_gid << " new_gid=" << fc.new_gid
       << " old_size=" << fc.old_size << " new_size=" << fc.new_size
       << " ts=" << events::format_time(fc.timestamp);
    e.evidence = ev.str();
    e.next_steps = "Diff against a known-good copy; if the change was expected, re-establish the baseline (B). "
                   "Do not assume malware from a single package-manager write.";
    e.details = "What: " + e.title + "\nWhy: " + e.why_suspicious +
                "\nEvidence: " + e.evidence + "\nNext: " + e.next_steps;
    event_log_->push(std::move(e));
}

void FileIntegrityMonitor::watch_loop() {
    while (running_) {
        scan();
        std::unique_lock<std::mutex> lock(cv_mutex_);
        if (cv_.wait_for(lock, std::chrono::seconds(10), [this] { return !running_.load(); }))
            break;
    }
}

} // namespace integrity
