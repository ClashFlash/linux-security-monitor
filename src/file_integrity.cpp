#include "file_integrity.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <stdexcept>
#include <cstring>

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
        case ChangeType::MODIFIED: return "MODIFIED";
        case ChangeType::CREATED:  return "CREATED";
        case ChangeType::DELETED:  return "DELETED";
    }
    return "?";
}

// ─── FileIntegrityMonitor ──────────────────────────────────────────────────

FileIntegrityMonitor::FileIntegrityMonitor(
    std::shared_ptr<events::EventLog> log,
    std::vector<std::filesystem::path> watched)
    : event_log_(std::move(log)), watched_(std::move(watched))
{}

FileIntegrityMonitor::~FileIntegrityMonitor() { stop(); }

void FileIntegrityMonitor::start() {
    baseline();
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
    return baseline_;
}

FileRecord FileIntegrityMonitor::make_record(const std::filesystem::path& p) const {
    FileRecord r;
    r.path   = p;
    r.exists = std::filesystem::exists(p);
    if (!r.exists) return r;
    r.hash   = sha256_file(p);
    try {
        r.size   = std::filesystem::file_size(p);
        r.mtime  = std::filesystem::last_write_time(p);
    } catch (...) {}
    return r;
}

void FileIntegrityMonitor::collect_paths(const std::filesystem::path& root,
                                          std::vector<std::filesystem::path>& out) const
{
    std::error_code ec;
    if (std::filesystem::is_regular_file(root, ec)) {
        out.push_back(root);
    } else if (std::filesystem::is_directory(root, ec)) {
        for (const auto& e : std::filesystem::recursive_directory_iterator(root, ec)) {
            if (!ec && e.is_regular_file()) out.push_back(e.path());
        }
    }
}

void FileIntegrityMonitor::baseline() {
    std::lock_guard<std::mutex> lock(mutex_);
    baseline_.clear();

    std::vector<std::filesystem::path> all;
    for (const auto& w : watched_) collect_paths(w, all);

    for (const auto& p : all) {
        auto r = make_record(p);
        if (r.exists) baseline_[p] = r;
    }
}

std::vector<FileChange> FileIntegrityMonitor::scan() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FileChange> changes;
    auto now = std::chrono::system_clock::now();

    // Collect current state
    std::vector<std::filesystem::path> all;
    for (const auto& w : watched_) collect_paths(w, all);

    std::map<std::filesystem::path, FileRecord> current;
    for (const auto& p : all) {
        FileRecord r;
        r.path = p;
        r.exists = std::filesystem::exists(p);
        if (!r.exists) continue;
        try {
            r.size  = std::filesystem::file_size(p);
            r.mtime = std::filesystem::last_write_time(p);
        } catch (...) {}

        // Optimization: check if baseline already has this exact file with same size and mtime.
        // If unchanged, reuse hash to avoid hashing gigabytes of disk every cycle.
        auto base_it = baseline_.find(p);
        if (base_it != baseline_.end() && base_it->second.size == r.size && base_it->second.mtime == r.mtime) {
            r.hash = base_it->second.hash;
        } else {
            r.hash = sha256_file(p);
        }
        current[p] = std::move(r);
    }

    // Check for modifications and deletions
    for (const auto& [path, old_rec] : baseline_) {
        auto it = current.find(path);
        if (it == current.end()) {
            // Deleted
            FileChange fc{ChangeType::DELETED, path, old_rec.hash, "", now};
            changes.push_back(fc);
            history_.push_back(fc);
            emit_change(fc);
        } else if (it->second.hash != old_rec.hash) {
            // Modified
            FileChange fc{ChangeType::MODIFIED, path, old_rec.hash, it->second.hash, now};
            changes.push_back(fc);
            history_.push_back(fc);
            emit_change(fc);
        }
    }

    // Check for new files
    for (const auto& [path, rec] : current) {
        if (baseline_.find(path) == baseline_.end()) {
            FileChange fc{ChangeType::CREATED, path, "", rec.hash, now};
            changes.push_back(fc);
            history_.push_back(fc);
            emit_change(fc);
        }
    }

    // Update baseline
    baseline_ = current;
    return changes;
}

void FileIntegrityMonitor::emit_change(const FileChange& fc) {
    auto sev = (fc.type == ChangeType::MODIFIED) ? events::Severity::HIGH
             : (fc.type == ChangeType::DELETED)   ? events::Severity::HIGH
                                                   : events::Severity::MEDIUM;
    event_log_->push({
        fc.timestamp,
        events::Category::FILE,
        sev,
        "file_integrity",
        "File " + fc.type_str() + ": " + fc.path.filename().string(),
        fc.path.string() +
            (fc.old_hash.empty() ? "" : "\nOld: " + fc.old_hash.substr(0, 16) + "...") +
            (fc.new_hash.empty() ? "" : "\nNew: " + fc.new_hash.substr(0, 16) + "...")
    });
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
