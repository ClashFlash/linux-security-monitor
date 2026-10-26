# Linux Security Monitor

A real-time Linux security monitoring tool written in C++17. Displays CPU, memory, processes, network connections, file integrity events, and SSH authentication activity in a terminal dashboard.

## Features

### System Overview
- Real-time CPU usage with per-core bars and overall percentage
- RAM display as `USED / TOTAL MB` with progress bar
- Current date/time in header

### Process Monitor
- Full process table: PID, PPID, username, CPU%, MEM%, state, command, executable path, start time
- Sort by CPU (`c`), Memory (`m`), or PID (`p`)
- Search/filter by process name (`/`)
- Process detail screen with open FD count (`Enter`)
- Anomaly highlighting: processes from `/tmp`, deleted executables, root from suspicious paths

### Network Monitor
- All network interfaces with RX/TX bytes, packets, errors, and live rates
- Active connections with local/remote address:port, state, PID, and process name
- Listening ports
- TCP/TCP6/UDP/UDP6 from `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
- Detection of newly opened listening ports (vs. baseline at startup)
- Detection of closed established connections

### SSH Authentication Monitor
- Parses `/var/log/auth.log` (falls back to `journalctl -u ssh`)
- Detects: failed password, invalid user, successful login
- Records source IP, username, timestamp
- Brute force detection: configurable threshold (default: 5 failures / 60 seconds)

### File Integrity Monitor
- SHA-256 hashing (built-in, no OpenSSL dependency)
- Detects: file modification, creation, deletion
- Configurable watched paths in `config/monitored_files.conf`
- Runs in its own thread, rescans every 10 seconds

### Security Rules Engine
- Process executing from `/tmp`, `/dev/shm`, `/run/user`, `/var/tmp`
- Process with deleted executable still running
- Root process (UID=0) from suspicious location → CRITICAL
- Process that opened a new listening port
- Process with suspicious outbound connection

### Event System
- In-memory ring buffer (last 1000 events)
- Persistent log as JSON Lines at `~/.local/share/linux-security-monitor/events.log`
- Filter by category: Auth / Process / Network / File / System
- Keyword search
- Severity levels: LOW / MEDIUM / HIGH / CRITICAL

### Alerting
- Terminal bell (BEL) on HIGH/CRITICAL events
- Desktop notification via `notify-send` (non-blocking fork/exec)
- Configurable thresholds in `config/thresholds.conf`

## Build

### Requirements
- GCC 10+ or Clang 12+ with C++17 support
- CMake 3.16+
- Internet connection (CMake fetches Google Test automatically)

### Quick build
```bash
git clone https://github.com/ClashFlash/linux-security-monitor.git
cd linux-security-monitor
make debug      # Debug build with ASan/UBSan
make release    # Optimized release build
make test       # Run all unit tests
```

### Manual CMake
```bash
cmake -B build/debug   -DCMAKE_BUILD_TYPE=Debug   && cmake --build build/debug   -j$(nproc)
cmake -B build/release -DCMAKE_BUILD_TYPE=Release && cmake --build build/release -j$(nproc)
```

### Run
```bash
./build/release/monitor           # most features work unprivileged
sudo ./build/release/monitor      # needed for /var/log/auth.log
```

## Keyboard Controls

| Key | Action |
|-----|--------|
| `Tab` / `1`-`4` | Switch panel |
| `q` | Quit |
| `h` | Help panel |
| **Processes** | |
| `↑` `↓` | Navigate |
| `Enter` | Process detail |
| `Esc` | Back from detail |
| `c` / `m` / `p` | Sort by CPU / Memory / PID |
| `/` | Search by name |
| **Events** | |
| `↑` `↓` `PgUp` `PgDn` | Scroll |
| `f` | Cycle filter (All → Auth → Process → Network → File → System) |
| `/` | Search events |
| **Network** | |
| `↑` `↓` | Scroll connections |

## Configuration

### `config/monitored_files.conf`
One path per line. Directories are watched recursively.

### `config/thresholds.conf`
```ini
terminal_bell=HIGH
desktop_notify=HIGH
ssh_fail_count=5
ssh_fail_window=60
sound_enabled=true
notify_enabled=true
```

## Architecture & Concurrency

```
main.cpp                  — Startup orchestration, signal handling & synchronized teardown
├── cpu.{hpp,cpp}         — /proc/stat parser: delta-based CPU% & per-core utilization
├── memory.{hpp,cpp}      — /proc/meminfo parser: RAM usage, buffers, and swap
├── process.{hpp,cpp}     — /proc/*/stat & /proc/*/status: thread-safe process cache & sorting
├── network.{hpp,cpp}     — /proc/net/tcp*, udp*, /proc/net/dev, socket inode resolver
├── ssh_monitor.{hpp,cpp} — Real-time auth.log / journalctl watcher with regex event extraction
├── file_integrity.*      — Incremental multi-threaded SHA-256 baseline & anomaly detection
├── security_rules.*      — Pure-function security rules engine & event deduplicator
├── event_system.*        — Thread-safe ring buffer (1000 events) + persistent JSONL logging
├── alert.*               — Rate-limited terminal bell & async notify-send desktop alerts
├── config.*              — Robust INI/conf parser with aliases, comments, and whitespace trimming
└── ui.*                  — High-performance ANSI raw TUI dashboard with select-based event loop
```

### Concurrency & Reliability Highlights
- **Thread-safe State Snapshots:** The UI event loop operates on local thread-safe snapshots (`procs_snapshot`, `conns_snapshot`) to prevent race conditions during live sorting, filtering, and detail inspection.
- **Responsive I/O Multiplexing:** Input handling leverages POSIX `select()` on `STDIN_FILENO` with a 50ms polling slice, guaranteeing immediate keystroke responsiveness without stalling background monitoring threads.
- **Clean Signal Teardown:** Condition variable notifications (`g_shutdown_cv`) ensure background worker threads terminate immediately on `SIGINT`/`SIGTERM` without blocking during sleep cycles.
- **Port Alert Deduplication:** Dynamic tracking of newly bound listening sockets alerts once upon detection and resets when unbound, preventing notification spam.

## Testing & Quality Assurance

A comprehensive GoogleTest suite with **61 unit tests** ensures detection accuracy and engine stability across edge cases:

- **CPU Monitor (7 tests):** Delta CPU usage math, core calculations, and crash resilience on malformed procfs data.
- **SSH Parser (8 tests):** Failed password patterns, invalid user accounts, combined failures, accepted password/public-key logins, IPv4 and IPv6 source addresses, and empty/unrelated log lines.
- **File Integrity Monitor (9 tests):** SHA-256 known RFC test vectors, modification, creation, deletion detections, and event emissions.
- **Security Rules Engine (15 tests):** Execution from `/tmp`, `/dev/shm`, and `/run/user`, deleted running executables, critical alerts for root executions, newly opened listening ports, suspicious outbound connections, and alert deduplication.
- **Network Hex Parser (13 tests):** Hex-to-IPv4 conversions (loopback, private, broadcast, zeros), port endian conversions (HTTP, HTTPS, SSH, edge values), `/proc/net/tcp` parsing, interface traffic, and connection state checks.
- **Process Monitor (6 tests):** Process enumeration, sorting by PID/CPU/Memory, regex/substring search filters, and file descriptor detail extraction.
- **Configuration Engine (3 tests):** Default fallback guarantees, alias normalization, whitespace handling, and comment stripping in configuration files.

```bash
make test
# or
cd build/debug && ctest --output-on-failure
```
