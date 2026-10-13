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
git clone <repo>
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

## Architecture

```
main.cpp                  — thin wiring: starts threads, runs UI loop
├── cpu.{hpp,cpp}         — /proc/stat → CPU%
├── memory.{hpp,cpp}      — /proc/meminfo → RAM stats
├── process.{hpp,cpp}     — /proc/*/stat → process table with CPU delta
├── network.{hpp,cpp}     — /proc/net/tcp* + /proc/PID/fd → connections
├── ssh_monitor.{hpp,cpp} — tail auth.log + journalctl, regex parsing
├── file_integrity.*      — SHA-256 baseline, change detection
├── security_rules.*      — pure-function rule evaluators + SecurityEngine
├── event_system.*        — thread-safe ring buffer + JSON log
├── alert.*               — bell + notify-send alerter
├── config.*              — load monitored_files.conf + thresholds.conf
└── ui.*                  — raw terminal TUI, keyboard input, all panels
```

## Testing

61 unit tests covering:
- CPU% calculation with synthetic /proc/stat deltas
- SSH auth.log line parser (7 test cases, regex edge cases)
- File integrity: SHA-256 known vectors, modification/creation/deletion detection
- Security rules: all 6 rules with positive and negative cases + deduplication
- Network hex parser: IP/port conversion with known values
- Process monitor: PID/CPU/Memory sorting, process details, filtering, and caching
- Configuration loader: threshold settings, aliases, comments, and whitespace trimming

```bash
make test
# or
cd build/debug && ctest --output-on-failure
```
