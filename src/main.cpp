#include "cpu.hpp"
#include "memory.hpp"
#include "process.hpp"
#include "network.hpp"
#include "ssh_monitor.hpp"
#include "file_integrity.hpp"
#include "security_rules.hpp"
#include "event_system.hpp"
#include "incident.hpp"
#include "ui.hpp"
#include "alert.hpp"
#include "config.hpp"
#include <thread>
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <set>
#include <sys/select.h>
#include <unistd.h>

static std::atomic<bool> g_running{true};
static std::condition_variable g_shutdown_cv;
static std::mutex g_shutdown_mutex;

static void handle_signal(int) {
    g_running = false;
    g_shutdown_cv.notify_all();
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    // Install signal handlers
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    // ── Configuration ──────────────────────────────────────────────────────
    std::filesystem::path config_dir;
    // 1. Check ./config in current working directory
    if (std::filesystem::exists("config/thresholds.conf")) {
        config_dir = "config";
    } else {
        // 2. Check relative to binary location
        char exe_buf[1024] = {};
        ssize_t len = readlink("/proc/self/exe", exe_buf, sizeof(exe_buf) - 1);
        if (len > 0) {
            std::filesystem::path exe_dir = std::filesystem::path(std::string(exe_buf, len)).parent_path();
            if (std::filesystem::exists(exe_dir / "config" / "thresholds.conf")) {
                config_dir = exe_dir / "config";
            } else if (std::filesystem::exists(exe_dir.parent_path() / "config" / "thresholds.conf")) {
                config_dir = exe_dir.parent_path() / "config";
            }
        }
    }
    if (config_dir.empty()) {
        config_dir = std::filesystem::path(__FILE__).parent_path().parent_path() / "config";
    }
    auto cfg = config::AppConfig::load(config_dir);

    // ── Event log ──────────────────────────────────────────────────────────
    auto event_log = std::make_shared<events::EventLog>(cfg.event_log_path);

    // ── Incident store ─────────────────────────────────────────────────────
    auto incident_store = std::make_shared<incidents::IncidentStore>(cfg.incidents_path);
    // Feed every event into the incident correlator
    event_log->on_event([&](const events::Event& e) {
        incident_store->ingest(e);
    });

    // ── Alerter ────────────────────────────────────────────────────────────
    alert::Thresholds thr;
    thr.terminal_bell          = cfg.terminal_bell;
    thr.desktop_notify         = cfg.desktop_notify;
    thr.ssh_fail_count         = cfg.ssh_fail_threshold;
    thr.ssh_fail_window_secs   = cfg.ssh_fail_window_secs;
    thr.sound_enabled          = cfg.sound_enabled;
    thr.notify_send_enabled    = cfg.notify_send_enabled;

    alert::Alerter alerter(thr);
    event_log->on_event([&](const events::Event& e) {
        alerter.handle(e);
    });

    // Log startup
    event_log->push({
        std::chrono::system_clock::now(),
        events::Category::SYSTEM,
        events::Severity::LOW,
        "main",
        "Monitor started",
        "Linux Security Monitor started. Monitoring " +
            std::to_string(cfg.monitored_paths.size()) + " paths."
    });

    // ── Data collection modules ────────────────────────────────────────────
    cpu::CpuMonitor    cpu_mon;
    mem::MemoryMonitor mem_mon;
    proc::ProcessMonitor proc_mon;
    net::NetworkMonitor  net_mon(cfg.trusted_ports_path);

    // Initial data: take first baseline snapshot, wait briefly, then refresh
    // so delta calculations (CPU%, process CPU, network rates) have non-zero deltas on launch
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    cpu_mon.refresh();
    mem_mon.refresh();
    proc_mon.refresh();
    net_mon.refresh();

    // ── Security engine ───────────────────────────────────────────────────
    rules::SecurityEngine security_engine(event_log);

    // ── Background threads ─────────────────────────────────────────────────

    // 1. SSH monitor thread
    ssh::SshMonitor ssh_mon(event_log, cfg.ssh_thresholds(), cfg.known_auth_ips_path);
    ssh_mon.start();

    // 2. File integrity monitor thread
    integrity::FileIntegrityMonitor file_mon(event_log, cfg.monitored_paths, cfg.file_baseline_path);
    file_mon.start();

    // 3. Data collection + security engine thread (2s cycle)
    std::atomic<bool> data_updated{true};
    std::set<uint16_t> alerted_new_ports;

    std::thread data_thread([&]() {
        while (g_running) {
            cpu_mon.refresh();
            mem_mon.refresh();
            proc_mon.refresh();
            net_mon.refresh();

            auto procs_snap = proc_mon.processes();
            auto conns_snap = net_mon.connections();
            auto new_ports  = net_mon.new_listening_ports();

            // Run security rules on fresh data
            security_engine.evaluate(procs_snap, new_ports, conns_snap);

            // Emit events for newly closed connections
            for (const auto& c : net_mon.closed_connections()) {
                event_log->push({
                    std::chrono::system_clock::now(),
                    events::Category::NETWORK,
                    events::Severity::LOW,
                    "network",
                    "Connection closed",
                    c.local_addr + ":" + std::to_string(c.local_port) + " <-> " +
                        c.remote_addr + ":" + std::to_string(c.remote_port) +
                        (c.process_name.empty() ? "" : " (" + c.process_name + ")")
                });
            }

            // Emit events for new listening ports (deduplicated so each fires once)
            std::set<uint16_t> current_new_ports;
            for (const auto& c : new_ports) {
                current_new_ports.insert(c.local_port);
                if (alerted_new_ports.insert(c.local_port).second) {
                    event_log->push({
                        std::chrono::system_clock::now(),
                        events::Category::NETWORK,
                        events::Severity::MEDIUM,
                        "network",
                        "New listening port detected",
                        "Port " + std::to_string(c.local_port) +
                            (c.process_name.empty() ? "" : " by " + c.process_name)
                    });
                }
            }
            // Remove ports that stopped listening so reopening will alert again
            for (auto it = alerted_new_ports.begin(); it != alerted_new_ports.end(); ) {
                if (current_new_ports.find(*it) == current_new_ports.end())
                    it = alerted_new_ports.erase(it);
                else
                    ++it;
            }

            // Emit events for connection bursts
            auto bursts = net_mon.detect_bursts(cfg.conn_burst_count, cfg.conn_burst_window);
            for (const auto& b : bursts) {
                std::string key = "net:burst:" + b.remote_addr + ":" + std::to_string(b.remote_port);
                event_log->push({
                    std::chrono::system_clock::now(),
                    events::Category::NETWORK,
                    events::Severity::HIGH,
                    "network",
                    "Connection burst detected",
                    std::string("Repeated connection attempts to ") + b.remote_addr +
                        ":" + std::to_string(b.remote_port) +
                        " (" + std::to_string(b.count) + " in " +
                        std::to_string(b.window_secs) + "s)" +
                        (b.owner_known ? " by " + b.process_name + " (pid=" +
                                         std::to_string(b.pid) + ")" : " (owner unknown)"),
                    "",         // id
                    key,        // grouping_key
                    "Repeated outbound connection attempts can indicate scanning, beaconing, or C2 communication.",
                    "remote=" + b.remote_addr + ":" + std::to_string(b.remote_port) +
                        " count=" + std::to_string(b.count) + " window=" +
                        std::to_string(b.window_secs) + "s pid=" + std::to_string(b.pid),
                    "Identify the remote host; confirm whether this is expected traffic (update, backup, monitoring); otherwise block or investigate.",
                    b.pid,      // pid
                    -1,         // ppid
                    "",         // exe_path
                    "",         // username
                    b.remote_addr + ":" + std::to_string(b.remote_port) // extra
                });
            }

            data_updated = true;

            std::unique_lock<std::mutex> lk(g_shutdown_mutex);
            g_shutdown_cv.wait_for(lk, std::chrono::seconds(2), [&] { return !g_running.load(); });
        }
    });

    // ── UI loop ────────────────────────────────────────────────────────────
    {
        ui::Terminal term;
        ui::UiState  ui_state;

        std::vector<proc::ProcessInfo> procs_snapshot = proc_mon.processes();
        std::vector<net::Connection>   conns_snapshot = net_mon.connections();

        while (g_running && !ui_state.quit) {
            if (data_updated.exchange(false)) {
                procs_snapshot = proc_mon.processes();
                conns_snapshot = net_mon.connections();
            }

            // Build sorted process view from thread-safe local snapshot
            std::vector<const proc::ProcessInfo*> sorted;
            sorted.reserve(procs_snapshot.size());
            for (const auto& p : procs_snapshot) {
                if (ui_state.proc_search.empty() ||
                    p.name.find(ui_state.proc_search) != std::string::npos ||
                    p.cmdline.find(ui_state.proc_search) != std::string::npos)
                {
                    sorted.push_back(&p);
                }
            }

            std::sort(sorted.begin(), sorted.end(),
                [&](const proc::ProcessInfo* a, const proc::ProcessInfo* b) {
                    if (ui_state.proc_sort == proc::SortField::CPU)
                        return a->cpu_pct > b->cpu_pct;
                    if (ui_state.proc_sort == proc::SortField::MEM)
                        return a->mem_pct > b->mem_pct;
                    return a->pid < b->pid;
                });

            ui::DisplayData dd{
                &cpu_mon, &mem_mon, &proc_mon, &net_mon, event_log.get(),
                &ssh_mon, &file_mon, incident_store.get(),
                cfg.reports_dir,
                sorted, conns_snapshot
            };

            term.draw(dd, ui_state);

            // Wait for keypress or timeout (50ms) using select
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(STDIN_FILENO, &fds);
            struct timeval tv{0, 50000}; // 50ms
            int sel = select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv);

            if (sel > 0 && FD_ISSET(STDIN_FILENO, &fds)) {
                int key = term.get_key();
                while (key != -1) {
                    term.handle_key(ui_state, key, dd);
                    key = term.get_key();
                }
            }
        }
    } // Terminal destructor restores terminal

    // ── Shutdown ──────────────────────────────────────────────────────────
    g_running = false;
    g_shutdown_cv.notify_all();
    ssh_mon.stop();
    file_mon.stop();
    if (data_thread.joinable()) data_thread.join();

    return 0;
}
