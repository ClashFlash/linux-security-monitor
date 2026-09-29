#include "cpu.hpp"
#include "memory.hpp"
#include "process.hpp"
#include "network.hpp"
#include "ssh_monitor.hpp"
#include "file_integrity.hpp"
#include "security_rules.hpp"
#include "event_system.hpp"
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

static std::atomic<bool> g_running{true};

static void handle_signal(int) {
    g_running = false;
}

int main(int argc, char** argv) {
    // Install signal handlers
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    // ── Configuration ──────────────────────────────────────────────────────
    std::filesystem::path config_dir =
        std::filesystem::path(__FILE__).parent_path().parent_path() / "config";
    auto cfg = config::AppConfig::load(config_dir);

    // ── Event log ──────────────────────────────────────────────────────────
    auto event_log = std::make_shared<events::EventLog>(cfg.event_log_path);

    // ── Alerter ────────────────────────────────────────────────────────────
    alert::Thresholds thr;
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
    net::NetworkMonitor  net_mon;

    // Initial data
    cpu_mon.refresh();
    mem_mon.refresh();
    proc_mon.refresh();

    // ── Security engine ───────────────────────────────────────────────────
    rules::SecurityEngine security_engine(event_log);

    // ── Background threads ─────────────────────────────────────────────────

    // 1. SSH monitor thread (started inside)
    ssh::SshMonitor ssh_mon(event_log, cfg.ssh_fail_threshold, cfg.ssh_fail_window_secs);
    ssh_mon.start();

    // 2. File integrity monitor thread
    integrity::FileIntegrityMonitor file_mon(event_log, cfg.monitored_paths);
    file_mon.start();

    // 3. Data collection + security engine thread (2s cycle)
    std::thread data_thread([&]() {
        while (g_running) {
            cpu_mon.refresh();
            mem_mon.refresh();
            proc_mon.refresh();
            net_mon.refresh();

            // Run security rules on fresh data
            security_engine.evaluate(
                proc_mon.processes(),
                net_mon.new_listening_ports(),
                net_mon.connections()
            );

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
            for (const auto& c : net_mon.new_listening_ports()) {
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

            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    });

    // ── UI loop ────────────────────────────────────────────────────────────
    {
        ui::Terminal term;
        ui::UiState  ui_state;

        while (g_running && !ui_state.quit) {
            // Build sorted process view
            auto sorted = ui_state.proc_search.empty()
                ? proc_mon.sorted(ui_state.proc_sort)
                : proc_mon.filter(ui_state.proc_search);

            // Sort filtered results too
            if (!ui_state.proc_search.empty()) {
                std::sort(sorted.begin(), sorted.end(),
                    [&](const proc::ProcessInfo* a, const proc::ProcessInfo* b) {
                        if (ui_state.proc_sort == proc::SortField::CPU)
                            return a->cpu_pct > b->cpu_pct;
                        if (ui_state.proc_sort == proc::SortField::MEM)
                            return a->mem_pct > b->mem_pct;
                        return a->pid < b->pid;
                    });
            }

            ui::DisplayData dd{
                &cpu_mon, &mem_mon, &proc_mon, &net_mon, event_log.get(),
                sorted, net_mon.connections()
            };

            term.draw(dd, ui_state);

            // Handle input (non-blocking)
            int key = term.get_key();
            if (key != -1)
                term.handle_key(ui_state, key, sorted, proc_mon);

            // ~30fps
            std::this_thread::sleep_for(std::chrono::milliseconds(33));
        }
    } // Terminal destructor restores terminal

    // ── Shutdown ──────────────────────────────────────────────────────────
    g_running = false;
    ssh_mon.stop();
    file_mon.stop();
    if (data_thread.joinable()) data_thread.join();

    return 0;
}
