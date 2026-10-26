#pragma once
#include "cpu.hpp"
#include "memory.hpp"
#include "process.hpp"
#include "network.hpp"
#include "ssh_monitor.hpp"
#include "file_integrity.hpp"
#include "event_system.hpp"
#include "incident.hpp"
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>

namespace ui {

enum class Panel { PROCESSES, NETWORK, AUTH, EVENTS, INCIDENTS, HELP };

enum class EventFilter { ALL, AUTH, PROCESS, NETWORK, FILE, SYSTEM };

enum class ConfirmAction { NONE, KILL_PROCESS, REBASE };

struct UiState {
    Panel       active_panel     = Panel::PROCESSES;

    int         proc_selected    = 0;
    proc::SortField proc_sort    = proc::SortField::CPU;
    std::string proc_search;
    bool        proc_searching   = false;
    bool        proc_detail      = false;

    EventFilter event_filter     = EventFilter::ALL;
    int         event_scroll     = 0;
    int         event_selected   = 0;
    bool        event_detail     = false;
    std::string event_search;
    bool        event_searching  = false;

    int         net_scroll       = 0;
    int         net_selected     = 0;
    bool        net_show_timeline = false;

    int         auth_selected    = 0;
    int         auth_scroll      = 0;

    int         inc_selected     = 0;
    int         inc_scroll       = 0;
    bool        inc_detail       = false;

    int         help_scroll      = 0;

    ConfirmAction confirm        = ConfirmAction::NONE;
    int           confirm_pid    = -1;
    std::string   status_message;
    std::chrono::steady_clock::time_point status_message_time;
    bool        quit             = false;
};

struct DisplayData {
    cpu::CpuMonitor*                        cpu = nullptr;
    mem::MemoryMonitor*                     mem = nullptr;
    proc::ProcessMonitor*                   procs = nullptr;
    net::NetworkMonitor*                    net = nullptr;
    events::EventLog*                       events = nullptr;
    ssh::SshMonitor*                        ssh = nullptr;
    integrity::FileIntegrityMonitor*        files = nullptr;
    incidents::IncidentStore*               incidents = nullptr;
    std::filesystem::path                   reports_dir;
    std::vector<const proc::ProcessInfo*>   sorted_procs;
    std::vector<net::Connection>            connections;
};

class Terminal {
public:
    Terminal();
    ~Terminal();

    void draw(const DisplayData& data, const UiState& state);

    bool handle_key(UiState& state, int key, DisplayData& data);

    int  get_key();
    void get_terminal_size(int& rows, int& cols);

private:
    void draw_header(const cpu::CpuMonitor& cpu, const mem::MemoryMonitor& mem,
                     int cols);
    void draw_tab_bar(const UiState& state, int cols);
    void draw_processes(const DisplayData& d, const UiState& state,
                        int top_row, int rows, int cols);
    void draw_process_detail(const proc::ProcessInfo& p, const DisplayData& d,
                             int rows, int cols);
    void draw_network(const DisplayData& d, const UiState& state,
                      int top_row, int rows, int cols);
    void draw_auth(const DisplayData& d, const UiState& state,
                   int top_row, int rows, int cols);
    void draw_events(const DisplayData& d, const UiState& state,
                     int top_row, int rows, int cols);
    void draw_event_detail(const events::Event& e, int rows, int cols);
    void draw_incidents(const DisplayData& d, const UiState& state,
                        int top_row, int rows, int cols);
    void draw_incident_detail(const incidents::Incident& inc, int rows, int cols);
    void draw_help(const UiState& state, int top_row, int rows, int cols);
    void draw_footer(const UiState& state, int cols);
    void draw_confirm(const UiState& state, int cols);

    static std::string progress_bar(float pct, int width);
    static void set_cursor(int row, int col);
    static void clear_screen();
    static void color(int ansi_code);
    static void reset_color();
    static std::string severity_color(events::Severity s);
};

} // namespace ui
