#pragma once
#include "cpu.hpp"
#include "memory.hpp"
#include "process.hpp"
#include "network.hpp"
#include "ssh_monitor.hpp"
#include "file_integrity.hpp"
#include "event_system.hpp"
#include <string>
#include <vector>
#include <memory>
#include <atomic>

namespace ui {

enum class Panel { PROCESSES, NETWORK, EVENTS, HELP };

enum class EventFilter { ALL, AUTH, PROCESS, NETWORK, FILE, SYSTEM };

struct UiState {
    Panel       active_panel     = Panel::PROCESSES;

    // Process panel
    int         proc_selected    = 0;
    proc::SortField proc_sort    = proc::SortField::CPU;
    std::string proc_search;
    bool        proc_searching   = false;
    bool        proc_detail      = false;    // showing detail screen

    // Events panel
    EventFilter event_filter     = EventFilter::ALL;
    int         event_scroll     = 0;
    std::string event_search;
    bool        event_searching  = false;

    // Network panel
    int         net_scroll       = 0;

    bool        quit             = false;
};

struct DisplayData {
    cpu::CpuMonitor*                        cpu;
    mem::MemoryMonitor*                     mem;
    proc::ProcessMonitor*                   procs;
    net::NetworkMonitor*                    net;
    events::EventLog*                       events;
    // for detail screen
    std::vector<const proc::ProcessInfo*>   sorted_procs;
    std::vector<net::Connection>            connections;
};

class Terminal {
public:
    Terminal();
    ~Terminal();

    // Draw full screen — call each frame
    void draw(const DisplayData& data, const UiState& state);

    // Handle a keypress — updates state, returns true to keep running
    bool handle_key(UiState& state, int key,
                    const std::vector<const proc::ProcessInfo*>& procs,
                    proc::ProcessMonitor& pm);

    int  get_key();           // non-blocking: returns -1 if no key
    void get_terminal_size(int& rows, int& cols);

private:
    void draw_header(const cpu::CpuMonitor& cpu, const mem::MemoryMonitor& mem,
                     int cols);
    void draw_tab_bar(const UiState& state, int cols);
    void draw_processes(const DisplayData& d, const UiState& state,
                        int top_row, int rows, int cols);
    void draw_process_detail(const proc::ProcessInfo& p, int rows, int cols);
    void draw_network(const DisplayData& d, const UiState& state,
                      int top_row, int rows, int cols);
    void draw_events(const DisplayData& d, const UiState& state,
                     int top_row, int rows, int cols);
    void draw_help(int rows, int cols);
    void draw_footer(const UiState& state, int cols);

    // ASCII progress bar: e.g. [████░░░░] 42%
    static std::string progress_bar(float pct, int width);

    // ANSI helpers
    static void set_cursor(int row, int col);
    static void clear_screen();
    static void color(int ansi_code);
    static void reset_color();
    static std::string severity_color(events::Severity s);
};

} // namespace ui
