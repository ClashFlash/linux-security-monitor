#include "ui.hpp"
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>

namespace ui {

// ─── ANSI codes ────────────────────────────────────────────────────────────
#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_DIM     "\033[2m"
#define ANSI_REVERSE "\033[7m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"
#define ANSI_BRED    "\033[91m"
#define ANSI_BGREEN  "\033[92m"
#define ANSI_BYELLOW "\033[93m"
#define ANSI_BBLUE   "\033[94m"
#define ANSI_BCYAN   "\033[96m"
#define ANSI_BG_DARK "\033[48;5;235m"

static struct termios saved_termios;

Terminal::Terminal() {
    // Raw mode
    struct termios raw;
    tcgetattr(STDIN_FILENO, &saved_termios);
    raw = saved_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0; // non-blocking
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    // Hide cursor, clear screen
    printf("\033[?25l");
    clear_screen();
}

Terminal::~Terminal() {
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    printf("\033[?25h" ANSI_RESET); // Show cursor
    clear_screen();
    fflush(stdout);
}

void Terminal::get_terminal_size(int& rows, int& cols) {
    struct winsize w{};
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    rows = w.ws_row  ? w.ws_row  : 24;
    cols = w.ws_col  ? w.ws_col  : 80;
}

void Terminal::set_cursor(int row, int col) {
    printf("\033[%d;%dH", row, col);
}

void Terminal::clear_screen() {
    printf("\033[2J\033[H");
}

std::string Terminal::progress_bar(float pct, int width) {
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    int filled = static_cast<int>(pct / 100.f * width);
    std::string bar = "[";
    for (int i = 0; i < width; i++)
        bar += (i < filled) ? "\u2588" : "\u2591";
    bar += "]";
    return bar;
}

std::string Terminal::severity_color(events::Severity s) {
    switch (s) {
        case events::Severity::LOW:      return ANSI_GREEN;
        case events::Severity::MEDIUM:   return ANSI_YELLOW;
        case events::Severity::HIGH:     return ANSI_RED;
        case events::Severity::CRITICAL: return ANSI_BRED;
    }
    return ANSI_RESET;
}

// ─── Input ─────────────────────────────────────────────────────────────────

int Terminal::get_key() {
    char buf[8] = {};
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) return -1;
    if (n == 1) return static_cast<unsigned char>(buf[0]);
    // Escape sequences
    if (buf[0] == '\033' && buf[1] == '[') {
        if (buf[2] == 'A') return 1000; // Up
        if (buf[2] == 'B') return 1001; // Down
        if (buf[2] == 'C') return 1002; // Right
        if (buf[2] == 'D') return 1003; // Left
        if (buf[2] == '5' && buf[3] == '~') return 1004; // PgUp
        if (buf[2] == '6' && buf[3] == '~') return 1005; // PgDn
    }
    return static_cast<unsigned char>(buf[0]);
}

// Key constants
constexpr int KEY_UP    = 1000;
constexpr int KEY_DOWN  = 1001;
constexpr int KEY_RIGHT = 1002;
constexpr int KEY_LEFT  = 1003;
constexpr int KEY_PGUP  = 1004;
constexpr int KEY_PGDN  = 1005;
constexpr int KEY_ENTER = 13;
constexpr int KEY_ESC   = 27;
constexpr int KEY_TAB   = 9;
constexpr int KEY_BS    = 127;

bool Terminal::handle_key(UiState& state, int key,
                           const std::vector<const proc::ProcessInfo*>& procs,
                           proc::ProcessMonitor& pm)
{
    if (key == -1) return true;

    // Global keys
    if (!state.proc_searching && !state.event_searching) {
        if (key == 'q' || key == 'Q') { state.quit = true; return false; }
        if (key == KEY_TAB || key == '\t') {
            state.active_panel = static_cast<Panel>(
                (static_cast<int>(state.active_panel) + 1) % 4);
            return true;
        }
        if (key == '1') { state.active_panel = Panel::PROCESSES; return true; }
        if (key == '2') { state.active_panel = Panel::NETWORK;   return true; }
        if (key == '3') { state.active_panel = Panel::EVENTS;    return true; }
        if (key == '4') { state.active_panel = Panel::HELP;      return true; }
        if (key == 'h') { state.active_panel = Panel::HELP;      return true; }
    }

    if (state.active_panel == Panel::PROCESSES) {
        if (state.proc_detail) {
            if (key == KEY_ESC || key == 'q') { state.proc_detail = false; return true; }
            return true;
        }
        if (state.proc_searching) {
            if (key == KEY_ENTER || key == KEY_ESC) {
                state.proc_searching = false;
            } else if (key == KEY_BS && !state.proc_search.empty()) {
                state.proc_search.pop_back();
            } else if (key >= 32 && key < 127) {
                state.proc_search += static_cast<char>(key);
            }
            state.proc_selected = 0;
            return true;
        }
        if (key == '/') { state.proc_searching = true; state.proc_search.clear(); return true; }
        if (key == 'c') { state.proc_sort = proc::SortField::CPU; return true; }
        if (key == 'm') { state.proc_sort = proc::SortField::MEM; return true; }
        if (key == 'p') { state.proc_sort = proc::SortField::PID; return true; }
        if (key == KEY_UP   && state.proc_selected > 0)
            state.proc_selected--;
        if (key == KEY_DOWN && state.proc_selected < (int)procs.size() - 1)
            state.proc_selected++;
        if (key == KEY_ENTER && !procs.empty() && state.proc_selected < (int)procs.size()) {
            state.proc_detail = true;
        }
    }

    if (state.active_panel == Panel::EVENTS) {
        if (state.event_searching) {
            if (key == KEY_ENTER || key == KEY_ESC) { state.event_searching = false; }
            else if (key == KEY_BS && !state.event_search.empty()) { state.event_search.pop_back(); }
            else if (key >= 32 && key < 127) { state.event_search += static_cast<char>(key); }
            state.event_scroll = 0;
            return true;
        }
        if (key == '/') { state.event_searching = true; state.event_search.clear(); return true; }
        if (key == 'f') {
            state.event_filter = static_cast<EventFilter>(
                (static_cast<int>(state.event_filter) + 1) % 6);
            state.event_scroll = 0;
            return true;
        }
        if (key == KEY_UP   && state.event_scroll > 0) state.event_scroll--;
        if (key == KEY_DOWN) state.event_scroll++;
        if (key == KEY_PGUP && state.event_scroll > 10) state.event_scroll -= 10;
        if (key == KEY_PGDN) state.event_scroll += 10;
    }

    if (state.active_panel == Panel::NETWORK) {
        if (key == KEY_UP   && state.net_scroll > 0) state.net_scroll--;
        if (key == KEY_DOWN) state.net_scroll++;
    }

    return true;
}

// ─── Drawing ───────────────────────────────────────────────────────────────

void Terminal::draw(const DisplayData& d, const UiState& state) {
    int rows, cols;
    get_terminal_size(rows, cols);

    set_cursor(1, 1);
    draw_header(*d.cpu, *d.mem, cols);
    draw_tab_bar(state, cols);

    int top_row   = 5; // after header(2) + blank + tab_bar + blank
    int body_rows = rows - top_row - 2; // leave 2 for footer

    switch (state.active_panel) {
        case Panel::PROCESSES:
            if (state.proc_detail && !d.sorted_procs.empty() &&
                state.proc_selected < (int)d.sorted_procs.size())
                draw_process_detail(*d.sorted_procs[state.proc_selected], rows, cols);
            else
                draw_processes(d, state, top_row, body_rows, cols);
            break;
        case Panel::NETWORK:
            draw_network(d, state, top_row, body_rows, cols);
            break;
        case Panel::EVENTS:
            draw_events(d, state, top_row, body_rows, cols);
            break;
        case Panel::HELP:
            draw_help(rows, cols);
            break;
    }

    draw_footer(state, cols);
    fflush(stdout);
}

void Terminal::draw_header(const cpu::CpuMonitor& cpu,
                            const mem::MemoryMonitor& mem, int cols)
{
    // Current time
    time_t now = time(nullptr);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // CPU bar
    float cpu_pct = cpu.overall_pct();
    std::string cpu_color = cpu_pct > 80 ? ANSI_BRED : cpu_pct > 50 ? ANSI_BYELLOW : ANSI_BGREEN;
    std::string cpu_bar = progress_bar(cpu_pct, 20);

    // RAM
    const auto& mi = mem.info();
    float mem_pct = mi.used_pct();
    std::string mem_color = mem_pct > 80 ? ANSI_BRED : mem_pct > 60 ? ANSI_BYELLOW : ANSI_BGREEN;
    std::string mem_bar = progress_bar(mem_pct, 20);
    std::string mem_str = std::to_string(mi.used_mb()) + " / " + std::to_string(mi.total_mb()) + " MB";

    set_cursor(1, 1);
    printf(ANSI_BOLD ANSI_BCYAN " Linux Security Monitor" ANSI_RESET);
    // Right-align timestamp
    int ts_col = cols - static_cast<int>(strlen(timebuf)) - 1;
    set_cursor(1, ts_col);
    printf(ANSI_DIM "%s" ANSI_RESET, timebuf);

    set_cursor(2, 1);
    printf(" CPU " ANSI_BOLD "%s%s%3.0f%%" ANSI_RESET
           "  RAM " ANSI_BOLD "%s%s%3.0f%%" ANSI_RESET "  %s",
           cpu_color.c_str(), cpu_bar.c_str(), cpu_pct,
           mem_color.c_str(), mem_bar.c_str(), mem_pct,
           mem_str.c_str());

    // Per-core mini bars if space
    const auto& cores = cpu.cores();
    if (!cores.empty() && cols > 100) {
        set_cursor(2, cols - static_cast<int>(cores.size()) * 7 - 1);
        for (const auto& c : cores) {
            const char* col = c.usage_pct > 80 ? ANSI_RED : c.usage_pct > 50 ? ANSI_YELLOW : ANSI_GREEN;
            printf("%s%3.0f%%" ANSI_RESET " ", col, c.usage_pct);
        }
    }
    printf("\n");
}

void Terminal::draw_tab_bar(const UiState& state, int cols) {
    set_cursor(4, 1);
    struct Tab { Panel p; const char* label; };
    Tab tabs[] = {
        {Panel::PROCESSES, " [1] Processes "},
        {Panel::NETWORK,   " [2] Network   "},
        {Panel::EVENTS,    " [3] Events    "},
        {Panel::HELP,      " [4] Help      "},
    };
    for (const auto& t : tabs) {
        if (t.p == state.active_panel)
            printf(ANSI_REVERSE ANSI_BOLD "%s" ANSI_RESET, t.label);
        else
            printf(ANSI_DIM "%s" ANSI_RESET, t.label);
    }
    printf("\n");
}

// Helper: truncate string to width
static std::string trunc(const std::string& s, int w) {
    if (w <= 0) return "";
    if ((int)s.size() <= w) return s + std::string(w - s.size(), ' ');
    return s.substr(0, w - 1) + "…";
}

void Terminal::draw_processes(const DisplayData& d, const UiState& state,
                               int top_row, int rows, int cols)
{
    auto& sorted = const_cast<std::vector<const proc::ProcessInfo*>&>(d.sorted_procs);

    // Header
    set_cursor(top_row, 1);
    printf(ANSI_BOLD ANSI_BCYAN
           "%-7s %-7s %-10s %-6s %-6s %-2s %-20s %-*s %s" ANSI_RESET "\n",
           "PID", "PPID", "USER", "CPU%", "MEM%", "S",
           "COMMAND", cols - 64, "EXE PATH", "STARTED");

    // Search bar
    if (state.proc_searching || !state.proc_search.empty()) {
        set_cursor(top_row + 1, 1);
        printf(ANSI_YELLOW " Search: %s_" ANSI_RESET "\n", state.proc_search.c_str());
    }

    int row_offset = state.proc_searching ? 2 : 1;
    int visible = rows - row_offset - 1;

    // Scroll so selected is visible
    int scroll = std::max(0, state.proc_selected - visible + 3);

    for (int i = 0; i < visible && (i + scroll) < (int)sorted.size(); i++) {
        const auto* p = sorted[i + scroll];
        bool selected = (i + scroll) == state.proc_selected;

        // State color
        const char* state_col =
            (p->state == proc::ProcState::Running)  ? ANSI_BGREEN :
            (p->state == proc::ProcState::Waiting)   ? ANSI_BYELLOW :
            (p->state == proc::ProcState::Zombie)    ? ANSI_BRED : ANSI_RESET;

        // Anomaly highlight
        const char* row_col = ANSI_RESET;
        if (p->root_from_suspicious) row_col = ANSI_BRED;
        else if (p->from_tmp || p->exe_deleted) row_col = ANSI_BYELLOW;

        if (selected) printf(ANSI_REVERSE);
        printf("%s", row_col);

        char state_c = static_cast<char>(p->state);
        printf("%-7d %-7d %-10s %5.1f%% %5.1f%% %s%c%s %-20s %-*s %s\n",
               p->pid, p->ppid,
               trunc(p->username, 10).c_str(),
               p->cpu_pct, p->mem_pct,
               state_col, state_c, ANSI_RESET,
               trunc(p->name, 20).c_str(),
               cols - 65, trunc(p->exe_path.size() > 40 ? p->exe_path.substr(p->exe_path.size()-38) : p->exe_path, cols - 65).c_str(),
               p->start_time_str.c_str());
        printf(ANSI_RESET);
    }

    // Sort indicator
    set_cursor(top_row, cols - 20);
    const char* sort_lbl = state.proc_sort == proc::SortField::CPU ? "Sort:CPU" :
                           state.proc_sort == proc::SortField::MEM ? "Sort:MEM" : "Sort:PID";
    printf(ANSI_DIM "%s" ANSI_RESET, sort_lbl);
}

void Terminal::draw_process_detail(const proc::ProcessInfo& p, int rows, int cols) {
    set_cursor(5, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Process Detail ──────────────────────" ANSI_RESET "\n");
    auto line = [&](const char* lbl, const std::string& val) {
        printf(ANSI_BOLD " %-16s" ANSI_RESET " %s\n", lbl, val.c_str());
    };
    line("PID:",       std::to_string(p.pid));
    line("PPID:",      std::to_string(p.ppid));
    line("User:",      p.username + " (uid=" + std::to_string(p.uid) + ")");
    line("State:",     std::string(1, static_cast<char>(p.state)));
    line("CPU%:",      std::to_string(p.cpu_pct).substr(0,5) + "%");
    line("Memory%:",   std::to_string(p.mem_pct).substr(0,5) + "% (" + std::to_string(p.rss_kb/1024) + " MB)");
    line("Name:",      p.name);
    line("Cmdline:",   p.cmdline.substr(0, cols - 20));
    line("Exe:",       p.exe_path);
    line("Started:",   p.start_time_str);
    line("Open FDs:",  std::to_string(p.fd_count));
    if (p.exe_deleted)          printf(ANSI_BRED " ⚠ Executable deleted\n" ANSI_RESET);
    if (p.from_tmp)             printf(ANSI_BYELLOW " ⚠ Running from temp directory\n" ANSI_RESET);
    if (p.root_from_suspicious) printf(ANSI_BRED " ⚠ Root process from suspicious path\n" ANSI_RESET);
    printf(ANSI_DIM "\n Press ESC to return\n" ANSI_RESET);
}

void Terminal::draw_network(const DisplayData& d, const UiState& state,
                             int top_row, int rows, int cols)
{
    set_cursor(top_row, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Network Interfaces ──────────────────" ANSI_RESET "\n");
    printf(ANSI_BOLD "%-12s %10s %10s %12s %12s %8s %8s" ANSI_RESET "\n",
           "INTERFACE", "RX/s", "TX/s", "RX bytes", "TX bytes", "RX err", "TX err");

    for (const auto& iface : d.net->interfaces()) {
        auto fmt_rate = [](double r) -> std::string {
            if (r > 1e6) return std::to_string((int)(r/1e6)) + " MB/s";
            if (r > 1e3) return std::to_string((int)(r/1e3)) + " KB/s";
            return std::to_string((int)r) + " B/s";
        };
        printf("%-12s %10s %10s %12lu %12lu %8lu %8lu\n",
               iface.name.c_str(),
               fmt_rate(iface.rx_rate).c_str(), fmt_rate(iface.tx_rate).c_str(),
               iface.rx_bytes, iface.tx_bytes,
               iface.rx_errors, iface.tx_errors);
    }

    printf("\n" ANSI_BOLD ANSI_BCYAN " ── Connections ─────────────────────────" ANSI_RESET "\n");
    printf(ANSI_BOLD "%-6s %-22s %-22s %-12s %-6s %-15s" ANSI_RESET "\n",
           "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS");

    int line = 0;
    int skip = state.net_scroll;
    for (const auto& c : d.connections) {
        if (skip-- > 0) continue;
        if (line++ > rows - 10) break;

        const char* state_col =
            c.state == net::ConnState::ESTABLISHED ? ANSI_GREEN :
            c.state == net::ConnState::LISTEN       ? ANSI_CYAN  :
            c.state == net::ConnState::TIME_WAIT    ? ANSI_YELLOW: ANSI_RESET;

        printf("%s%-6s%s %-22s %-22s %s%-12s%s %-6d %-15s\n",
               ANSI_DIM, c.proto_str().c_str(), ANSI_RESET,
               (c.local_addr + ":" + std::to_string(c.local_port)).c_str(),
               (c.remote_addr + ":" + std::to_string(c.remote_port)).c_str(),
               state_col, c.state_str().c_str(), ANSI_RESET,
               c.pid,
               trunc(c.process_name, 15).c_str());
    }
}

void Terminal::draw_events(const DisplayData& d, const UiState& state,
                            int top_row, int rows, int cols)
{
    auto all = d.events->snapshot();
    // Apply filter
    std::vector<events::Event> filtered;
    for (const auto& e : all) {
        if (state.event_filter != EventFilter::ALL) {
            events::Category expected;
            switch (state.event_filter) {
                case EventFilter::AUTH:    expected = events::Category::AUTH;    break;
                case EventFilter::PROCESS: expected = events::Category::PROCESS; break;
                case EventFilter::NETWORK: expected = events::Category::NETWORK; break;
                case EventFilter::FILE:    expected = events::Category::FILE;    break;
                case EventFilter::SYSTEM:  expected = events::Category::SYSTEM;  break;
                default: expected = e.category; break;
            }
            if (e.category != expected) continue;
        }
        if (!state.event_search.empty() &&
            e.title.find(state.event_search) == std::string::npos &&
            e.details.find(state.event_search) == std::string::npos)
            continue;
        filtered.push_back(e);
    }

    // Newest first
    std::reverse(filtered.begin(), filtered.end());

    set_cursor(top_row, 1);
    const char* filter_names[] = {"ALL","AUTH","PROC","NET","FILE","SYS"};
    printf(ANSI_BOLD ANSI_BCYAN " ── Security Events [%zu total]" ANSI_RESET
           "  Filter: " ANSI_YELLOW "%s" ANSI_RESET
           "  (f=cycle, /=search)\n",
           all.size(), filter_names[static_cast<int>(state.event_filter)]);

    if (state.event_searching || !state.event_search.empty()) {
        printf(ANSI_YELLOW " Search: %s_" ANSI_RESET "\n", state.event_search.c_str());
        top_row++;
    }

    printf(ANSI_BOLD "%-20s %-8s %-9s %-12s %s" ANSI_RESET "\n",
           "TIME", "SEV", "CAT", "SOURCE", "TITLE / DETAILS");

    int visible = rows - 5;
    int scroll  = state.event_scroll;
    // Clamp scroll
    if (scroll > (int)filtered.size() - 1) scroll = std::max(0, (int)filtered.size() - 1);

    for (int i = 0; i < visible && (i + scroll) < (int)filtered.size(); i++) {
        const auto& e = filtered[i + scroll];
        printf("%s%-20s " ANSI_RESET "%-8s " ANSI_DIM "%-9s %-12s" ANSI_RESET " %s\n",
               severity_color(e.severity).c_str(),
               e.timestamp_str().c_str(),
               e.severity_str().c_str(),
               e.category_str().c_str(),
               trunc(e.source, 12).c_str(),
               trunc(e.title, cols - 54).c_str());
    }
}

void Terminal::draw_help(int rows, int cols) {
    set_cursor(5, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Keyboard Reference ──────────────────\n\n" ANSI_RESET);
    const char* help[] = {
        "  TAB / 1-4    Switch panel",
        "  q            Quit",
        "  h / 4        Show this help",
        "",
        "  PROCESSES:",
        "    ↑ ↓        Navigate process list",
        "    Enter       Process detail screen",
        "    ESC         Back from detail",
        "    c           Sort by CPU%",
        "    m           Sort by MEM%",
        "    p           Sort by PID",
        "    /           Search / filter by name",
        "",
        "  EVENTS:",
        "    ↑ ↓ PgUp PgDn   Scroll events",
        "    f           Cycle filter (All/Auth/Proc/Net/File/Sys)",
        "    /           Search event titles & details",
        "",
        "  NETWORK:",
        "    ↑ ↓         Scroll connection list",
        nullptr
    };
    for (int i = 0; help[i]; i++)
        printf("%s\n", help[i]);
}

void Terminal::draw_footer(const UiState& state, int cols) {
    int rows, c2;
    get_terminal_size(rows, c2);
    set_cursor(rows - 1, 1);

    printf(ANSI_REVERSE ANSI_BOLD);
    std::string footer;
    switch (state.active_panel) {
        case Panel::PROCESSES:
            footer = " q:Quit  TAB:Switch  c:CPU  m:MEM  p:PID  /:Search  Enter:Detail  1-4:Panels";
            break;
        case Panel::NETWORK:
            footer = " q:Quit  TAB:Switch  ↑↓:Scroll  1-4:Panels";
            break;
        case Panel::EVENTS:
            footer = " q:Quit  TAB:Switch  f:Filter  /:Search  ↑↓PgUp PgDn:Scroll  1-4:Panels";
            break;
        case Panel::HELP:
            footer = " q:Quit  TAB:Switch  1-4:Panels";
            break;
    }
    // Pad to full width
    footer += std::string(std::max(0, cols - (int)footer.size()), ' ');
    printf("%.*s" ANSI_RESET, cols, footer.c_str());
}

} // namespace ui
