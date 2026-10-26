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

// ─── ANSI codes (TrueColor / 24-bit with high contrast against adaptive wallpapers/transparency) ───
#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_DIM     "\033[2m"
#define ANSI_REVERSE "\033[7m"
#define ANSI_RED     "\033[38;2;255;95;86m"
#define ANSI_GREEN   "\033[38;2;40;210;120m"
#define ANSI_YELLOW  "\033[38;2;255;215;0m"
#define ANSI_BLUE    "\033[38;2;90;150;255m"
#define ANSI_MAGENTA "\033[38;2;240;110;220m"
#define ANSI_CYAN    "\033[38;2;80;230;240m"
#define ANSI_WHITE   "\033[38;2;250;250;250m"
#define ANSI_BRED    "\033[1;38;2;255;95;86m"
#define ANSI_BGREEN  "\033[1;38;2;40;220;120m"
#define ANSI_BYELLOW "\033[1;38;2;255;220;50m"
#define ANSI_BBLUE   "\033[1;38;2;110;170;255m"
#define ANSI_BCYAN   "\033[1;38;2;90;240;255m"
#define ANSI_SEL_BG  "\033[48;2;45;75;135m\033[38;2;255;255;255m\033[1m"
#define ANSI_CLEAR_LINE "\033[K"
#define ANSI_CLEAR_DOWN "\033[J"

static struct termios saved_termios;

Terminal::Terminal() {
    // Raw mode
    struct termios raw;
    tcgetattr(STDIN_FILENO, &saved_termios);
    raw = saved_termios;
    raw.c_lflag &= ~(ECHO | ICANON | ISIG); // Disable echo, canonical mode, and signals interfering with keys
    raw.c_iflag &= ~(IXON | ICRNL);        // Disable flow control and CR to NL mapping
    raw.c_cc[VMIN]  = 0;
    raw.c_cc[VTIME] = 0;                   // Non-blocking
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    // Enter alternate screen buffer, hide cursor, clear screen
    printf("\033[?1049h\033[?25l");
    clear_screen();
    fflush(stdout);
}

Terminal::~Terminal() {
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    // Show cursor, exit alternate screen buffer, reset styles
    printf("\033[?25h\033[?1049l" ANSI_RESET);
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
    char buf[16] = {};
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    if (n == 1) {
        unsigned char c = static_cast<unsigned char>(buf[0]);
        if (c == 10 || c == 13) return 13; // Normalize newline/return
        return c;
    }

    // Escape sequences: ESC [ ... or ESC O ...
    if (buf[0] == 27) {
        if (buf[1] == '[') {
            if (n >= 3) {
                if (buf[2] == 'A') return 1000; // Up
                if (buf[2] == 'B') return 1001; // Down
                if (buf[2] == 'C') return 1002; // Right
                if (buf[2] == 'D') return 1003; // Left
                if (buf[2] == 'H') return 1006; // Home
                if (buf[2] == 'F') return 1007; // End
            }
            if (n >= 4) {
                if (buf[2] == '5' && buf[3] == '~') return 1004; // PgUp
                if (buf[2] == '6' && buf[3] == '~') return 1005; // PgDn
                if (buf[2] == '1' && buf[3] == '~') return 1006; // Home
                if (buf[2] == '4' && buf[3] == '~') return 1007; // End
                if (buf[2] == '7' && buf[3] == '~') return 1006; // Home
                if (buf[2] == '8' && buf[3] == '~') return 1007; // End
            }
            if (n >= 4) {
                if (buf[n - 1] == 'A') return 1000;
                if (buf[n - 1] == 'B') return 1001;
                if (buf[n - 1] == 'C') return 1002;
                if (buf[n - 1] == 'D') return 1003;
            }
        } else if (buf[1] == 'O'&& n >= 3) {
            // Application cursor mode SS3
            if (buf[2] == 'A') return 1000; // Up
            if (buf[2] == 'B') return 1001; // Down
            if (buf[2] == 'C') return 1002; // Right
            if (buf[2] == 'D') return 1003; // Left
            if (buf[2] == 'H') return 1006; // Home
            if (buf[2] == 'F') return 1007; // End
        }
        return 27; // ESC
    }
    return static_cast<unsigned char>(buf[0]);
}

// Key constants
constexpr int KEY_UP    = 1000;
constexpr int KEY_DOWN  = 1001;
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
    (void)pm;
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
        if (key == 'h' || key == 'H') { state.active_panel = Panel::HELP; return true; }
    }

    if (state.active_panel == Panel::PROCESSES) {
        if (state.proc_detail) {
            if (key == KEY_ESC || key == 'q' || key == 'Q') { state.proc_detail = false; return true; }
            return true;
        }
        if (state.proc_searching) {
            if (key == KEY_ENTER || key == KEY_ESC) {
                state.proc_searching = false;
            } else if ((key == KEY_BS || key == 8 || key == 127) && !state.proc_search.empty()) {
                state.proc_search.pop_back();
            } else if (key >= 32 && key < 127) {
                state.proc_search += static_cast<char>(key);
            }
            state.proc_selected = 0;
            return true;
        }
        if (key == '/') { state.proc_searching = true; state.proc_search.clear(); return true; }
        if (key == 'c' || key == 'C') { state.proc_sort = proc::SortField::CPU; return true; }
        if (key == 'm' || key == 'M') { state.proc_sort = proc::SortField::MEM; return true; }
        if (key == 'p' || key == 'P') { state.proc_sort = proc::SortField::PID; return true; }
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.proc_selected > 0)
            state.proc_selected--;
        if ((key == KEY_DOWN || key == 'j' || key == 'J') && state.proc_selected < static_cast<int>(procs.size()) - 1)
            state.proc_selected++;
        if (key == 1006) // Home
            state.proc_selected = 0;
        if (key == 1007 && !procs.empty()) // End
            state.proc_selected = static_cast<int>(procs.size()) - 1;
        if (key == KEY_PGUP)
            state.proc_selected = std::max(0, state.proc_selected - 10);
        if (key == KEY_PGDN && !procs.empty())
            state.proc_selected = std::min(static_cast<int>(procs.size()) - 1, state.proc_selected + 10);
        if ((key == KEY_ENTER || key == 10) && !procs.empty() && state.proc_selected < static_cast<int>(procs.size())) {
            state.proc_detail = true;
        }
    }

    if (state.active_panel == Panel::EVENTS) {
        if (state.event_searching) {
            if (key == KEY_ENTER || key == KEY_ESC) { state.event_searching = false; }
            else if ((key == KEY_BS || key == 8 || key == 127) && !state.event_search.empty()) { state.event_search.pop_back(); }
            else if (key >= 32 && key < 127) { state.event_search += static_cast<char>(key); }
            state.event_scroll = 0;
            return true;
        }
        if (key == '/') { state.event_searching = true; state.event_search.clear(); return true; }
        if (key == 'f' || key == 'F') {
            state.event_filter = static_cast<EventFilter>(
                (static_cast<int>(state.event_filter) + 1) % 6);
            state.event_scroll = 0;
            return true;
        }
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.event_scroll > 0) state.event_scroll--;
        if (key == KEY_DOWN || key == 'j' || key == 'J') state.event_scroll++;
        if (key == KEY_PGUP) state.event_scroll = std::max(0, state.event_scroll - 10);
        if (key == KEY_PGDN) state.event_scroll += 10;
    }

    if (state.active_panel == Panel::NETWORK) {
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.net_scroll > 0) state.net_scroll--;
        if (key == KEY_DOWN || key == 'j' || key == 'J') state.net_scroll++;
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
                state.proc_selected < static_cast<int>(d.sorted_procs.size()))
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
    char timebuf[32] = {};
    struct tm tm_info{};
    if (localtime_r(&now, &tm_info)) {
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);
    }

    // CPU bar
    float cpu_pct = cpu.overall_pct();
    std::string cpu_color = cpu_pct > 80 ? ANSI_BRED : cpu_pct > 50 ? ANSI_BYELLOW : ANSI_BGREEN;
    std::string cpu_bar = progress_bar(cpu_pct, 20);

    // RAM
    const auto mi = mem.info();
    float mem_pct = mi.used_pct();
    std::string mem_color = mem_pct > 80 ? ANSI_BRED : mem_pct > 60 ? ANSI_BYELLOW : ANSI_BGREEN;
    std::string mem_bar = progress_bar(mem_pct, 20);
    std::string mem_str = std::to_string(mi.used_mib()) + " / " + std::to_string(mi.total_mib()) + " MiB";

    set_cursor(1, 1);
    printf(ANSI_BOLD ANSI_BCYAN " Linux Security Monitor" ANSI_RESET "%s", ANSI_CLEAR_LINE);
    // Right-align timestamp
    int ts_len = static_cast<int>(strlen(timebuf));
    if (cols > ts_len + 30) {
        set_cursor(1, cols - ts_len);
        printf(ANSI_DIM "%s" ANSI_RESET, timebuf);
    }

    set_cursor(2, 1);
    printf(" CPU " ANSI_BOLD "%s%s%3.0f%%" ANSI_RESET
           "  RAM " ANSI_BOLD "%s%s%3.0f%%" ANSI_RESET "  %s%s",
           cpu_color.c_str(), cpu_bar.c_str(), cpu_pct,
           mem_color.c_str(), mem_bar.c_str(), mem_pct,
           mem_str.c_str(), ANSI_CLEAR_LINE);

    // Per-core mini bars if space
    const auto cores = cpu.cores();
    if (!cores.empty() && cols > 100) {
        int avail_cols = cols - 65;
        int max_cores = avail_cols / 7;
        if (max_cores > 0) {
            int display_count = std::min(static_cast<int>(cores.size()), max_cores);
            set_cursor(2, cols - display_count * 7);
            for (int i = 0; i < display_count; ++i) {
                const auto& c = cores[i];
                const char* col = c.usage_pct > 80 ? ANSI_RED : c.usage_pct > 50 ? ANSI_YELLOW : ANSI_GREEN;
                printf("%s%3.0f%%" ANSI_RESET " ", col, c.usage_pct);
            }
        }
    }
    printf("\n");
}

void Terminal::draw_tab_bar(const UiState& state, int cols) {
    (void)cols;
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
    printf("%s\n", ANSI_CLEAR_LINE);
}

// Helper: truncate string to width
static std::string trunc(const std::string& s, int w) {
    if (w <= 0) return "";
    if (static_cast<int>(s.size()) <= w) return s;
    if (w <= 3) return s.substr(0, w);
    return s.substr(0, w - 3) + "...";
}

void Terminal::draw_processes(const DisplayData& d, const UiState& state,
                               int top_row, int rows, int cols)
{
    const auto& sorted = d.sorted_procs;
    auto fmt_mem = [](uint64_t kb) -> std::string {
        if (kb >= 1048576) {
            char b[16];
            snprintf(b, sizeof(b), "%.1fG", static_cast<double>(kb) / 1048576.0);
            return b;
        } else if (kb >= 1024) {
            return std::to_string(kb / 1024) + "M";
        } else {
            return std::to_string(kb) + "K";
        }
    };

    int exe_col_width = std::max(10, cols - 66);

    // Header
    set_cursor(top_row, 1);
    printf(ANSI_BOLD ANSI_BCYAN
           "%-7s %-7s %-10s %6s %7s %-3s %-20s %-*s %s" ANSI_RESET "%s\n",
           "PID", "PPID", "USER", "CPU%", "MEM", "S",
           "COMMAND", exe_col_width, "EXE PATH", "STARTED", ANSI_CLEAR_LINE);

    // Search bar
    if (state.proc_searching || !state.proc_search.empty()) {
        set_cursor(top_row + 1, 1);
        printf(ANSI_YELLOW " Search: %s_" ANSI_RESET "%s\n", state.proc_search.c_str(), ANSI_CLEAR_LINE);
    }

    int row_offset = state.proc_searching ? 2 : 1;
    int visible = std::max(0, rows - row_offset);

    // Scroll so selected is visible
    int scroll = std::max(0, state.proc_selected - visible + 3);

    int drawn_count = 0;
    for (int i = 0; i < visible && (i + scroll) < static_cast<int>(sorted.size()); i++) {
        const auto* p = sorted[i + scroll];
        bool selected = (i + scroll) == state.proc_selected;

        // State color
        const char* state_col =
            (p->state == proc::ProcState::Running)  ? ANSI_BGREEN :
            (p->state == proc::ProcState::Waiting)  ? ANSI_BYELLOW :
            (p->state == proc::ProcState::Zombie)   ? ANSI_BRED : ANSI_RESET;

        // Anomaly highlight
        const char* row_col = ANSI_RESET;
        if (p->root_from_suspicious) row_col = ANSI_BRED;
        else if (p->from_tmp || p->exe_deleted) row_col = ANSI_BYELLOW;

        set_cursor(top_row + row_offset + i, 1);
        if (selected) {
            printf(ANSI_SEL_BG);
        } else {
            printf("%s", row_col);
        }

        char state_c = static_cast<char>(p->state);
        std::string short_exe = p->exe_path.size() > 40
            ? p->exe_path.substr(p->exe_path.size() - 38)
            : p->exe_path;

        if (selected) {
            // High contrast text inside selection bar, perfectly aligned
            printf("%-7d %-7d %-10s %5.1f%% %7s %-3c %-20s %-*s %s",
                   p->pid, p->ppid,
                   trunc(p->username, 10).c_str(),
                   p->cpu_pct, fmt_mem(p->rss_kb).c_str(),
                   state_c,
                   trunc(p->name, 20).c_str(),
                   exe_col_width, trunc(short_exe, exe_col_width).c_str(),
                   p->start_time_str.c_str());
        } else {
            // Non-selected row: print fields matching exact header column widths
            printf("%-7d %-7d %-10s %5.1f%% %7s %s%-3c" ANSI_RESET "%s%-20s %-*s %s",
                   p->pid, p->ppid,
                   trunc(p->username, 10).c_str(),
                   p->cpu_pct, fmt_mem(p->rss_kb).c_str(),
                   state_col, state_c, row_col,
                   trunc(p->name, 20).c_str(),
                   exe_col_width, trunc(short_exe, exe_col_width).c_str(),
                   p->start_time_str.c_str());
        }
        printf(ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
        drawn_count++;
    }

    // Clear any extra rows in body
    for (int i = drawn_count; i < visible; ++i) {
        set_cursor(top_row + row_offset + i, 1);
        printf("%s\n", ANSI_CLEAR_LINE);
    }

    // Sort indicator
    if (cols > 30) {
        set_cursor(top_row, cols - 15);
        const char* sort_lbl = state.proc_sort == proc::SortField::CPU ? "Sort:CPU" :
                               state.proc_sort == proc::SortField::MEM ? "Sort:MEM" : "Sort:PID";
        printf(ANSI_DIM "%s" ANSI_RESET, sort_lbl);
    }
}

void Terminal::draw_process_detail(const proc::ProcessInfo& p, int rows, int cols) {
    (void)rows;
    set_cursor(5, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Process Detail ──────────────────────" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    auto line = [&](const char* lbl, const std::string& val) {
        printf(ANSI_BOLD " %-16s" ANSI_RESET " %s%s\n", lbl, val.c_str(), ANSI_CLEAR_LINE);
    };
    line("PID:",       std::to_string(p.pid));
    line("PPID:",      std::to_string(p.ppid));
    line("User:",      p.username + " (uid=" + std::to_string(p.uid) + ")");
    line("State:",     std::string(1, static_cast<char>(p.state)));
    line("CPU%:",      std::to_string(p.cpu_pct).substr(0, 5) + "%");
    line("Memory%:",   std::to_string(p.mem_pct).substr(0, 5) + "% (" + std::to_string(p.rss_kb / 1024) + " MiB)");
    line("Name:",      p.name);
    int cmd_width = std::max(10, cols - 20);
    line("Cmdline:",   trunc(p.cmdline, cmd_width));
    line("Exe:",       p.exe_path);
    line("Started:",   p.start_time_str);
    line("Open FDs:",  std::to_string(p.fd_count));
    if (p.exe_deleted)          printf(ANSI_BRED " ⚠ Executable deleted" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    if (p.from_tmp)             printf(ANSI_BYELLOW " ⚠ Running from temp directory" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    if (p.root_from_suspicious) printf(ANSI_BRED " ⚠ Root process from suspicious path" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    printf(ANSI_DIM "\n Press ESC to return" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    printf("%s", ANSI_CLEAR_DOWN);
}

void Terminal::draw_network(const DisplayData& d, const UiState& state,
                             int top_row, int rows, int cols)
{
    (void)cols;
    set_cursor(top_row, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Network Interfaces ──────────────────" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    printf(ANSI_BOLD "%-12s %10s %10s %12s %12s %8s %8s" ANSI_RESET "%s\n",
           "INTERFACE", "RX/s", "TX/s", "RX bytes", "TX bytes", "RX err", "TX err", ANSI_CLEAR_LINE);

    for (const auto& iface : d.net->interfaces()) {
        auto fmt_rate = [](double r) -> std::string {
            if (r > 1e6) return std::to_string(static_cast<int>(r / 1e6)) + " MB/s";
            if (r > 1e3) return std::to_string(static_cast<int>(r / 1e3)) + " KB/s";
            return std::to_string(static_cast<int>(r)) + " B/s";
        };
        printf("%-12s %10s %10s %12lu %12lu %8lu %8lu%s\n",
               iface.name.c_str(),
               fmt_rate(iface.rx_rate).c_str(), fmt_rate(iface.tx_rate).c_str(),
               iface.rx_bytes, iface.tx_bytes,
               iface.rx_errors, iface.tx_errors, ANSI_CLEAR_LINE);
    }

    printf("\n" ANSI_BOLD ANSI_BCYAN " ── Connections ─────────────────────────" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    printf(ANSI_BOLD "%-7s %-22s %-22s %-13s %-7s %-15s" ANSI_RESET "%s\n",
           "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS", ANSI_CLEAR_LINE);

    int line = 0;
    int skip = state.net_scroll;
    for (const auto& c : d.connections) {
        if (skip-- > 0) continue;
        if (line++ > rows - 10) break;

        const char* state_col =
            c.state == net::ConnState::ESTABLISHED ? ANSI_GREEN :
            c.state == net::ConnState::LISTEN      ? ANSI_CYAN  :
            c.state == net::ConnState::TIME_WAIT   ? ANSI_YELLOW : ANSI_RESET;

        printf("%s%-7s" ANSI_RESET " %-22s %-22s %s%-13s" ANSI_RESET " %-7d %-15s%s\n",
               ANSI_DIM, trunc(c.proto_str(), 7).c_str(),
               trunc(c.local_addr + ":" + std::to_string(c.local_port), 22).c_str(),
               trunc(c.remote_addr + ":" + std::to_string(c.remote_port), 22).c_str(),
               state_col, trunc(c.state_str(), 13).c_str(),
               c.pid,
               trunc(c.process_name, 15).c_str(), ANSI_CLEAR_LINE);
    }
    printf("%s", ANSI_CLEAR_DOWN);
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
           "  (f=cycle, /=search)%s\n",
           all.size(), filter_names[static_cast<int>(state.event_filter)], ANSI_CLEAR_LINE);

    int cur_row = top_row + 1;
    if (state.event_searching || !state.event_search.empty()) {
        set_cursor(cur_row++, 1);
        printf(ANSI_YELLOW " Search: %s_" ANSI_RESET "%s\n", state.event_search.c_str(), ANSI_CLEAR_LINE);
    }

    set_cursor(cur_row++, 1);
    printf(ANSI_BOLD "%-20s %-8s %-9s %-12s %s" ANSI_RESET "%s\n",
           "TIME", "SEV", "CAT", "SOURCE", "TITLE / DETAILS", ANSI_CLEAR_LINE);

    int visible = std::max(0, rows - (cur_row - top_row));
    int scroll  = state.event_scroll;
    if (scroll > static_cast<int>(filtered.size()) - 1)
        scroll = std::max(0, static_cast<int>(filtered.size()) - 1);

    int drawn = 0;
    int title_width = std::max(10, cols - 54);
    for (int i = 0; i < visible && (i + scroll) < static_cast<int>(filtered.size()); i++) {
        const auto& e = filtered[i + scroll];
        set_cursor(cur_row + i, 1);
        printf("%s%-20s " ANSI_RESET "%-8s " ANSI_DIM "%-9s %-12s" ANSI_RESET " %s%s\n",
               severity_color(e.severity).c_str(),
               e.timestamp_str().c_str(),
               e.severity_str().c_str(),
               e.category_str().c_str(),
               trunc(e.source, 12).c_str(),
               trunc(e.title, title_width).c_str(),
               ANSI_CLEAR_LINE);
        drawn++;
    }

    for (int i = drawn; i < visible; ++i) {
        set_cursor(cur_row + i, 1);
        printf("%s\n", ANSI_CLEAR_LINE);
    }
}

void Terminal::draw_help(int rows, int cols) {
    (void)rows; (void)cols;
    set_cursor(5, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Keyboard Reference ──────────────────\n\n" ANSI_RESET);
    const char* help[] = {
        "  TAB / 1-4    Switch panel",
        "  q            Quit",
        "  h / 4        Show this help",
        "",
        "  PROCESSES:",
        "    ↑ ↓ / j k  Navigate process list",
        "    Home / End Jump to top / bottom",
        "    PgUp / PgDn Jump 10 rows",
        "    Enter       Process detail screen",
        "    ESC         Back from detail",
        "    c           Sort by CPU%",
        "    m           Sort by MEM%",
        "    p           Sort by PID",
        "    /           Search / filter by name",
        "",
        "  EVENTS:",
        "    ↑ ↓ / j k   Scroll events",
        "    PgUp / PgDn Page up / down",
        "    f           Cycle filter (All/Auth/Proc/Net/File/Sys)",
        "    /           Search event titles & details",
        "",
        "  NETWORK:",
        "    ↑ ↓ / j k   Scroll connection list",
        nullptr
    };
    for (int i = 0; help[i]; i++)
        printf("%s%s\n", help[i], ANSI_CLEAR_LINE);
    printf("%s", ANSI_CLEAR_DOWN);
}

void Terminal::draw_footer(const UiState& state, int cols) {
    int rows, c2;
    get_terminal_size(rows, c2);
    set_cursor(rows, 1);

    printf(ANSI_REVERSE ANSI_BOLD);
    std::string footer;
    switch (state.active_panel) {
        case Panel::PROCESSES:
            footer = " q:Quit  TAB:Switch  ↑↓/jk:Nav  c:CPU  m:MEM  p:PID  /:Search  Enter:Detail  1-4:Panels";
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
    footer += std::string(std::max(0, cols - static_cast<int>(footer.size())), ' ');
    printf("%.*s" ANSI_RESET, cols, footer.c_str());
}

} // namespace ui
