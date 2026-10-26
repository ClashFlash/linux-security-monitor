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
#include <csignal>
#include <map>

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

bool Terminal::handle_key(UiState& state, int key, DisplayData& data)
{
    const auto& procs = data.sorted_procs;
    if (key == -1) return true;

    if (state.confirm != ConfirmAction::NONE) {
        if (key == 'y' || key == 'Y') {
            if (state.confirm == ConfirmAction::KILL_PROCESS && state.confirm_pid > 0) {
                if (::kill(state.confirm_pid, SIGTERM) == 0) {
                    state.status_message = "Sent SIGTERM to PID " + std::to_string(state.confirm_pid);
                    state.status_message_time = std::chrono::steady_clock::now();
                    if (data.events) {
                        events::Event e;
                        e.timestamp = std::chrono::system_clock::now();
                        e.category = events::Category::SYSTEM;
                        e.severity = events::Severity::MEDIUM;
                        e.source = "response";
                        e.title = "Process termination requested";
                        e.details = "Operator confirmed SIGTERM for PID " + std::to_string(state.confirm_pid);
                        e.why_suspicious = "Manual response action, not an automated kill.";
                        e.evidence = "pid=" + std::to_string(state.confirm_pid) + " signal=SIGTERM";
                        e.next_steps = "Confirm the process exited and watch for respawn.";
                        e.pid = state.confirm_pid;
                        e.grouping_key = "resp:kill:" + std::to_string(state.confirm_pid);
                        data.events->push(std::move(e));
                    }
                } else {
                    state.status_message = "Failed to signal PID " + std::to_string(state.confirm_pid);
                    state.status_message_time = std::chrono::steady_clock::now();
                }
            } else if (state.confirm == ConfirmAction::REBASE && data.files) {
                data.files->baseline();
                state.status_message = "Integrity baseline re-established from current disk contents.";
                state.status_message_time = std::chrono::steady_clock::now();
                if (data.events) {
                    events::Event e;
                    e.timestamp = std::chrono::system_clock::now();
                    e.category = events::Category::SYSTEM;
                    e.severity = events::Severity::LOW;
                    e.source = "file_integrity";
                    e.title = "File integrity baseline re-established";
                    e.details = "Operator accepted current files as the new approved snapshot.";
                    e.next_steps = "Future FILE alerts compare against this new snapshot.";
                    data.events->push(std::move(e));
                }
            }
            state.confirm = ConfirmAction::NONE;
            state.confirm_pid = -1;
            return true;
        }
        if (key == 'n' || key == 'N' || key == KEY_ESC) {
            state.confirm = ConfirmAction::NONE;
            state.confirm_pid = -1;
            state.status_message = "Action cancelled";
            state.status_message_time = std::chrono::steady_clock::now();
            return true;
        }
        return true;
    }

    if (!state.proc_searching && !state.event_searching) {
        if (key == 'q' || key == 'Q') { state.quit = true; return false; }
        if (key == KEY_TAB || key == '\t') {
            state.active_panel = static_cast<Panel>(
                (static_cast<int>(state.active_panel) + 1) % 6);
            return true;
        }
        if (key == '1') { state.active_panel = Panel::PROCESSES; return true; }
        if (key == '2') { state.active_panel = Panel::NETWORK;   return true; }
        if (key == '3') { state.active_panel = Panel::AUTH;      return true; }
        if (key == '4') { state.active_panel = Panel::EVENTS;    return true; }
        if (key == '5') { state.active_panel = Panel::INCIDENTS; return true; }
        if (key == '6' || key == 'h' || key == 'H') { state.active_panel = Panel::HELP; return true; }
        if (key == 'B') {
            state.confirm = ConfirmAction::REBASE;
            return true;
        }
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
        if (key == 'x' && !procs.empty() && state.proc_selected < static_cast<int>(procs.size())) {
            state.confirm = ConfirmAction::KILL_PROCESS;
            state.confirm_pid = procs[state.proc_selected]->pid;
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
        if (state.event_detail) {
            if (key == KEY_ESC) { state.event_detail = false; return true; }
        }
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.event_selected > 0) state.event_selected--;
        if (key == KEY_DOWN || key == 'j' || key == 'J') state.event_selected++;
        if (key == KEY_PGUP) state.event_selected = std::max(0, state.event_selected - 10);
        if (key == KEY_PGDN) state.event_selected += 10;
        if (key == KEY_ENTER) state.event_detail = true;
        if (key == KEY_ESC) state.event_detail = false;
        state.event_scroll = state.event_selected;
    }

    if (state.active_panel == Panel::NETWORK) {
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.net_selected > 0) {
            state.net_selected--;
            if (state.net_scroll > state.net_selected) state.net_scroll = state.net_selected;
        }
        if (key == KEY_DOWN || key == 'j' || key == 'J') state.net_selected++;
        if (key == 'l' || key == 'L') state.net_show_timeline = !state.net_show_timeline;
        if ((key == 't' || key == 'T') && data.net &&
            state.net_selected < static_cast<int>(data.connections.size())) {
            const auto& c = data.connections[state.net_selected];
            if (c.state == net::ConnState::LISTEN) {
                if (data.net->is_trusted(c.local_port)) {
                    data.net->untrust_port(c.local_port);
                    state.status_message = "Untrusted port " + std::to_string(c.local_port);
                } else {
                    data.net->trust_port(c.local_port);
                    state.status_message = "Trusted port " + std::to_string(c.local_port);
                }
            }
        }
    }

    if (state.active_panel == Panel::AUTH) {
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.auth_selected > 0)
            state.auth_selected--;
        if (key == KEY_DOWN || key == 'j' || key == 'J') state.auth_selected++;
    }

    if (state.active_panel == Panel::INCIDENTS && data.incidents) {
        auto list = data.incidents->snapshot();
        if (state.inc_detail) {
            if (key == KEY_ESC) { state.inc_detail = false; return true; }
        }
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.inc_selected > 0)
            state.inc_selected--;
        if ((key == KEY_DOWN || key == 'j' || key == 'J') &&
            state.inc_selected + 1 < static_cast<int>(list.size()))
            state.inc_selected++;
        if (key == KEY_ENTER && !list.empty()) state.inc_detail = true;
        if (!list.empty() && state.inc_selected < static_cast<int>(list.size())) {
            const auto& id = list[state.inc_selected].id;
            if (key == 'a' || key == 'A')
                data.incidents->set_status(id, incidents::Status::ACKNOWLEDGED);
            if (key == 'i' || key == 'I')
                data.incidents->set_status(id, incidents::Status::INVESTIGATING);
            if (key == 'r' || key == 'R')
                data.incidents->set_status(id, incidents::Status::RESOLVED);
            if (key == 'e' || key == 'E') {
                auto path = data.incidents->export_report(id, data.reports_dir);
                state.status_message = path.empty() ? "Export failed"
                                                    : "Exported " + path.string();
            }
            if (key == 'x' || key == 'X') {
                int pid = list[state.inc_selected].related_pid;
                if (pid > 0) {
                    state.confirm = ConfirmAction::KILL_PROCESS;
                    state.confirm_pid = pid;
                } else {
                    state.status_message = "No related PID to terminate";
                }
            }
        }
    }

    if (state.active_panel == Panel::HELP) {
        if ((key == KEY_UP || key == 'k' || key == 'K') && state.help_scroll > 0) state.help_scroll--;
        if (key == KEY_DOWN || key == 'j' || key == 'J') state.help_scroll++;
        if (key == KEY_PGUP) state.help_scroll = std::max(0, state.help_scroll - 10);
        if (key == KEY_PGDN) state.help_scroll += 10;
        if (key == 1006) state.help_scroll = 0; // Home
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
                draw_process_detail(*d.sorted_procs[state.proc_selected], d, rows, cols);
            else
                draw_processes(d, state, top_row, body_rows, cols);
            break;
        case Panel::NETWORK:
            draw_network(d, state, top_row, body_rows, cols);
            break;
        case Panel::AUTH:
            draw_auth(d, state, top_row, body_rows, cols);
            break;
        case Panel::EVENTS:
            draw_events(d, state, top_row, body_rows, cols);
            break;
        case Panel::INCIDENTS:
            draw_incidents(d, state, top_row, body_rows, cols);
            break;
        case Panel::HELP:
            draw_help(state, top_row, body_rows, cols);
            break;
    }

    if (state.confirm != ConfirmAction::NONE)
        draw_confirm(state, cols);
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
        {Panel::AUTH,      " [3] Auth      "},
        {Panel::EVENTS,    " [4] Events    "},
        {Panel::INCIDENTS, " [5] Incidents "},
        {Panel::HELP,      " [6] Help      "},
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
    // Strip control characters (newlines, tabs, escape sequences) that break column layout.
    std::string clean;
    clean.reserve(s.size());
    bool in_esc = false;
    for (unsigned char c : s) {
        if (in_esc) { if (c == 'm') in_esc = false; continue; }
        if (c == '\033') { in_esc = true; continue; }
        if (c < 32 || c == 127) continue; // strip control chars
        clean += static_cast<char>(c);
    }
    if (w <= 0) return "";
    if (static_cast<int>(clean.size()) <= w) return clean;
    if (w <= 3) return clean.substr(0, w);
    return clean.substr(0, w - 3) + "...";
}

void Terminal::draw_processes(const DisplayData& d, const UiState& state,
                               int top_row, int rows, int cols)
{
    const auto& sorted = d.sorted_procs;
    auto fmt_mem = [](uint64_t kb) -> std::string {
        char b[16];
        if (kb < 1000) {
            snprintf(b, sizeof(b), "%luK", kb);
        } else if (kb < 10000) {
            snprintf(b, sizeof(b), "%.1fM", static_cast<double>(kb) / 1024.0);
        } else if (kb < 1024 * 1000) {
            snprintf(b, sizeof(b), "%luM", (kb + 512) / 1024);
        } else {
            double gb = static_cast<double>(kb) / (1024.0 * 1024.0);
            if (gb < 10.0) {
                snprintf(b, sizeof(b), "%.1fG", gb);
            } else {
                snprintf(b, sizeof(b), "%dG", static_cast<int>(gb + 0.5));
            }
        }
        return b;
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

void Terminal::draw_process_detail(const proc::ProcessInfo& p, const DisplayData& d,
                                    int rows, int cols)
{
    (void)rows;
    // Enrich with parent info from current snapshot
    std::string parent_info = "—";
    for (const auto* pp : d.sorted_procs) {
        if (pp && pp->pid == p.ppid) {
            parent_info = pp->name + " (pid=" + std::to_string(pp->pid) +
                          " user=" + pp->username + ")";
            break;
        }
    }
    // Active connections for this PID
    int conn_count = 0;
    std::string conn_summary;
    for (const auto& c : d.connections) {
        if (c.pid != p.pid) continue;
        conn_count++;
        if (conn_count <= 3) {
            if (!conn_summary.empty()) conn_summary += "  ";
            conn_summary += c.proto_str() + " " + c.state_str() + " " +
                            c.local_addr + ":" + std::to_string(c.local_port);
            if (c.state == net::ConnState::ESTABLISHED)
                conn_summary += " -> " + c.remote_addr + ":" + std::to_string(c.remote_port);
        }
    }
    if (conn_count > 3)
        conn_summary += " (+" + std::to_string(conn_count - 3) + " more)";
    if (conn_summary.empty()) conn_summary = "none";

    set_cursor(5, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Process Detail ──────────────────────" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    auto lbl = [&](const char* l, const std::string& val) {
        printf(ANSI_BOLD " %-18s" ANSI_RESET " %s%s\n", l, val.c_str(), ANSI_CLEAR_LINE);
    };
    lbl("PID:",          std::to_string(p.pid));
    lbl("PPID (parent):", std::to_string(p.ppid) + "  " + parent_info);
    lbl("User:",         p.username + " (uid=" + std::to_string(p.uid) + ")");
    lbl("State:",        std::string(1, static_cast<char>(p.state)));
    lbl("CPU%:",         std::to_string(p.cpu_pct).substr(0, 5) + "%");
    lbl("Memory:",       std::to_string(p.mem_pct).substr(0, 5) + "%  RSS " +
                         std::to_string(p.rss_kb / 1024) + " MiB");
    lbl("Name:",         p.name);
    int cmd_width = std::max(20, cols - 22);
    lbl("Cmdline:",      trunc(p.cmdline, cmd_width));
    lbl("Executable:",   p.exe_path);
    lbl("Started:",      p.start_time_str);
    lbl("Open FDs:",     std::to_string(p.fd_count));
    lbl("Connections:",  conn_summary);

    // Threat indicators
    printf("\n");
    if (p.root_from_suspicious)
        printf(ANSI_BRED " ⚠ CRITICAL: Root process running from suspicious location" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    if (p.exe_deleted)
        printf(ANSI_BRED " ⚠ HIGH: Executable was deleted from disk (possible evasion)" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    if (p.from_tmp)
        printf(ANSI_BYELLOW " ⚠ HIGH: Running from temp/user-writable directory" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    if (p.from_writable_path && !p.from_tmp)
        printf(ANSI_BYELLOW " ⚠ MEDIUM: Running from world/group-writable path" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    if (!p.root_from_suspicious && !p.exe_deleted && !p.from_tmp && !p.from_writable_path)
        printf(ANSI_GREEN " ✓ No immediate threat indicators" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);

    printf(ANSI_DIM "\n ESC:Back  x:Kill(SIGTERM)" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
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

// ─── Auth panel ───────────────────────────────────────────────────────────

void Terminal::draw_auth(const DisplayData& d, const UiState& state,
                         int top_row, int rows, int cols)
{
    if (!d.ssh) {
        set_cursor(top_row, 1);
        printf(ANSI_DIM " SSH monitor not available.%s\n" ANSI_RESET, ANSI_CLEAR_LINE);
        return;
    }
    auto events_snap = d.ssh->recent_events();
    auto ip_stats    = d.ssh->ip_stats();

    // Split view: top half = IP summary, bottom = event timeline
    int half = rows / 2;

    set_cursor(top_row, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Authentication Sources (%zu IPs) ────" ANSI_RESET "%s\n",
           ip_stats.size(), ANSI_CLEAR_LINE);
    printf(ANSI_BOLD "%-18s %6s %6s %6s %-12s %-20s" ANSI_RESET "%s\n",
           "SOURCE IP", "FAILS", "OK", "INV", "LAST SEEN", "USERNAMES TRIED", ANSI_CLEAR_LINE);

    int drawn = 0;
    int ip_skip = state.auth_scroll;
    // Sort IPs by fail count desc
    std::vector<const ssh::IpStats*> sorted_ips;
    for (const auto& [ip, st] : ip_stats) sorted_ips.push_back(&st);
    std::sort(sorted_ips.begin(), sorted_ips.end(),
        [](const ssh::IpStats* a, const ssh::IpStats* b) { return a->fail_count > b->fail_count; });

    for (const auto* st : sorted_ips) {
        if (ip_skip-- > 0) continue;
        if (drawn >= half - 3) break;
        bool selected = drawn == state.auth_selected;
        const char* row_col = ANSI_RESET;
        if (st->fail_count >= 10) row_col = ANSI_BRED;
        else if (st->fail_count >= 5) row_col = ANSI_YELLOW;
        else if (st->success_count > 0) row_col = ANSI_GREEN;

        // Format last_seen
        auto ts = std::chrono::system_clock::to_time_t(st->last_seen);
        char tsbuf[32] = {};
        struct tm tm_info{};
        if (localtime_r(&ts, &tm_info)) strftime(tsbuf, sizeof(tsbuf), "%m/%d %H:%M", &tm_info);

        // Usernames tried (show first 3)
        std::string users;
        int nu = 0;
        for (const auto& u : st->usernames_tried) {
            if (nu++ >= 3) { users += "+more"; break; }
            if (!users.empty()) users += ",";
            users += u;
        }

        set_cursor(top_row + 2 + drawn, 1);
        if (selected)
            printf(ANSI_SEL_BG "%-18s %6d %6d %6d %-12s %-20s" ANSI_RESET "%s\n",
                   trunc(st->ip, 18).c_str(), st->fail_count, st->success_count,
                   st->invalid_count, tsbuf, trunc(users, 20).c_str(), ANSI_CLEAR_LINE);
        else
            printf("%s%-18s %6d %6d %6d %-12s %-20s" ANSI_RESET "%s\n",
                   row_col, trunc(st->ip, 18).c_str(), st->fail_count,
                   st->success_count, st->invalid_count, tsbuf,
                   trunc(users, 20).c_str(), ANSI_CLEAR_LINE);
        drawn++;
    }
    for (int i = drawn; i < half - 3; ++i) {
        set_cursor(top_row + 2 + i, 1);
        printf("%s\n", ANSI_CLEAR_LINE);
    }

    // ── Timeline ──────────────────────────────────────────────────────────
    int tl_top = top_row + half;
    set_cursor(tl_top, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Auth Timeline (most recent first) ───" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    printf(ANSI_BOLD "%-20s %-11s %-16s %-12s" ANSI_RESET "%s\n",
           "TIME", "TYPE", "SOURCE IP", "USERNAME", ANSI_CLEAR_LINE);

    int tl_visible = rows - half - 2;
    int tl_row = tl_top + 2;
    int tl_drawn = 0;
    // Newest first
    for (int i = static_cast<int>(events_snap.size()) - 1;
         i >= 0 && tl_drawn < tl_visible; --i) {
        const auto& ev = events_snap[i];
        auto ts2 = std::chrono::system_clock::to_time_t(ev.timestamp);
        char ts2buf[32] = {};
        struct tm tm2{};
        if (localtime_r(&ts2, &tm2)) strftime(ts2buf, sizeof(ts2buf), "%m/%d %H:%M:%S", &tm2);

        const char* type_col = ANSI_RESET;
        const char* type_str = ev.type_str().c_str();
        if (ev.type == ssh::AuthEvent::Type::FAIL || ev.type == ssh::AuthEvent::Type::INVALID_USER)
            type_col = ANSI_YELLOW;
        else if (ev.type == ssh::AuthEvent::Type::SUCCESS)
            type_col = ANSI_GREEN;

        set_cursor(tl_row + tl_drawn, 1);
        printf("%-20s %s%-11s" ANSI_RESET " %-16s %-12s%s\n",
               ts2buf, type_col, type_str,
               trunc(ev.source_ip, 16).c_str(),
               trunc(ev.username, 12).c_str(),
               ANSI_CLEAR_LINE);
        tl_drawn++;
    }
    for (int i = tl_drawn; i < tl_visible; ++i) {
        set_cursor(tl_row + i, 1);
        printf("%s\n", ANSI_CLEAR_LINE);
    }
    (void)cols;
}

// ─── Event detail overlay ─────────────────────────────────────────────────

void Terminal::draw_event_detail(const events::Event& e, int rows, int cols)
{
    (void)rows;
    set_cursor(5, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Event Detail ────────────────────────" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    auto lbl = [&](const char* l, const std::string& val) {
        int vw = std::max(10, cols - 20);
        printf(ANSI_BOLD " %-16s" ANSI_RESET " %s%s\n", l, trunc(val, vw).c_str(), ANSI_CLEAR_LINE);
    };
    lbl("ID:",         e.id);
    lbl("Time:",       e.timestamp_str());
    lbl("Severity:",   e.severity_str());
    lbl("Category:",   e.category_str());
    lbl("Source:",     e.source);
    lbl("Title:",      e.title);
    if (e.pid > 0) lbl("PID:",    std::to_string(e.pid));
    if (e.ppid > 0) lbl("PPID:",  std::to_string(e.ppid));
    if (!e.username.empty()) lbl("User:",    e.username);
    if (!e.exe_path.empty()) lbl("Exe:",     e.exe_path);
    if (!e.extra.empty())    lbl("Extra:",   e.extra);

    if (!e.why_suspicious.empty()) {
        printf(ANSI_BOLD ANSI_BYELLOW "\n Why suspicious:" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
        printf("   %s%s\n", trunc(e.why_suspicious, cols - 4).c_str(), ANSI_CLEAR_LINE);
    }
    if (!e.evidence.empty()) {
        printf(ANSI_BOLD "\n Evidence:" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
        // Word-wrap evidence at cols - 4
        std::string ev = e.evidence;
        while (!ev.empty()) {
            int take = std::min(static_cast<int>(ev.size()), cols - 4);
            printf("   %s%s\n", ev.substr(0, take).c_str(), ANSI_CLEAR_LINE);
            if (take >= static_cast<int>(ev.size())) break;
            ev = ev.substr(take);
        }
    }
    if (!e.next_steps.empty()) {
        printf(ANSI_BOLD ANSI_BCYAN "\n What to check next:" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
        printf("   %s%s\n", trunc(e.next_steps, cols - 4).c_str(), ANSI_CLEAR_LINE);
    }
    printf(ANSI_DIM "\n ESC:Back" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    printf("%s", ANSI_CLEAR_DOWN);
}

// ─── Incidents panel ──────────────────────────────────────────────────────

void Terminal::draw_incidents(const DisplayData& d, const UiState& state,
                               int top_row, int rows, int cols)
{
    if (!d.incidents) {
        set_cursor(top_row, 1);
        printf(ANSI_DIM " Incident store not available.%s\n" ANSI_RESET, ANSI_CLEAR_LINE);
        return;
    }
    auto list = d.incidents->snapshot();

    if (state.inc_detail && !list.empty() &&
        state.inc_selected < static_cast<int>(list.size())) {
        draw_incident_detail(list[state.inc_selected], rows, cols);
        return;
    }

    set_cursor(top_row, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Incidents (%zu total, %zu open) ─────" ANSI_RESET "%s\n",
           list.size(), d.incidents->count_open(), ANSI_CLEAR_LINE);
    printf(ANSI_BOLD "%-10s %-11s %-9s %-9s %-20s %-20s" ANSI_RESET "%s\n",
           "ID", "STATUS", "SEV", "CAT", "FIRST SEEN", "TITLE", ANSI_CLEAR_LINE);

    int visible = std::max(0, rows - 3);
    int skip    = state.inc_scroll;
    int drawn   = 0;

    for (int i = 0; i < static_cast<int>(list.size()) && drawn < visible; ++i) {
        if (skip-- > 0) continue;
        const auto& inc = list[i];
        bool selected   = i == state.inc_selected;

        // Store in local variables — severity_color() returns a temporary std::string,
        // so calling .c_str() inline produces a dangling pointer and stray characters.
        std::string sev_col_str = severity_color(inc.max_severity);
        const char* sev_col = sev_col_str.c_str();
        const char* stat_col =
            inc.status == incidents::Status::OPEN           ? ANSI_BRED :
            inc.status == incidents::Status::ACKNOWLEDGED   ? ANSI_BYELLOW :
            inc.status == incidents::Status::INVESTIGATING  ? ANSI_BCYAN :
            inc.status == incidents::Status::RESOLVED       ? ANSI_GREEN : ANSI_RESET;

        auto ts = std::chrono::system_clock::to_time_t(inc.first_seen);
        char tsbuf[20] = {};
        struct tm tm_info{};
        if (localtime_r(&ts, &tm_info)) strftime(tsbuf, sizeof(tsbuf), "%m/%d %H:%M", &tm_info);

        int title_w = std::max(10, cols - 73);
        set_cursor(top_row + 2 + drawn, 1);
        if (selected) {
            printf(ANSI_SEL_BG "%-10s %-11s %-9s %-9s %-20s %-*s" ANSI_RESET "%s\n",
                   trunc(inc.id, 10).c_str(),
                   trunc(inc.status_str(), 11).c_str(),
                   trunc(events::severity_to_str(inc.max_severity), 9).c_str(),
                   trunc(events::category_to_str(inc.category), 9).c_str(),
                   tsbuf,
                   title_w, trunc(inc.title, title_w).c_str(), ANSI_CLEAR_LINE);
        } else {
            printf("%-10s %s%-11s" ANSI_RESET " %s%-9s" ANSI_RESET
                   " %-9s %-20s %-*s%s\n",
                   trunc(inc.id, 10).c_str(),
                   stat_col, trunc(inc.status_str(), 11).c_str(),
                   sev_col, trunc(events::severity_to_str(inc.max_severity), 9).c_str(),
                   trunc(events::category_to_str(inc.category), 9).c_str(),
                   tsbuf,
                   title_w, trunc(inc.title, title_w).c_str(), ANSI_CLEAR_LINE);
        }
        drawn++;
    }
    for (int i = drawn; i < visible; ++i) {
        set_cursor(top_row + 2 + i, 1);
        printf("%s\n", ANSI_CLEAR_LINE);
    }
}

void Terminal::draw_incident_detail(const incidents::Incident& inc, int rows, int cols)
{
    set_cursor(5, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Incident Detail ─────────────────────" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
    auto lbl = [&](const char* l, const std::string& val) {
        int vw = std::max(10, cols - 20);
        printf(ANSI_BOLD " %-16s" ANSI_RESET " %s%s\n", l, trunc(val, vw).c_str(), ANSI_CLEAR_LINE);
    };
    lbl("Incident ID:",  inc.id);
    lbl("Status:",       inc.status_str());
    lbl("Severity:",     events::severity_to_str(inc.max_severity));
    lbl("Category:",     events::category_to_str(inc.category));
    lbl("First seen:",   events::format_time(inc.first_seen));
    lbl("Last seen:",    events::format_time(inc.last_seen));
    lbl("Title:",        inc.title);
    if (inc.related_pid > 0) lbl("Related PID:", std::to_string(inc.related_pid));
    if (!inc.related_user.empty())  lbl("User:",  inc.related_user);
    if (!inc.related_path.empty())  lbl("Path:",  inc.related_path);
    if (!inc.extra.empty())         lbl("Key:",   inc.extra);

    int ev_count = static_cast<int>(inc.evidence_events.size());
    lbl("Evidence events:", std::to_string(ev_count));

    if (!inc.explanation.empty()) {
        printf(ANSI_BOLD ANSI_BYELLOW "\n Why suspicious:" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
        printf("   %s%s\n", trunc(inc.explanation, cols - 4).c_str(), ANSI_CLEAR_LINE);
    }
    if (!inc.next_steps.empty()) {
        printf(ANSI_BOLD ANSI_BCYAN "\n What to check next:" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
        printf("   %s%s\n", trunc(inc.next_steps, cols - 4).c_str(), ANSI_CLEAR_LINE);
    }

    // Show up to 5 most recent evidence events
    int show_ev = std::min(ev_count, 5);
    if (show_ev > 0) {
        printf(ANSI_BOLD "\n Recent evidence:" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);
        for (int i = ev_count - show_ev; i < ev_count; ++i) {
            const auto& e = inc.evidence_events[i];
            // Store severity color in a local — temporary std::string::c_str() is dangling.
            std::string ev_col_str = severity_color(e.severity);
            printf("  %s[%s] %s %s%s" ANSI_RESET " %s%s\n",
                   ev_col_str.c_str(),
                   e.timestamp_str().c_str(),
                   e.severity_str().c_str(),
                   e.category_str().c_str(),
                   ANSI_RESET,
                   trunc(e.title, cols - 40).c_str(),
                   ANSI_CLEAR_LINE);
        }
    }

    // Status actions and available keys
    printf(ANSI_DIM "\n ESC:Back  a:Acknowledge  i:Investigating  r:Resolve  e:Export  x:Kill PID" ANSI_RESET "%s\n",
           ANSI_CLEAR_LINE);
    printf("%s", ANSI_CLEAR_DOWN);
    (void)rows;
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

    // Show detail overlay if requested
    if (state.event_detail && !filtered.empty()) {
        int sel = std::min(state.event_selected, static_cast<int>(filtered.size()) - 1);
        if (sel >= 0) {
            draw_event_detail(filtered[sel], rows, cols);
            return;
        }
    }

    set_cursor(top_row, 1);
    const char* filter_names[] = {"ALL","AUTH","PROC","NET","FILE","SYS"};
    printf(ANSI_BOLD ANSI_BCYAN " ── Security Events [%zu total]" ANSI_RESET
           "  Filter: " ANSI_YELLOW "%s" ANSI_RESET
           "  (f=cycle, /=search, Enter=detail)%s\n",
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
        bool selected = (i + scroll) == state.event_selected;
        set_cursor(cur_row + i, 1);
        if (selected) {
            printf(ANSI_SEL_BG "%-20s %-8s %-9s %-12s %s" ANSI_RESET "%s\n",
                   e.timestamp_str().c_str(),
                   e.severity_str().c_str(),
                   e.category_str().c_str(),
                   trunc(e.source, 12).c_str(),
                   trunc(e.title, title_width).c_str(),
                   ANSI_CLEAR_LINE);
        } else {
            // Store locally — temporary std::string::c_str() is dangling in printf args.
            std::string ev_row_col = severity_color(e.severity);
            printf("%s%-20s " ANSI_RESET "%-8s " ANSI_DIM "%-9s %-12s" ANSI_RESET " %s%s\n",
                   ev_row_col.c_str(),
                   e.timestamp_str().c_str(),
                   e.severity_str().c_str(),
                   e.category_str().c_str(),
                   trunc(e.source, 12).c_str(),
                   trunc(e.title, title_width).c_str(),
                   ANSI_CLEAR_LINE);
        }
        drawn++;
    }

    for (int i = drawn; i < visible; ++i) {
        set_cursor(cur_row + i, 1);
        printf("%s\n", ANSI_CLEAR_LINE);
    }
}

void Terminal::draw_help(const UiState& state, int top_row, int rows, int cols) {
    (void)cols;
    set_cursor(top_row, 1);
    printf(ANSI_BOLD ANSI_BCYAN " ── Linux Security Monitor Guide & Reference ────────────────────────" ANSI_RESET "%s\n", ANSI_CLEAR_LINE);

    const char* guide[] = {
        ANSI_BOLD ANSI_BYELLOW "[1] GLOBAL CONTROLS & SHORTCUTS" ANSI_RESET,
        "  TAB / 1-5    Switch active panel (1:Processes, 2:Network, 3:Events, 4:Incidents, 5:Help)",
        "  q / Q        Gracefully terminate and restore terminal",
        "  h / 4        Open this reference guide",
        "  ↑ ↓ / j k    Navigate or scroll active tables and event lists",
        "  Home / End   Jump directly to top or bottom of table",
        "  PgUp / PgDn  Scroll 10 lines up or down",
        "",
        ANSI_BOLD ANSI_BYELLOW "[2] PROCESSES PANEL (TAB 1)" ANSI_RESET,
        "  Interactive Keys:",
        "    c / m / p    Sort processes by CPU%, Memory usage, or PID",
        "    /            Search/filter processes live by process name or cmdline",
        "    Enter        Open full process detail screen with file descriptors",
        "    ESC          Exit search mode or return from detail view",
        "",
        "  Table Columns & Field Meanings:",
        "    PID          Process Identifier (unique integer assigned by kernel)",
        "    PPID         Parent Process ID (the process that spawned this process)",
        "    USER         Username (or UID) that owns and executes this process",
        "    CPU%         Active CPU utilization normalized across all CPU cores",
        "                 (100% means 1 full core utilized, matching top/htop)",
        "    MEM          Resident Physical Memory (RSS) in RAM in compact K/M/G units",
        "                 (e.g., 512K = Kilobytes, 45M = Megabytes, 1.4G = Gigabytes)",
        "    S (State)    Process Execution State from /proc/[pid]/stat:",
        "                 • " ANSI_BGREEN "R (Running)" ANSI_RESET "   : Actively executing on CPU or in run queue ready to run",
        "                 • " ANSI_BYELLOW "S (Sleeping)" ANSI_RESET "  : Waiting for an event/resource (I/O, timer, input)",
        "                 • " ANSI_BRED "D (Disk Sleep)" ANSI_RESET ": Uninterruptible disk or driver I/O sleep",
        "                 • " ANSI_BRED "Z (Zombie)" ANSI_RESET "    : Terminated process waiting for parent to read exit code",
        "                 • " ANSI_DIM "T (Stopped)" ANSI_RESET "   : Suspended by SIGSTOP or debugger",
        "    COMMAND      Short comm/binary executable name (e.g. systemd, bash, sshd)",
        "    EXE PATH     Absolute path to binary on disk resolved via /proc/[pid]/exe",
        "    STARTED      Date and local time the process was spawned",
        "",
        "  Security Threat Row Highlights:",
        "    • " ANSI_SEL_BG " Blue Highlight " ANSI_RESET "         : Currently selected row (press Enter for details)",
        "    • " ANSI_BRED "Bright Red Text" ANSI_RESET "         : Critical Anomaly: Root process (UID 0) running",
        "                                  from suspicious directory (/tmp, /dev/shm)",
        "    • " ANSI_BYELLOW "Bright Yellow Text" ANSI_RESET "      : Suspicious Anomaly: Running from temp folder or",
        "                                  binary deleted from disk while in memory",
        "",
        ANSI_BOLD ANSI_BYELLOW "[3] NETWORK MONITOR PANEL (TAB 2)" ANSI_RESET,
        "  Interfaces Table:",
        "    RX/s, TX/s   Live network throughput rate (bytes/s, KB/s, or MB/s)",
        "    RX/TX bytes  Cumulative transfer volume since interface came up",
        "    RX/TX err    Packet receive/transmit errors detected by kernel",
        "",
        "  Connections Table:",
        "    PROTO        Protocol family: TCP, TCP6, UDP, UDP6",
        "    LOCAL        Local IP address and listening/binding port number",
        "    REMOTE       Remote peer address and connection port",
        "    STATE        Socket status (ESTABLISHED = Connected, LISTEN = Open port)",
        "    PID/PROCESS  Owning Process ID and command name that holds the open socket",
        "",
        ANSI_BOLD ANSI_BYELLOW "[4] SECURITY EVENTS PANEL (TAB 3)" ANSI_RESET,
        "  Event Feed & Filter:",
        "    f            Cycle category filter: ALL → AUTH → PROC → NET → FILE → SYS",
        "    /            Live search across event titles and detail explanations",
        "",
        "  Event Categories:",
        "    AUTH         SSH logins: successful logins, password failures, brute-force",
        "    PROCESS      Threat heuristics: temp path execution, deleted binaries",
        "    NETWORK      New listening ports opened, closed connections",
        "    FILE         File Integrity Monitor: changes to watched config/system files",
        "    SYSTEM       Core system events and engine notifications",
        "",
        "  Severity Levels:",
        "    " ANSI_BGREEN "LOW" ANSI_RESET " / " ANSI_BYELLOW "MEDIUM" ANSI_RESET " / " ANSI_RED "HIGH" ANSI_RESET " / " ANSI_BRED "CRITICAL" ANSI_RESET " (Emits desktop alert & terminal bell)",
        "",
        ANSI_BOLD ANSI_BYELLOW "[5] INCIDENTS PANEL (key 5)" ANSI_RESET,
        "  Overview List Keys:",
        "    ↑ ↓ / j k    Navigate the incident list",
        "    Enter        Open incident detail view",
        "    a            Acknowledge the selected incident (mark seen)",
        "    i            Set status to Investigating",
        "    r            Mark incident Resolved",
        "    e            Export full incident report to disk (reports/ directory)",
        "    x            Send SIGTERM to the incident's related PID (confirmation required)",
        "    ESC          Return from detail view to the incident list",
        "",
        "  Incident Lifecycle:",
        "    OPEN → ACKNOWLEDGED → INVESTIGATING → RESOLVED",
        "    Each status change is persisted to disk and survives restarts.",
        "    Resolved incidents remain in the list for audit purposes.",
        "",
        ANSI_BOLD ANSI_BYELLOW "[6] BURST DETECTION (NETWORK ANOMALY)" ANSI_RESET,
        "  Burst detection watches for sudden spikes in connection activity:",
        "    • A burst is triggered when a process opens more connections than the",
        "      configured threshold within a single monitoring interval.",
        "    • Bursts are emitted as NETWORK/HIGH events and automatically create",
        "      or update an Incident grouped by the owning process's PID.",
        "    • Trusted ports (marked with 't' on the Network panel) are excluded.",
        "",
        "  Investigating a burst:",
        "    1. Check the Incidents panel (key 5) for grouped burst alerts.",
        "    2. Open the incident detail to see first/last seen, related PID, path.",
        "    3. Use the Events panel (key 3) and filter by NET to see per-event detail.",
        "    4. If the process is expected (e.g. a backup tool), mark the incident Resolved.",
        "",
        ANSI_BOLD ANSI_BYELLOW "[7] INCIDENT INGESTION (EVENT → INCIDENT PIPELINE)" ANSI_RESET,
        "  Every security event is evaluated against the IncidentStore for grouping:",
        "    • Events sharing a group key (PID, source IP, file path, or port) are",
        "      merged into a single Incident rather than flooding the list.",
        "    • The incident's severity is promoted if a new event is more severe.",
        "    • Incidents persist across restarts in ~/.local/share/linux-security-monitor/",
        "",
        "  Group keys by category:",
        "    AUTH     Grouped by source IP address",
        "    PROCESS  Grouped by PID (or executable path for ephemeral processes)",
        "    NETWORK  Grouped by port number (listening) or remote IP (outbound)",
        "    FILE     Grouped by absolute file path",
        "    SYSTEM   Grouped by event title",
        "",
        ANSI_BOLD ANSI_BYELLOW "[8] PROCESS PARENT-CHAIN ANALYSIS" ANSI_RESET,
        "  The security engine walks the process tree to detect anomalous spawn chains:",
        "    • A service process (nginx, sshd, httpd, etc.) that spawns an interactive",
        "      shell (bash, sh, zsh, python, perl, ruby) triggers a HIGH alert.",
        "    • The alert records: suspicious PID, parent PID, parent name, executable",
        "      path, owning user, start time, and any associated open connections.",
        "    • Each finding is annotated with a human-readable reason explaining why",
        "      the parent-child relationship is unusual.",
        "",
        "  Interpreting a parent-chain alert:",
        "    • It means a service that normally has no interactive children has one.",
        "    • This is a known pattern for web-shell exploitation and SSH pivoting.",
        "    • It is an indicator, not proof: verify the process in the detail view",
        "      (Enter on the Processes panel) and check its command line and connections.",
        nullptr
    };

    int total_lines = 0;
    while (guide[total_lines] != nullptr) total_lines++;

    int visible = std::max(0, rows - 1);
    int scroll = state.help_scroll;
    if (scroll > total_lines - visible) scroll = std::max(0, total_lines - visible);

    int drawn = 0;
    for (int i = 0; i < visible && (i + scroll) < total_lines; ++i) {
        set_cursor(top_row + 1 + i, 1);
        printf(" %s%s\n", guide[i + scroll], ANSI_CLEAR_LINE);
        drawn++;
    }

    for (int i = drawn; i < visible; ++i) {
        set_cursor(top_row + 1 + i, 1);
        printf("%s\n", ANSI_CLEAR_LINE);
    }
}

void Terminal::draw_confirm(const UiState& state, int cols)
{
    int rows, c2;
    get_terminal_size(rows, c2);
    // Draw a centered confirmation prompt 3 rows from bottom
    int y = rows - 4;
    std::string msg;
    if (state.confirm == ConfirmAction::KILL_PROCESS)
        msg = "  Send SIGTERM to PID " + std::to_string(state.confirm_pid) + "? [y/N]  ";
    else if (state.confirm == ConfirmAction::REBASE)
        msg = "  Re-establish file integrity baseline from current disk state? [y/N]  ";
    else
        msg = "  Confirm action? [y/N]  ";

    int start_col = std::max(1, (cols - static_cast<int>(msg.size())) / 2);
    set_cursor(y, start_col);
    printf(ANSI_REVERSE ANSI_BRED "%s" ANSI_RESET, msg.c_str());
}

void Terminal::draw_footer(const UiState& state, int cols) {
    int rows, c2;
    get_terminal_size(rows, c2);
    set_cursor(rows, 1);

    printf(ANSI_REVERSE ANSI_BOLD);
    std::string footer;
    switch (state.active_panel) {
        case Panel::PROCESSES:
            footer = " q:Quit  TAB:Next  ↑↓/jk:Nav  c:CPU  m:MEM  p:PID  /:Search  Enter:Detail  x:Kill  B:Rebaseline";
            break;
        case Panel::NETWORK:
            footer = " q:Quit  TAB:Next  ↑↓:Scroll  t:Trust/Untrust  l:Timeline  1-6:Panels";
            break;
        case Panel::AUTH:
            footer = " q:Quit  TAB:Next  ↑↓/jk:Nav  1-6:Panels";
            break;
        case Panel::EVENTS:
            footer = " q:Quit  TAB:Next  f:Filter  /:Search  ↑↓:Nav  Enter:Detail  ESC:Back  1-6:Panels";
            break;
        case Panel::INCIDENTS:
            footer = " q:Quit  TAB:Next  ↑↓:Nav  Enter:Detail  a:Ack  i:Invest  r:Resolve  e:Export  x:Kill PID";
            break;
        case Panel::HELP:
            footer = " q:Quit  TAB:Next  ↑↓/jk/PgUp/PgDn:Scroll  1-6:Panels";
            break;
    }
    if (!state.status_message.empty()) {
        // Auto-hide after 3 seconds.
        auto age = std::chrono::steady_clock::now() - state.status_message_time;
        if (std::chrono::duration_cast<std::chrono::seconds>(age).count() < 3) {
            std::string msg = "  [" + state.status_message + "]";
            int pad = std::max(0, cols - static_cast<int>(footer.size()) - static_cast<int>(msg.size()));
            footer += std::string(pad, ' ') + msg;
        }
    }
    footer += std::string(std::max(0, cols - static_cast<int>(footer.size())), ' ');
    printf("%.*s" ANSI_RESET, cols, footer.c_str());
}

} // namespace ui
