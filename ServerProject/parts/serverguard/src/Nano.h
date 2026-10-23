#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <cstdlib>
#include <ctime>
#include <utility>
#include <limits>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <sstream>
#include <locale>
#include <codecvt>
#include <climits>

#include <libssh2.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#endif

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

namespace nanoed
{
    static const size_t MAX_FILE_SIZE = 1024 * 1024;
    static const size_t MAX_UNDO = 50;

    typedef std::wstring WStr;

    struct RunResult
    {
        bool started = false;
        int exitCode = -1;
        std::string out;
        std::string err;
    };

    inline std::string trimStr(const std::string& s)
    {
        size_t a = 0;
        size_t b = s.size();

        while (a < b && std::isspace(static_cast<unsigned char>(s[a])))
            ++a;

        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
            --b;

        return s.substr(a, b - a);
    }

    inline std::string unquote(std::string s)
    {
        s = trimStr(s);

        if (s.size() >= 2 &&
            ((s.front() == '"' && s.back() == '"') ||
                (s.front() == '\'' && s.back() == '\'')))
        {
            s = s.substr(1, s.size() - 2);
        }

        return s;
    }

    inline std::string shQuote(const std::string& s)
    {
        std::string r = "'";

        for (char c : s)
        {
            if (c == '\'')
                r += "'\\''";
            else
                r += c;
        }

        r += "'";
        return r;
    }

    inline std::string remotePath(const std::string& p)
    {
        if (p == "~")
            return "\"$HOME\"";

        if (p.rfind("~/", 0) == 0)
            return "\"$HOME\"/" + shQuote(p.substr(2));

        return shQuote(p);
    }

    inline bool utf8ToW(const std::string& s, WStr& out)
    {
        out.clear();

        if (s.empty())
            return true;

#ifdef _WIN32
        if (s.size() > static_cast<size_t>(INT_MAX))
            return false;

        int n = MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            s.data(),
            static_cast<int>(s.size()),
            nullptr,
            0
        );

        if (n <= 0)
            return false;

        out.resize(static_cast<size_t>(n));

        return MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            s.data(),
            static_cast<int>(s.size()),
            &out[0],
            n
        ) > 0;
#else
        try
        {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
            out = conv.from_bytes(s);
            return true;
        }
        catch (...)
        {
            out.clear();
            return false;
        }
#endif
    }

    inline WStr toW(const std::string& s)
    {
        WStr w;

        if (s.empty())
            return w;

#ifdef _WIN32
        if (s.size() > static_cast<size_t>(INT_MAX))
            return w;

        int n = MultiByteToWideChar(
            CP_UTF8, 0, s.data(),
            static_cast<int>(s.size()), nullptr, 0
        );

        if (n <= 0)
            return w;

        w.resize(static_cast<size_t>(n));

        MultiByteToWideChar(
            CP_UTF8, 0, s.data(),
            static_cast<int>(s.size()), &w[0], n
        );
#else
        try
        {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
            w = conv.from_bytes(s);
        }
        catch (...)
        {
            w.clear();
        }
#endif

        return w;
    }

    inline std::string toU8(const WStr& w)
    {
        std::string s;

        if (w.empty())
            return s;

#ifdef _WIN32
        if (w.size() > static_cast<size_t>(INT_MAX))
            return s;

        int n = WideCharToMultiByte(
            CP_UTF8, 0, w.data(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr
        );

        if (n <= 0)
            return s;

        s.resize(static_cast<size_t>(n));

        WideCharToMultiByte(
            CP_UTF8, 0, w.data(),
            static_cast<int>(w.size()), &s[0], n, nullptr, nullptr
        );
#else
        try
        {
            std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
            s = conv.to_bytes(w);
        }
        catch (...)
        {
            s.clear();
        }
#endif

        return s;
    }

    inline RunResult runRemote(
        LIBSSH2_SESSION* session,
        const std::string& command,
        const std::string& input = "")
    {
        RunResult res;

        if (!session)
            return res;

        LIBSSH2_CHANNEL* ch = libssh2_channel_open_session(session);

        if (!ch)
            return res;

        if (libssh2_channel_exec(ch, command.c_str()) != 0)
        {
            libssh2_channel_free(ch);
            return res;
        }

        res.started = true;

        size_t off = 0;

        while (off < input.size())
        {
            auto rc = libssh2_channel_write(
                ch,
                input.data() + off,
                input.size() - off
            );

            if (rc < 0)
                break;

            if (rc == 0)
                break;

            off += static_cast<size_t>(rc);
        }

        libssh2_channel_send_eof(ch);

        char buf[4096];

        while (true)
        {
            auto n = libssh2_channel_read(ch, buf, sizeof(buf));

            if (n > 0)
            {
                res.out.append(buf, static_cast<size_t>(n));

                if (res.out.size() > MAX_FILE_SIZE + 65536)
                    break;

                continue;
            }

            if (n == LIBSSH2_ERROR_EAGAIN)
            {
                if (libssh2_channel_eof(ch))
                    break;

                continue;
            }

            break;
        }

        while (true)
        {
            auto n = libssh2_channel_read_stderr(ch, buf, sizeof(buf));

            if (n > 0)
            {
                res.err.append(buf, static_cast<size_t>(n));

                if (res.err.size() > 65536)
                    break;

                continue;
            }

            if (n == LIBSSH2_ERROR_EAGAIN)
            {
                if (libssh2_channel_eof(ch))
                    break;

                continue;
            }

            break;
        }

        libssh2_channel_wait_eof(ch);
        libssh2_channel_wait_closed(ch);

        res.exitCode = libssh2_channel_get_exit_status(ch);

        libssh2_channel_free(ch);

        return res;
    }

    enum class FileKind
    {
        Missing,
        Regular,
        Directory,
        Error
    };

    inline FileKind detectKind(
        LIBSSH2_SESSION* session,
        const std::string& cwd,
        const std::string& path)
    {
        std::string P = remotePath(path);

        std::string cmd =
            "cd " + shQuote(cwd) + " && "
            "if [ -d " + P + " ]; then echo D; "
            "elif [ -e " + P + " ]; then echo F; "
            "else echo N; fi";

        RunResult r = runRemote(session, cmd);

        if (!r.started || r.exitCode != 0)
            return FileKind::Error;

        std::string o = trimStr(r.out);

        if (o == "D")
            return FileKind::Directory;

        if (o == "F")
            return FileKind::Regular;

        if (o == "N")
            return FileKind::Missing;

        return FileKind::Error;
    }

    inline bool downloadFile(
        LIBSSH2_SESSION* session,
        const std::string& password,
        const std::string& cwd,
        const std::string& path,
        std::string& content,
        std::string& err)
    {
        std::string P = remotePath(path);

        RunResult r = runRemote(
            session,
            "cd " + shQuote(cwd) + " && cat -- " + P
        );

        if (r.started && r.exitCode == 0)
        {
            content = r.out;
            return true;
        }

        if (!password.empty())
        {
            r = runRemote(
                session,
                "cd " + shQuote(cwd) +
                " && sudo -S -p '' cat -- " + P,
                password + "\n"
            );

            if (r.started && r.exitCode == 0)
            {
                content = r.out;
                return true;
            }
        }

        err = trimStr(r.err);

        if (err.empty())
            err = "cannot read file";

        return false;
    }

    inline bool uploadFile(
        LIBSSH2_SESSION* session,
        const std::string& password,
        const std::string& cwd,
        const std::string& path,
        const std::string& content,
        std::string& err)
    {
        std::string P = remotePath(path);

        std::srand(static_cast<unsigned>(std::time(nullptr)));

        std::string tmp =
            "/tmp/.serverguard_nano_" +
            std::to_string(std::rand()) + "_" +
            std::to_string(std::rand());

        RunResult up = runRemote(
            session,
            "umask 077; cat > " + shQuote(tmp),
            content
        );

        if (!up.started || up.exitCode != 0)
        {
            err = trimStr(up.err);

            if (err.empty())
                err = "cannot write temporary file";

            return false;
        }

        RunResult cp = runRemote(
            session,
            "cd " + shQuote(cwd) +
            " && cat -- " + shQuote(tmp) + " > " + P
        );

        bool ok = cp.started && cp.exitCode == 0;

        if (!ok && !password.empty())
        {
            cp = runRemote(
                session,
                "cd " + shQuote(cwd) +
                " && sudo -S -p '' sh -c 'cat \"$1\" > \"$2\"' sh " +
                shQuote(tmp) + " " + P,
                password + "\n"
            );

            ok = cp.started && cp.exitCode == 0;
        }

        runRemote(session, "rm -f -- " + shQuote(tmp));

        if (!ok)
        {
            err = trimStr(cp.err);

            if (err.empty())
                err = "permission denied";
        }

        return ok;
    }

    enum KeyType
    {
        KT_NONE,
        KT_CHAR,
        KT_CTRL,
        KT_ALT,
        KT_UP,
        KT_DOWN,
        KT_LEFT,
        KT_RIGHT,
        KT_HOME,
        KT_END,
        KT_PGUP,
        KT_PGDN,
        KT_DEL,
        KT_BS,
        KT_ENTER,
        KT_TAB,
        KT_ESC,
        KT_CTRL_LEFT,
        KT_CTRL_RIGHT,
        KT_CTRL_HOME,
        KT_CTRL_END,
        KT_RESIZE,
        KT_EOF
    };

    struct Key
    {
        KeyType t = KT_NONE;
        wchar_t ch = 0;
        int vk = 0;
    };

    struct Pos
    {
        size_t y = 0;
        size_t x = 0;
    };

    inline bool posLess(const Pos& a, const Pos& b)
    {
        return a.y < b.y || (a.y == b.y && a.x < b.x);
    }

    struct Snap
    {
        std::vector<WStr> lines;
        size_t cy = 0;
        size_t cx = 0;
    };

    typedef std::vector<std::pair<WStr, WStr>> Bar;

    inline size_t dispCol(const WStr& l, size_t x)
    {
        size_t c = 0;

        for (size_t i = 0; i < x && i < l.size(); ++i)
            c += (l[i] == L'\t') ? 8 - c % 8 : 1;

        return c;
    }

    inline size_t xFromDisp(const WStr& l, size_t dcol)
    {
        size_t col = 0;

        for (size_t i = 0; i < l.size(); ++i)
        {
            size_t w = (l[i] == L'\t') ? 8 - col % 8 : 1;

            if (col + w > dcol)
                return i;

            col += w;
        }

        return l.size();
    }

    inline WStr lowerW(WStr s)
    {
        for (wchar_t& c : s)
            c = static_cast<wchar_t>(std::towlower(c));

        return s;
    }

    inline bool isWordCh(wchar_t c)
    {
        return std::iswalnum(c) || c == L'_';
    }

    enum LastOp
    {
        OP_NONE,
        OP_TYPE,
        OP_BACK,
        OP_DEL,
        OP_CUT
    };

    class Editor
    {
    public:
        Editor(
            LIBSSH2_SESSION* s,
            const std::string& pw,
            const std::string& cwd_,
            const std::string& path_,
            std::vector<WStr> ls,
            bool isNew_,
            bool crlf_)
            : session(s),
            password(pw),
            cwd(cwd_),
            path(path_),
            lines(std::move(ls)),
            isNew(isNew_),
            crlf(crlf_)
        {
            if (lines.empty())
                lines.push_back(L"");

            savedLines = lines;
        }

        bool init()
        {
#ifdef _WIN32
            hIn = GetStdHandle(STD_INPUT_HANDLE);
            hOut = GetStdHandle(STD_OUTPUT_HANDLE);

            if (hIn == INVALID_HANDLE_VALUE ||
                hOut == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            if (!GetConsoleMode(hIn, &oldIn) ||
                !GetConsoleMode(hOut, &oldOut))
            {
                return false;
            }

            DWORD outMode = oldOut | ENABLE_PROCESSED_OUTPUT |
                ENABLE_VIRTUAL_TERMINAL_PROCESSING;

            if (!SetConsoleMode(hOut, outMode))
                return false;

            DWORD inMode = (oldIn | ENABLE_EXTENDED_FLAGS |
                ENABLE_WINDOW_INPUT) &
                ~(DWORD)(ENABLE_PROCESSED_INPUT |
                    ENABLE_LINE_INPUT |
                    ENABLE_ECHO_INPUT |
                    ENABLE_QUICK_EDIT_MODE |
                    ENABLE_MOUSE_INPUT);

            if (!SetConsoleMode(hIn, inMode))
            {
                SetConsoleMode(hOut, oldOut);
                return false;
            }

            FlushConsoleInputBuffer(hIn);
#else
            if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
                return false;

            if (tcgetattr(STDIN_FILENO, &oldTermios) != 0)
                return false;

            struct termios raw = oldTermios;

            raw.c_lflag &= static_cast<tcflag_t>(
                ~(ECHO | ICANON | IEXTEN | ISIG)
                );

            raw.c_iflag &= static_cast<tcflag_t>(
                ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP)
                );

            raw.c_oflag &= static_cast<tcflag_t>(~OPOST);
            raw.c_cflag |= CS8;

            raw.c_cc[VMIN] = 1;
            raw.c_cc[VTIME] = 0;

            if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
                return false;
#endif

            active = true;
            writeOut(L"\x1b[?1049h\x1b[2J\x1b[H");
            updateSize();

            return true;
        }

        void shutdown()
        {
            if (!active)
                return;

            writeOut(L"\x1b[0m\x1b[?25h\x1b[?1049l");

#ifdef _WIN32
            SetConsoleMode(hIn, oldIn | ENABLE_EXTENDED_FLAGS);
            SetConsoleMode(hOut, oldOut);
            FlushConsoleInputBuffer(hIn);
#else
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldTermios);
#endif

            active = false;
        }

        void run()
        {
            if (isNew)
            {
                msg = L"New File";
            }
            else
            {
                size_t n = lines.size();

                if (n > 1 && lines.back().empty())
                    --n;

                msg = L"Read " + std::to_wstring(n) +
                    (n == 1 ? L" line" : L" lines");
            }

            for (;;)
            {
                draw();

                Key k = readKey();

                if (k.t == KT_RESIZE)
                    continue;

                if (k.t == KT_EOF)
                    return;

                msg.clear();

                LastOp op = OP_NONE;
                bool vertical = false;

                switch (k.t)
                {
                case KT_CHAR:
                    insertChar(k.ch);
                    op = OP_TYPE;
                    break;

                case KT_TAB:
                    insertChar(L'\t');
                    op = OP_TYPE;
                    break;

                case KT_ENTER:
                    doEnter();
                    break;

                case KT_BS:
                    doBackspace();
                    op = OP_BACK;
                    break;

                case KT_DEL:
                    doDelete();
                    op = OP_DEL;
                    break;

                case KT_UP:
                    moveUp(1);
                    vertical = true;
                    break;

                case KT_DOWN:
                    moveDown(1);
                    vertical = true;
                    break;

                case KT_LEFT:
                    moveLeft();
                    break;

                case KT_RIGHT:
                    moveRight();
                    break;

                case KT_HOME:
                    cx = 0;
                    break;

                case KT_END:
                    cx = lines[cy].size();
                    break;

                case KT_PGUP:
                    moveUp(static_cast<size_t>(editRows));
                    vertical = true;
                    break;

                case KT_PGDN:
                    moveDown(static_cast<size_t>(editRows));
                    vertical = true;
                    break;

                case KT_CTRL_LEFT:
                    wordLeft();
                    break;

                case KT_CTRL_RIGHT:
                    wordRight();
                    break;

                case KT_CTRL_HOME:
                    cy = 0;
                    cx = 0;
                    break;

                case KT_CTRL_END:
                    cy = lines.size() - 1;
                    cx = lines[cy].size();
                    break;

                case KT_CTRL:
                    if (!ctrlKey(k.ch, op, vertical))
                        return;
                    break;

                case KT_ALT:
                    altKey(k.ch);
                    break;

                default:
                    break;
                }

                if (!vertical)
                    desired = dispCol(lines[cy], cx);

                lastOp = op;
            }
        }

    private:
        LIBSSH2_SESSION* session;
        std::string password;
        std::string cwd;
        std::string path;

        std::vector<WStr> lines;
        std::vector<WStr> savedLines;

        bool isNew = false;
        bool crlf = false;

        size_t cy = 0;
        size_t cx = 0;
        size_t desired = 0;
        size_t top = 0;
        size_t left = 0;

        bool modified = false;
        bool markOn = false;
        Pos mark;

        std::vector<Snap> undo;
        std::vector<Snap> redo;

        std::vector<WStr> clip;
        bool clipWhole = false;

        WStr lastSearch;
        WStr msg;
        LastOp lastOp = OP_NONE;

#ifdef _WIN32
        HANDLE hIn = nullptr;
        HANDLE hOut = nullptr;
        DWORD oldIn = 0;
        DWORD oldOut = 0;
#else
        struct termios oldTermios {};
#endif

        bool active = false;

        int W = 80;
        int H = 25;
        int editRows = 20;

        bool prompting = false;
        WStr pLabel;
        WStr pInput;
        size_t pCur = 0;
        Bar pb1;
        Bar pb2;

        void writeOut(const WStr& s)
        {
#ifdef _WIN32
            size_t off = 0;

            while (off < s.size())
            {
                DWORD chunk = static_cast<DWORD>(
                    std::min<size_t>(s.size() - off, 16000)
                    );

                DWORD written = 0;

                if (!WriteConsoleW(
                    hOut,
                    s.data() + off,
                    chunk,
                    &written,
                    nullptr))
                {
                    break;
                }

                if (written == 0)
                    break;

                off += written;
            }
#else
            std::string bytes = toU8(s);
            size_t off = 0;

            while (off < bytes.size())
            {
                ssize_t n = ::write(
                    STDOUT_FILENO,
                    bytes.data() + off,
                    bytes.size() - off
                );

                if (n < 0)
                {
                    if (errno == EINTR)
                        continue;

                    break;
                }

                if (n == 0)
                    break;

                off += static_cast<size_t>(n);
            }
#endif
        }

        void updateSize()
        {
#ifdef _WIN32
            CONSOLE_SCREEN_BUFFER_INFO info{};

            if (GetConsoleScreenBufferInfo(hOut, &info))
            {
                W = info.srWindow.Right - info.srWindow.Left + 1;
                H = info.srWindow.Bottom - info.srWindow.Top + 1;
            }
#else
            struct winsize ws {};

            if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0)
            {
                if (ws.ws_col > 0)
                    W = ws.ws_col;

                if (ws.ws_row > 0)
                    H = ws.ws_row;
            }
#endif

            W = std::max(W, 1);
            H = std::max(H, 1);
        }

        static WStr at(int row, int col)
        {
            return L"\x1b[" + std::to_wstring(row) +
                L";" + std::to_wstring(col) + L"H";
        }

        bool inSel(size_t y, size_t x) const
        {
            if (!markOn)
                return false;

            Pos a = mark;
            Pos b;
            b.y = cy;
            b.x = cx;

            if (posLess(b, a))
                std::swap(a, b);

            Pos p;
            p.y = y;
            p.x = x;

            return !posLess(p, a) && posLess(p, b);
        }

        void appendBar(WStr& f, int row, const Bar& items)
        {
            f += at(row, 1);

            int cw = W / 6;

            if (cw < 1)
                cw = 1;

            int used = 0;

            for (size_t i = 0; i < items.size(); ++i)
            {
                int w = (i + 1 == items.size() && items.size() == 6)
                    ? W - used
                    : cw;

                if (w <= 0)
                    break;

                WStr key = items[i].first;
                WStr label = items[i].second;

                if (key.empty())
                {
                    f += WStr(static_cast<size_t>(w), L' ');
                    used += w;
                    continue;
                }

                WStr cell = key + L" " + label;

                if (static_cast<int>(cell.size()) > w - 1)
                {
                    cell.resize(static_cast<size_t>(
                        std::max(w - 1, 0)
                        ));
                }

                size_t kl = std::min(key.size(), cell.size());

                f += L"\x1b[7m";
                f += cell.substr(0, kl);
                f += L"\x1b[0m";
                f += cell.substr(kl);

                if (static_cast<int>(cell.size()) < w)
                {
                    f += WStr(
                        static_cast<size_t>(w) - cell.size(),
                        L' '
                    );
                }

                used += w;
            }

            if (used < W)
                f += WStr(static_cast<size_t>(W - used), L' ');
        }

        void draw()
        {
            updateSize();

            WStr f = L"\x1b[?25l";

            if (H < 7 || W < 30)
            {
                f += L"\x1b[2J\x1b[H";
                f += L"Window too small";
                writeOut(f);
                return;
            }

            editRows = H - 4;

            if (cy < top)
                top = cy;

            if (cy >= top + static_cast<size_t>(editRows))
            {
                top = cy - static_cast<size_t>(editRows) + 1;
            }

            size_t cdc = dispCol(lines[cy], cx);
            size_t uw = static_cast<size_t>(W);

            if (cdc < left || cdc >= left + uw - 1)
            {
                left = (cdc < uw - 1) ? 0 : cdc - uw / 2;
            }

            {
                WStr bar(uw, L' ');
                WStr l = L"  GNU nano 7.2";
                WStr m = path.empty() ? L"New Buffer" : toW(path);
                WStr r = modified ? L"Modified  " : L"";

                if (uw > 30 && m.size() > uw - 30)
                    m = m.substr(m.size() - (uw - 30));

                for (size_t i = 0; i < l.size() && i < uw; ++i)
                    bar[i] = l[i];

                size_t mp = (uw > m.size()) ? (uw - m.size()) / 2 : 0;

                for (size_t i = 0; i < m.size() && mp + i < uw; ++i)
                    bar[mp + i] = m[i];

                for (size_t i = 0; i < r.size() && uw >= r.size(); ++i)
                    bar[uw - r.size() + i] = r[i];

                f += at(1, 1) + L"\x1b[7m" + bar + L"\x1b[0m";
            }

            struct Cell
            {
                wchar_t c;
                size_t idx;
            };

            for (int r = 0; r < editRows; ++r)
            {
                size_t ly = top + static_cast<size_t>(r);

                f += at(r + 2, 1);

                if (ly >= lines.size())
                {
                    f += L"\x1b[K";
                    continue;
                }

                const WStr& l = lines[ly];

                std::vector<Cell> cells;
                size_t col = 0;

                for (size_t i = 0; i < l.size() && col <= left + uw; ++i)
                {
                    if (l[i] == L'\t')
                    {
                        size_t tw = 8 - col % 8;

                        for (size_t j = 0; j < tw; ++j)
                            cells.push_back({ L' ', i });

                        col += tw;
                    }
                    else
                    {
                        wchar_t c = l[i];

                        if (c < 32 || c == 127)
                            c = L'?';

                        cells.push_back({ c, i });
                        ++col;
                    }
                }

                size_t endc = std::min(cells.size(), left + uw);
                bool trunc = cells.size() > left + uw;
                bool cur = false;
                size_t shown = 0;

                for (size_t c = left; c < endc; ++c)
                {
                    bool selected = inSel(ly, cells[c].idx);

                    if (selected != cur)
                    {
                        f += selected ? L"\x1b[7m" : L"\x1b[0m";
                        cur = selected;
                    }

                    wchar_t ch = (trunc && c == left + uw - 1)
                        ? L'$'
                        : cells[c].c;

                    f += ch;
                    ++shown;
                }

                f += L"\x1b[0m";

                if (shown < uw)
                    f += L"\x1b[K";
            }

            f += at(H - 2, 1);

            if (prompting)
            {
                WStr total = pLabel + pInput;
                size_t curPos = pLabel.size() + pCur;
                size_t start = (curPos > uw - 2) ? curPos - (uw - 2) : 0;

                WStr shown = total.substr(std::min(start, total.size()));

                if (shown.size() > uw - 1)
                    shown.resize(uw - 1);

                if (shown.size() < uw)
                    shown += WStr(uw - shown.size(), L' ');

                f += L"\x1b[7m" + shown + L"\x1b[0m";
            }
            else if (!msg.empty())
            {
                WStr t = L"[ " + msg + L" ]";

                if (t.size() > uw - 2)
                    t.resize(uw - 2);

                size_t pad = (uw - t.size()) / 2;

                f += WStr(pad, L' ');
                f += L"\x1b[7m" + t + L"\x1b[0m";

                if (uw > pad + t.size())
                    f += WStr(uw - pad - t.size(), L' ');
            }
            else
            {
                f += WStr(uw, L' ');
            }

            if (prompting)
            {
                appendBar(f, H - 1, pb1);
                appendBar(f, H, pb2);
            }
            else
            {
                Bar b1 = {
                    { L"^G", L"Help" },
                    { L"^O", L"Write Out" },
                    { L"^W", L"Where Is" },
                    { L"^K", L"Cut" },
                    { L"^C", L"Location" },
                    { L"M-U", L"Undo" }
                };

                Bar b2 = {
                    { L"^X", L"Exit" },
                    { L"^\\", L"Replace" },
                    { L"^U", L"Paste" },
                    { L"^/", L"Go To Line" },
                    { L"M-6", L"Copy" },
                    { L"M-E", L"Redo" }
                };

                appendBar(f, H - 1, b1);
                appendBar(f, H, b2);
            }

            if (prompting)
            {
                size_t curPos = pLabel.size() + pCur;
                size_t start = (curPos > uw - 2) ? curPos - (uw - 2) : 0;

                f += at(
                    H - 2,
                    static_cast<int>(curPos - start) + 1
                );
            }
            else
            {
                size_t cursorCol = cdc >= left ? cdc - left : 0;

                if (cursorCol >= uw)
                    cursorCol = uw - 1;

                f += at(
                    static_cast<int>(cy - top) + 2,
                    static_cast<int>(cursorCol) + 1
                );
            }

            f += L"\x1b[?25h";
            writeOut(f);
        }

        bool readByte(unsigned char& ch, int timeoutMs = -1)
        {
#ifdef _WIN32
            DWORD waitTime = timeoutMs < 0
                ? INFINITE
                : static_cast<DWORD>(timeoutMs);

            DWORD waitResult = WaitForSingleObject(hIn, waitTime);

            if (waitResult != WAIT_OBJECT_0)
                return false;

            INPUT_RECORD rec{};
            DWORD count = 0;

            while (ReadConsoleInputW(hIn, &rec, 1, &count) && count)
            {
                if (rec.EventType != KEY_EVENT)
                    continue;

                KEY_EVENT_RECORD e = rec.Event.KeyEvent;

                if (!e.bKeyDown)
                    continue;

                wchar_t c = e.uChar.UnicodeChar;

                if (c > 0 && c < 128)
                {
                    ch = static_cast<unsigned char>(c);
                    return true;
                }
            }

            return false;
#else
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(STDIN_FILENO, &rfds);

            struct timeval tv {};
            struct timeval* tvp = nullptr;

            if (timeoutMs >= 0)
            {
                tv.tv_sec = timeoutMs / 1000;
                tv.tv_usec = (timeoutMs % 1000) * 1000;
                tvp = &tv;
            }

            int ready = select(
                STDIN_FILENO + 1,
                &rfds,
                nullptr,
                nullptr,
                tvp
            );

            if (ready <= 0)
                return false;

            unsigned char b = 0;
            ssize_t n = ::read(STDIN_FILENO, &b, 1);

            if (n != 1)
                return false;

            ch = b;
            return true;
#endif
        }

        Key readKey()
        {
#ifdef _WIN32
            for (;;)
            {
                INPUT_RECORD r{};
                DWORD n = 0;

                if (!ReadConsoleInputW(hIn, &r, 1, &n) || n == 0)
                {
                    Key k;
                    k.t = KT_EOF;
                    return k;
                }

                if (r.EventType == WINDOW_BUFFER_SIZE_EVENT)
                {
                    Key k;
                    k.t = KT_RESIZE;
                    return k;
                }

                if (r.EventType != KEY_EVENT)
                    continue;

                const KEY_EVENT_RECORD& e = r.Event.KeyEvent;

                if (!e.bKeyDown)
                    continue;

                WORD vk = e.wVirtualKeyCode;
                DWORD cs = e.dwControlKeyState;
                wchar_t ch = e.uChar.UnicodeChar;

                bool ctrl = (cs & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
                bool alt = (cs & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED)) != 0;

                Key k;
                k.vk = vk;
                k.ch = ch;

                if (ctrl && alt && ch >= 32)
                {
                    k.t = KT_CHAR;
                    return k;
                }

                if (ctrl && !alt)
                {
                    switch (vk)
                    {
                    case VK_LEFT:  k.t = KT_CTRL_LEFT; return k;
                    case VK_RIGHT: k.t = KT_CTRL_RIGHT; return k;
                    case VK_HOME:  k.t = KT_CTRL_HOME; return k;
                    case VK_END:   k.t = KT_CTRL_END; return k;
                    default: break;
                    }

                    if (vk >= 'A' && vk <= 'Z')
                    {
                        k.t = KT_CTRL;
                        k.ch = static_cast<wchar_t>(L'a' + vk - 'A');
                        return k;
                    }

                    if (vk == VK_OEM_5)
                    {
                        k.t = KT_CTRL;
                        k.ch = L'\\';
                        return k;
                    }

                    if (vk == VK_OEM_2 || ch == 0x1F)
                    {
                        k.t = KT_CTRL;
                        k.ch = L'/';
                        return k;
                    }

                    if (vk == '6' || ch == 0x1E)
                    {
                        k.t = KT_CTRL;
                        k.ch = L'6';
                        return k;
                    }
                }

                if (alt && !ctrl)
                {
                    if (vk >= 'A' && vk <= 'Z')
                    {
                        k.t = KT_ALT;
                        k.ch = static_cast<wchar_t>(L'a' + vk - 'A');
                        return k;
                    }

                    if (vk >= '0' && vk <= '9')
                    {
                        k.t = KT_ALT;
                        k.ch = static_cast<wchar_t>(vk);
                        return k;
                    }

                    continue;
                }

                switch (vk)
                {
                case VK_UP:     k.t = KT_UP; return k;
                case VK_DOWN:   k.t = KT_DOWN; return k;
                case VK_LEFT:   k.t = KT_LEFT; return k;
                case VK_RIGHT:  k.t = KT_RIGHT; return k;
                case VK_HOME:   k.t = KT_HOME; return k;
                case VK_END:    k.t = KT_END; return k;
                case VK_PRIOR:  k.t = KT_PGUP; return k;
                case VK_NEXT:   k.t = KT_PGDN; return k;
                case VK_DELETE: k.t = KT_DEL; return k;
                case VK_BACK:   k.t = KT_BS; return k;
                case VK_RETURN: k.t = KT_ENTER; return k;
                case VK_TAB:    k.t = KT_TAB; return k;
                case VK_ESCAPE: k.t = KT_ESC; return k;
                default: break;
                }

                if (ch >= 32 && ch != 127)
                {
                    k.t = KT_CHAR;
                    return k;
                }
            }
#else
            unsigned char c = 0;

            if (!readByte(c))
            {
                Key k;
                k.t = KT_EOF;
                return k;
            }

            Key k;

            if (c == 3)
            {
                k.t = KT_CTRL;
                k.ch = L'c';
                return k;
            }

            if (c == 1) { k.t = KT_CTRL; k.ch = L'a'; return k; }
            if (c == 2) { k.t = KT_CTRL; k.ch = L'b'; return k; }
            if (c == 4) { k.t = KT_CTRL; k.ch = L'd'; return k; }
            if (c == 5) { k.t = KT_CTRL; k.ch = L'e'; return k; }
            if (c == 6) { k.t = KT_CTRL; k.ch = L'f'; return k; }
            if (c == 7) { k.t = KT_CTRL; k.ch = L'g'; return k; }
            if (c == 8 || c == 127) { k.t = KT_BS; return k; }
            if (c == 9) { k.t = KT_TAB; return k; }
            if (c == 10 || c == 13) { k.t = KT_ENTER; return k; }
            if (c == 11) { k.t = KT_CTRL; k.ch = L'k'; return k; }
            if (c == 12) { k.t = KT_CTRL; k.ch = L'l'; return k; }
            if (c == 14) { k.t = KT_CTRL; k.ch = L'n'; return k; }
            if (c == 16) { k.t = KT_CTRL; k.ch = L'p'; return k; }
            if (c == 18) { k.t = KT_CTRL; k.ch = L'r'; return k; }
            if (c == 21) { k.t = KT_CTRL; k.ch = L'u'; return k; }
            if (c == 23) { k.t = KT_CTRL; k.ch = L'w'; return k; }
            if (c == 24) { k.t = KT_CTRL; k.ch = L'x'; return k; }
            if (c == 25) { k.t = KT_CTRL; k.ch = L'y'; return k; }
            if (c == 26) { k.t = KT_CTRL; k.ch = L'z'; return k; }

            if (c == 27)
            {
                unsigned char c2 = 0;

                if (!readByte(c2, 35))
                {
                    k.t = KT_ESC;
                    return k;
                }

                if (c2 != '[' && c2 != 'O')
                {
                    if (c2 >= 'a' && c2 <= 'z')
                    {
                        k.t = KT_ALT;
                        k.ch = static_cast<wchar_t>(c2);
                        return k;
                    }

                    if (c2 >= 'A' && c2 <= 'Z')
                    {
                        k.t = KT_ALT;
                        k.ch = static_cast<wchar_t>(c2 - 'A' + 'a');
                        return k;
                    }

                    k.t = KT_ESC;
                    return k;
                }

                std::string seq;
                seq.push_back(static_cast<char>(c2));

                for (int i = 0; i < 12; ++i)
                {
                    unsigned char next = 0;

                    if (!readByte(next, 25))
                        break;

                    seq.push_back(static_cast<char>(next));

                    if ((next >= 'A' && next <= 'Z') ||
                        next == '~')
                    {
                        break;
                    }
                }

                if (seq == "[A" || seq == "OA") k.t = KT_UP;
                else if (seq == "[B" || seq == "OB") k.t = KT_DOWN;
                else if (seq == "[C" || seq == "OC") k.t = KT_RIGHT;
                else if (seq == "[D" || seq == "OD") k.t = KT_LEFT;
                else if (seq == "[H" || seq == "OH" || seq == "[1~" ||
                    seq == "[7~") k.t = KT_HOME;
                else if (seq == "[F" || seq == "OF" || seq == "[4~" ||
                    seq == "[8~") k.t = KT_END;
                else if (seq == "[5~") k.t = KT_PGUP;
                else if (seq == "[6~") k.t = KT_PGDN;
                else if (seq == "[3~") k.t = KT_DEL;
                else if (seq == "[1;5D" || seq == "[5D") k.t = KT_CTRL_LEFT;
                else if (seq == "[1;5C" || seq == "[5C") k.t = KT_CTRL_RIGHT;
                else if (seq == "[1;5H") k.t = KT_CTRL_HOME;
                else if (seq == "[1;5F") k.t = KT_CTRL_END;
                else k.t = KT_NONE;

                return k;
            }

            if (c >= 32 && c < 127)
            {
                k.t = KT_CHAR;
                k.ch = static_cast<wchar_t>(c);
                return k;
            }

            if (c >= 128)
            {
                std::string bytes(1, static_cast<char>(c));

                int need = (c & 0xE0) == 0xC0 ? 1 :
                    (c & 0xF0) == 0xE0 ? 2 :
                    (c & 0xF8) == 0xF0 ? 3 : 0;

                for (int i = 0; i < need; ++i)
                {
                    unsigned char next = 0;

                    if (!readByte(next, 100))
                        break;

                    bytes.push_back(static_cast<char>(next));
                }

                WStr decoded;

                if (utf8ToW(bytes, decoded) && !decoded.empty())
                {
                    k.t = KT_CHAR;
                    k.ch = decoded[0];
                    return k;
                }
            }

            k.t = KT_NONE;
            return k;
#endif
        }

        bool prompt(
            const WStr& label,
            WStr& value,
            const Bar& b1,
            const Bar& b2)
        {
            prompting = true;
            pLabel = label;
            pInput = value;
            pCur = pInput.size();
            pb1 = b1;
            pb2 = b2;

            bool ok = false;

            for (;;)
            {
                draw();

                Key k = readKey();

                if (k.t == KT_RESIZE)
                    continue;

                if (k.t == KT_EOF || k.t == KT_ESC)
                    break;

                if (k.t == KT_ENTER)
                {
                    ok = true;
                    break;
                }

                if (k.t == KT_CHAR)
                {
                    pInput.insert(pCur, 1, k.ch);
                    ++pCur;
                }
                else if (k.t == KT_BS)
                {
                    if (pCur > 0)
                    {
                        pInput.erase(pCur - 1, 1);
                        --pCur;
                    }
                }
                else if (k.t == KT_DEL)
                {
                    if (pCur < pInput.size())
                        pInput.erase(pCur, 1);
                }
                else if (k.t == KT_LEFT)
                {
                    if (pCur > 0)
                        --pCur;
                }
                else if (k.t == KT_RIGHT)
                {
                    if (pCur < pInput.size())
                        ++pCur;
                }
                else if (k.t == KT_HOME)
                {
                    pCur = 0;
                }
                else if (k.t == KT_END)
                {
                    pCur = pInput.size();
                }
                else if (k.t == KT_CTRL)
                {
                    if (k.ch == L'c')
                        break;

                    if (k.ch == L'a')
                        pCur = 0;
                    else if (k.ch == L'e')
                        pCur = pInput.size();
                    else if (k.ch == L'b')
                    {
                        if (pCur > 0)
                            --pCur;
                    }
                    else if (k.ch == L'f')
                    {
                        if (pCur < pInput.size())
                            ++pCur;
                    }
                    else if (k.ch == L'd')
                    {
                        if (pCur < pInput.size())
                            pInput.erase(pCur, 1);
                    }
                    else if (k.ch == L'h')
                    {
                        if (pCur > 0)
                        {
                            pInput.erase(pCur - 1, 1);
                            --pCur;
                        }
                    }
                    else if (k.ch == L'k')
                    {
                        pInput.erase(pCur);
                    }
                }
            }

            prompting = false;

            if (ok)
                value = pInput;

            return ok;
        }

        char ask(const WStr& label, bool withAll)
        {
            prompting = true;
            pLabel = label;
            pInput.clear();
            pCur = 0;

            pb1 = {
                { L" Y", L"Yes" },
                { L" N", L"No" }
            };

            if (withAll)
                pb1.push_back({ L" A", L"All" });

            pb2 = { { L"^C", L"Cancel" } };

            char res = 'c';

            for (;;)
            {
                draw();

                Key k = readKey();

                if (k.t == KT_RESIZE)
                    continue;

                if (k.t == KT_EOF || k.t == KT_ESC)
                    break;

                if (k.t == KT_CTRL && k.ch == L'c')
                    break;

                if (k.t == KT_CHAR)
                {
                    wchar_t ch = static_cast<wchar_t>(std::towlower(k.ch));

                    if (ch == L'y') { res = 'y'; break; }
                    if (ch == L'n') { res = 'n'; break; }
                    if (withAll && ch == L'a') { res = 'a'; break; }
                }
            }

            prompting = false;
            return res;
        }

        void snapshot()
        {
            Snap s;
            s.lines = lines;
            s.cy = cy;
            s.cx = cx;

            undo.push_back(std::move(s));

            if (undo.size() > MAX_UNDO)
                undo.erase(undo.begin());

            redo.clear();
            modified = true;
        }

        void insertChar(wchar_t c)
        {
            if (lastOp != OP_TYPE)
                snapshot();

            lines[cy].insert(cx, 1, c);
            ++cx;
        }

        void doEnter()
        {
            snapshot();

            WStr tail = lines[cy].substr(cx);
            lines[cy].erase(cx);

            lines.insert(
                lines.begin() + static_cast<std::ptrdiff_t>(cy) + 1,
                tail
            );

            ++cy;
            cx = 0;
        }

        void doBackspace()
        {
            if (cx > 0)
            {
                if (lastOp != OP_BACK)
                    snapshot();

                lines[cy].erase(cx - 1, 1);
                --cx;
            }
            else if (cy > 0)
            {
                snapshot();

                cx = lines[cy - 1].size();
                lines[cy - 1] += lines[cy];

                lines.erase(
                    lines.begin() + static_cast<std::ptrdiff_t>(cy)
                );

                --cy;
            }
        }

        void doDelete()
        {
            if (cx < lines[cy].size())
            {
                if (lastOp != OP_DEL)
                    snapshot();

                lines[cy].erase(cx, 1);
            }
            else if (cy + 1 < lines.size())
            {
                snapshot();

                lines[cy] += lines[cy + 1];

                lines.erase(
                    lines.begin() + static_cast<std::ptrdiff_t>(cy) + 1
                );
            }
        }

        void moveUp(size_t n)
        {
            if (cy == 0)
                return;

            cy = (cy >= n) ? cy - n : 0;
            cx = xFromDisp(lines[cy], desired);
        }

        void moveDown(size_t n)
        {
            cy = std::min(cy + n, lines.size() - 1);
            cx = xFromDisp(lines[cy], desired);
        }

        void moveLeft()
        {
            if (cx > 0)
                --cx;
            else if (cy > 0)
            {
                --cy;
                cx = lines[cy].size();
            }
        }

        void moveRight()
        {
            if (cx < lines[cy].size())
                ++cx;
            else if (cy + 1 < lines.size())
            {
                ++cy;
                cx = 0;
            }
        }

        void wordLeft()
        {
            if (cx == 0)
            {
                if (cy > 0)
                {
                    --cy;
                    cx = lines[cy].size();
                }

                return;
            }

            const WStr& l = lines[cy];

            while (cx > 0 && !isWordCh(l[cx - 1]))
                --cx;

            while (cx > 0 && isWordCh(l[cx - 1]))
                --cx;
        }

        void wordRight()
        {
            const WStr& l = lines[cy];

            if (cx >= l.size())
            {
                if (cy + 1 < lines.size())
                {
                    ++cy;
                    cx = 0;
                }

                return;
            }

            while (cx < l.size() && isWordCh(l[cx]))
                ++cx;

            while (cx < l.size() && !isWordCh(l[cx]))
                ++cx;
        }

        bool selRange(Pos& a, Pos& b) const
        {
            if (!markOn)
                return false;

            Pos c;
            c.y = cy;
            c.x = cx;

            if (posLess(mark, c))
            {
                a = mark;
                b = c;
            }
            else
            {
                a = c;
                b = mark;
            }

            return true;
        }

        std::vector<WStr> extract(const Pos& a, const Pos& b) const
        {
            std::vector<WStr> out;

            if (a.y == b.y)
            {
                out.push_back(lines[a.y].substr(a.x, b.x - a.x));
            }
            else
            {
                out.push_back(lines[a.y].substr(a.x));

                for (size_t y = a.y + 1; y < b.y; ++y)
                    out.push_back(lines[y]);

                out.push_back(lines[b.y].substr(0, b.x));
            }

            return out;
        }

        void removeRange(const Pos& a, const Pos& b)
        {
            if (a.y == b.y)
            {
                lines[a.y].erase(a.x, b.x - a.x);
            }
            else
            {
                WStr head = lines[a.y].substr(0, a.x);
                WStr tail = lines[b.y].substr(b.x);

                lines.erase(
                    lines.begin() + static_cast<std::ptrdiff_t>(a.y),
                    lines.begin() + static_cast<std::ptrdiff_t>(b.y) + 1
                );

                lines.insert(
                    lines.begin() + static_cast<std::ptrdiff_t>(a.y),
                    head + tail
                );
            }

            cy = a.y;
            cx = a.x;
        }

        void cutText(LastOp& op)
        {
            Pos a, b;

            if (selRange(a, b))
            {
                if (a.y == b.y && a.x == b.x)
                {
                    markOn = false;
                    return;
                }

                snapshot();

                clip = extract(a, b);
                clipWhole = false;

                removeRange(a, b);

                markOn = false;
                op = OP_CUT;

                return;
            }

            snapshot();

            if (lastOp != OP_CUT)
                clip.clear();

            clipWhole = true;
            clip.push_back(lines[cy]);

            if (lines.size() == 1)
            {
                lines[0].clear();
            }
            else
            {
                lines.erase(
                    lines.begin() + static_cast<std::ptrdiff_t>(cy)
                );

                if (cy >= lines.size())
                    cy = lines.size() - 1;
            }

            cx = 0;
            op = OP_CUT;
        }

        void copyText()
        {
            Pos a, b;

            if (selRange(a, b))
            {
                clip = extract(a, b);
                clipWhole = false;
                markOn = false;
            }
            else
            {
                clip.clear();
                clip.push_back(lines[cy]);
                clipWhole = true;
            }

            size_t n = clip.size();

            msg = L"Copied " + std::to_wstring(n) +
                (n == 1 ? L" line" : L" lines");
        }

        void pasteText()
        {
            if (clip.empty())
            {
                msg = L"Cutbuffer is empty";
                return;
            }

            snapshot();
            markOn = false;

            if (clipWhole)
            {
                lines.insert(
                    lines.begin() + static_cast<std::ptrdiff_t>(cy),
                    clip.begin(),
                    clip.end()
                );

                cy += clip.size();

                if (cy >= lines.size())
                    cy = lines.size() - 1;

                cx = std::min(cx, lines[cy].size());
                return;
            }

            WStr head = lines[cy].substr(0, cx);
            WStr tail = lines[cy].substr(cx);

            if (clip.size() == 1)
            {
                lines[cy] = head + clip[0] + tail;
                cx += clip[0].size();
                return;
            }

            lines[cy] = head + clip[0];

            std::vector<WStr> rest(clip.begin() + 1, clip.end());
            size_t lastLen = rest.back().size();

            rest.back() += tail;

            lines.insert(
                lines.begin() + static_cast<std::ptrdiff_t>(cy) + 1,
                rest.begin(),
                rest.end()
            );

            cy += rest.size();
            cx = lastLen;
        }

        void doUndo()
        {
            if (undo.empty())
            {
                msg = L"Nothing to undo";
                return;
            }

            Snap cur;
            cur.lines = lines;
            cur.cy = cy;
            cur.cx = cx;

            redo.push_back(std::move(cur));

            Snap s = std::move(undo.back());
            undo.pop_back();

            lines = std::move(s.lines);

            if (lines.empty())
                lines.push_back(L"");

            cy = std::min(s.cy, lines.size() - 1);
            cx = std::min(s.cx, lines[cy].size());

            markOn = false;
            modified = (lines != savedLines);
            msg = L"Undid action";
        }

        void doRedo()
        {
            if (redo.empty())
            {
                msg = L"Nothing to redo";
                return;
            }

            Snap cur;
            cur.lines = lines;
            cur.cy = cy;
            cur.cx = cx;

            undo.push_back(std::move(cur));

            Snap s = std::move(redo.back());
            redo.pop_back();

            lines = std::move(s.lines);

            if (lines.empty())
                lines.push_back(L"");

            cy = std::min(s.cy, lines.size() - 1);
            cx = std::min(s.cx, lines[cy].size());

            markOn = false;
            modified = (lines != savedLines);
            msg = L"Redid action";
        }

        bool findFrom(
            size_t sy,
            size_t sx,
            const WStr& nl,
            size_t& fy,
            size_t& fx) const
        {
            for (size_t y = sy; y < lines.size(); ++y)
            {
                WStr low = lowerW(lines[y]);
                size_t from = (y == sy) ? sx : 0;

                if (from > low.size())
                    continue;

                size_t p = low.find(nl, from);

                if (p != WStr::npos)
                {
                    fy = y;
                    fx = p;
                    return true;
                }
            }

            return false;
        }

        void doSearch(bool again)
        {
            WStr q;

            if (!again)
            {
                WStr label = lastSearch.empty()
                    ? WStr(L"Search: ")
                    : L"Search [" + lastSearch + L"]: ";

                WStr in;

                Bar b1 = {
                    { L"^G", L"Help" },
                    { L"^C", L"Cancel" }
                };

                Bar b2;

                if (!prompt(label, in, b1, b2))
                {
                    msg = L"Cancelled";
                    return;
                }

                q = in.empty() ? lastSearch : in;
            }
            else
            {
                q = lastSearch;
            }

            if (q.empty())
            {
                msg = L"Cancelled";
                return;
            }

            lastSearch = q;
            WStr nl = lowerW(q);

            size_t fy = 0;
            size_t fx = 0;

            if (findFrom(cy, cx + 1, nl, fy, fx))
            {
                cy = fy;
                cx = fx;
                return;
            }

            if (findFrom(0, 0, nl, fy, fx))
            {
                cy = fy;
                cx = fx;
                msg = L"Search Wrapped";
            }
            else
            {
                msg = L"\"" + q + L"\" not found";
            }
        }

        void doReplace()
        {
            WStr q, rep;

            Bar b1 = {
                { L"^G", L"Help" },
                { L"^C", L"Cancel" }
            };

            Bar b2;

            WStr label = lastSearch.empty()
                ? WStr(L"Search (to replace): ")
                : L"Search (to replace) [" + lastSearch + L"]: ";

            if (!prompt(label, q, b1, b2))
            {
                msg = L"Cancelled";
                return;
            }

            if (q.empty())
                q = lastSearch;

            if (q.empty())
            {
                msg = L"Cancelled";
                return;
            }

            lastSearch = q;

            if (!prompt(L"Replace with: ", rep, b1, b2))
            {
                msg = L"Cancelled";
                return;
            }

            WStr nl = lowerW(q);

            size_t oy = cy;
            size_t ox = cx;
            size_t y = cy;
            size_t x = cx;

            bool wrapped = false;
            bool all = false;
            bool snapped = false;

            size_t count = 0;

            for (;;)
            {
                size_t fy = 0;
                size_t fx = 0;

                bool ok = findFrom(y, x, nl, fy, fx);

                if (!ok && !wrapped)
                {
                    wrapped = true;
                    y = 0;
                    x = 0;
                    continue;
                }

                if (!ok)
                    break;

                if (wrapped && (fy > oy || (fy == oy && fx >= ox)))
                    break;

                cy = fy;
                cx = fx;

                if (!all)
                {
                    char a = ask(L"Replace this instance?", true);

                    if (a == 'c')
                        break;

                    if (a == 'n')
                    {
                        y = fy;
                        x = fx + 1;
                        continue;
                    }

                    if (a == 'a')
                        all = true;
                }

                if (!snapped)
                {
                    snapshot();
                    snapped = true;
                }

                lines[fy].replace(fx, q.size(), rep);
                ++count;

                y = fy;
                x = fx + rep.size();
                cx = x;
            }

            markOn = false;

            if (lines.empty())
                lines.push_back(L"");

            cy = std::min(cy, lines.size() - 1);
            cx = std::min(cx, lines[cy].size());

            if (count > 0)
            {
                msg = L"Replaced " + std::to_wstring(count) +
                    (count == 1 ? L" occurrence" : L" occurrences");
            }
            else
            {
                msg = L"No replacements made";
            }
        }

        void doGoto()
        {
            WStr in;

            Bar b1 = {
                { L"^G", L"Help" },
                { L"^C", L"Cancel" }
            };

            Bar b2;

            if (!prompt(L"Enter line number, column number: ", in, b1, b2))
            {
                msg = L"Cancelled";
                return;
            }

            size_t ln = 0;
            size_t col = 0;

            try
            {
                size_t comma = in.find(L',');

                ln = std::stoul(in.substr(0, comma));

                if (comma != WStr::npos)
                    col = std::stoul(in.substr(comma + 1));
            }
            catch (...)
            {
                msg = L"Invalid line or column number";
                return;
            }

            if (ln < 1)
                ln = 1;

            if (ln > lines.size())
                ln = lines.size();

            cy = ln - 1;
            cx = (col > 0)
                ? std::min(col - 1, lines[cy].size())
                : 0;
        }

        void showLocation()
        {
            size_t totalLines = lines.size();
            size_t totalChars = 0;
            size_t before = 0;

            for (size_t i = 0; i < lines.size(); ++i)
            {
                if (i < cy)
                    before += lines[i].size() + 1;

                totalChars += lines[i].size() + 1;
            }

            before += cx;

            size_t col = dispCol(lines[cy], cx) + 1;
            size_t colMax = dispCol(lines[cy], lines[cy].size()) + 1;

            auto pct = [](size_t a, size_t b) -> size_t
                {
                    return b ? a * 100 / b : 0;
                };

            msg = L"line " + std::to_wstring(cy + 1) +
                L"/" + std::to_wstring(totalLines) +
                L" (" + std::to_wstring(pct(cy + 1, totalLines)) +
                L"%), col " + std::to_wstring(col) +
                L"/" + std::to_wstring(colMax) +
                L" (" + std::to_wstring(pct(col, colMax)) +
                L"%), char " + std::to_wstring(before + 1) +
                L"/" + std::to_wstring(totalChars) +
                L" (" + std::to_wstring(pct(before + 1, totalChars)) +
                L"%)";
        }

        void showHelp()
        {
            static const wchar_t* text[] = {
                L"ServerGuard nano editor help",
                L"",
                L" ^G   Display this help text",
                L" ^X   Exit from the editor",
                L" ^O   Write the current file to the server",
                L" ^W   Search; M-W repeats the search",
                L" ^\\   Replace text",
                L" ^K   Cut the current line or marked region",
                L" ^U   Paste the cutbuffer",
                L" M-6  Copy the current line or marked region",
                L" ^6   Set/unset mark (also M-A)",
                L" ^C   Display cursor position",
                L" ^/   Go to line and column (also M-G)",
                L" M-U  Undo",
                L" M-E  Redo",
                L"",
                L" Home / ^A   Start of line",
                L" End / ^E    End of line",
                L" PgUp / ^Y   Page up",
                L" PgDn / ^V   Page down",
                L" Ctrl+Left / Right   Move by word",
                L" Ctrl+Home / End     First / last line",
                L" Delete / ^D   Delete character",
                L" Backspace / ^H   Backspace",
                L"",
                L" Press any key to return"
            };

            WStr f = L"\x1b[?25l\x1b[2J\x1b[H";
            int row = 1;

            for (const wchar_t* line : text)
            {
                if (row >= H)
                    break;

                f += at(row++, 1);

                WStr s = line;

                if (static_cast<int>(s.size()) > W - 1)
                    s.resize(static_cast<size_t>(W - 1));

                f += s;
            }

            writeOut(f);

            for (;;)
            {
                Key k = readKey();

                if (k.t == KT_RESIZE)
                    continue;

                break;
            }
        }

        std::string serialize() const
        {
            WStr w;

            for (size_t i = 0; i < lines.size(); ++i)
            {
                w += lines[i];

                if (i + 1 < lines.size())
                    w += L'\n';
            }

            if (!lines.back().empty())
                w += L'\n';

            std::string s = toU8(w);

            if (crlf)
            {
                std::string r;
                r.reserve(s.size() + s.size() / 16);

                for (char c : s)
                {
                    if (c == '\n')
                        r += '\r';

                    r += c;
                }

                return r;
            }

            return s;
        }

        bool doWrite()
        {
            WStr name = toW(path);

            Bar b1 = {
                { L"^G", L"Help" },
                { L"^C", L"Cancel" }
            };

            Bar b2;

            if (!prompt(L"File Name to Write: ", name, b1, b2))
            {
                msg = L"Cancelled";
                return false;
            }

            std::string np = unquote(toU8(name));

            if (np.empty())
            {
                msg = L"Cancelled";
                return false;
            }

            std::string err;

            if (uploadFile(
                session,
                password,
                cwd,
                np,
                serialize(),
                err))
            {
                path = np;
                savedLines = lines;
                modified = false;
                isNew = false;

                size_t n = lines.size();

                if (n > 1 && lines.back().empty())
                    --n;

                msg = L"Wrote " + std::to_wstring(n) +
                    (n == 1 ? L" line" : L" lines");

                return true;
            }

            msg = L"Error writing " + toW(np) + L": " + toW(err);
            return false;
        }

        bool doExit()
        {
            if (!modified)
                return true;

            char a = ask(
                L"Save modified buffer? (No discards changes.)",
                false
            );

            if (a == 'c')
                return false;

            if (a == 'n')
                return true;

            return doWrite();
        }

        bool ctrlKey(wchar_t c, LastOp& op, bool& vertical)
        {
            switch (c)
            {
            case L'x':
                if (doExit())
                    return false;
                break;

            case L'o':
                doWrite();
                break;

            case L'w':
                doSearch(false);
                break;

            case L'\\':
                doReplace();
                break;

            case L'k':
                cutText(op);
                break;

            case L'u':
                pasteText();
                break;

            case L'c':
                showLocation();
                break;

            case L'g':
                showHelp();
                break;

            case L'/':
                doGoto();
                break;

            case L'6':
                toggleMark();
                break;

            case L'a':
                cx = 0;
                break;

            case L'e':
                cx = lines[cy].size();
                break;

            case L'y':
                moveUp(static_cast<size_t>(editRows));
                vertical = true;
                break;

            case L'v':
                moveDown(static_cast<size_t>(editRows));
                vertical = true;
                break;

            case L'b':
                moveLeft();
                break;

            case L'f':
                moveRight();
                break;

            case L'p':
                moveUp(1);
                vertical = true;
                break;

            case L'n':
                moveDown(1);
                vertical = true;
                break;

            case L'd':
                doDelete();
                op = OP_DEL;
                break;

            case L'h':
                doBackspace();
                op = OP_BACK;
                break;

            case L'i':
                insertChar(L'\t');
                op = OP_TYPE;
                break;

            case L'm':
                doEnter();
                break;

            default:
                break;
            }

            return true;
        }

        void altKey(wchar_t c)
        {
            switch (c)
            {
            case L'u':
                doUndo();
                break;

            case L'e':
                doRedo();
                break;

            case L'6':
                copyText();
                break;

            case L'a':
                toggleMark();
                break;

            case L'g':
                doGoto();
                break;

            case L'w':
                doSearch(true);
                break;

            default:
                break;
            }
        }

        void toggleMark()
        {
            if (markOn)
            {
                markOn = false;
                msg = L"Mark Unset";
            }
            else
            {
                markOn = true;
                mark.y = cy;
                mark.x = cx;
                msg = L"Mark Set";
            }
        }
    };

    inline std::vector<WStr> splitLinesW(const WStr& text, bool crlf)
    {
        std::vector<WStr> lines;
        WStr cur;

        for (wchar_t c : text)
        {
            if (c == L'\n')
            {
                if (crlf && !cur.empty() && cur.back() == L'\r')
                    cur.pop_back();

                lines.push_back(cur);
                cur.clear();
            }
            else
            {
                cur += c;
            }
        }

        if (crlf && !cur.empty() && cur.back() == L'\r')
            cur.pop_back();

        lines.push_back(cur);

        return lines;
    }

    inline void run(
        LIBSSH2_SESSION* session,
        const std::string& password,
        const std::string& cwd,
        const std::string& rawArg)
    {
        std::string path = unquote(rawArg);

        if (path.empty())
        {
            std::cout << "Usage: nano <file>\n";
            return;
        }

        FileKind kind = detectKind(session, cwd, path);

        if (kind == FileKind::Error)
        {
            std::cout << "Cannot check the file on the server.\n";
            return;
        }

        if (kind == FileKind::Directory)
        {
            std::cout << "Error: " << path << " is a directory.\n";
            return;
        }

        std::vector<WStr> lines;
        bool isNew = (kind == FileKind::Missing);
        bool crlf = false;

        if (!isNew)
        {
            std::string content;
            std::string err;

            if (!downloadFile(
                session,
                password,
                cwd,
                path,
                content,
                err))
            {
                std::cout << "Cannot read file: " << err << "\n";
                return;
            }

            if (content.size() > MAX_FILE_SIZE)
            {
                std::cout
                    << "File is larger than 1 MB, the editor will not open it.\n";
                return;
            }

            if (content.find('\0') != std::string::npos)
            {
                std::cout
                    << "Looks like a binary file, will not open it.\n";
                return;
            }

            WStr w;

            if (!utf8ToW(content, w))
            {
                std::cout
                    << "File is not valid UTF-8, will not open it.\n";
                return;
            }

            crlf = (content.find("\r\n") != std::string::npos);
            lines = splitLinesW(w, crlf);
        }
        else
        {
            lines.push_back(L"");
        }

        Editor ed(
            session,
            password,
            cwd,
            path,
            std::move(lines),
            isNew,
            crlf
        );

        if (!ed.init())
        {
#ifdef _WIN32
            std::cout
                << "The editor requires a real Windows console "
                << "(cmd / PowerShell / Windows Terminal).\n";
#else
            std::cout
                << "The editor requires an interactive terminal (TTY).\n";
#endif
            ed.shutdown();
            return;
        }

        ed.run();
        ed.shutdown();
    }
}

// Entry point used by main.cpp
inline void runNano(
    LIBSSH2_SESSION* session,
    const std::string& password,
    const std::string& currentDirectory,
    const std::string& arg)
{
    nanoed::run(
        session,
        password,
        currentDirectory,
        arg
    );
}