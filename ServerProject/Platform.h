
#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <climits>

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <wininet.h>
#include <urlmon.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

inline int closesocket(SOCKET s) { return ::close(s); }
inline int WSAGetLastError() { return errno; }

#endif

namespace plat
{

#ifdef _WIN32
    constexpr char PATH_SEP = '\\';
    constexpr bool IS_WINDOWS = true;
#else
    constexpr char PATH_SEP = '/';
    constexpr bool IS_WINDOWS = false;
#endif

    inline bool initNetwork()
    {
#ifdef _WIN32
        WSADATA wsadata{};
        return WSAStartup(MAKEWORD(2, 2), &wsadata) == 0;
#else
        signal(SIGPIPE, SIG_IGN);
        return true;
#endif
    }

    inline void cleanupNetwork()
    {
#ifdef _WIN32
        WSACleanup();
#endif
    }

    inline bool setNonBlocking(SOCKET s, bool enable)
    {
#ifdef _WIN32
        u_long mode = enable ? 1UL : 0UL;
        return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
        int flags = fcntl(s, F_GETFL, 0);

        if (flags < 0)
            return false;

        flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        return fcntl(s, F_SETFL, flags) == 0;
#endif
    }

    inline int shutdownBoth(SOCKET s)
    {
#ifdef _WIN32
        return ::shutdown(s, SD_BOTH);
#else
        return ::shutdown(s, SHUT_RDWR);
#endif
    }

    inline bool setExclusiveAddrUse(SOCKET s)
    {
#ifdef _WIN32
        BOOL exclusive = TRUE;

        return setsockopt(
            s,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive),
            sizeof(exclusive)) == 0;
#else
        (void)s;
        return true;
#endif
    }

    inline void sleepMs(unsigned ms)
    {
#ifdef _WIN32
        Sleep(ms);
#else
        usleep(ms * 1000);
#endif
    }

    inline std::string getEnv(const char* name)
    {
        if (name == nullptr)
            return {};

#ifdef _WIN32
        char* value = nullptr;
        size_t length = 0;

        if (_dupenv_s(&value, &length, name) != 0 || value == nullptr)
        {
            std::free(value);
            return {};
        }

        std::string result(value);
        std::free(value);

        return result;
#else
        const char* value = std::getenv(name);
        return value ? std::string(value) : std::string();
#endif
    }

    inline std::string joinPath(
        const std::string& a,
        const std::string& b)
    {
        if (a.empty())
            return b;

        if (a.back() == '/' || a.back() == '\\')
            return a + b;

        return a + PATH_SEP + b;
    }

    inline bool fileExists(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);
        return f.good();
    }

    inline bool removeFile(const std::string& path)
    {
#ifdef _WIN32
        return DeleteFileA(path.c_str()) != 0;
#else
        return ::unlink(path.c_str()) == 0;
#endif
    }

    inline std::string makeTempFile(const std::string& prefix)
    {
#ifdef _WIN32
        char dir[MAX_PATH] = {};
        char file[MAX_PATH] = {};

        DWORD n = GetTempPathA(MAX_PATH, dir);

        if (n == 0 || n >= MAX_PATH)
            return {};

        std::string shortPrefix = prefix.substr(0, 3);

        if (shortPrefix.empty())
            shortPrefix = "SG";

        if (!GetTempFileNameA(
            dir, shortPrefix.c_str(), 0, file))
        {
            return {};
        }

        return std::string(file);
#else
        std::string dir = getEnv("TMPDIR");

        if (dir.empty())
            dir = "/tmp";

        std::string tmpl = joinPath(dir, prefix + "XXXXXX");
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');

        int fd = ::mkstemp(buf.data());

        if (fd < 0)
            return {};

        ::close(fd);

        return std::string(buf.data());
#endif
    }

    inline bool downloadFile(
        const std::string& url,
        const std::string& path,
        size_t maxBytes = 4 * 1024 * 1024)
    {
#ifdef _WIN32
        (void)maxBytes;
        DeleteUrlCacheEntryA(url.c_str());

        return URLDownloadToFileA(
            nullptr, url.c_str(), path.c_str(), 0, nullptr) == S_OK;
#else
        if (url.compare(0, 8, "https://") != 0)
            return false;

        const std::string maxStr = std::to_string(maxBytes);

        pid_t pid = fork();

        if (pid < 0)
            return false;

        if (pid == 0)
        {
            execlp(
                "curl", "curl",
                "-fsSL",
                "--proto", "=https",
                "--proto-redir", "=https",
                "--max-time", "60",
                "--max-filesize", maxStr.c_str(),
                "-H", "Cache-Control: no-cache",
                "-o", path.c_str(),
                url.c_str(),
                static_cast<char*>(nullptr));

            _exit(127);
        }

        int status = 0;

        while (waitpid(pid, &status, 0) < 0)
        {
            if (errno != EINTR)
                return false;
        }

        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
    }

    inline std::string homeDir()
    {
#ifdef _WIN32
        return getEnv("USERPROFILE");
#else
        return getEnv("HOME");
#endif
    }

    inline std::string exeDirectory()
    {
#ifdef _WIN32
        char path[MAX_PATH] = {};
        DWORD n = GetModuleFileNameA(nullptr, path, MAX_PATH);

        if (n == 0 || n >= MAX_PATH)
            return {};

        std::string full(path, n);
#else
        char path[PATH_MAX] = {};
        ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);

        if (n <= 0)
            return {};

        std::string full(path, static_cast<size_t>(n));
#endif

        size_t slash = full.find_last_of("\\/");

        return slash == std::string::npos
            ? std::string()
            : full.substr(0, slash);
    }

    inline std::string appDataDir()
    {
        static std::string dir;

        if (!dir.empty())
            return dir;

#ifdef _WIN32
        std::string base = getEnv("LOCALAPPDATA");

        if (base.empty())
        {
            dir = ".";
            return dir;
        }

        dir = base + "\\ServerGuard";

        if (!CreateDirectoryA(dir.c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS)
        {
            std::cout << "Warning: cannot create folder " << dir
                << " (Windows error " << GetLastError()
                << "). Using current folder.\n";

            dir = ".";
        }
#else
        std::string cfg = getEnv("XDG_CONFIG_HOME");

        if (cfg.empty())
        {
            std::string home = homeDir();

            if (home.empty())
            {
                dir = ".";
                return dir;
            }

            cfg = home + "/.config";
        }

        mkdir(cfg.c_str(), 0700);

        dir = cfg + "/serverguard";

        if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST)
        {
            std::cout << "Warning: cannot create folder " << dir
                << " (errno " << errno
                << "). Using current folder.\n";

            dir = ".";
        }
#endif

        return dir;
    }

    inline void restrictFile(const std::string& path)
    {
#ifndef _WIN32
        chmod(path.c_str(), 0600);
#else
        (void)path;
#endif
    }

    inline bool replaceFile(
        const std::string& src,
        const std::string& dst)
    {
#ifdef _WIN32
        return MoveFileExA(
            src.c_str(),
            dst.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
        return std::rename(src.c_str(), dst.c_str()) == 0;
#endif
    }

    inline unsigned long lastSystemError()
    {
#ifdef _WIN32
        return GetLastError();
#else
        return static_cast<unsigned long>(errno);
#endif
    }

    inline char* cstrdup(const char* s)
    {
#ifdef _WIN32
        return _strdup(s);
#else
        return strdup(s);
#endif
    }

    inline void secureZero(void* p, size_t n)
    {
#ifdef _WIN32
        SecureZeroMemory(p, n);
#else
        volatile unsigned char* v =
            static_cast<volatile unsigned char*>(p);

        while (n--)
            *v++ = 0;
#endif
    }

    inline bool openUrl(const std::string& url)
    {
#ifdef _WIN32
        return reinterpret_cast<INT_PTR>(
            ShellExecuteA(
                nullptr, "open", url.c_str(),
                nullptr, nullptr, SW_SHOWNORMAL)) > 32;
#else
        pid_t pid = fork();

        if (pid < 0)
            return false;

        if (pid == 0)
        {
            pid_t pid2 = fork();

            if (pid2 != 0)
                _exit(pid2 < 0 ? 1 : 0);

            int devnull = ::open("/dev/null", O_RDWR);

            if (devnull >= 0)
            {
                dup2(devnull, STDIN_FILENO);
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);

                if (devnull > STDERR_FILENO)
                    ::close(devnull);
            }

            execlp(
                "xdg-open", "xdg-open",
                url.c_str(),
                static_cast<char*>(nullptr));

            _exit(127);
        }

        int status = 0;

        while (waitpid(pid, &status, 0) < 0)
        {
            if (errno != EINTR)
                return false;
        }

        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
    }

    inline bool launchUpdater(
        const std::string& path,
        const std::string& workDir)
    {
#ifdef _WIN32
        HINSTANCE rc = ShellExecuteA(
            nullptr, "open", path.c_str(),
            nullptr, workDir.c_str(), SW_SHOWNORMAL);

        return reinterpret_cast<INT_PTR>(rc) > 32;
#else
        (void)workDir;
        std::cout.flush();

        execl(
            "/bin/bash",
            "bash",
            path.c_str(),
            static_cast<char*>(nullptr));

        std::cerr << "Failed to launch updater: "
            << path << " (errno " << errno << ")\n";

        return false;
#endif
    }

    inline std::string readSecret(const std::string& prompt)
    {
        std::cout << prompt;
        std::cout.flush();

        std::string line;

#ifdef _WIN32
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;

        bool hidden = (GetConsoleMode(hIn, &mode) != 0);

        if (hidden)
            SetConsoleMode(hIn, mode & ~ENABLE_ECHO_INPUT);

        std::getline(std::cin, line);

        if (hidden)
            SetConsoleMode(hIn, mode);
#else
        termios oldt{};
        bool hidden =
            isatty(STDIN_FILENO) &&
            tcgetattr(STDIN_FILENO, &oldt) == 0;

        if (hidden)
        {
            termios newt = oldt;
            newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        }

        std::getline(std::cin, line);

        if (hidden)
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

        std::cout << "\n";

        while (!line.empty() &&
            (line.back() == '\r' || line.back() == '\n'))
        {
            line.pop_back();
        }

        return line;
    }

    inline std::string hexEncode(
        const unsigned char* data,
        size_t len)
    {
        static const char* digits = "0123456789abcdef";

        std::string out;
        out.reserve(len * 2);

        for (size_t i = 0; i < len; i++)
        {
            out += digits[data[i] >> 4];
            out += digits[data[i] & 0x0F];
        }

        return out;
    }

    inline bool hexDecode(
        const std::string& hex,
        std::string& out)
    {
        out.clear();

        if (hex.size() % 2 != 0)
            return false;

        auto val = [](char c) -> int
            {
                if (c >= '0' && c <= '9')
                    return c - '0';

                if (c >= 'a' && c <= 'f')
                    return c - 'a' + 10;

                if (c >= 'A' && c <= 'F')
                    return c - 'A' + 10;

                return -1;
            };

        for (size_t i = 0; i < hex.size(); i += 2)
        {
            int hi = val(hex[i]);
            int lo = val(hex[i + 1]);

            if (hi < 0 || lo < 0)
                return false;

            out += static_cast<char>((hi << 4) | lo);
        }

        return true;
    }

#ifndef _WIN32
    inline bool loadOrCreateKey(unsigned char key[32])
    {
        std::string path = joinPath(appDataDir(), "secret.key");

        int fd = ::open(path.c_str(), O_RDONLY);

        if (fd >= 0)
        {
            ssize_t n = ::read(fd, key, 32);
            ::close(fd);

            if (n == 32)
                return true;
        }

        if (RAND_bytes(key, 32) != 1)
            return false;

        fd = ::open(
            path.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC,
            0600);

        if (fd < 0)
            return false;

        bool ok = (::write(fd, key, 32) == 32);
        ::close(fd);

        return ok;
    }
#endif

    inline std::string protectSecret(const std::string& plain)
    {
        if (plain.empty())
            return {};

#ifdef _WIN32
        DATA_BLOB in{};
        in.pbData = reinterpret_cast<BYTE*>(
            const_cast<char*>(plain.data()));
        in.cbData = static_cast<DWORD>(plain.size());

        DATA_BLOB out{};

        if (!CryptProtectData(
            &in, L"ServerGuard", nullptr, nullptr,
            nullptr, 0, &out))
        {
            return {};
        }

        std::string hex = hexEncode(out.pbData, out.cbData);
        LocalFree(out.pbData);

        return hex;
#else
        unsigned char key[32]{};

        if (!loadOrCreateKey(key))
            return {};

        unsigned char iv[12]{};
        unsigned char tag[16]{};

        if (RAND_bytes(iv, sizeof(iv)) != 1)
        {
            secureZero(key, sizeof(key));
            return {};
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

        if (!ctx)
        {
            secureZero(key, sizeof(key));
            return {};
        }

        std::string ct(plain.size(), '\0');

        int len = 0;
        int total = 0;

        bool ok =
            EVP_EncryptInit_ex(
                ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_IVLEN,
                sizeof(iv), nullptr) == 1 &&
            EVP_EncryptInit_ex(
                ctx, nullptr, nullptr, key, iv) == 1 &&
            EVP_EncryptUpdate(
                ctx,
                reinterpret_cast<unsigned char*>(&ct[0]),
                &len,
                reinterpret_cast<const unsigned char*>(plain.data()),
                static_cast<int>(plain.size())) == 1;

        total = len;

        ok = ok &&
            EVP_EncryptFinal_ex(
                ctx,
                reinterpret_cast<unsigned char*>(&ct[0]) + total,
                &len) == 1;

        total += len;

        ok = ok &&
            EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_GET_TAG,
                sizeof(tag), tag) == 1;

        EVP_CIPHER_CTX_free(ctx);
        secureZero(key, sizeof(key));

        if (!ok)
            return {};

        std::string blob(
            reinterpret_cast<char*>(iv), sizeof(iv));

        blob.append(
            reinterpret_cast<char*>(tag), sizeof(tag));

        blob.append(ct.data(), static_cast<size_t>(total));

        return hexEncode(
            reinterpret_cast<const unsigned char*>(blob.data()),
            blob.size());
#endif
    }

    inline std::string unprotectSecret(const std::string& hex)
    {
        if (hex.empty())
            return {};

        std::string raw;

        if (!hexDecode(hex, raw) || raw.empty())
            return {};

#ifdef _WIN32
        DATA_BLOB in{};
        in.pbData = reinterpret_cast<BYTE*>(raw.data());
        in.cbData = static_cast<DWORD>(raw.size());

        DATA_BLOB out{};

        if (!CryptUnprotectData(
            &in, nullptr, nullptr, nullptr,
            nullptr, 0, &out))
        {
            return {};
        }

        std::string plain(
            reinterpret_cast<char*>(out.pbData),
            out.cbData);

        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);

        return plain;
#else
        if (raw.size() <= 28)
            return {};

        unsigned char key[32]{};

        if (!loadOrCreateKey(key))
            return {};

        const unsigned char* iv =
            reinterpret_cast<const unsigned char*>(raw.data());

        unsigned char tag[16]{};
        std::memcpy(tag, raw.data() + 12, 16);

        const unsigned char* ct =
            reinterpret_cast<const unsigned char*>(raw.data()) + 28;

        int ctLen = static_cast<int>(raw.size() - 28);

        EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();

        if (!c)
        {
            secureZero(key, sizeof(key));
            return {};
        }

        std::string plain(static_cast<size_t>(ctLen), '\0');

        int len = 0;
        int total = 0;

        bool ok =
            EVP_DecryptInit_ex(
                c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(
                c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_DecryptInit_ex(
                c, nullptr, nullptr, key, iv) == 1 &&
            EVP_DecryptUpdate(
                c,
                reinterpret_cast<unsigned char*>(&plain[0]),
                &len, ct, ctLen) == 1;

        total = len;

        ok = ok &&
            EVP_CIPHER_CTX_ctrl(
                c, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1 &&
            EVP_DecryptFinal_ex(
                c,
                reinterpret_cast<unsigned char*>(&plain[0]) + total,
                &len) == 1;

        total += len;

        EVP_CIPHER_CTX_free(c);
        secureZero(key, sizeof(key));

        if (!ok)
            return {};

        plain.resize(static_cast<size_t>(total));

        return plain;
#endif
    }

#ifndef _WIN32
    inline std::string exePath()
    {
        char path[PATH_MAX] = {};
        ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);

        if (n <= 0)
            return {};

        std::string full(path, static_cast<size_t>(n));
        const std::string suffix = " (deleted)";

        if (full.size() > suffix.size() &&
            full.compare(
                full.size() - suffix.size(),
                suffix.size(),
                suffix) == 0)
        {
            full.resize(full.size() - suffix.size());
        }

        return full;
    }

    inline bool isRoot()
    {
        return geteuid() == 0;
    }

    inline std::string findInPath(const std::string& name)
    {
        std::string pathEnv = getEnv("PATH");

        if (pathEnv.empty())
        {
            pathEnv =
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        }

        size_t start = 0;

        while (start <= pathEnv.size())
        {
            size_t end = pathEnv.find(':', start);

            if (end == std::string::npos)
                end = pathEnv.size();

            std::string dir = pathEnv.substr(start, end - start);

            if (!dir.empty())
            {
                std::string full = dir + "/" + name;

                if (::access(full.c_str(), X_OK) == 0)
                    return full;
            }

            start = end + 1;
        }

        return {};
    }

    inline int runProcess(const std::vector<std::string>& args)
    {
        if (args.empty())
            return -1;

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);

        for (const std::string& a : args)
            argv.push_back(const_cast<char*>(a.c_str()));

        argv.push_back(nullptr);

        std::cout.flush();

        pid_t pid = fork();

        if (pid < 0)
            return -1;

        if (pid == 0)
        {
            execvp(argv[0], argv.data());
            _exit(127);
        }

        int status = 0;

        while (waitpid(pid, &status, 0) < 0)
        {
            if (errno != EINTR)
                return -1;
        }

        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    inline std::string sha256File(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);

        if (!f)
            return {};

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        if (!ctx)
            return {};

        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdLen = 0;

        bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
        char buf[65536];

        while (ok && f)
        {
            f.read(buf, sizeof(buf));
            std::streamsize n = f.gcount();

            if (n > 0)
            {
                ok = EVP_DigestUpdate(
                    ctx, buf, static_cast<size_t>(n)) == 1;
            }
        }

        if (ok)
            ok = EVP_DigestFinal_ex(ctx, md, &mdLen) == 1;

        EVP_MD_CTX_free(ctx);

        return ok ? hexEncode(md, mdLen) : std::string();
    }

    inline bool restartSelf(const std::string& exe, char** argv)
    {
        std::cout.flush();
        setenv("SERVERGUARD_UPDATED", "1", 1);
        execv(exe.c_str(), argv);
        return false;
    }
#endif

}
