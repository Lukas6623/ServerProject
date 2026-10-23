
#define NOMINMAX

#include "Platform.h"
#include "Web.h"
#include "WebServer.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <system_error>
#include <cstdio>
#include <limits>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/sha.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace fs = std::filesystem;

static const char* MANIFEST_URL =
"https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/updates/manifest.json";

static constexpr size_t MAX_MANIFEST_BYTES = 256 * 1024;
static constexpr size_t MAX_ZIP_BYTES = 64 * 1024 * 1024;

std::string webBaseDir()
{
#ifdef _WIN32
    const std::string value = plat::getEnv("LOCALAPPDATA");

    if (!value.empty())
        return (fs::path(value) / "ServerGuard").string();

    return "";
#else
    const std::string dataHome = plat::getEnv("XDG_DATA_HOME");

    if (!dataHome.empty())
        return (fs::path(dataHome) / "ServerGuard").string();

    const std::string home = plat::getEnv("HOME");

    if (!home.empty())
        return (fs::path(home) / ".local" / "share" / "ServerGuard").string();

    return "";
#endif
}

std::string webRootPath()
{
    const std::string base = webBaseDir();

    if (base.empty())
    {
#ifdef _WIN32
        return "C:\\Program Files\\ServerGuard\\web";
#else
        return "/opt/serverguard/web";
#endif
    }

    return (fs::path(base) / "web").string();
}

static fs::path shaFilePath()
{
    return fs::path(webBaseDir()) / "web.sha256";
}

static std::string installedSha()
{
    std::ifstream in(shaFilePath());

    std::string value;
    std::getline(in, value);

    return value;
}

static std::string lowerCopy(std::string s)
{
    std::transform(
        s.begin(), s.end(), s.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(std::tolower(c));
        });

    return s;
}

static std::string trimCopy(const std::string& s)
{
    size_t a = 0;
    size_t b = s.size();

    while (a < b && std::isspace(static_cast<unsigned char>(s[a])))
        ++a;

    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1])))
        --b;

    return s.substr(a, b - a);
}

static std::string jsonString(
    const std::string& json,
    const std::string& key)
{
    const std::string needle = "\"" + key + "\"";

    size_t p = json.find(needle);

    if (p == std::string::npos)
        return "";

    p = json.find(':', p + needle.size());

    if (p == std::string::npos)
        return "";

    ++p;

    while (p < json.size() &&
        std::isspace(static_cast<unsigned char>(json[p])))
        ++p;

    if (p >= json.size() || json[p] != '"')
        return "";

    ++p;

    std::string result;

    while (p < json.size())
    {
        const char c = json[p++];

        if (c == '"')
            return trimCopy(result);

        if (c == '\\')
        {
            if (p >= json.size())
                return "";

            const char escaped = json[p++];

            switch (escaped)
            {
            case '"':  result += '"'; break;
            case '\\': result += '\\'; break;
            case '/':  result += '/'; break;
            case 'n':  result += '\n'; break;
            case 'r':  result += '\r'; break;
            case 't':  result += '\t'; break;

            default:
                return "";
            }
        }
        else
        {
            result += c;
        }
    }

    return "";
}

static bool validHttpsUrl(const std::string& url)
{
    if (url.rfind("https://", 0) != 0)
        return false;

    if (url.size() > 4096)
        return false;

    for (unsigned char c : url)
    {
        if (c <= 0x20 || c == 0x7f ||
            c == '"' || c == '\'' || c == '`' ||
            c == '<' || c == '>' || c == '\\' ||
            c == '|' || c == ';' || c == '$' ||
            c == '(' || c == ')' || c == '{' ||
            c == '}' || c == '\n' || c == '\r')
        {
            return false;
        }
    }

    return url.size() > 8;
}

#ifndef _WIN32
static std::string shellQuote(const std::string& value)
{
    std::string result = "'";

    for (char c : value)
    {
        if (c == '\'')
            result += "'\\''";
        else
            result += c;
    }

    result += "'";
    return result;
}
#else
static std::string shellQuote(const std::string& value)
{
    std::string result = "\"";

    for (char c : value)
    {
        if (c == '"')
            result += "\\\"";
        else
            result += c;
    }

    result += "\"";
    return result;
}
#endif

static int runCommand(const std::string& command)
{
#ifdef _WIN32
    return std::system(command.c_str());
#else
    const pid_t pid = fork();

    if (pid < 0)
        return -1;

    if (pid == 0)
    {
        execl(
            "/bin/sh",
            "sh",
            "-c",
            command.c_str(),
            static_cast<char*>(nullptr));

        _exit(127);
    }

    int status = 0;

    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno != EINTR)
            return -1;
    }

    if (WIFEXITED(status))
        return WEXITSTATUS(status);

    return -1;
#endif
}

#ifndef _WIN32

static bool commandExists(const std::string& name)
{
    if (name.empty())
        return false;

    return runCommand(
        "command -v " + shellQuote(name) +
        " >/dev/null 2>&1") == 0;
}

static bool ensureUnzip()
{
    if (commandExists("unzip"))
        return true;

    std::cout << "Required dependency 'unzip' is missing.\n";
    std::cout << "Attempting to install unzip...\n";

    std::string installer;

    if (commandExists("apt-get"))
    {
        installer =
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y unzip";
    }
    else if (commandExists("dnf"))
    {
        installer = "dnf install -y unzip";
    }
    else if (commandExists("yum"))
    {
        installer = "yum install -y unzip";
    }
    else if (commandExists("pacman"))
    {
        installer = "pacman -S --needed --noconfirm unzip";
    }
    else if (commandExists("zypper"))
    {
        installer = "zypper --non-interactive install unzip";
    }
    else if (commandExists("apk"))
    {
        installer = "apk add unzip";
    }
    else
    {
        std::cout
            << "Cannot install unzip automatically: "
            << "no supported package manager was found.\n";
        return false;
    }

    if (geteuid() != 0)
    {
        if (!commandExists("sudo"))
        {
            std::cout
                << "Administrator privileges are required. "
                << "Install unzip manually or run ServerGuard with sudo.\n";
            return false;
        }

        installer = "sudo " + installer;
    }

    const int result = runCommand(installer);

    if (result != 0)
    {
        std::cout
            << "Automatic installation of unzip failed "
            << "(exit code " << result << ").\n";

        return false;
    }

    if (!commandExists("unzip"))
    {
        std::cout
            << "Installation finished, but unzip is unavailable in PATH.\n";
        return false;
    }

    std::cout << "Dependency unzip is ready.\n";
    return true;
}

#endif

static bool readBinaryFile(
    const fs::path& path,
    std::string& data,
    size_t maxBytes)
{
    data.clear();

    std::error_code ec;
    const auto fileSize = fs::file_size(path, ec);

    if (ec || fileSize > maxBytes)
        return false;

    std::ifstream in(path, std::ios::binary);

    if (!in)
        return false;

    data.resize(static_cast<size_t>(fileSize));

    if (!data.empty())
        in.read(&data[0], static_cast<std::streamsize>(data.size()));

    return in.good() || in.eof();
}

static bool writeBinaryFile(
    const fs::path& path,
    const std::string& data)
{
    std::ofstream out(
        path,
        std::ios::binary | std::ios::trunc);

    if (!out)
        return false;

    out.write(
        data.data(),
        static_cast<std::streamsize>(data.size()));

    return static_cast<bool>(out);
}

static bool httpGet(
    const std::string& url,
    std::string& out,
    size_t maxBytes,
    const fs::path& downloadPath)
{
    out.clear();

    if (!validHttpsUrl(url))
    {
        std::cout << "Invalid or unsupported HTTPS URL.\n";
        return false;
    }

    std::error_code ec;
    fs::remove(downloadPath, ec);

    std::string command;

#ifdef _WIN32
    command =
        "curl.exe --fail --location --silent --show-error "
        "--max-time 60 --max-filesize " +
        std::to_string(maxBytes) +
        " --output " + shellQuote(downloadPath.string()) +
        " " + shellQuote(url);
#else
    command =
        "curl --fail --location --silent --show-error "
        "--max-time 60 --max-filesize " +
        std::to_string(maxBytes) +
        " --output " + shellQuote(downloadPath.string()) +
        " " + shellQuote(url);
#endif

    const int result = runCommand(command);

    if (result != 0)
    {
        fs::remove(downloadPath, ec);

        std::cout << "HTTPS download failed (curl exit code "
            << result << ").\n";

        return false;
    }

    if (!readBinaryFile(downloadPath, out, maxBytes))
    {
        fs::remove(downloadPath, ec);
        std::cout << "Downloaded file is missing or too large.\n";
        return false;
    }

    return true;
}

static bool sha256Hex(
    const std::string& data,
    std::string& hex)
{
    unsigned char digest[32] = {};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    if (!BCRYPT_SUCCESS(
        BCryptOpenAlgorithmProvider(
            &alg,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0)))
    {
        return false;
    }

    DWORD objectLength = 0;
    DWORD copied = 0;

    bool ok = BCRYPT_SUCCESS(
        BCryptGetProperty(
            alg,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectLength),
            sizeof(objectLength),
            &copied,
            0));

    std::vector<UCHAR> object(ok ? objectLength : 0);

    if (ok)
    {
        ok =
            BCRYPT_SUCCESS(
                BCryptCreateHash(
                    alg,
                    &hash,
                    object.data(),
                    objectLength,
                    nullptr,
                    0,
                    0)) &&
            data.size() <= std::numeric_limits<ULONG>::max() &&
            BCRYPT_SUCCESS(
                BCryptHashData(
                    hash,
                    reinterpret_cast<PUCHAR>(
                        const_cast<char*>(data.data())),
                    static_cast<ULONG>(data.size()),
                    0)) &&
            BCRYPT_SUCCESS(
                BCryptFinishHash(
                    hash,
                    digest,
                    sizeof(digest),
                    0));
    }

    if (hash)
        BCryptDestroyHash(hash);

    BCryptCloseAlgorithmProvider(alg, 0);

    if (!ok)
        return false;
#else
    if (!SHA256(
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(),
        digest))
    {
        return false;
    }
#endif

    static const char* digits = "0123456789abcdef";

    hex.clear();
    hex.reserve(64);

    for (unsigned char b : digest)
    {
        hex += digits[b >> 4];
        hex += digits[b & 0x0F];
    }

    return true;
}

static bool extractZip(
    const fs::path& zip,
    const fs::path& dest)
{
    std::error_code ec;

    fs::create_directories(dest, ec);

    if (ec)
        return false;

#ifdef _WIN32
    std::string command =
        "powershell.exe -NoProfile -NonInteractive "
        "-ExecutionPolicy Bypass -Command "
        "\"Expand-Archive -LiteralPath '" +
        zip.string() +
        "' -DestinationPath '" +
        dest.string() +
        "' -Force\"";

    if (runCommand(command) == 0)
        return true;

    command =
        "tar.exe -xf " + shellQuote(zip.string()) +
        " -C " + shellQuote(dest.string());

    return runCommand(command) == 0;
#else
    if (!ensureUnzip())
        return false;

    const std::string command =
        "unzip -q -o " + shellQuote(zip.string()) +
        " -d " + shellQuote(dest.string());

    return runCommand(command) == 0;
#endif
}

bool installWebFiles()
{
    std::error_code ec;

    const std::string base = webBaseDir();

    if (base.empty())
    {
#ifdef _WIN32
        std::cout << "LOCALAPPDATA is not available.\n";
#else
        std::cout << "HOME and XDG_DATA_HOME are not available.\n";
#endif
        return false;
    }

    const fs::path baseDir(base);
    const fs::path target(webRootPath());
    const fs::path tmpDir = baseDir / "web_tmp";
    const fs::path zipPath = baseDir / "web_download.zip";
    const fs::path manifestPath = baseDir / "manifest_download.json";

    fs::create_directories(baseDir, ec);

    if (ec)
    {
        std::cout << "Cannot create folder: "
            << baseDir.string() << " (" << ec.message() << ")\n";
        return false;
    }

#ifndef _WIN32
    fs::permissions(
        baseDir,
        fs::perms::owner_all,
        fs::perm_options::replace,
        ec);
    ec.clear();
#endif

    auto cleanup = [&]()
        {
            std::error_code e;
            fs::remove_all(tmpDir, e);
            fs::remove(zipPath, e);
            fs::remove(manifestPath, e);
        };

    std::cout << "Reading manifest...\n";

    std::string manifest;

    if (!httpGet(
        MANIFEST_URL,
        manifest,
        MAX_MANIFEST_BYTES,
        manifestPath))
    {
        std::cout << "Cannot download manifest.json.\n";
        cleanup();
        return false;
    }

    const std::string webUrl =
        jsonString(manifest, "web_url");

    const std::string webSha =
        lowerCopy(jsonString(manifest, "web_sha256"));

    if (!validHttpsUrl(webUrl) || webSha.size() != 64 ||
        !std::all_of(
            webSha.begin(),
            webSha.end(),
            [](unsigned char c)
            {
                return std::isxdigit(c) != 0;
            }))
    {
        std::cout << "manifest.json has no valid web_url / web_sha256.\n";
        cleanup();
        return false;
    }

    std::cout << "Downloading: " << webUrl << "\n";

    std::string zipData;

    if (!httpGet(webUrl, zipData, MAX_ZIP_BYTES, zipPath))
    {
        std::cout << "Cannot download web archive.\n";
        cleanup();
        return false;
    }

    std::cout << "Downloaded "
        << (zipData.size() / 1024) << " KB.\n";

    std::string actualSha;

    if (!sha256Hex(zipData, actualSha))
    {
        std::cout << "Cannot calculate SHA256.\n";
        cleanup();
        return false;
    }

    if (actualSha != webSha)
    {
        std::cout << "SHA256 mismatch! Installation aborted.\n";
        std::cout << "Expected: " << webSha << "\n";
        std::cout << "Actual:   " << actualSha << "\n";
        cleanup();
        return false;
    }

    std::cout << "SHA256 verified.\n";

    fs::remove_all(tmpDir, ec);
    ec.clear();

    fs::create_directories(tmpDir, ec);

    if (ec)
    {
        std::cout << "Cannot create temporary directory: "
            << ec.message() << "\n";
        cleanup();
        return false;
    }

#ifndef _WIN32
    fs::permissions(
        tmpDir,
        fs::perms::owner_all,
        fs::perm_options::replace,
        ec);
    ec.clear();
#endif

    std::cout << "Extracting...\n";

    if (!extractZip(zipPath, tmpDir))
    {
        std::cout
            << "Cannot extract web archive. "
            << "Check the package manager, permissions, "
            << "and unzip installation.\n";

        cleanup();
        return false;
    }

    fs::path sourceRoot;

    if (fs::exists(tmpDir / "index.html", ec) && !ec)
    {
        sourceRoot = tmpDir;
    }
    else
    {
        ec.clear();

        fs::directory_iterator it(tmpDir, ec);
        fs::directory_iterator end;

        for (; !ec && it != end; it.increment(ec))
        {
            std::error_code itemEc;

            if (it->is_directory(itemEc) && !itemEc &&
                fs::exists(it->path() / "index.html", itemEc) &&
                !itemEc)
            {
                sourceRoot = it->path();
                break;
            }
        }
    }

    if (sourceRoot.empty())
    {
        std::cout << "index.html not found in the archive.\n";
        cleanup();
        return false;
    }

    fs::create_directories(target.parent_path(), ec);

    if (ec)
    {
        std::cout << "Cannot create installation parent directory: "
            << ec.message() << "\n";
        cleanup();
        return false;
    }

    const fs::path backup = baseDir / "web_previous";

    fs::remove_all(backup, ec);
    ec.clear();

    const bool hadOldWeb = fs::exists(target, ec) && !ec;

    if (hadOldWeb)
    {
        fs::rename(target, backup, ec);

        if (ec)
        {
            std::cout << "Cannot move existing web directory: "
                << ec.message() << "\n";
            cleanup();
            return false;
        }
    }

    fs::rename(sourceRoot, target, ec);

    if (ec)
    {
        std::cout << "Cannot install web files: "
            << ec.message() << "\n";

        if (hadOldWeb)
        {
            std::error_code restoreEc;
            fs::rename(backup, target, restoreEc);

            if (restoreEc)
            {
                std::cout << "WARNING: automatic restore failed: "
                    << restoreEc.message() << "\n";
                std::cout << "Previous files remain at: "
                    << backup.string() << "\n";
            }
        }

        cleanup();
        return false;
    }

#ifndef _WIN32
    fs::permissions(
        target,
        fs::perms::owner_all,
        fs::perm_options::replace,
        ec);
    ec.clear();
#endif

    fs::remove_all(backup, ec);
    ec.clear();

    {
        std::ofstream shaOut(shaFilePath(), std::ios::trunc);

        if (!shaOut)
        {
            std::cout << "WARNING: website installed, but cannot write "
                << shaFilePath().string() << "\n";
        }
        else
        {
            shaOut << webSha << '\n';
        }
    }

    cleanup();

    std::cout << "Web installed to: "
        << target.string() << "\n";

    return true;
}

bool removeWebFiles()
{
    std::error_code ec;

    fs::remove_all(webRootPath(), ec);

    if (ec)
    {
        std::cout << "Cannot remove web files: "
            << ec.message() << "\n";
        return false;
    }

    ec.clear();
    fs::remove(shaFilePath(), ec);

    if (ec)
    {
        std::cout << "Cannot remove SHA256 file: "
            << ec.message() << "\n";
        return false;
    }

    return true;
}

void handleWebCommand(
    const std::string& arg,
    WebServer* webServer)
{
    if (!webServer)
    {
        std::cout << "Web server is not available.\n";
        return;
    }

    if (arg == "install" || arg == "update")
    {
        if (!installWebFiles())
            return;

        if (!webServer->isRunning())
        {
            if (webServer->start())
            {
                std::cout << "Open: "
                    << webServer->accessUrl() << "\n";
            }
            else
            {
                std::cout
                    << "Web files installed, "
                    << "but the server failed to start.\n";
            }
        }
        else
        {
            std::cout << "Web server is running: "
                << webServer->accessUrl() << "\n";
        }

        return;
    }

    if (arg == "status")
    {
        std::error_code ec;

        const bool installed =
            fs::exists(fs::path(webRootPath()) / "index.html", ec) &&
            !ec;

        const std::string sha = installedSha();

        std::cout << "Web root:  " << webRootPath() << "\n";
        std::cout << "Installed: "
            << (installed ? "yes" : "no") << "\n";

        if (installed && !sha.empty())
            std::cout << "SHA256:    " << sha << "\n";

        std::cout << "Running:   "
            << (webServer->isRunning() ? "yes" : "no") << "\n";

        return;
    }

    if (arg == "url")
    {
        if (webServer->isRunning())
        {
            std::cout << webServer->accessUrl() << "\n";
        }
        else
        {
            std::cout
                << "Web server is not running. "
                << "Type 'web install'.\n";
        }

        return;
    }

    if (arg == "remove")
    {
        webServer->stop();

        if (removeWebFiles())
            std::cout << "Web removed.\n";

        return;
    }

    std::cout
        << "Usage: web install | web update | web status | web url | web remove\n";
}
