#include "Security.h"

#include <libssh2.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>

#include "Platform.h"
#include "config.h"

static const char* MODULE_NAME = "ServerGuard Security";
static const char* MODULE_VERSION = "1.0.0";

struct ModuleCommand
{
    const char* key;
    const char* title;
};

static const ModuleCommand MODULE_COMMANDS[] = {
    { "1", "Install / enable protection" },
    { "2", "Start protection" },
    { "3", "Stop protection" },
    { "4", "Disable automatic startup" },
    { "5", "Check status" },
    { "6", "Show logs" },
    { "7", "Update Security" },
    { "8", "Uninstall Security" },
    { "0", "Back" },
};

static const std::string SECURITY_DIR = "/opt/serverguard";
static const std::string SECURITY_DATA_DIR = "/opt/serverguard/data";
static const std::string SECURITY_SCRIPT = "/opt/serverguard/brute_force_guard.py";
static const std::string SECURITY_TEMP_SCRIPT = "/opt/serverguard/brute_force_guard.py.update";
static const std::string SECURITY_SERVICE = "serverguard-security.service";
static const std::string SECURITY_SERVICE_PATH = "/etc/systemd/system/serverguard-security.service";
static const std::string SECURITY_BACKUP_DIR = "/opt/serverguard/backups/security";
static const std::string SECURITY_BACKUP_SCRIPT = "/opt/serverguard/backups/security/brute_force_guard.py";
static const std::string SECURITY_STATS_FILE = "/opt/serverguard/data/stats.json";

static const std::string SECURITY_UPDATE_URL = ServerGuardConfig::SECURITY_SCRIPT_URL;
static const std::string SECURITY_MANIFEST_URL = ServerGuardConfig::SECURITY_MANIFEST_URL;
static const std::string SECURITY_SIGNATURE_URL = ServerGuardConfig::SECURITY_SIGNATURE_URL;

static const int SECURITY_BACKUP_KEEP = 5;

static const size_t SECURITY_MAX_MANIFEST_SIZE = 64 * 1024;
static const size_t SECURITY_MAX_SIGNATURE_SIZE = 64;
static const size_t SECURITY_MAX_SCRIPT_SIZE = 4 * 1024 * 1024;

static const char* SECURITY_MANIFEST_ENTRY = ServerGuardConfig::SECURITY_MAIN_SCRIPT_NAME;

static const std::string SECURITY_TEMP_BASE64 = "/tmp/.sg_security.b64";

static const unsigned char SECURITY_PUBLIC_KEY[32] = {
    0xd3, 0x6e, 0x36, 0x10, 0xbb, 0x16, 0xc3, 0x3b,
    0xca, 0x3f, 0x0c, 0x34, 0x58, 0x74, 0xd0, 0x33,
    0x72, 0x6e, 0xd8, 0x34, 0x00, 0x02, 0x48, 0x00,
    0xcf, 0xf0, 0x8d, 0x31, 0x17, 0x2c, 0x17, 0x69
};


static void sleepMs(int ms)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

static std::string shellQuote(const std::string& value)
{
    std::string result = "'";

    for (char c : value)
    {
        if (c == '\'')
        {
            result += "'\\''";
        }
        else
        {
            result += c;
        }
    }

    result += "'";

    return result;
}

static std::string trim(const std::string& value)
{
    size_t start = 0;

    while (start < value.size() &&
        std::isspace(static_cast<unsigned char>(value[start])))
    {
        ++start;
    }

    size_t end = value.size();

    while (end > start &&
        std::isspace(static_cast<unsigned char>(value[end - 1])))
    {
        --end;
    }

    return value.substr(start, end - start);
}

static std::string toLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return value;
}

static bool contains(const std::string& haystack, const std::string& needle)
{
    return haystack.find(needle) != std::string::npos;
}

static bool isDigits(const std::string& value)
{
    if (value.empty())
    {
        return false;
    }

    for (char c : value)
    {
        if (!std::isdigit(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }

    return true;
}

static bool validPort(const std::string& value)
{
    if (!isDigits(value) || value.size() > 5)
    {
        return false;
    }

    const int port = std::stoi(value);

    return port >= 1 && port <= 65535;
}

static bool validIpText(const std::string& value)
{
    if (value.empty() || value.size() > 45)
    {
        return false;
    }

    for (char c : value)
    {
        if (!std::isxdigit(static_cast<unsigned char>(c)) && c != ':' && c != '.')
        {
            return false;
        }
    }

    return true;
}

static void addUnique(std::vector<std::string>& list, const std::string& value)
{
    if (std::find(list.begin(), list.end(), value) == list.end())
    {
        list.push_back(value);
    }
}

static std::vector<std::string> splitWords(const std::string& text)
{
    std::vector<std::string> words;
    std::istringstream stream(text);
    std::string word;

    while (stream >> word)
    {
        words.push_back(word);
    }

    return words;
}

static std::vector<std::string> splitLines(const std::string& text)
{
    std::vector<std::string> lines;
    std::istringstream stream(text);
    std::string line;

    while (std::getline(stream, line))
    {
        lines.push_back(line);
    }

    return lines;
}

static bool parseLocalPort(const std::string& token, std::string& port, bool& loopback)
{
    const size_t pos = token.rfind(':');

    if (pos == std::string::npos)
    {
        return false;
    }

    port = token.substr(pos + 1);

    const std::string address = token.substr(0, pos);

    loopback =
        address.rfind("127.", 0) == 0 ||
        address == "[::1]" ||
        address == "::1" ||
        address.find("%lo") != std::string::npos;

    return validPort(port);
}

static void printOutput(const std::string& output)
{
    if (!output.empty())
    {
        std::cout << output;

        if (output.back() != '\n')
        {
            std::cout << "\n";
        }
    }
}

static std::string securityJsonEscape(const std::string& value)
{
    std::string result;

    for (unsigned char c : value)
    {
        switch (c)
        {
        case '\"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;

        default:
            if (c < 0x20)
            {
                const char* hex = "0123456789ABCDEF";
                result += "\\u00";
                result += hex[(c >> 4) & 0x0F];
                result += hex[c & 0x0F];
            }
            else
            {
                result += static_cast<char>(c);
            }

            break;
        }
    }

    return result;
}

static bool downloadToFile(const std::string& url, const std::string& path)
{
    return plat::downloadFile(url, path, SECURITY_MAX_SCRIPT_SIZE);
}

static bool readBinaryFile(const std::string& path, std::string& data, size_t maxSize)
{
    data.clear();

    std::ifstream file(path, std::ios::binary);

    if (!file)
    {
        return false;
    }

    file.seekg(0, std::ios::end);

    const std::streamoff size = file.tellg();

    if (size < 0 || static_cast<unsigned long long>(size) > maxSize)
    {
        return false;
    }

    file.seekg(0, std::ios::beg);

    data.resize(static_cast<size_t>(size));

    if (!data.empty())
    {
        file.read(&data[0], static_cast<std::streamsize>(data.size()));

        if (!file || file.gcount() != static_cast<std::streamsize>(data.size()))
        {
            data.clear();
            return false;
        }
    }

    return true;
}

static bool verifyEd25519(const std::string& manifest, const std::string& signature)
{
    if (signature.size() != SECURITY_MAX_SIGNATURE_SIZE || manifest.empty())
    {
        return false;
    }

    EVP_PKEY* rawKey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519,
        nullptr,
        SECURITY_PUBLIC_KEY,
        sizeof(SECURITY_PUBLIC_KEY));

    if (!rawKey)
    {
        std::cerr << "OpenSSL could not create the Ed25519 public key.\n";
        return false;
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(rawKey, EVP_PKEY_free);

    EVP_MD_CTX* rawContext = EVP_MD_CTX_new();

    if (!rawContext)
    {
        return false;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(rawContext, EVP_MD_CTX_free);

    if (EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1)
    {
        return false;
    }

    return EVP_DigestVerify(
        context.get(),
        reinterpret_cast<const unsigned char*>(signature.data()),
        signature.size(),
        reinterpret_cast<const unsigned char*>(manifest.data()),
        manifest.size()) == 1;
}

static bool getExpectedScriptHash(const std::string& manifest, std::string& expectedHash)
{
    expectedHash.clear();

    if (manifest.find("\"format\"") == std::string::npos ||
        manifest.find("\"ServerGuardModuleManifest\"") == std::string::npos ||
        !std::regex_search(
            manifest,
            std::regex(R"REGEX("version"\s*:\s*1(?:\s*[,}]))REGEX")) ||
        manifest.find("\"algorithm\"") == std::string::npos ||
        manifest.find("\"Ed25519\"") == std::string::npos)
    {
        return false;
    }

    const std::string entry = SECURITY_MANIFEST_ENTRY;

    std::string escaped;

    for (char c : entry)
    {
        if (c == '.')
        {
            escaped += "\\.";
        }
        else
        {
            escaped += c;
        }
    }

    const std::regex pathPattern("\"path\"\\s*:\\s*\"" + escaped + "\"");

    const std::regex entryPattern(
        "\"path\"\\s*:\\s*\"" + escaped +
        "\"\\s*,\\s*\"sha256\"\\s*:\\s*\"([0-9a-fA-F]{64})\"");

    size_t count = 0;

    for (std::sregex_iterator it(manifest.begin(), manifest.end(), pathPattern), end;
        it != end;
        ++it)
    {
        ++count;
    }

    if (count != 1)
    {
        return false;
    }

    std::smatch match;

    if (!std::regex_search(manifest, match, entryPattern))
    {
        return false;
    }

    expectedHash = toLower(match[1].str());

    return true;
}

static std::string sha256Hex(const std::string& data)
{
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLength = 0;

    if (EVP_Digest(
        data.data(),
        data.size(),
        digest,
        &digestLength,
        EVP_sha256(),
        nullptr) != 1)
    {
        return {};
    }

    if (digestLength != 32)
    {
        return {};
    }

    std::ostringstream result;
    result << std::hex << std::setfill('0');

    for (unsigned int i = 0; i < digestLength; ++i)
    {
        result << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }

    return result.str();
}

static std::string base64Encode(const std::string& input)
{
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;

    while (i + 2 < input.size())
    {
        const unsigned int value =
            (static_cast<unsigned char>(input[i]) << 16) |
            (static_cast<unsigned char>(input[i + 1]) << 8) |
            static_cast<unsigned char>(input[i + 2]);

        output += alphabet[(value >> 18) & 63];
        output += alphabet[(value >> 12) & 63];
        output += alphabet[(value >> 6) & 63];
        output += alphabet[value & 63];

        i += 3;
    }

    if (i + 1 == input.size())
    {
        const unsigned int value = static_cast<unsigned char>(input[i]) << 16;

        output += alphabet[(value >> 18) & 63];
        output += alphabet[(value >> 12) & 63];
        output += "==";
    }
    else if (i + 2 == input.size())
    {
        const unsigned int value =
            (static_cast<unsigned char>(input[i]) << 16) |
            (static_cast<unsigned char>(input[i + 1]) << 8);

        output += alphabet[(value >> 18) & 63];
        output += alphabet[(value >> 12) & 63];
        output += alphabet[(value >> 6) & 63];
        output += '=';
    }

    return output;
}


Security::Security(LIBSSH2_SESSION* sshSession, const std::string& password)
    : session(sshSession),
    sudoPassword(password),
    sshSecurity(false),
    sudoRequired(false),
    sudoAuthenticated(false),
    sudoNoPassword(false),
    needPty(false),
    inPrivilegeCheck(false),
    privilegeFailures(0),
    lastPrivilegeAttempt(0),
    mutex_(std::make_shared<std::recursive_mutex>())
{}

void Security::setSession(LIBSSH2_SESSION* sshSession)
{
    std::lock_guard<std::recursive_mutex> guard(*mutex_);

    session = sshSession;
}

void Security::setSudoPassword(const std::string& password)
{
    std::lock_guard<std::recursive_mutex> guard(*mutex_);

    sudoPassword = password;
    sudoAuthenticated = false;
    sudoNoPassword = false;
    privilegeFailures = 0;
    lastPrivilegeAttempt = 0;
}

void Security::setReconnectCallback(std::function<LIBSSH2_SESSION* ()> callback)
{
    std::lock_guard<std::recursive_mutex> guard(*mutex_);

    reconnectCallback = callback;
}

std::string Security::getLastError() const
{
    std::lock_guard<std::recursive_mutex> guard(*mutex_);

    return lastError;
}

void Security::setError(const std::string& message)
{
    lastError = message;
}

bool Security::isSSHSecurityEnabled() const
{
    return sshSecurity;
}


bool Security::reconnect()
{
    if (!reconnectCallback)
    {
        return false;
    }

    std::cout << "[WARN] SSH connection problem. Reconnecting...\n";

    LIBSSH2_SESSION* newSession = nullptr;

    try
    {
        newSession = reconnectCallback();
    }
    catch (...)
    {
        newSession = nullptr;
    }

    if (newSession == nullptr)
    {
        setError("SSH reconnect failed.");
        return false;
    }

    session = newSession;

    std::cout << "[OK] SSH reconnected.\n";

    return true;
}


int Security::executeOnce(
    const std::string& command,
    std::string& output,
    int& exitCode,
    bool elevated,
    int timeoutSec)
{
    output.clear();
    exitCode = -1;

    if (session == nullptr)
    {
        output = "SSH session is not available.";
        return 1;
    }

    struct ModeGuard
    {
        LIBSSH2_SESSION* s;
        int blocking;
        long timeout;

        explicit ModeGuard(LIBSSH2_SESSION* x)
            : s(x),
            blocking(libssh2_session_get_blocking(x)),
            timeout(libssh2_session_get_timeout(x))
        {
            libssh2_session_set_blocking(s, 1);
            libssh2_session_set_timeout(s, 10000);
        }

        ~ModeGuard()
        {
            libssh2_session_set_timeout(s, timeout);
            libssh2_session_set_blocking(s, blocking);
        }
    } modeGuard(session);

    LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);

    if (channel == nullptr)
    {
        char* errorMessage = nullptr;
        const int code = libssh2_session_last_error(session, &errorMessage, nullptr, 0);

        output = "Failed to open SSH channel (libssh2 error " + std::to_string(code) + ")";

        if (errorMessage != nullptr)
        {
            output += ": ";
            output += errorMessage;
        }

        return 1;
    }

    auto release = [&]()
        {
            libssh2_channel_close(channel);
            libssh2_channel_free(channel);
        };

    libssh2_channel_handle_extended_data2(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);

    const bool usePty = elevated && needPty;

    if (usePty)
    {
        libssh2_channel_request_pty(channel, "xterm");
    }

    const std::string wrapped =
        "export LC_ALL=C PATH=\"$PATH:/usr/local/sbin:/usr/sbin:/sbin\"; " + command;

    std::string finalCommand;
    bool sendPassword = false;

    if (!elevated)
    {
        finalCommand = "sh -c " + shellQuote(wrapped);
    }
    else if (sudoNoPassword)
    {
        finalCommand = "sudo -n sh -c " + shellQuote(wrapped);
    }
    else
    {
        if (sudoPassword.empty())
        {
            output = "Sudo password is empty, and the remote user requires sudo.";
            release();
            return 2;
        }

        finalCommand = "sudo -S -p '' sh -c " + shellQuote(wrapped);
        sendPassword = true;
    }

    const int execResult = libssh2_channel_exec(channel, finalCommand.c_str());

    if (execResult != 0)
    {
        char* errorMessage = nullptr;
        libssh2_session_last_error(session, &errorMessage, nullptr, 0);

        output = "Failed to execute remote command. libssh2 error: " + std::to_string(execResult);

        if (errorMessage != nullptr)
        {
            output += " | ";
            output += errorMessage;
        }

        release();
        return 1;
    }

    if (sendPassword)
    {
        const std::string passwordLine = sudoPassword + "\n";
        size_t totalWritten = 0;

        const auto writeDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);

        while (totalWritten < passwordLine.size())
        {
            const ssize_t written = libssh2_channel_write(
                channel,
                passwordLine.data() + totalWritten,
                passwordLine.size() - totalWritten);

            if (written > 0)
            {
                totalWritten += static_cast<size_t>(written);
                continue;
            }

            if ((written == LIBSSH2_ERROR_EAGAIN || written == LIBSSH2_ERROR_TIMEOUT) &&
                std::chrono::steady_clock::now() < writeDeadline)
            {
                sleepMs(10);
                continue;
            }

            output = "Failed to send sudo password.";
            release();
            return 1;
        }
    }

    if (!usePty)
    {
        libssh2_channel_send_eof(channel);
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(timeoutSec > 0 ? timeoutSec : 60);

    char buffer[4096];
    bool timedOut = false;
    bool transportError = false;

    while (true)
    {
        const ssize_t bytesRead = libssh2_channel_read(channel, buffer, sizeof(buffer));

        if (bytesRead > 0)
        {
            output.append(buffer, static_cast<size_t>(bytesRead));
            continue;
        }

        if (bytesRead == LIBSSH2_ERROR_EAGAIN ||
            bytesRead == LIBSSH2_ERROR_TIMEOUT ||
            bytesRead == 0)
        {
            if (libssh2_channel_eof(channel))
            {
                break;
            }

            if (std::chrono::steady_clock::now() > deadline)
            {
                timedOut = true;
                break;
            }

            if (bytesRead != LIBSSH2_ERROR_TIMEOUT)
            {
                sleepMs(10);
            }

            continue;
        }

        char* errorMessage = nullptr;
        libssh2_session_last_error(session, &errorMessage, nullptr, 0);

        output += "\n[libssh2 channel read error: " + std::to_string(static_cast<int>(bytesRead)) + "]";

        if (errorMessage != nullptr)
        {
            output += " ";
            output += errorMessage;
        }

        transportError = true;
        break;
    }

    if (timedOut)
    {
        output += "\n[timeout after " + std::to_string(timeoutSec) + " seconds]";
        release();
        exitCode = -2;
        return 2;
    }

    if (transportError)
    {
        release();
        return 1;
    }

    libssh2_channel_close(channel);
    libssh2_channel_wait_closed(channel);

    exitCode = libssh2_channel_get_exit_status(channel);

    char* exitSignal = nullptr;
    size_t exitSignalLength = 0;

    if (libssh2_channel_get_exit_signal(
        channel, &exitSignal, &exitSignalLength,
        nullptr, nullptr, nullptr, nullptr) == 0 &&
        exitSignal != nullptr && exitSignalLength > 0)
    {
        output += "\n[terminated by signal " + std::string(exitSignal, exitSignalLength) + "]";

        if (exitCode == 0)
        {
            exitCode = -3;
        }
    }

    libssh2_channel_free(channel);

    output.erase(std::remove(output.begin(), output.end(), '\r'), output.end());

    return 0;
}

bool Security::executeRemote(
    const std::string& command,
    std::string& output,
    int& exitCode,
    bool useSudo,
    int timeoutSec)
{
    std::lock_guard<std::recursive_mutex> guard(*mutex_);

    output.clear();
    exitCode = -1;

    if (useSudo && !inPrivilegeCheck && !sudoAuthenticated)
    {
        if (!ensurePrivileges())
        {
            output = "Administrator privileges are not available: " + lastError;
            return false;
        }
    }

    const int maxAttempts = 3;

    for (int attempt = 0; attempt < maxAttempts; ++attempt)
    {
        const bool elevated = useSudo && sudoRequired;

        const int status = executeOnce(command, output, exitCode, elevated, timeoutSec);

        if (status == 0)
        {
            if (elevated && exitCode != 0 && !needPty)
            {
                const std::string low = toLower(output);

                if (contains(low, "must have a tty") || contains(low, "requiretty"))
                {
                    needPty = true;
                    continue;
                }
            }

            return exitCode == 0;
        }

        if (status == 2)
        {
            return false;
        }

        if (attempt + 1 < maxAttempts)
        {
            if (!reconnect())
            {
                sleepMs(700 * (attempt + 1));
            }
        }
    }

    setError("SSH command failed after retries: " + trim(output));

    return false;
}


bool Security::ensurePrivileges()
{
    if (sudoAuthenticated)
    {
        return true;
    }

    if (privilegeFailures >= 3)
    {
        return false;
    }

    const std::time_t now = std::time(nullptr);

    if (lastPrivilegeAttempt != 0 && now - lastPrivilegeAttempt < 30)
    {
        return false;
    }

    return checkPrivileges(false);
}

bool Security::authenticateSudo()
{
    std::string output;
    int exitCode = -1;

    if (executeRemote("true", output, exitCode, true, 30))
    {
        sudoAuthenticated = true;
        privilegeFailures = 0;
        return true;
    }

    sudoAuthenticated = false;

    const std::string low = toLower(output);

    if (contains(low, "incorrect password") || contains(low, "sorry, try again") ||
        contains(low, "no password was provided"))
    {
        setError("Incorrect sudo password. Update it with setSudoPassword().");
    }
    else if (contains(low, "not in the sudoers") || contains(low, "may not run sudo"))
    {
        setError("The remote user is not allowed to use sudo.");
    }
    else if (contains(low, "command not found") || contains(low, "sudo: not found"))
    {
        setError("sudo is not installed on the server and the user is not root.");
    }
    else
    {
        setError("sudo authentication failed: " + trim(output));
    }

    return false;
}

bool Security::checkPrivileges(bool verbose)
{
    std::lock_guard<std::recursive_mutex> guard(*mutex_);

    if (sudoAuthenticated)
    {
        return true;
    }

    if (privilegeFailures >= 3)
    {
        setError("sudo authentication failed 3 times; refusing to retry to avoid locking the account. "
            "Update the password with setSudoPassword().");

        if (verbose)
        {
            std::cout << "[ERROR] " << lastError << "\n";
        }

        return false;
    }

    struct Flag
    {
        bool& flag;
        explicit Flag(bool& f) : flag(f) { flag = true; }
        ~Flag() { flag = false; }
    } flag(inPrivilegeCheck);

    lastPrivilegeAttempt = std::time(nullptr);

    std::string output;
    int exitCode = -1;

    if (!executeRemote("id -u", output, exitCode, false, 20))
    {
        setError("Cannot determine the remote user: " + trim(output));

        if (verbose)
        {
            std::cout << "[ERROR] " << lastError << "\n";
        }

        return false;
    }

    if (trim(output) == "0")
    {
        sudoRequired = false;
        sudoNoPassword = false;
        sudoAuthenticated = true;
        privilegeFailures = 0;

        return true;
    }

    sudoRequired = true;

    output.clear();

    if (executeRemote("sudo -n true", output, exitCode, false, 20) && exitCode == 0)
    {
        sudoNoPassword = true;
        sudoAuthenticated = true;
        privilegeFailures = 0;

        if (verbose)
        {
            std::cout << "Administrator privileges: passwordless sudo.\n";
        }

        return true;
    }

    sudoNoPassword = false;

    if (sudoPassword.empty())
    {
        setError("The remote user is not root, sudo needs a password, but the password is empty.");

        if (verbose)
        {
            std::cout << "[ERROR] " << lastError << "\n";
        }

        return false;
    }

    if (verbose)
    {
        std::cout << "Administrator privileges are required.\n";
    }

    if (!authenticateSudo())
    {
        ++privilegeFailures;

        if (verbose)
        {
            std::cout << "[ERROR] " << lastError << "\n";
        }

        return false;
    }

    return true;
}

bool Security::checkRootOrSudo()
{
    return checkPrivileges(true);
}


bool Security::commandExists(const std::string& command)
{
    std::string output;
    int exitCode = -1;

    return executeRemote("command -v " + shellQuote(command) + " >/dev/null 2>&1", output, exitCode, false, 20);
}

std::string Security::detectPackageManager()
{
    if (commandExists("apt-get"))
    {
        return "apt";
    }

    if (commandExists("dnf"))
    {
        return "dnf";
    }

    if (commandExists("yum"))
    {
        return "yum";
    }

    return "";
}

bool Security::installPackages(const std::vector<std::string>& packages)
{
    const std::string manager = detectPackageManager();

    if (manager.empty())
    {
        setError("No supported package manager (apt-get, dnf, yum) found.");
        return false;
    }

    std::string list;

    for (const std::string& package : packages)
    {
        list += " " + shellQuote(package);
    }

    std::string command;

    if (manager == "apt")
    {
        command =
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get -o DPkg::Lock::Timeout=300 update -qq >/dev/null 2>&1; "
            "apt-get -o DPkg::Lock::Timeout=300 install -y" + list;
    }
    else
    {
        command = manager + " install -y" + list;
    }

    for (int attempt = 1; attempt <= 3; ++attempt)
    {
        std::string output;
        int exitCode = -1;

        if (executeRemote(command, output, exitCode, true, 900))
        {
            return true;
        }

        std::cout << "[WARN] Package installation attempt " << attempt << "/3 failed.\n";

        const std::string low = toLower(output);

        if (attempt == 3)
        {
            printOutput(output);
            setError("Package installation failed: " + trim(output));
            break;
        }

        if (manager == "apt" && contains(low, "dpkg --configure -a"))
        {
            std::string fixOutput;
            int fixCode = -1;

            std::cout << "Repairing interrupted dpkg...\n";
            executeRemote("DEBIAN_FRONTEND=noninteractive dpkg --configure -a", fixOutput, fixCode, true, 600);
        }
        else if (contains(low, "lock"))
        {
            std::cout << "Package manager is busy, waiting...\n";
            sleepMs(20000);
        }
        else
        {
            sleepMs(5000);
        }
    }

    return false;
}

bool Security::ensureCommand(
    const std::string& command,
    const std::string& aptPackage,
    const std::string& rpmPackage)
{
    if (commandExists(command))
    {
        std::cout << "[OK] " << command << " is available.\n";
        return true;
    }

    std::cout << command << " is missing. Installing...\n";

    const std::string manager = detectPackageManager();
    const std::string package = (manager == "apt") ? aptPackage : rpmPackage;

    if (!installPackages({ package }) || !commandExists(command))
    {
        std::cout << "[ERROR] Could not install " << command << ".\n";
        setError("Could not install required command: " + command);
        return false;
    }

    std::cout << "[OK] " << command << " installed.\n";

    return true;
}

bool Security::checkPythonVersion()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,6) else 1)'",
        output, exitCode, false, 20))
    {
        std::cout << "[ERROR] Python 3.6 or newer is required on the server.\n";
        setError("Python 3.6+ is required.");
        return false;
    }

    return true;
}

std::string Security::pythonPath()
{
    std::string output;
    int exitCode = -1;

    if (executeRemote("command -v python3", output, exitCode, false, 20))
    {
        const std::string path = trim(output);

        if (!path.empty() && path[0] == '/' &&
            path.find_first_of(" \t\n'\"\\") == std::string::npos)
        {
            return path;
        }
    }

    return "/usr/bin/python3";
}


std::vector<std::string> Security::detectSshPorts()
{
    std::vector<std::string> ports;
    std::string output;
    int exitCode = -1;

    if (executeRemote("echo \"${SSH_CONNECTION##* }\"", output, exitCode, false, 15))
    {
        const std::string port = trim(output);

        if (validPort(port))
        {
            addUnique(ports, port);
        }
    }

    output.clear();

    if (executeRemote("sshd -T 2>/dev/null | awk '$1 == \"port\" {print $2}'", output, exitCode, true, 30))
    {
        for (const std::string& word : splitWords(output))
        {
            if (validPort(word))
            {
                addUnique(ports, word);
            }
        }
    }

    output.clear();

    if (executeRemote("ss -ltnp 2>/dev/null | grep sshd", output, exitCode, true, 20))
    {
        for (const std::string& line : splitLines(output))
        {
            const std::vector<std::string> words = splitWords(line);
            std::string port;
            bool loopback = false;

            if (words.size() >= 4 && parseLocalPort(words[3], port, loopback))
            {
                addUnique(ports, port);
            }
        }
    }

    output.clear();

    if (executeRemote(
        "grep -rhiE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null "
        "| awk '{print $2}'",
        output, exitCode, true, 20))
    {
        for (const std::string& word : splitWords(output))
        {
            if (validPort(word))
            {
                addUnique(ports, word);
            }
        }
    }

    return ports;
}

std::vector<std::string> Security::listeningPorts(bool udp)
{
    std::vector<std::string> ports;
    std::string output;
    int exitCode = -1;

    executeRemote(udp ? "ss -lun 2>/dev/null" : "ss -ltn 2>/dev/null", output, exitCode, false, 20);

    for (const std::string& line : splitLines(output))
    {
        const std::vector<std::string> words = splitWords(line);
        std::string port;
        bool loopback = false;

        if (words.size() < 4 || !parseLocalPort(words[3], port, loopback) || loopback)
        {
            continue;
        }

        addUnique(ports, port);
    }

    return ports;
}

bool Security::ufwIsActive()
{
    std::string output;
    int exitCode = -1;

    return executeRemote("ufw status", output, exitCode, true, 30) &&
        contains(output, "Status: active");
}

bool Security::setupFirewall(bool& firewallManaged)
{
    firewallManaged = false;

    std::cout << "\n----------------------------------------\n Firewall configuration\n----------------------------------------\n";

    const std::string manager = detectPackageManager();

    if (!commandExists("ufw") && manager == "apt")
    {
        std::cout << "UFW is not installed. Installing...\n";

        if (installPackages({ "ufw" }) && commandExists("ufw"))
        {
            std::cout << "[OK] UFW installed.\n";
        }
        else
        {
            std::cout << "[WARN] Could not install UFW.\n";
        }
    }

    auto useIptablesFallback = [&](const std::string& reason) -> bool
        {
            std::cout << "[WARN] " << reason << "\n";

            if (!commandExists("iptables"))
            {
                std::cout << "Installing iptables as the firewall backend...\n";

                if (!installPackages({ "iptables" }) && !installPackages({ "iptables-nft" }))
                {
                    setError("Neither UFW nor iptables is available; the guard cannot block IPs.");
                    std::cout << "[ERROR] " << lastError << "\n";
                    return false;
                }
            }

            if (!commandExists("iptables"))
            {
                setError("Neither UFW nor iptables is available; the guard cannot block IPs.");
                std::cout << "[ERROR] " << lastError << "\n";
                return false;
            }

            std::cout << "[OK] ServerGuard will use iptables to block IPs.\n";
            return true;
        };

    if (!commandExists("ufw"))
    {
        return useIptablesFallback("UFW is not available on this system.");
    }

    std::string output;
    int exitCode = -1;

    if (!executeRemote("ufw status", output, exitCode, true, 30))
    {
        printOutput(output);
        return useIptablesFallback("UFW is installed but does not work.");
    }

    const bool wasActive = contains(output, "Status: active");

    const std::vector<std::string> sshPorts = detectSshPorts();

    if (sshPorts.empty())
    {
        if (wasActive)
        {
            std::cout << "[OK] UFW is already active (SSH port could not be verified, rules left untouched).\n";
            firewallManaged = true;
            return true;
        }

        return useIptablesFallback(
            "Could not safely determine the SSH port. UFW will NOT be enabled (lockout protection).");
    }

    std::cout << "Detected SSH port(s): ";

    for (size_t i = 0; i < sshPorts.size(); ++i)
    {
        std::cout << sshPorts[i] << (i + 1 < sshPorts.size() ? ", " : "");
    }

    std::cout << "\n";

    bool sshAllowed = true;

    for (const std::string& port : sshPorts)
    {
        output.clear();

        if (!executeRemote("ufw allow " + shellQuote(port + "/tcp"), output, exitCode, true, 30))
        {
            std::cout << "[ERROR] Failed to allow SSH port " << port << ".\n";
            printOutput(output);
            sshAllowed = false;
        }
    }

    if (!sshAllowed)
    {
        return useIptablesFallback("SSH could not be allowed in UFW. UFW will NOT be enabled.");
    }

    if (wasActive)
    {
        std::cout << "[OK] UFW is already active. SSH ports are allowed.\n";
        firewallManaged = true;
        return true;
    }

    std::vector<std::string> tcpPorts = { "80", "443" };

    std::string cyberPanel;
    executeRemote("test -d /usr/local/CyberCP", cyberPanel, exitCode, false, 15);

    if (exitCode == 0)
    {
        addUnique(tcpPorts, "8090");
    }

    const std::vector<std::string> blockedDatabases = { "3306", "5432", "6379", "11211", "27017" };
    std::vector<std::string> skippedDatabases;

    for (const std::string& port : listeningPorts(false))
    {
        if (std::find(blockedDatabases.begin(), blockedDatabases.end(), port) != blockedDatabases.end())
        {
            skippedDatabases.push_back(port);
            continue;
        }

        addUnique(tcpPorts, port);
    }

    for (const std::string& port : tcpPorts)
    {
        output.clear();

        if (executeRemote("ufw allow " + shellQuote(port + "/tcp"), output, exitCode, true, 30))
        {
            std::cout << "[OK] Allowed " << port << "/tcp\n";
        }
        else
        {
            std::cout << "[WARN] Could not allow " << port << "/tcp\n";
        }
    }

    if (std::find(tcpPorts.begin(), tcpPorts.end(), "21") != tcpPorts.end())
    {
        output.clear();
        executeRemote("ufw allow 40110:40210/tcp", output, exitCode, true, 30);
    }

    static const std::vector<std::string> ignoredUdp = { "68", "123", "323", "546", "5353", "5355" };

    for (const std::string& port : listeningPorts(true))
    {
        if (std::find(ignoredUdp.begin(), ignoredUdp.end(), port) != ignoredUdp.end() ||
            std::stoi(port) >= 32768)
        {
            continue;
        }

        output.clear();

        if (executeRemote("ufw allow " + shellQuote(port + "/udp"), output, exitCode, true, 30))
        {
            std::cout << "[OK] Allowed " << port << "/udp\n";
        }
    }

    if (!skippedDatabases.empty())
    {
        std::cout << "[INFO] Database/cache ports stay closed to the outside: ";

        for (const std::string& port : skippedDatabases)
        {
            std::cout << port << " ";
        }

        std::cout << "\n       (open them manually with 'ufw allow <port>/tcp' if remote access is needed)\n";
    }

    std::cout << "\nEnabling UFW...\n";

    output.clear();

    if (!executeRemote("ufw --force enable", output, exitCode, true, 60))
    {
        printOutput(output);
        return useIptablesFallback("Failed to enable UFW.");
    }

    output.clear();

    if (!executeRemote("ufw status verbose", output, exitCode, true, 30) ||
        !contains(output, "Status: active"))
    {
        printOutput(output);
        executeRemote("ufw --force disable", output, exitCode, true, 30);
        return useIptablesFallback("UFW did not become active.");
    }

    for (const std::string& port : sshPorts)
    {
        if (!contains(output, port + "/tcp"))
        {
            std::string disableOutput;
            executeRemote("ufw --force disable", disableOutput, exitCode, true, 30);

            return useIptablesFallback(
                "SSH port " + port + " is missing from the UFW rules. UFW was disabled again to keep SSH reachable.");
        }
    }

    std::cout << "\nFirewall status:\n" << output << "\n";
    std::cout << "[OK] UFW is active.\n";

    firewallManaged = true;

    return true;
}


bool Security::createDirectories()
{
    std::string output;
    int exitCode = -1;

    const std::string command =
        "mkdir -p " + shellQuote(SECURITY_DIR) + " " + shellQuote(SECURITY_DATA_DIR) +
        " && chmod 700 " + shellQuote(SECURITY_DIR) + " " + shellQuote(SECURITY_DATA_DIR);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to create ServerGuard directories.\n";
        printOutput(output);
        setError("Failed to create ServerGuard directories: " + trim(output));
        return false;
    }

    return true;
}

bool Security::setFilePermissions()
{
    std::string output;
    int exitCode = -1;

    const std::string command =
        "chown root:root " + shellQuote(SECURITY_SCRIPT) +
        " && chmod 700 " + shellQuote(SECURITY_SCRIPT);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to set security script permissions.\n";
        printOutput(output);
        return false;
    }

    return true;
}

bool Security::createSystemdService()
{
    const std::string serviceContent =
        "[Unit]\n"
        "Description=ServerGuard SSH Brute Force Protection\n"
        "After=network-online.target ssh.service sshd.service ufw.service\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=0\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=" + pythonPath() + " -u " + SECURITY_SCRIPT + "\n"
        "Restart=always\n"
        "RestartSec=5\n"
        "User=root\n"
        "Group=root\n"
        "WorkingDirectory=" + SECURITY_DIR + "\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        "KillSignal=SIGTERM\n"
        "TimeoutStopSec=20\n"
        "NoNewPrivileges=false\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    std::string output;
    int exitCode = -1;

    const std::string command =
        "printf '%s' " + shellQuote(serviceContent) +
        " > " + shellQuote(SECURITY_SERVICE_PATH + ".tmp") +
        " && mv -f " + shellQuote(SECURITY_SERVICE_PATH + ".tmp") + " " + shellQuote(SECURITY_SERVICE_PATH) +
        " && chmod 644 " + shellQuote(SECURITY_SERVICE_PATH) +
        " && chown root:root " + shellQuote(SECURITY_SERVICE_PATH);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to create systemd service.\n";
        printOutput(output);
        setError("Failed to create systemd service: " + trim(output));
        return false;
    }

    return true;
}

bool Security::reloadSystemd()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("systemctl daemon-reload", output, exitCode, true))
    {
        std::cout << "[ERROR] systemd daemon-reload failed.\n";
        printOutput(output);
        return false;
    }

    return true;
}

bool Security::enableService()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("systemctl enable " + SECURITY_SERVICE, output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to enable security service.\n";
        printOutput(output);
        return false;
    }

    return true;
}

bool Security::serviceExists()
{
    std::string output;
    int exitCode = -1;

    return executeRemote("test -f " + shellQuote(SECURITY_SERVICE_PATH), output, exitCode, false);
}

bool Security::serviceIsActive()
{
    std::string output;
    int exitCode = -1;

    const bool active = executeRemote("systemctl is-active --quiet " + SECURITY_SERVICE, output, exitCode, false);

    sshSecurity = active;

    return active;
}

int Security::serviceRestartCount()
{
    std::string output;
    int exitCode = -1;

    if (executeRemote("systemctl show -p NRestarts --value " + SECURITY_SERVICE + " 2>/dev/null",
        output, exitCode, false, 20))
    {
        const std::string value = trim(output);

        if (isDigits(value) && value.size() < 9)
        {
            return std::stoi(value);
        }
    }

    return 0;
}

bool Security::waitServiceStable(int seconds)
{
    const int baseline = serviceRestartCount();

    for (int i = 0; i < seconds; ++i)
    {
        sleepMs(1000);

        if (!serviceIsActive())
        {
            return false;
        }
    }

    return serviceRestartCount() == baseline;
}

void Security::printServiceDiagnostics()
{
    std::string output;
    int exitCode = -1;

    executeRemote("systemctl status " + SECURITY_SERVICE + " --no-pager -l 2>&1 | tail -n 25", output, exitCode, true, 30);

    if (!output.empty())
    {
        std::cout << "\n" << output << "\n";
    }

    output.clear();

    executeRemote("journalctl -u " + SECURITY_SERVICE + " -n 30 --no-pager 2>&1", output, exitCode, true, 30);

    if (!output.empty())
    {
        std::cout << "\n" << output << "\n";
    }
}

bool Security::startServiceOnce()
{
    std::string output;
    int exitCode = -1;

    executeRemote("systemctl reset-failed " + SECURITY_SERVICE + " 2>/dev/null; true", output, exitCode, true, 30);

    output.clear();

    if (!executeRemote("systemctl restart " + SECURITY_SERVICE, output, exitCode, true, 60))
    {
        std::cout << "[ERROR] systemctl restart failed.\n";
        printOutput(output);
        sshSecurity = false;
        return false;
    }

    if (!waitServiceStable(8))
    {
        sshSecurity = false;
        return false;
    }

    sshSecurity = true;

    return true;
}

bool Security::repairService()
{
    std::cout << "[REPAIR] Trying to repair the Security service automatically...\n";

    if (!ensureScriptHealthy())
    {
        return false;
    }

    if (!createSystemdService() || !reloadSystemd())
    {
        return false;
    }

    enableService();

    return true;
}

bool Security::startService()
{
    if (startServiceOnce())
    {
        return true;
    }

    std::cout << "[WARN] Service did not start cleanly.\n";

    if (!repairService())
    {
        printServiceDiagnostics();
        setError("Security service failed to start and automatic repair failed.");
        sshSecurity = false;
        return false;
    }

    if (startServiceOnce())
    {
        std::cout << "[OK] Service repaired and started.\n";
        return true;
    }

    printServiceDiagnostics();
    setError("Security service failed to start even after automatic repair.");
    sshSecurity = false;

    return false;
}

bool Security::stopService()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("systemctl stop " + SECURITY_SERVICE, output, exitCode, true, 60))
    {
        return false;
    }

    sshSecurity = false;

    return true;
}

bool Security::disableService()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("systemctl disable " + SECURITY_SERVICE, output, exitCode, true))
    {
        return false;
    }

    sshSecurity = false;

    return true;
}


bool Security::verifyScriptFile(const std::string& path, bool runSelfTest)
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "test -s " + shellQuote(path) +
        " && [ \"$(wc -c < " + shellQuote(path) + ")\" -gt 2000 ]",
        output, exitCode, true))
    {
        std::cout << "[ERROR] Security script is missing, empty or truncated.\n";
        return false;
    }

    output.clear();

    if (!executeRemote("grep -q 'ServerGuard' " + shellQuote(path), output, exitCode, true))
    {
        std::cout << "[ERROR] File does not look like the ServerGuard script.\n";
        return false;
    }

    output.clear();

    const std::string syntaxCommand =
        "python3 -c " +
        shellQuote(
            "import ast,sys;"
            "p=open(sys.argv[1],encoding='utf-8').read();"
            "ast.parse(p,filename=sys.argv[1]);"
            "print('Python syntax: OK')") +
        " " + shellQuote(path);

    if (!executeRemote(syntaxCommand, output, exitCode, true))
    {
        std::cout << "[ERROR] Security script has invalid Python syntax.\n";
        printOutput(output);
        return false;
    }

    if (runSelfTest)
    {
        std::string timeoutCheck;
        int timeoutExit = -1;

        if (executeRemote("command -v timeout >/dev/null 2>&1", timeoutCheck, timeoutExit, false, 15))
        {
            output.clear();

            const bool ok = executeRemote(
                "timeout 30 python3 " + shellQuote(path) + " --selftest",
                output, exitCode, true, 60);

            if (!ok)
            {
                if (exitCode == 124)
                {
                    std::cout << "[WARN] Script has no --selftest support (older version), skipping.\n";
                }
                else
                {
                    std::cout << "[ERROR] Script self-test failed.\n";
                    printOutput(output);
                    setError("Security script self-test failed: " + trim(output));
                    return false;
                }
            }
            else
            {
                printOutput(output);
            }
        }
    }

    return true;
}

bool Security::downloadScriptToTemp()
{
    std::string manifestPath = plat::makeTempFile("sgm");
    std::string signaturePath = plat::makeTempFile("sgs");
    std::string scriptPath = plat::makeTempFile("sgp");

    const auto cleanup = [&]()
        {
            if (!manifestPath.empty()) plat::removeFile(manifestPath);
            if (!signaturePath.empty()) plat::removeFile(signaturePath);
            if (!scriptPath.empty()) plat::removeFile(scriptPath);
        };

    if (manifestPath.empty() || signaturePath.empty() || scriptPath.empty())
    {
        setError("Cannot create temporary files.");
        std::cout << "[ERROR] " << lastError << "\n";
        cleanup();
        return false;
    }

    std::cout << "Downloading signed module files...\n";

    struct DownloadItem
    {
        const char* label;
        const std::string* url;
        const std::string* path;
    };

    const DownloadItem items[] = {
        { "manifest.json", &SECURITY_MANIFEST_URL,  &manifestPath },
        { "manifest.sig",  &SECURITY_SIGNATURE_URL, &signaturePath },
        { "script",        &SECURITY_UPDATE_URL,    &scriptPath },
    };

    for (const DownloadItem& item : items)
    {
        if (!downloadToFile(*item.url, *item.path))
        {
            setError(std::string("Download failed (") + item.label + "): " + *item.url);

            std::cout << "[ERROR] Download failed (" << item.label << "):\n"
                << "        " << *item.url << "\n"
                << "        Check that the file exists at this URL (open it in a browser).\n"
                << "        On Linux the 'curl' command must be installed locally.\n"
                << "        Installation cancelled.\n";

            cleanup();
            return false;
        }
    }

    std::string manifest;
    std::string signature;
    std::string script;

    if (!readBinaryFile(manifestPath, manifest, SECURITY_MAX_MANIFEST_SIZE) ||
        !readBinaryFile(signaturePath, signature, SECURITY_MAX_SIGNATURE_SIZE) ||
        !readBinaryFile(scriptPath, script, SECURITY_MAX_SCRIPT_SIZE))
    {
        setError("Cannot read downloaded files or a size limit was exceeded "
            "(manifest.sig must be exactly 64 raw bytes).");
        std::cout << "[ERROR] " << lastError << "\n";
        cleanup();
        return false;
    }

    cleanup();

    std::cout << "Checking Ed25519 signature...\n";

    if (!verifyEd25519(manifest, signature))
    {
        setError("Invalid module signature.");
        std::cout << "[ERROR] SECURITY ERROR: Invalid module signature. Installation cancelled.\n";
        return false;
    }

    std::cout << "Signature valid. Checking manifest structure...\n";

    std::string expectedHash;

    if (!getExpectedScriptHash(manifest, expectedHash))
    {
        setError("Invalid manifest structure or missing script hash.");
        std::cout << "[ERROR] SECURITY ERROR: Invalid manifest structure or missing script hash. "
            "Installation cancelled.\n";
        return false;
    }

    const std::string actualHash = sha256Hex(script);

    if (actualHash.empty() || actualHash != expectedHash)
    {
        setError("SHA-256 mismatch.");
        std::cout << "[ERROR] SECURITY ERROR: SHA-256 mismatch. "
            "Downloaded module may have been modified. Installation cancelled.\n";
        return false;
    }

    std::cout << "[OK] Ed25519 and SHA-256 verified successfully.\n";
    std::cout << "Uploading verified script to the server...\n";

    std::string output;
    int exitCode = -1;

    if (!commandExists("base64"))
    {
        setError("base64 command is missing on the server.");
        std::cout << "[ERROR] " << lastError << "\n";
        return false;
    }

    const std::string encoded = base64Encode(script);
    const size_t chunkSize = 6000;

    if (!executeRemote(
        "umask 077; : > " + shellQuote(SECURITY_TEMP_BASE64),
        output, exitCode, false, 30))
    {
        setError("Cannot create temporary upload file on the server.");
        std::cout << "[ERROR] " << lastError << "\n";
        return false;
    }

    for (size_t pos = 0; pos < encoded.size(); pos += chunkSize)
    {
        const std::string chunk = encoded.substr(pos, chunkSize);

        if (!executeRemote(
            "printf %s " + shellQuote(chunk) + " >> " + shellQuote(SECURITY_TEMP_BASE64),
            output, exitCode, false, 60))
        {
            executeRemote("rm -f " + shellQuote(SECURITY_TEMP_BASE64), output, exitCode, false, 30);
            setError("Upload to the server failed.");
            std::cout << "[ERROR] " << lastError << "\n";
            return false;
        }
    }

    const bool decoded = executeRemote(
        "mkdir -p " + shellQuote(SECURITY_DIR) +
        " && base64 -d " + shellQuote(SECURITY_TEMP_BASE64) +
        " > " + shellQuote(SECURITY_TEMP_SCRIPT) +
        " && chown root:root " + shellQuote(SECURITY_TEMP_SCRIPT) +
        " && chmod 600 " + shellQuote(SECURITY_TEMP_SCRIPT),
        output, exitCode, true, 60);

    std::string cleanupOutput;
    int cleanupCode = -1;
    executeRemote("rm -f " + shellQuote(SECURITY_TEMP_BASE64), cleanupOutput, cleanupCode, false, 30);

    if (!decoded)
    {
        printOutput(output);
        setError("Could not decode the uploaded script on the server.");
        std::cout << "[ERROR] " << lastError << "\n";
        return false;
    }

    output.clear();

    if (!executeRemote(
        "sha256sum " + shellQuote(SECURITY_TEMP_SCRIPT) + " | cut -d' ' -f1",
        output, exitCode, true, 30) ||
        toLower(trim(output)) != expectedHash)
    {
        executeRemote("rm -f " + shellQuote(SECURITY_TEMP_SCRIPT), cleanupOutput, cleanupCode, true, 30);
        setError("Uploaded script hash does not match the verified hash.");
        std::cout << "[ERROR] " << lastError << "\n";
        return false;
    }

    std::cout << "[OK] Verified script uploaded.\n";

    if (!verifyScriptFile(SECURITY_TEMP_SCRIPT, true))
    {
        executeRemote("rm -f " + shellQuote(SECURITY_TEMP_SCRIPT), cleanupOutput, cleanupCode, true, 30);
        return false;
    }

    return true;
}

bool Security::backupCurrentSecurityScript()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("test -s " + shellQuote(SECURITY_SCRIPT), output, exitCode, true))
    {
        return true;
    }

    const std::string command =
        "mkdir -p " + shellQuote(SECURITY_BACKUP_DIR) +
        " && cp -f " + shellQuote(SECURITY_SCRIPT) + " " + shellQuote(SECURITY_BACKUP_SCRIPT) +
        " && cp -f " + shellQuote(SECURITY_SCRIPT) + " " + shellQuote(SECURITY_BACKUP_SCRIPT) + ".$(date +%Y%m%d%H%M%S)" +
        " && chown -R root:root " + shellQuote(SECURITY_BACKUP_DIR) +
        " && chmod -R go-rwx " + shellQuote(SECURITY_BACKUP_DIR) +
        " && ls -1t " + shellQuote(SECURITY_BACKUP_SCRIPT) + ".* 2>/dev/null"
        " | tail -n +" + std::to_string(SECURITY_BACKUP_KEEP + 1) + " | xargs -r rm -f --";

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to create Security backup.\n";
        printOutput(output);
        setError("Failed to create Security backup: " + trim(output));
        return false;
    }

    std::cout << "Backup created: " << SECURITY_BACKUP_SCRIPT << "\n";

    return true;
}

bool Security::installScriptFromTemp()
{
    std::string output;
    int exitCode = -1;

    const std::string command =
        "mv -f " + shellQuote(SECURITY_TEMP_SCRIPT) + " " + shellQuote(SECURITY_SCRIPT) +
        " && chown root:root " + shellQuote(SECURITY_SCRIPT) +
        " && chmod 700 " + shellQuote(SECURITY_SCRIPT);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to install the security script.\n";
        printOutput(output);
        setError("Failed to install the security script: " + trim(output));
        return false;
    }

    return true;
}

bool Security::rollbackSecurityUpdate()
{
    std::cout << "\n[ROLLBACK] Restoring previous Security script...\n";

    std::string output;
    int exitCode = -1;

    const std::string command =
        "test -s " + shellQuote(SECURITY_BACKUP_SCRIPT) +
        " && cp -f " + shellQuote(SECURITY_BACKUP_SCRIPT) + " " + shellQuote(SECURITY_SCRIPT) +
        " && chown root:root " + shellQuote(SECURITY_SCRIPT) +
        " && chmod 700 " + shellQuote(SECURITY_SCRIPT);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "[ERROR] Rollback failed (no backup available).\n";
        printOutput(output);
        return false;
    }

    std::cout << "[OK] Previous Security script restored.\n";

    return true;
}

bool Security::ensureScriptHealthy()
{
    std::string output;
    int exitCode = -1;

    if (executeRemote("test -s " + shellQuote(SECURITY_SCRIPT), output, exitCode, true))
    {
        if (verifyScriptFile(SECURITY_SCRIPT, false))
        {
            std::cout << "[OK] Security script is present and valid.\n";
            return true;
        }

        std::cout << "[WARN] Installed script is damaged.\n";

        if (rollbackSecurityUpdate() && verifyScriptFile(SECURITY_SCRIPT, false))
        {
            return true;
        }
    }
    else
    {
        std::cout << "Security script is missing.\n";
    }

    if (!downloadScriptToTemp())
    {
        return false;
    }

    if (!installScriptFromTemp())
    {
        return false;
    }

    if (!verifyScriptFile(SECURITY_SCRIPT, false))
    {
        return false;
    }

    std::cout << "[OK] Security script installed: " << SECURITY_SCRIPT << "\n";

    return true;
}

void Security::registerTrustedClientIp()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("echo \"${SSH_CONNECTION%% *}\"", output, exitCode, false, 15))
    {
        return;
    }

    const std::string ip = trim(output);

    if (!validIpText(ip))
    {
        return;
    }

    output.clear();

    if (executeRemote("python3 " + shellQuote(SECURITY_SCRIPT) + " --trust " + shellQuote(ip),
        output, exitCode, true, 30))
    {
        std::cout << "[OK] Your current IP (" << ip << ") is trusted and will never be blocked.\n";
    }
}


bool Security::installSecurity()
{
    std::cout << "\n========================================\n"
        << " ServerGuard Security Installation\n"
        << "========================================\n\n";

    if (!checkRootOrSudo())
    {
        std::cout << "[ERROR] Administrator privileges are required.\n";
        return false;
    }

    std::cout << "Checking server requirements...\n";

    if (!commandExists("systemctl"))
    {
        std::cout << "[ERROR] systemd (systemctl) is required.\n";
        setError("systemd (systemctl) is required.");
        return false;
    }

    std::cout << "[OK] systemctl is available.\n";

    if (!ensureCommand("python3", "python3", "python3"))
    {
        return false;
    }

    if (!checkPythonVersion())
    {
        return false;
    }

    if (!ensureCommand("base64", "coreutils", "coreutils"))
    {
        return false;
    }

    if (!commandExists("ss"))
    {
        ensureCommand("ss", "iproute2", "iproute");
    }

    if (!commandExists("sshd"))
    {
        std::cout << "[WARN] sshd binary not found in PATH; SSH port detection may be limited.\n";
    }

    bool firewallManaged = false;

    if (!setupFirewall(firewallManaged))
    {
        return false;
    }

    std::cout << "\nCreating ServerGuard directories...\n";

    if (!createDirectories())
    {
        return false;
    }

    std::cout << "[OK] Directories created.\n";

    std::cout << "\nChecking security script...\n";

    if (!ensureScriptHealthy())
    {
        std::cout << "[ERROR] Could not prepare the security script.\n";
        return false;
    }

    if (!setFilePermissions())
    {
        return false;
    }

    std::cout << "[OK] Security script permissions configured.\n";

    std::cout << "Creating systemd service...\n";

    if (!createSystemdService() || !reloadSystemd())
    {
        return false;
    }

    std::cout << "[OK] Systemd service configured.\n";

    if (!enableService())
    {
        std::cout << "[WARN] Could not enable automatic startup (the service can still run).\n";
    }
    else
    {
        std::cout << "[OK] Automatic startup enabled.\n";
    }

    registerTrustedClientIp();

    std::cout << "Starting service...\n";

    if (!startService())
    {
        std::cout << "[ERROR] Security service failed to start.\n";
        sshSecurity = false;
        return false;
    }

    std::cout << "[OK] Security service started.\n";

    sshSecurity = true;

    std::cout << "\n========================================\n"
        << " ServerGuard Security ACTIVE\n"
        << "========================================\n\n";

    std::cout << "[OK] Firewall: " << (firewallManaged ? "UFW ACTIVE" : "iptables fallback") << "\n";
    std::cout << "[OK] Security script: INSTALLED\n";
    std::cout << "[OK] SSH brute-force protection: ACTIVE\n";
    std::cout << "[OK] systemd automatic startup: ENABLED\n";
    std::cout << "[OK] Security service: RUNNING\n";
    std::cout << "\nProtection is ready.\n";

    return true;
}


bool Security::updateSecurity()
{
    std::cout << "\n========================================\n       UPDATE SERVERGUARD SECURITY\n========================================\n\n";

    if (!checkRootOrSudo())
    {
        std::cout << "\n[ERROR] Administrator privileges are required.\n";
        return false;
    }

    std::string output;
    int exitCode = -1;

    if (!executeRemote("test -s " + shellQuote(SECURITY_SCRIPT), output, exitCode, true))
    {
        std::cout << "Security is not installed yet. Running the full installation instead...\n";
        return installSecurity();
    }

    if (!ensureCommand("python3", "python3", "python3") || !checkPythonVersion())
    {
        return false;
    }

    if (!ensureCommand("base64", "coreutils", "coreutils"))
    {
        return false;
    }

    std::cout << "\n[1/7] Downloading and verifying new Security script...\n";

    if (!downloadScriptToTemp())
    {
        return false;
    }

    auto cleanupTemp = [&]()
        {
            std::string out;
            int code = -1;
            executeRemote("rm -f " + shellQuote(SECURITY_TEMP_SCRIPT), out, code, true);
        };

    std::cout << "[2/7] Signature and verification passed.\n";

    output.clear();

    if (executeRemote("cmp -s " + shellQuote(SECURITY_TEMP_SCRIPT) + " " + shellQuote(SECURITY_SCRIPT),
        output, exitCode, true))
    {
        cleanupTemp();

        std::cout << "[OK] Already up to date.\n";

        if (!serviceExists())
        {
            createSystemdService();
            reloadSystemd();
            enableService();
        }

        if (!serviceIsActive() && !startService())
        {
            return false;
        }

        registerTrustedClientIp();

        return true;
    }

    std::cout << "[3/7] Creating backup of current Security script...\n";

    if (!backupCurrentSecurityScript())
    {
        cleanupTemp();
        return false;
    }

    std::cout << "[4/7] Installing new Security script...\n";

    if (!installScriptFromTemp())
    {
        cleanupTemp();
        return false;
    }

    std::cout << "[5/7] Verifying installed Security script...\n";

    auto rollbackAndRestart = [&](const std::string& reason) -> bool
        {
            std::cout << "[ERROR] " << reason << "\nStarting rollback...\n";

            rollbackSecurityUpdate();

            std::string out;
            int code = -1;
            executeRemote("systemctl restart " + SECURITY_SERVICE, out, code, true, 60);

            if (waitServiceStable(5))
            {
                std::cout << "[OK] Previous version restored and service is running.\n";
            }
            else
            {
                std::cout << "[ERROR] Previous version restored, but the service is still not running.\n";
                printServiceDiagnostics();
            }

            cleanupTemp();
            setError(reason);

            return false;
        };

    if (!verifyScriptFile(SECURITY_SCRIPT, false))
    {
        return rollbackAndRestart("Installed Security script failed verification.");
    }

    std::cout << "[6/7] Restarting Security service...\n";

    if (!createSystemdService() || !reloadSystemd())
    {
        return rollbackAndRestart("Failed to refresh the systemd service.");
    }

    enableService();

    output.clear();

    if (!executeRemote("systemctl restart " + SECURITY_SERVICE, output, exitCode, true, 60))
    {
        printOutput(output);
        return rollbackAndRestart("Failed to restart the Security service.");
    }

    std::cout << "[7/7] Checking Security service stability...\n";

    if (!waitServiceStable(8))
    {
        return rollbackAndRestart("Security service is not stable after the update.");
    }

    cleanupTemp();
    registerTrustedClientIp();

    sshSecurity = true;

    std::cout << "\n========================================\n SECURITY UPDATE SUCCESSFUL\n========================================\n";

    std::cout << "Source:\n" << SECURITY_UPDATE_URL << "\n\n";
    std::cout << "Script:\n" << SECURITY_SCRIPT << "\n\n";
    std::cout << "Backup:\n" << SECURITY_BACKUP_SCRIPT << "\n\n";
    std::cout << "Service: ACTIVE\n";
    std::cout << "Protection: RUNNING\n";
    std::cout << "Runtime data: PRESERVED\n";
    std::cout << "========================================\n";

    return true;
}


bool Security::uninstallSecurity()
{
    std::cout
        << "\n========================================\n"
        << " ServerGuard Security Removal\n"
        << "========================================\n\n";

    if (!checkRootOrSudo())
    {
        std::cout << "[ERROR] Administrator privileges are required.\n";
        return false;
    }

    std::string output;
    int exitCode = -1;

    std::cout << "[1/6] Stopping Security service...\n";

    const std::string stopCommand =
        "if systemctl cat " + shellQuote(SECURITY_SERVICE) + " >/dev/null 2>&1; then "
        "systemctl stop " + shellQuote(SECURITY_SERVICE) + "; "
        "systemctl disable " + shellQuote(SECURITY_SERVICE) + "; "
        "systemctl reset-failed " + shellQuote(SECURITY_SERVICE) + " 2>/dev/null; "
        "fi; "
        "! systemctl is-active --quiet " + shellQuote(SECURITY_SERVICE);

    if (!executeRemote(stopCommand, output, exitCode, true, 60))
    {
        std::cout << "[ERROR] Failed to stop the Security service.\n";
        printOutput(output);
        setError("Failed to stop the Security service: " + trim(output));
        return false;
    }

    std::cout << "[OK] Service stopped and disabled, if it existed.\n";

    std::cout << "[2/6] Removing firewall blocks created by ServerGuard...\n";

    output.clear();

    if (executeRemote("test -s " + shellQuote(SECURITY_SCRIPT), output, exitCode, true))
    {
        output.clear();

        if (executeRemote("python3 " + shellQuote(SECURITY_SCRIPT) + " --cleanup", output, exitCode, true, 180))
        {
            printOutput(output);
            std::cout << "[OK] Blocks removed.\n";
        }
        else
        {
            printOutput(output);
            std::cout << "[WARN] Some blocked IPs could not be removed from the firewall.\n";
        }
    }

    std::cout << "[3/6] Removing systemd service...\n";

    output.clear();

    if (!executeRemote("rm -f " + shellQuote(SECURITY_SERVICE_PATH) + " && systemctl daemon-reload",
        output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to remove systemd service.\n";
        printOutput(output);
        return false;
    }

    std::cout << "[OK] Systemd service removed.\n";

    std::cout << "[4/6] Removing Security scripts...\n";

    output.clear();

    if (!executeRemote("rm -f " + shellQuote(SECURITY_SCRIPT) + " " + shellQuote(SECURITY_TEMP_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to remove Security scripts.\n";
        printOutput(output);
        return false;
    }

    std::cout << "[OK] Security scripts removed.\n";

    std::cout << "[5/6] Removing Security backups...\n";

    output.clear();

    if (!executeRemote("rm -rf -- " + shellQuote(SECURITY_BACKUP_DIR), output, exitCode, true))
    {
        std::cout << "[ERROR] Failed to remove Security backups.\n";
        printOutput(output);
        return false;
    }

    std::cout << "[OK] Security backups removed.\n";

    std::cout << "[6/6] Verifying removal...\n";

    output.clear();

    const std::string verifyCommand =
        "test ! -e " + shellQuote(SECURITY_SERVICE_PATH) +
        " && test ! -e " + shellQuote(SECURITY_SCRIPT) +
        " && test ! -e " + shellQuote(SECURITY_TEMP_SCRIPT) +
        " && test ! -e " + shellQuote(SECURITY_BACKUP_DIR);

    if (!executeRemote(verifyCommand, output, exitCode, true))
    {
        std::cout << "[ERROR] Removal verification failed.\n";
        printOutput(output);
        return false;
    }

    sshSecurity = false;

    std::cout
        << "\n========================================\n"
        << " SECURITY REMOVED SUCCESSFULLY\n"
        << "========================================\n"
        << "[OK] Security service: REMOVED\n"
        << "[OK] Security script: REMOVED\n"
        << "[OK] Security backups: REMOVED\n"
        << "[OK] ServerGuard IP blocks: REMOVED\n"
        << "[OK] Other ServerGuard modules: PRESERVED\n"
        << "[OK] Runtime data: PRESERVED\n"
        << "[OK] UFW firewall and its other rules: PRESERVED\n\n";

    return true;
}


void Security::menu()
{
    while (true)
    {
        std::cout << "\n========================================\n "
            << MODULE_NAME << " v" << MODULE_VERSION
            << "\n========================================\n\n";

        for (const ModuleCommand& item : MODULE_COMMANDS)
        {
            std::cout << item.key << ". " << item.title << "\n";
        }

        std::cout << "\nSelect: ";

        std::string choice;

        if (!std::getline(std::cin, choice))
        {
            break;
        }

        choice = trim(choice);

        if (choice == "1")
        {
            installSecurity();
            continue;
        }

        if (choice == "2" || choice == "3" || choice == "4")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            if (!serviceExists())
            {
                std::cout << "\n[ERROR] Security service is not installed.\n";
                std::cout << "Use option 1 first.\n";
                continue;
            }

            if (choice == "2")
            {
                registerTrustedClientIp();
                std::cout << (startService()
                    ? "\n[OK] Security protection started.\n"
                    : "\n[ERROR] Failed to start security protection.\n");
            }
            else if (choice == "3")
            {
                std::cout << (stopService()
                    ? "\n[OK] Security protection stopped.\n"
                    : "\n[ERROR] Failed to stop protection.\n");
            }
            else
            {
                std::cout << (disableService()
                    ? "\n[OK] Automatic startup disabled.\n"
                    : "\n[ERROR] Failed to disable automatic startup.\n");
            }

            continue;
        }

        if (choice == "5")
        {
            if (!checkRootOrSudo())
            {
                continue;
            }

            std::cout << "\n----------------------------------------\n ServerGuard Security Status\n----------------------------------------\n";

            if (serviceExists())
            {
                std::cout << "Service installed: YES\n";
                std::cout << "Protection status: " << (serviceIsActive() ? "ACTIVE" : "INACTIVE") << "\n";

                std::string serviceOutput;
                int serviceExitCode = -1;

                if (executeRemote("systemctl is-enabled " + SECURITY_SERVICE + " 2>/dev/null", serviceOutput, serviceExitCode, false))
                {
                    std::cout << "Startup: " << trim(serviceOutput) << "\n";
                }
                else
                {
                    std::cout << "Startup: disabled\n";
                }
            }
            else
            {
                sshSecurity = false;

                std::cout << "Service installed: NO\n";
                std::cout << "Protection status: NOT INSTALLED\n";
            }

            std::string scriptOutput;
            int scriptExitCode = -1;

            std::cout << "Security script: "
                << (executeRemote("test -s " + shellQuote(SECURITY_SCRIPT), scriptOutput, scriptExitCode, true)
                    ? "INSTALLED" : "MISSING")
                << "\n";

            if (commandExists("ufw"))
            {
                std::cout << "UFW installed: YES\n";

                std::string firewallOutput;
                int firewallExitCode = -1;

                if (executeRemote("ufw status verbose", firewallOutput, firewallExitCode, true))
                {
                    std::cout << "\nFirewall:\n" << firewallOutput << "\n";
                }
                else
                {
                    std::cout << "UFW status: ERROR\n";
                    printOutput(firewallOutput);
                }
            }
            else
            {
                std::cout << "UFW installed: NO\n";
            }

            std::cout << "----------------------------------------\n";

            continue;
        }

        if (choice == "6")
        {
            std::cout << "\n----------------------------------------\n ServerGuard Security Logs\n----------------------------------------\n";

            printOutput(webLogs());

            continue;
        }

        if (choice == "7")
        {
            std::cout << "\nUpdate Security from GitHub?\n\n"
                << "The current brute_force_guard.py will be backed up before replacement.\n"
                << "Runtime data in /opt/serverguard/data will NOT be changed.\n"
                << "The Security service will be restarted after the update.\n"
                << "If the new version does not run, the previous one is restored automatically.\n"
                << "The module is verified (Ed25519 + SHA-256) before it is uploaded.\n\n"
                << "Source:\n" << SECURITY_UPDATE_URL << "\n\n"
                << "Continue? [y/N]: ";

            std::string confirm;
            std::getline(std::cin, confirm);
            confirm = toLower(trim(confirm));

            if (confirm == "y" || confirm == "yes")
            {
                updateSecurity();
            }
            else
            {
                std::cout << "Update cancelled.\n";
            }

            continue;
        }

        if (choice == "8")
        {
            std::cout
                << "\nWARNING: This will remove ServerGuard Security "
                << "from the connected server.\n"
                << "IPs blocked by ServerGuard will be unblocked.\n"
                << "The UFW firewall and its other rules will remain unchanged.\n"
                << "Other ServerGuard modules and runtime data will be preserved.\n\n"
                << "Are you sure? [y/N]: ";

            std::string confirm;
            std::getline(std::cin, confirm);
            confirm = toLower(trim(confirm));

            if (confirm == "y" || confirm == "yes")
            {
                std::cout << (uninstallSecurity()
                    ? "\n[OK] Security uninstalled successfully.\n"
                    : "\n[ERROR] Security removal failed.\n");
            }
            else
            {
                std::cout << "Removal cancelled.\n";
            }

            continue;
        }

        if (choice == "0")
        {
            break;
        }

        std::cout << "\nUnknown option.\n";
    }
}


bool Security::webInstall()
{
    if (!installSecurity())
    {
        return false;
    }

    return serviceExists() && serviceIsActive();
}

bool Security::webStart()
{
    if (!checkPrivileges(false) || !serviceExists())
    {
        if (!serviceExists())
        {
            setError("Security service is not installed.");
        }

        return false;
    }

    registerTrustedClientIp();

    return startService() && serviceIsActive();
}

bool Security::webStop()
{
    if (!checkPrivileges(false))
    {
        return false;
    }

    if (!serviceExists())
    {
        setError("Security service is not installed.");
        return false;
    }

    return stopService() && !serviceIsActive();
}

bool Security::webDisable()
{
    if (!checkPrivileges(false))
    {
        return false;
    }

    if (!serviceExists())
    {
        setError("Security service is not installed.");
        return false;
    }

    return disableService();
}

bool Security::webUpdate()
{
    return updateSecurity();
}

bool Security::webUninstall()
{
    return uninstallSecurity();
}

long long Security::webThreats()
{
    std::string output;
    int exitCode = -1;

    const std::string command =
        "if [ -f " + shellQuote(SECURITY_STATS_FILE) + " ]; then "
        "python3 -c "
        + shellQuote("import json,sys;print(int(json.load(open(sys.argv[1])).get('blocked',0)))") +
        " " + shellQuote(SECURITY_STATS_FILE) + " 2>/dev/null || echo 0; "
        "else echo 0; fi";

    if (!executeRemote(command, output, exitCode, true, 30))
    {
        return 0;
    }

    const std::string value = trim(output);

    if (!isDigits(value) || value.size() > 18)
    {
        return 0;
    }

    try
    {
        return std::stoll(value);
    }
    catch (...)
    {
        return 0;
    }
}

std::string Security::webStatus()
{
    const bool installed = serviceExists();

    bool active = false;
    bool enabled = false;

    if (installed)
    {
        active = serviceIsActive();

        std::string output;
        int exitCode = -1;

        enabled = executeRemote("systemctl is-enabled " + SECURITY_SERVICE + " >/dev/null 2>&1", output, exitCode, false);
    }

    bool script = false;

    {
        std::string output;
        int exitCode = -1;

        script = executeRemote("test -s " + shellQuote(SECURITY_SCRIPT), output, exitCode, true);
    }

    const bool ufwInstalled = commandExists("ufw");
    const bool ufwActive = ufwInstalled && ufwIsActive();

    const bool iptablesInstalled = commandExists("iptables");

    const std::string backend =
        ufwActive ? "ufw" : (iptablesInstalled ? "iptables" : "none");

    const std::vector<std::string> sshPorts = detectSshPorts();

    const bool sudoOk = sudoAuthenticated;

    std::ostringstream json;

    json << "{"
        << "\"installed\":" << (installed ? "true" : "false")
        << ",\"active\":" << (active ? "true" : "false")
        << ",\"enabled\":" << (enabled ? "true" : "false")
        << ",\"script\":" << (script ? "true" : "false")
        << ",\"ufwInstalled\":" << (ufwInstalled ? "true" : "false")
        << ",\"ufwActive\":" << (ufwActive ? "true" : "false")
        << ",\"backend\":\"" << backend << "\""
        << ",\"sudoOk\":" << (sudoOk ? "true" : "false")
        << ",\"lastError\":\"" << securityJsonEscape(getLastError()) << "\""
        << ",\"service\":\"" << securityJsonEscape(SECURITY_SERVICE) << "\""
        << ",\"scriptPath\":\"" << securityJsonEscape(SECURITY_SCRIPT) << "\""
        << ",\"sshPorts\":[";

    for (size_t i = 0; i < sshPorts.size(); ++i)
    {
        if (i > 0)
        {
            json << ",";
        }

        json << "\"" << securityJsonEscape(sshPorts[i]) << "\"";
    }

    json << "]}";

    return json.str();
}

std::string Security::webLogs()
{
    if (!serviceExists())
    {
        return "Security service is not installed.";
    }

    std::string output;
    int exitCode = -1;

    const bool result = executeRemote(
        "journalctl -u " + SECURITY_SERVICE + " -n 100 --no-pager", output, exitCode, true, 60);

    if (!result && output.empty())
    {
        return "Failed to get Security logs: " + getLastError();
    }

    return output;
}