#include "SSHHardening.h"
#include "config.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

static const std::string SERVERGUARD_DIR = "/opt/serverguard";
static const std::string HARDENING_SCRIPT = ServerGuardConfig::SSH_HARDENING_SCRIPT_PATH;
static const std::string SSH_CONFIG = "/etc/ssh/sshd_config";
static const std::string BACKUP_DIR = "/opt/serverguard/backups";
static const std::string HARDENING_CONFIG = "/etc/ssh/sshd_config.d/99-serverguard-hardening.conf";
static const std::string HARDENING_UPDATE_URL = ServerGuardConfig::SSH_HARDENING_SCRIPT_URL;
static const std::string HARDENING_TEMP_SCRIPT = ServerGuardConfig::SSH_HARDENING_TEMP_SCRIPT_PATH;
static const std::string HARDENING_TEMP_MANIFEST = ServerGuardConfig::SSH_HARDENING_TEMP_MANIFEST_PATH;
static const std::string HARDENING_TEMP_SIGNATURE = ServerGuardConfig::SSH_HARDENING_TEMP_SIGNATURE_PATH;
static const std::string HARDENING_PUBLIC_KEY = ServerGuardConfig::SSH_HARDENING_PUBLIC_KEY_PATH;
static const std::string HARDENING_BACKUP_DIR = "/opt/serverguard/backups/ssh-hardening";
static const std::string HARDENING_BACKUP_SCRIPT = "/opt/serverguard/backups/ssh-hardening/ssh_hardening.py";
static const std::string HARDENING_CONFIG_BACKUP = "/opt/serverguard/backups/ssh-hardening/99-serverguard-hardening.conf";

static const std::string LINE = "============================================\n";

static const std::chrono::seconds COMMAND_TIMEOUT(600);
static const size_t MAX_OUTPUT_BYTES = 4u * 1024u * 1024u;

// ---------------------------------------------------------------- helpers

static std::string shellQuote(const std::string& value)
{
    std::string result = "'";
    for (char c : value)
    {
        if (c == '\'') result += "'\\''";
        else result += c;
    }
    return result + "'";
}

static void banner(const std::string& title)
{
    std::cout << "\n" << LINE << "  " << title << "\n" << LINE << "\n";
}

static void printIfNotEmpty(const std::string& text)
{
    if (!text.empty()) std::cout << text << "\n";
}

// chown root:root + chmod <mode>
static std::string chownChmod(const std::string& path, const std::string& mode)
{
    return "chown root:root " + shellQuote(path) +
        " && chmod " + mode + " " + shellQuote(path);
}

static std::string sshdValue(const std::string& output, const std::string& name)
{
    std::istringstream stream(output);
    std::string line;

    while (std::getline(stream, line))
    {
        std::istringstream lineStream(line);
        std::string key, value;
        lineStream >> key >> value;

        std::transform(key.begin(), key.end(), key.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (key == name) return value;
    }

    return "unknown";
}

static std::string jsonEscape(const std::string& text)
{
    std::string out;

    for (char c : text)
    {
        switch (c)
        {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20)
            {
                // Remaining control characters (ESC from colored ls, etc.)
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x",
                    static_cast<unsigned>(static_cast<unsigned char>(c)));
                out += buf;
            }
            else
            {
                out += c;
            }
            break;
        }
    }

    return out;
}

static std::string sessionError(LIBSSH2_SESSION* session, int& code)
{
    char* message = nullptr;
    int length = 0;
    code = libssh2_session_last_error(session, &message, &length, 0);

    return (message && length > 0)
        ? std::string(message, static_cast<size_t>(length))
        : std::string();
}

static void pauseBriefly()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
}

// Runs one command on a fresh channel, optionally feeding `input` to its stdin.
// Returns true if the command was executed (check exitCode for its result).
// Works in both blocking and non-blocking libssh2 modes and has a timeout.
static bool runCommand(
    LIBSSH2_SESSION* session,
    const std::string& command,
    const std::string& input,
    std::string& output,
    int& exitCode)
{
    output.clear();
    exitCode = -1;

    const auto deadline = std::chrono::steady_clock::now() + COMMAND_TIMEOUT;
    const auto expired = [&]() { return std::chrono::steady_clock::now() > deadline; };

    LIBSSH2_CHANNEL* channel = nullptr;

    while (!(channel = libssh2_channel_open_session(session)))
    {
        int code = 0;
        const std::string message = sessionError(session, code);

        if (code == LIBSSH2_ERROR_EAGAIN && !expired())
        {
            pauseBriefly();
            continue;
        }

        output = "Cannot open SSH channel.";
        if (!message.empty()) output += "\nlibssh2 error: " + message;
        output += "\nlibssh2 error code: " + std::to_string(code);
        return false;
    }

    const auto fail = [&](const std::string& text)
        {
            output = text;
            libssh2_channel_free(channel);
            return false;
        };

    libssh2_channel_handle_extended_data2(
        channel, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);

    int rc;

    while ((rc = libssh2_channel_exec(channel, command.c_str()))
        == LIBSSH2_ERROR_EAGAIN)
    {
        if (expired()) return fail("Timed out while starting remote command.");
        pauseBriefly();
    }

    if (rc != 0)
    {
        int code = 0;
        const std::string message = sessionError(session, code);

        std::string text = "Cannot execute remote command.";
        text += "\nlibssh2 channel_exec error code: " + std::to_string(rc);
        text += "\nlibssh2 session error code: " + std::to_string(code);
        if (!message.empty()) text += "\nlibssh2 error: " + message;
        text += "\nCommand: " + command;
        return fail(text);
    }

    // stdin (used for the sudo password; never placed on the command line)
    size_t sent = 0;

    while (sent < input.size())
    {
        const auto n = libssh2_channel_write(
            channel, input.data() + sent, input.size() - sent);

        if (n == LIBSSH2_ERROR_EAGAIN)
        {
            if (expired()) return fail("Timed out while writing to remote stdin.");
            pauseBriefly();
            continue;
        }

        if (n < 0) return fail("Cannot write to remote stdin.");

        sent += static_cast<size_t>(n);
    }

    // Always close stdin so commands that read it can never hang.
    while ((rc = libssh2_channel_send_eof(channel)) == LIBSSH2_ERROR_EAGAIN)
    {
        if (expired()) return fail("Timed out while closing remote stdin.");
        pauseBriefly();
    }

    // stdout + stderr (merged)
    char buffer[4096];
    bool timedOut = false;

    while (true)
    {
        const auto n = libssh2_channel_read(channel, buffer, sizeof(buffer));

        if (n > 0)
        {
            if (output.size() < MAX_OUTPUT_BYTES)
                output.append(buffer, static_cast<size_t>(n));
            continue;
        }

        if (n == LIBSSH2_ERROR_EAGAIN ||
            (n == 0 && !libssh2_channel_eof(channel)))
        {
            if (expired())
            {
                timedOut = true;
                break;
            }
            pauseBriefly();
            continue;
        }

        break;
    }

    if (timedOut)
    {
        output += "\nCommand timed out.";
        libssh2_channel_free(channel);
        return false;
    }

    while (libssh2_channel_wait_eof(channel) == LIBSSH2_ERROR_EAGAIN)
        pauseBriefly();

    while (libssh2_channel_wait_closed(channel) == LIBSSH2_ERROR_EAGAIN)
        pauseBriefly();

    exitCode = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);

    return true;
}

// ------------------------------------------------- effective sshd settings

struct SshdCheck
{
    const char* label;
    const char* key;
    const char* expected;
};

// What ServerGuard hardening must produce in `sshd -T`.
static const std::vector<SshdCheck> HARDENING_CHECKS = {
    { "PasswordAuthentication", "passwordauthentication", "no" },
    { "PubkeyAuthentication",   "pubkeyauthentication",   "yes" },
    { "PermitEmptyPasswords",   "permitemptypasswords",   "no" },
    { "MaxAuthTries",           "maxauthtries",           "3" },
    { "LoginGraceTime",         "logingracetime",         "30" },
    { "X11Forwarding",          "x11forwarding",          "no" },
    { "AllowAgentForwarding",   "allowagentforwarding",   "no" },
    { "Compression",            "compression",            "no" }
};

// Informational only (not part of the pass/fail verdict).
static const std::vector<std::pair<std::string, std::string>> SHOWN_OPTIONS = {
    { "PermitRootLogin", "permitrootlogin" },
    { "PasswordAuthentication", "passwordauthentication" },
    { "KbdInteractiveAuthentication", "kbdinteractiveauthentication" },
    { "PubkeyAuthentication", "pubkeyauthentication" },
    { "PermitEmptyPasswords", "permitemptypasswords" },
    { "MaxAuthTries", "maxauthtries" },
    { "LoginGraceTime", "logingracetime" },
    { "X11Forwarding", "x11forwarding" },
    { "AllowTcpForwarding", "allowtcpforwarding" },
    { "AllowAgentForwarding", "allowagentforwarding" },
    { "Compression", "compression" }
};

static bool evaluateHardening(const std::string& sshdOutput, bool print)
{
    bool allGood = true;

    if (print) std::cout << "\nVerification:\n";

    for (const auto& c : HARDENING_CHECKS)
    {
        const std::string actual = sshdValue(sshdOutput, c.key);
        const bool ok = (actual == c.expected);

        if (!ok) allGood = false;

        if (print)
        {
            if (ok)
                std::cout << "[OK] " << c.label << " = " << actual << "\n";
            else
                std::cout << "[FAIL] " << c.label << " = " << actual
                << " (expected " << c.expected << ")\n";
        }
    }

    return allGood;
}

// ------------------------------------------------------------ constructor

SSHHardening::SSHHardening(
    LIBSSH2_SESSION* sshSession,
    const std::string& password,
    bool isKeyAuthentication)
    : session(sshSession),
    sudoPassword(password),
    keyAuthentication(isKeyAuthentication),
    sudoRequired(false),
    sudoAuthenticated(false),
    hardeningEnabled(false),
    privilegesChecked(false),
    privilegesOk(false)
{}

// ------------------------------------------------------- remote execution

bool SSHHardening::executeRemote(
    const std::string& command,
    std::string& output,
    int& exitCode,
    bool useSudo)
{
    output.clear();
    exitCode = -1;

    if (!session)
    {
        output = "SSH session is invalid.";
        return false;
    }

    std::string finalCommand = command;
    std::string input;

    if (useSudo)
    {
        // Privileges are resolved lazily, so every entry point (including
        // webStatus / webBackups) behaves correctly for non-root users.
        if (!privilegesChecked && !checkRootOrSudo())
        {
            output = "Cannot obtain root privileges.";
            return false;
        }

        if (!privilegesOk)
        {
            output = "Cannot obtain root privileges.";
            return false;
        }

        if (sudoRequired)
        {
            // sudo timestamps are per tty/session, so a password cached by an
            // earlier channel is NOT visible to this one. Feed the password
            // through stdin every time instead of relying on `sudo -n`.
            finalCommand = "sudo -S -p '' bash -c " + shellQuote(command);
            input = sudoPassword + "\n";
        }
        else
        {
            finalCommand = "bash -c " + shellQuote(command);
        }
    }

    if (!runCommand(session, finalCommand, input, output, exitCode))
        return false;

    return exitCode == 0;
}

bool SSHHardening::authenticateSudo()
{
    if (!session) return false;

    if (!sudoRequired)
    {
        sudoAuthenticated = true;
        return true;
    }

    if (sudoPassword.empty())
    {
        std::cout << "Sudo password is empty.\n";
        return false;
    }

    std::cout << "Authenticating sudo...\n";

    std::string output;
    int exitCode = -1;

    // -k ignores any cached credentials so the password is really verified.
    const bool ran = runCommand(
        session, "sudo -S -p '' -k true", sudoPassword + "\n",
        output, exitCode);

    sudoAuthenticated = ran && exitCode == 0;

    if (sudoAuthenticated)
    {
        std::cout << "Sudo authentication successful.\n";
        return true;
    }

    std::cout << "Sudo authentication failed.\n";
    printIfNotEmpty(output);
    return false;
}

// ------------------------------------------------------------- pre-checks

bool SSHHardening::commandExists(const std::string& command)
{
    std::string output;
    int exitCode = -1;

    executeRemote(
        "command -v " + shellQuote(command) + " >/dev/null 2>&1",
        output, exitCode, false);

    return exitCode == 0;
}

bool SSHHardening::ensureTool(const std::string& tool, const std::string& package)
{
    if (commandExists(tool)) return true;

    std::cout << "Installing " << package << "...\n";

    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "apt-get update -qq || true; "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y " + shellQuote(package),
        output, exitCode, true))
    {
        std::cout << "Cannot install " << package << ".\n";
        printIfNotEmpty(output);
        return false;
    }

    return commandExists(tool);
}

void SSHHardening::removeTempFiles()
{
    std::string output;
    int exitCode = -1;

    executeRemote(
        "rm -f " + shellQuote(HARDENING_TEMP_SCRIPT) + " " +
        shellQuote(HARDENING_TEMP_MANIFEST) + " " +
        shellQuote(HARDENING_TEMP_SIGNATURE),
        output, exitCode, true);
}

bool SSHHardening::checkRootOrSudo()
{
    if (privilegesChecked) return privilegesOk;

    privilegesChecked = true;
    privilegesOk = false;

    std::string output;
    int exitCode = -1;

    if (!executeRemote("id -u", output, exitCode, false))
    {
        std::cout << "Cannot determine remote user.\n";
        return false;
    }

    output.erase(std::remove_if(output.begin(), output.end(),
        [](unsigned char c) { return std::isspace(c); }), output.end());

    if (output == "0")
    {
        sudoRequired = false;
        sudoAuthenticated = true;
        privilegesOk = true;
        return true;
    }

    if (!commandExists("sudo"))
    {
        std::cout << "sudo is not installed.\n";
        return false;
    }

    sudoRequired = true;

    if (!authenticateSudo())
    {
        std::cout << "Current user cannot use sudo.\n";
        return false;
    }

    privilegesOk = true;
    return true;
}

bool SSHHardening::checkScript()
{
    std::string output;
    int exitCode = -1;

    executeRemote(
        "test -f " + shellQuote(HARDENING_SCRIPT),
        output, exitCode, false);

    return exitCode == 0;
}

bool SSHHardening::setPermissions()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote(chownChmod(HARDENING_SCRIPT, "700"), output, exitCode, true))
    {
        std::cout << "Cannot configure script permissions.\n";
        printIfNotEmpty(output);
        return false;
    }

    return true;
}

// -------------------------------------------------------------- hardening

bool SSHHardening::runHardening()
{
    banner("APPLYING SSH HARDENING");

    std::string output;
    int exitCode = -1;

    const std::string authMethod =
        keyAuthentication ? "publickey" : "password";

    std::cout << "Authentication: "
        << (keyAuthentication ? "SSH private key" : "password") << "\n";

    const std::string command =
        "python3 " + shellQuote(HARDENING_SCRIPT) +
        " apply --auth-method=" + authMethod;

    std::cout << "Running SSH hardening pre-flight checks...\n";

    const bool result = executeRemote(command, output, exitCode, true);
    printIfNotEmpty(output);

    if (!result)
    {
        std::cout << "\nSSH hardening failed.\nPython exit code: "
            << exitCode << "\n";
        hardeningEnabled = false;
        return false;
    }

    if (!checkHardening())
    {
        std::cout << "\nSSH hardening was not verified.\n";
        hardeningEnabled = false;
        return false;
    }

    hardeningEnabled = true;
    std::cout << "\nSSH hardening completed successfully.\n";
    return true;
}

bool SSHHardening::checkHardening()
{
    banner("SSH HARDENING STATUS");

    std::string output;
    int exitCode = -1;

    if (!executeRemote("sshd -T 2>/dev/null", output, exitCode, true))
    {
        std::cout << "Cannot read effective SSH configuration.\n";
        hardeningEnabled = false;
        return false;
    }

    for (const auto& [label, key] : SHOWN_OPTIONS)
        std::cout << label << ": " << sshdValue(output, key) << "\n";

    bool allGood = evaluateHardening(output, true);

    if (checkSSHService())
        std::cout << "\nSSH service: ACTIVE\n";
    else
    {
        std::cout << "\nSSH service: NOT ACTIVE\n";
        allGood = false;
    }

    std::cout << "\n" << LINE << "ServerGuard hardening: "
        << (allGood ? "ENABLED" : "NOT ENABLED") << "\n" << LINE;

    hardeningEnabled = allGood;
    return allGood;
}

bool SSHHardening::checkSSHService()
{
    std::string output;
    int exitCode = -1;

    // Ubuntu may use ssh.service, sshd.service or socket activation.
    static const char* units[] = { "ssh", "sshd", "ssh.socket" };

    for (const char* unit : units)
    {
        executeRemote(
            std::string("systemctl is-active --quiet ") + unit,
            output, exitCode, false);

        if (exitCode == 0) return true;
    }

    return false;
}

bool SSHHardening::isSSHConfigValid(bool verbose)
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("sshd -t", output, exitCode, true))
    {
        if (verbose) printIfNotEmpty(output);
        return false;
    }

    return true;
}

// ---------------------------------------------------------------- backups

bool SSHHardening::showBackups()
{
    std::string output;
    int exitCode = -1;

    // A missing directory simply means "no backups yet", not an error.
    if (!executeRemote(
        "if [ -d " + shellQuote(BACKUP_DIR) + " ]; then ls -lah " +
        shellQuote(BACKUP_DIR) + "; fi",
        output, exitCode, true))
    {
        std::cout << "Cannot read backup directory.\n";
        return false;
    }

    banner("SSH BACKUPS");

    if (output.empty())
    {
        std::cout << "No backups found.\n";
        return false;
    }

    std::cout << output << "\n";
    return true;
}

bool SSHHardening::restoreConfiguration()
{
    std::cout << "\n";
    if (!showBackups()) return false;

    std::cout << "\nEnter backup filename (empty to cancel): ";

    std::string filename;
    std::getline(std::cin >> std::ws, filename);

    while (!filename.empty() &&
        std::isspace(static_cast<unsigned char>(filename.back())))
        filename.pop_back();

    if (filename.empty()) return false;

    // Strict whitelist instead of a blacklist of bad characters.
    const bool validChars = std::all_of(filename.begin(), filename.end(),
        [](unsigned char c)
        {
            return std::isalnum(c) || c == '.' || c == '_' || c == '-';
        });

    if (!validChars || filename.find("..") != std::string::npos)
    {
        std::cout << "Invalid backup filename.\n";
        return false;
    }

    const std::string prefix = "pre-hardening_";
    const std::string suffix = ".tar.gz";

    if (filename.size() <= prefix.size() + suffix.size() ||
        filename.compare(0, prefix.size(), prefix) != 0 ||
        filename.compare(filename.size() - suffix.size(),
            suffix.size(), suffix) != 0)
    {
        std::cout << "Unsupported backup type. Expected: pre-hardening_*.tar.gz\n";
        return false;
    }

    if (!checkRootOrSudo()) return false;

    if (!checkScript())
    {
        std::cout << "SSH Hardening script was not found:\n"
            << HARDENING_SCRIPT << "\n";
        return false;
    }

    const std::string backupPath = BACKUP_DIR + "/" + filename;
    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "test -f " + shellQuote(backupPath) +
        " && test -f " + shellQuote(backupPath + ".json"),
        output, exitCode, true))
    {
        std::cout << "Backup file (or its .json manifest) not found.\n";
        return false;
    }

    std::cout << "\nRestoring configuration...\n";

    const bool ok = executeRemote(
        "python3 " + shellQuote(HARDENING_SCRIPT) +
        " restore " + shellQuote(filename),
        output, exitCode, true);

    if (!output.empty()) std::cout << "\n" << output << "\n";

    if (!ok)
    {
        std::cout << "\nCannot restore configuration.\nPython exit code: "
            << exitCode << "\n";
        return false;
    }

    std::cout << "\nSSH configuration restored successfully.\n";
    checkHardening();
    return true;
}

// ---------------------------------------------------------- update helpers

bool SSHHardening::downloadUpdate()
{
    std::cout << "\n[1/6] Downloading script, manifest and signature...\n";

    std::string output;
    int exitCode = -1;

    removeTempFiles();

    const std::string curl =
        "curl -fLsS --proto '=https' --tlsv1.2 "
        "--connect-timeout 15 --max-time 120 --retry 2 -o ";

    const std::string command =
        "set -eu; umask 077; " +
        curl + shellQuote(HARDENING_TEMP_SCRIPT) + " " +
        shellQuote(ServerGuardConfig::SSH_HARDENING_SCRIPT_URL) + "; " +
        curl + shellQuote(HARDENING_TEMP_MANIFEST) + " " +
        shellQuote(ServerGuardConfig::SSH_HARDENING_MANIFEST_URL) + "; " +
        curl + shellQuote(HARDENING_TEMP_SIGNATURE) + " " +
        shellQuote(ServerGuardConfig::SSH_HARDENING_SIGNATURE_URL) + "; "
        "test -s " + shellQuote(HARDENING_TEMP_SCRIPT) + "; "
        "test -s " + shellQuote(HARDENING_TEMP_MANIFEST) + "; "
        "test -s " + shellQuote(HARDENING_TEMP_SIGNATURE);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Download failed. No update will be installed.\n";
        printIfNotEmpty(output);
        removeTempFiles();
        return false;
    }

    std::cout << "All update files downloaded.\n";
    return true;
}

bool SSHHardening::verifyUpdate()
{
    std::cout << "[2/6] Verifying Ed25519 signature and SHA-256...\n";

    std::string output;
    int exitCode = -1;

    const std::string publicKeyPem =
        ServerGuardConfig::SSH_HARDENING_PUBLIC_KEY_PEM;

    if (publicKeyPem.find("-----BEGIN PUBLIC KEY-----") == std::string::npos ||
        publicKeyPem.find("-----END PUBLIC KEY-----") == std::string::npos ||
        publicKeyPem.size() < 80)
    {
        std::cout << "Trusted public key is missing or invalid in config.h.\n";
        return false;
    }

    // The trusted public key is compiled into ServerGuard; it is never
    // downloaded from GitHub.
    const std::string writeKey =
        "umask 077; printf '%s' " + shellQuote(publicKeyPem) +
        " > " + shellQuote(HARDENING_PUBLIC_KEY) +
        " && " + chownChmod(HARDENING_PUBLIC_KEY, "600");

    if (!executeRemote(writeKey, output, exitCode, true))
    {
        std::cout << "Cannot write trusted public key.\n";
        printIfNotEmpty(output);
        return false;
    }

    // The exact manifest bytes are signed.
    const std::string verifySignature =
        "openssl pkeyutl -verify -rawin -pubin -inkey " +
        shellQuote(HARDENING_PUBLIC_KEY) +
        " -in " + shellQuote(HARDENING_TEMP_MANIFEST) +
        " -sigfile " + shellQuote(HARDENING_TEMP_SIGNATURE);

    if (!executeRemote(verifySignature, output, exitCode, true))
    {
        std::cout << "Ed25519 signature verification FAILED.\n";
        printIfNotEmpty(output);
        return false;
    }

    std::cout << "Ed25519 signature: VALID\n";

    // Expected manifest:
    // {"format":"ServerGuardModuleManifest","version":1,"algorithm":"Ed25519",
    //  "files":[{"path":"ssh_hardening.py","sha256":"<64 hex>"}]}
    const std::string pythonCommand =
        "import hashlib,json,sys,re,ast;"
        "m=json.load(open(sys.argv[1],encoding='utf-8'));"
        "assert m.get('format')=='ServerGuardModuleManifest','Invalid manifest format';"
        "assert m.get('version')==1,'Unsupported manifest version';"
        "assert m.get('algorithm')=='Ed25519','Unexpected signature algorithm';"
        "files=m.get('files');"
        "assert isinstance(files,list) and len(files)==1,'Unexpected manifest files';"
        "f=files[0];"
        "assert f.get('path')=='ssh_hardening.py','Unexpected module path';"
        "expected=f.get('sha256','');"
        "assert isinstance(expected,str) and re.fullmatch(r'[0-9a-fA-F]{64}',expected),'Invalid SHA-256';"
        "data=open(sys.argv[2],'rb').read();"
        "actual=hashlib.sha256(data).hexdigest();"
        "assert actual.lower()==expected.lower(),'SHA-256 mismatch';"
        "ast.parse(data.decode('utf-8'),filename='ssh_hardening.py');"
        "print('Manifest: VALID');"
        "print('SHA-256: MATCH');"
        "print('Python syntax: OK')";

    const std::string verifyContent =
        "python3 -c " + shellQuote(pythonCommand) + " " +
        shellQuote(HARDENING_TEMP_MANIFEST) + " " +
        shellQuote(HARDENING_TEMP_SCRIPT);

    if (!executeRemote(verifyContent, output, exitCode, true))
    {
        std::cout << "Manifest, SHA-256 or Python syntax verification FAILED.\n";
        printIfNotEmpty(output);
        return false;
    }

    printIfNotEmpty(output);

    std::cout << "Checking current SSH configuration...\n";

    if (!isSSHConfigValid())
    {
        std::cout << "Current SSH configuration is invalid. Update cancelled.\n";
        return false;
    }

    std::cout << "Update verification completed.\n";
    return true;
}

bool SSHHardening::backupCurrentScript()
{
    std::cout << "[3/6] Creating backup of current SSH Hardening script...\n";

    std::string output;
    int exitCode = -1;

    if (!checkScript())
    {
        std::cout << "Current SSH Hardening script not found.\n";
        return false;
    }

    if (!executeRemote(
        "mkdir -p -m 700 " + shellQuote(HARDENING_BACKUP_DIR),
        output, exitCode, true))
    {
        std::cout << "Cannot create backup directory.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (!executeRemote(
        "cp -p " + shellQuote(HARDENING_SCRIPT) + " " +
        shellQuote(HARDENING_BACKUP_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Cannot create backup.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (!executeRemote(chownChmod(HARDENING_BACKUP_SCRIPT, "600"),
        output, exitCode, true))
    {
        std::cout << "Cannot secure backup file.\n";
        printIfNotEmpty(output);
        return false;
    }

    std::cout << "Backup created:\n" << HARDENING_BACKUP_SCRIPT << "\n";
    return true;
}

bool SSHHardening::installUpdatedScript()
{
    std::cout << "[4/6] Installing verified SSH Hardening script...\n";

    std::string output;
    int exitCode = -1;

    // Fix owner/mode on the temp file first, then atomically move it into
    // place (same filesystem), so the script is never briefly world-writable.
    if (!executeRemote(chownChmod(HARDENING_TEMP_SCRIPT, "700"),
        output, exitCode, true))
    {
        std::cout << "Cannot configure updated script permissions.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (!executeRemote(
        "mv -f " + shellQuote(HARDENING_TEMP_SCRIPT) + " " +
        shellQuote(HARDENING_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Cannot replace SSH Hardening script.\n";
        printIfNotEmpty(output);
        return false;
    }

    return true;
}

bool SSHHardening::rollbackUpdate()
{
    std::cout << "\n" << LINE
        << "       ROLLING BACK SSH HARDENING\n" << LINE;

    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "test -f " + shellQuote(HARDENING_BACKUP_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Backup file not found.\n";
        return false;
    }

    if (!executeRemote(
        "cp -p " + shellQuote(HARDENING_BACKUP_SCRIPT) + " " +
        shellQuote(HARDENING_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Cannot restore previous script.\n";
        printIfNotEmpty(output);
        return false;
    }

    executeRemote(chownChmod(HARDENING_SCRIPT, "700"), output, exitCode, true);

    removeTempFiles();

    if (!isSSHConfigValid())
    {
        std::cout << "Previous script restored, but SSH configuration is still invalid.\n";
        return false;
    }

    std::cout << "\nRollback successful.\nPrevious SSH Hardening script restored.\n";
    return true;
}

bool SSHHardening::update()
{
    banner("UPDATE SSH HARDENING");

    std::string output;
    int exitCode = -1;

    if (!checkRootOrSudo()) return false;

    if (!checkScript())
    {
        std::cout << "SSH Hardening script is not installed:\n"
            << HARDENING_SCRIPT << "\n";
        return false;
    }

    if (!commandExists("python3"))
    {
        std::cout << "python3 is not installed.\n";
        return false;
    }

    if (!ensureTool("curl", "curl")) return false;

    if (!ensureTool("openssl", "openssl"))
    {
        std::cout << "Update aborted.\n";
        return false;
    }

    if (!downloadUpdate())
    {
        removeTempFiles();
        return false;
    }

    if (!verifyUpdate())
    {
        std::cout << "\nUpdate cancelled.\nCurrent SSH Hardening script was not changed.\n";
        removeTempFiles();
        return false;
    }

    if (!backupCurrentScript())
    {
        removeTempFiles();
        return false;
    }

    if (!installUpdatedScript())
    {
        std::cout << "\nNew SSH Hardening script was not installed.\n";
        rollbackUpdate();
        removeTempFiles();
        return false;
    }

    std::cout << "[5/6] Verifying installed SSH Hardening script...\n";

    const std::string pythonCommand =
        "import ast,sys;"
        "p=open(sys.argv[1],encoding='utf-8').read();"
        "ast.parse(p,filename='ssh_hardening.py');"
        "print('Installed script: OK')";

    // Script is root-only (700), so it must be read with privileges.
    if (!executeRemote(
        "python3 -c " + shellQuote(pythonCommand) + " " +
        shellQuote(HARDENING_SCRIPT),
        output, exitCode, true))
    {
        std::cout << "Installed script verification failed.\n";
        printIfNotEmpty(output);
        rollbackUpdate();
        return false;
    }

    printIfNotEmpty(output);
    std::cout << "[6/6] Final SSH configuration validation...\n";

    if (!isSSHConfigValid())
    {
        std::cout << "\nSSH configuration validation failed.\nStarting automatic rollback...\n";

        if (!rollbackUpdate())
            std::cout << "WARNING: rollback also failed. Check SSH configuration manually.\n";

        return false;
    }

    removeTempFiles();

    std::cout << "\n" << LINE
        << "   SSH HARDENING UPDATE SUCCESSFUL\n" << LINE
        << "Source:\n" << HARDENING_UPDATE_URL << "\n\n"
        << "Script:\n" << HARDENING_SCRIPT << "\n\n"
        << "Backup:\n" << HARDENING_BACKUP_SCRIPT << "\n\n"
        << "Signature: VERIFIED\n"
        << "SHA-256: VERIFIED\n"
        << "SSH configuration: VALID\n" << LINE;

    return true;
}

// ------------------------------------------------------------------- menu

void SSHHardening::menu()
{
    while (true)
    {
        std::cout << "\n" << LINE << "             SSH HARDENING\n" << LINE
            << "\n"
            << "1. Apply hardening\n"
            << "2. Check hardening status\n"
            << "3. Disable hardening\n"
            << "4. Show SSH configuration\n"
            << "5. Restore backup\n"
            << "6. Install / update hardening script\n"
            << "7. Remove hardening (config + script)\n"
            << "0. Back\n"
            << "\nSelect: ";

        std::string choice;
        if (!std::getline(std::cin, choice)) return; // EOF: don't loop forever

        if (choice == "0") return;

        if (choice == "1")
        {
            if (!webApply()) std::cout << "\nSSH hardening was not applied.\n\n";
            continue;
        }

        if (choice == "2")
        {
            if (checkRootOrSudo()) checkHardening();
            continue;
        }

        if (choice == "3")
        {
            if (!checkRootOrSudo()) continue;

            if (!checkScript())
            {
                std::cout << "\nSSH hardening script was not found:\n"
                    << HARDENING_SCRIPT << "\n\n";
                continue;
            }

            std::cout << "\nDisabling SSH hardening...\n";

            std::string output;
            int exitCode = -1;

            if (!executeRemote(
                "python3 " + shellQuote(HARDENING_SCRIPT) + " disable",
                output, exitCode, true))
            {
                std::cout << "\nSSH hardening disable failed. Python exit code: "
                    << exitCode << "\n";
                printIfNotEmpty(output);
                continue;
            }

            printIfNotEmpty(output);

            hardeningEnabled = false;
            std::cout << "\nSSH hardening disabled successfully.\n";
            continue;
        }

        if (choice == "4")
        {
            if (!checkRootOrSudo()) continue;

            std::string output;
            int exitCode = -1;

            if (!executeRemote("sshd -T 2>/dev/null", output, exitCode, true))
            {
                std::cout << "\nCannot read SSH configuration.\n";
                printIfNotEmpty(output);
                continue;
            }

            banner("EFFECTIVE SSH CONFIGURATION");

            for (const auto& [label, key] : SHOWN_OPTIONS)
                std::cout << label << ": " << sshdValue(output, key) << "\n";

            std::cout << "\n";
            continue;
        }

        if (choice == "5")
        {
            restoreConfiguration();
            continue;
        }

        if (choice == "6")
        {
            if (!checkRootOrSudo()) continue;

            if (!checkScript())
            {
                std::cout << "\nSSH hardening script is not installed. Installing...\n";

                if (!webInstall())
                    std::cout << "\nInstallation failed. Nothing was changed.\n";

                continue;
            }

            std::cout << "\nSSH hardening script is installed. Checking for a signed update...\n";

            if (!webUpdate())
                std::cout << "\nUpdate failed. The current script was kept.\n";

            continue;
        }

        if (choice == "7")
        {
            std::cout << "\nThis will remove the ServerGuard SSH hardening config\n"
                << HARDENING_CONFIG << "\n"
                << "and the script " << HARDENING_SCRIPT << ".\n"
                << "SSH settings will return to the server defaults.\n"
                << "A backup of the config is kept in:\n"
                << HARDENING_BACKUP_DIR << "\n"
                << "\nType yes to continue: ";

            std::string answer;
            const bool gotAnswer = static_cast<bool>(std::getline(std::cin, answer));

            while (!answer.empty() &&
                std::isspace(static_cast<unsigned char>(answer.back())))
                answer.pop_back();

            std::transform(answer.begin(), answer.end(), answer.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            if (!gotAnswer || (answer != "yes" && answer != "y"))
            {
                std::cout << "Cancelled.\n";
                continue;
            }

            if (!webRemove())
                std::cout << "\nRemoval was not completed.\n";

            continue;
        }

        std::cout << "\nInvalid option.\n";
    }
}

bool SSHHardening::isEnabled() const
{
    return hardeningEnabled;
}

// ------------------------------------------------------------- web API

bool SSHHardening::webInstall()
{
    banner("INSTALL SSH HARDENING");

    if (!checkRootOrSudo()) return false;

    if (!commandExists("python3"))
    {
        std::cout << "python3 is not installed.\n";
        return false;
    }

    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "mkdir -p -m 755 " + shellQuote(SERVERGUARD_DIR),
        output, exitCode, true))
    {
        std::cout << "Cannot create ServerGuard directory.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (!ensureTool("curl", "curl")) return false;

    if (!ensureTool("openssl", "openssl"))
    {
        std::cout << "Installation aborted.\n";
        return false;
    }

    // Do not trust an existing script merely because the file exists.
    if (!downloadUpdate())
    {
        removeTempFiles();
        return false;
    }

    if (!verifyUpdate())
    {
        std::cout << "Downloaded SSH Hardening script failed verification.\n";
        removeTempFiles();
        return false;
    }

    // If replacing an existing script, preserve a backup first.
    const bool hadScript = checkScript();

    if (hadScript && !backupCurrentScript())
    {
        std::cout << "Cannot back up the existing script; installation aborted.\n";
        removeTempFiles();
        return false;
    }

    if (!installUpdatedScript())
    {
        std::cout << "Cannot install SSH Hardening script.\n";

        if (hadScript) rollbackUpdate();

        removeTempFiles();
        return false;
    }

    if (!checkScript())
    {
        std::cout << "SSH Hardening installation verification failed.\n";
        removeTempFiles();
        return false;
    }

    removeTempFiles();

    std::cout << "\n" << LINE
        << "   SSH HARDENING INSTALLATION SUCCESSFUL\n" << LINE
        << "Script:\n" << HARDENING_SCRIPT << "\n\n"
        << "Ed25519 signature: VERIFIED\n"
        << "SHA-256: VERIFIED\n"
        << "SSH configuration was NOT changed.\n"
        << "Use Apply Hardening to apply the configuration.\n" << LINE;

    return true;
}

bool SSHHardening::webRemove()
{
    banner("REMOVE SSH HARDENING");

    if (!checkRootOrSudo()) return false;

    std::string output;
    int exitCode = -1;

    const std::string reloadCommand =
        "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null";

    if (!executeRemote(
        "mkdir -p -m 700 " + shellQuote(HARDENING_BACKUP_DIR),
        output, exitCode, true))
    {
        std::cout << "Cannot create hardening backup directory.\n";
        printIfNotEmpty(output);
        return false;
    }

    // Back up the current hardening config (only if it exists). A stale
    // backup from an older run must never be "restored" later.
    const bool hadConfig = executeRemote(
        "test -f " + shellQuote(HARDENING_CONFIG),
        output, exitCode, true);

    if (hadConfig)
    {
        if (!executeRemote(
            "cp -p " + shellQuote(HARDENING_CONFIG) + " " +
            shellQuote(HARDENING_CONFIG_BACKUP),
            output, exitCode, true))
        {
            std::cout << "Cannot backup SSH Hardening configuration.\n";
            printIfNotEmpty(output);
            return false;
        }
    }

    const auto restoreConfig = [&]()
        {
            if (!hadConfig) return;

            executeRemote(
                "cp -p " + shellQuote(HARDENING_CONFIG_BACKUP) + " " +
                shellQuote(HARDENING_CONFIG),
                output, exitCode, true);
        };

    std::cout << "Removing ServerGuard SSH configuration...\n";

    if (!executeRemote(
        "rm -f " + shellQuote(HARDENING_CONFIG),
        output, exitCode, true))
    {
        std::cout << "Cannot remove SSH Hardening configuration.\n";
        printIfNotEmpty(output);
        return false;
    }

    std::cout << "Validating SSH configuration...\n";

    if (!isSSHConfigValid())
    {
        std::cout << "\nSSH configuration became invalid after removal.\n"
            << "Restoring ServerGuard hardening configuration...\n";

        restoreConfig();

        if (isSSHConfigValid())
            std::cout << "SSH Hardening configuration restored.\n";
        else
            std::cout << "WARNING: SSH configuration could not be automatically restored.\n";

        return false;
    }

    // Apply the change first; only delete the script once it succeeded.
    std::cout << "Reloading SSH service...\n";

    if (!executeRemote(reloadCommand, output, exitCode, true))
    {
        std::cout << "SSH reload failed. Restoring previous configuration...\n";
        printIfNotEmpty(output);

        restoreConfig();

        if (isSSHConfigValid(false))
            executeRemote(reloadCommand, output, exitCode, true);
        else
            std::cout << "WARNING: SSH configuration could not be automatically restored.\n";

        return false;
    }

    std::cout << "Removing SSH Hardening script...\n";

    const std::string removeCommand =
        "rm -f " + shellQuote(HARDENING_SCRIPT) + " " +
        shellQuote(HARDENING_TEMP_SCRIPT) + " " +
        shellQuote(HARDENING_TEMP_MANIFEST) + " " +
        shellQuote(HARDENING_TEMP_SIGNATURE) + " " +
        shellQuote(HARDENING_PUBLIC_KEY);

    if (!executeRemote(removeCommand, output, exitCode, true))
    {
        std::cout << "Cannot remove SSH Hardening script.\n";
        printIfNotEmpty(output);
        return false;
    }

    if (checkScript())
    {
        std::cout << "SSH Hardening script still exists.\n";
        return false;
    }

    hardeningEnabled = false;

    std::cout << "\n" << LINE
        << "     SSH HARDENING REMOVED SUCCESSFULLY\n" << LINE
        << "Script removed:\n" << HARDENING_SCRIPT << "\n\n"
        << "ServerGuard configuration removed:\n" << HARDENING_CONFIG << "\n\n";

    if (hadConfig)
        std::cout << "Backup:\n" << HARDENING_CONFIG_BACKUP << "\n\n";

    std::cout << "Main SSH configuration was NOT deleted.\n"
        << "SSH configuration: VALID\n" << LINE;

    return true;
}

bool SSHHardening::webApply()
{
    if (!keyAuthentication)
    {
        std::cout << "\n" << LINE << "       SSH HARDENING SAFETY CHECK\n" << LINE
            << "\n"
            << "[FAIL] ServerGuard is connected using password authentication.\n"
            << "[FAIL] SSH hardening was blocked for safety.\n"
            << "[INFO] Password authentication will NOT be disabled.\n"
            << "[INFO] Connect to the server using an SSH private key first.\n\n";
        return false;
    }

    if (!checkRootOrSudo()) return false;

    if (!checkScript())
    {
        std::cout << "SSH Hardening script was not found:\n"
            << HARDENING_SCRIPT << "\n"
            << "Install it first (menu option 6 / web install).\n";
        return false;
    }

    return setPermissions() && runHardening();
}

bool SSHHardening::webValidate()
{
    return checkRootOrSudo() && isSSHConfigValid();
}

bool SSHHardening::webUpdate()
{
    return update();
}

std::string SSHHardening::webStatus()
{
    std::string output;
    int exitCode = -1;

    const auto b = [](bool v) { return v ? "true" : "false"; };
    const auto s = [](const std::string& k, const std::string& v)
        {
            return ",\"" + k + "\":\"" + jsonEscape(v) + "\"";
        };

    // Without this check a non-root user gets "unknown" for everything,
    // because `sshd -T` needs privileges.
    if (!checkRootOrSudo())
    {
        hardeningEnabled = false;

        std::ostringstream err;
        err << "{\"installed\":false,\"enabled\":false"
            << s("error", "Cannot obtain root privileges on the server") << "}";
        return err.str();
    }

    const bool sshActive = checkSSHService();

    bool realHardening = false;
    std::string sshdOutput;

    if (sshActive &&
        executeRemote("sshd -T 2>/dev/null", sshdOutput, exitCode, true))
    {
        realHardening = evaluateHardening(sshdOutput, false);
    }

    hardeningEnabled = realHardening;

    const auto v = [&](const char* key) { return sshdValue(sshdOutput, key); };

    std::ostringstream json;

    json << "{\"installed\":" << b(checkScript())
        << ",\"enabled\":" << b(realHardening)
        << ",\"sshActive\":" << b(sshActive)
        << ",\"configValid\":" << b(isSSHConfigValid(false))
        << s("scriptPath", HARDENING_SCRIPT)
        << s("configPath", SSH_CONFIG)
        << s("hardeningConfig", HARDENING_CONFIG)
        << s("permitRootLogin", v("permitrootlogin"))
        << s("passwordAuthentication", v("passwordauthentication"))
        << s("pubkeyAuthentication", v("pubkeyauthentication"))
        << s("permitEmptyPasswords", v("permitemptypasswords"))
        << s("maxAuthTries", v("maxauthtries"))
        << s("loginGraceTime", v("logingracetime"))
        << s("x11Forwarding", v("x11forwarding"))
        << s("allowTcpForwarding", v("allowtcpforwarding"))
        << s("allowAgentForwarding", v("allowagentforwarding"))
        << s("compression", v("compression"))
        << "}";

    return json.str();
}

std::string SSHHardening::webBackups()
{
    std::string output;
    int exitCode = -1;

    bool ok = false;

    if (checkRootOrSudo())
    {
        ok = executeRemote(
            "if [ -d " + shellQuote(BACKUP_DIR) + " ]; then ls -lah " +
            shellQuote(BACKUP_DIR) + "; fi",
            output, exitCode, true);
    }

    std::ostringstream json;

    json << "{\"ok\":" << (ok ? "true" : "false")
        << ",\"path\":\"" << jsonEscape(BACKUP_DIR) << "\""
        << ",\"text\":\"" << jsonEscape(output) << "\"}";

    return json.str();
}