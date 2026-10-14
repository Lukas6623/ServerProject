
#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <memory>
#include <cctype>
#include <regex>
#include <limits>

#include <winsock2.h>
#include <windows.h>
#include <urlmon.h>

#include <libssh2.h>
#include <openssl/evp.h>

#include "config.h"

#pragma comment(lib, "urlmon.lib")

class FirewallManager
{
public:
    FirewallManager(
        LIBSSH2_SESSION* session,
        const std::string& password,
        const std::string& username,
        int sshPort)
        : session_(session),
        password_(password),
        user_(username),
        sshPort_(sshPort)
    {}

    void handle(const std::string& arg)
    {
        if (arg.empty())
        {
            menu();
            return;
        }

        if (arg == "install")
        {
            install();
            return;
        }

        std::istringstream iss(arg);
        std::vector<std::string> tokens;
        std::string token;

        while (iss >> token)
            tokens.push_back(token);

        call(tokens);
    }

    void menu()
    {
        while (true)
        {
            std::cout
                << "\n========================================\n"
                << "          PORT MANAGER (UFW)\n"
                << "========================================\n"
                << " 1. Install / update on server\n"
                << " 2. Service status\n"
                << " 3. Firewall status\n"
                << " 4. Show rules (numbered)\n"
                << " 5. Listening ports\n"
                << " 6. Open port\n"
                << " 7. Close port (remove allow rule)\n"
                << " 8. Block port (deny)\n"
                << " 9. Unblock port\n"
                << "10. Limit port (anti-bruteforce)\n"
                << "11. Delete rule by number\n"
                << "12. Enable firewall\n"
                << "13. Disable firewall\n"
                << "14. Protected ports\n"
                << "15. Default policy\n"
                << "16. Remove service\n"
                << " 0. Back\n\n";

            const std::string choice = ask("Select: ");

            if (choice == "0" || !std::cin.good())
                return;

            if (choice == "1")
                install();
            else if (choice == "2")
                call({ "service-status" });
            else if (choice == "3")
                call({ "status" });
            else if (choice == "4")
                call({ "rules" });
            else if (choice == "5")
                call({ "listening" });
            else if (choice == "6")
                portAction("allow", false);
            else if (choice == "7")
                portAction("close", true);
            else if (choice == "8")
                portAction("deny", true);
            else if (choice == "9")
                portAction("unblock", false);
            else if (choice == "10")
                portAction("limit", false);
            else if (choice == "11")
            {
                const std::string number = ask("Rule number: ");

                if (!number.empty())
                    call({ "delete", number });
            }
            else if (choice == "12")
                call({ "enable" });
            else if (choice == "13")
            {
                if (confirm("Disable the firewall completely?"))
                    call({ "disable", "--force" });
            }
            else if (choice == "14")
                protectedMenu();
            else if (choice == "15")
            {
                const std::string direction =
                    ask("Direction (incoming/outgoing): ");

                const std::string policy =
                    ask("Policy (allow/deny/reject): ");

                if (!direction.empty() && !policy.empty())
                    call({ "default", direction, policy });
            }
            else if (choice == "16")
            {
                if (confirm("Remove the service from the server?"))
                {
                    call({ "uninstall-service" });
                    installed_ = false;
                }
            }
            else
            {
                std::cout << "Invalid option.\n";
            }
        }
    }

private:
    LIBSSH2_SESSION* session_ = nullptr;
    std::string password_;
    std::string user_;
    int sshPort_ = 22;

    // Состояние текущего экземпляра класса.
    bool installed_ = false;

    static constexpr size_t kMaxManifestSize = 64 * 1024;
    static constexpr size_t kMaxSignatureSize = 64;
    static constexpr size_t kMaxScriptSize = 4 * 1024 * 1024;

    static constexpr const char* kRemotePath =
        "/opt/serverguard/firewall_manager.py";

    // 32 байта публичного Ed25519-ключа.
    // Закрытый ключ не должен находиться в приложении.
    inline static constexpr unsigned char kPublicKey[32] = {
        0xb3, 0xb2, 0x08, 0xce, 0x51, 0xdc, 0x02, 0x8e,
        0xa5, 0xb5, 0x9c, 0xe6, 0xd9, 0x51, 0x5a, 0x9b,
        0x93, 0xc1, 0x33, 0x95, 0xb8, 0x1c, 0xe3, 0x98,
        0x46, 0xc0, 0x23, 0xc0, 0x14, 0xc5, 0xb6, 0x42
    };

    static std::string ask(const std::string& prompt)
    {
        std::cout << prompt;

        std::string value;
        std::getline(std::cin, value);

        const size_t first =
            value.find_first_not_of(" \t\r\n");

        if (first == std::string::npos)
            return {};

        const size_t last =
            value.find_last_not_of(" \t\r\n");

        return value.substr(first, last - first + 1);
    }

    static bool confirm(const std::string& question)
    {
        const std::string answer =
            ask(question + " (yes/no): ");

        return answer == "yes" || answer == "y";
    }

    // Экранирование аргумента для shell на удалённом Linux.
    static std::string q(const std::string& value)
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

    std::string commandLine(
        const std::vector<std::string>& args)
    {
        std::string command =
            std::string("python3 ") + q(kRemotePath);

        for (const auto& arg : args)
            command += " " + q(arg);

        return command;
    }

    int run(
        const std::string& command,
        std::string& out,
        bool useSudo = true)
    {
        out.clear();

        if (!session_)
        {
            out = "SSH session is not available.\n";
            return -1;
        }

        const bool needSudo =
            useSudo && user_ != "root";

        const bool feedPassword =
            needSudo && !password_.empty();

        std::string full = command;

        if (needSudo)
        {
            full = feedPassword
                ? "sudo -S -p '' " + command
                : "sudo -n " + command;
        }

        full += " 2>&1";

        LIBSSH2_CHANNEL* channel =
            libssh2_channel_open_session(session_);

        if (!channel)
        {
            out = "Cannot open SSH channel.\n";
            return -1;
        }

        if (libssh2_channel_exec(channel, full.c_str()) != 0)
        {
            out = "Cannot execute SSH command.\n";
            libssh2_channel_free(channel);
            return -1;
        }

        if (feedPassword)
        {
            const std::string input = password_ + "\n";
            size_t sent = 0;

            while (sent < input.size())
            {
                const ssize_t written =
                    libssh2_channel_write(
                        channel,
                        input.data() + sent,
                        static_cast<unsigned int>(
                            input.size() - sent));

                if (written <= 0)
                    break;

                sent += static_cast<size_t>(written);
            }

            if (sent != input.size())
            {
                out = "Failed to send sudo input.\n";
                libssh2_channel_free(channel);
                return -1;
            }
        }

        libssh2_channel_send_eof(channel);

        char buffer[4096];

        while (true)
        {
            const ssize_t count =
                libssh2_channel_read(
                    channel, buffer, sizeof(buffer));

            if (count > 0)
            {
                out.append(buffer, static_cast<size_t>(count));
            }
            else if (count == 0)
            {
                if (libssh2_channel_eof(channel))
                    break;

                // Для неблокирующей SSH-сессии нужна обработка EAGAIN.
                break;
            }
            else if (count == LIBSSH2_ERROR_EAGAIN)
            {
                out +=
                    "\nSSH read would block; operation may be incomplete.\n";
                libssh2_channel_free(channel);
                return -1;
            }
            else
            {
                out += "\nSSH channel read failed.\n";
                libssh2_channel_free(channel);
                return -1;
            }
        }

        libssh2_channel_close(channel);
        libssh2_channel_wait_closed(channel);

        const int status =
            libssh2_channel_get_exit_status(channel);

        libssh2_channel_free(channel);

        return status;
    }

    int call(const std::vector<std::string>& args)
    {
        if (!ensureInstalled())
            return -1;

        std::string output;
        const int rc = run(commandLine(args), output);

        std::cout << output;

        if (!output.empty() && output.back() != '\n')
            std::cout << '\n';

        return rc;
    }

    bool ensureInstalled()
    {
        if (installed_)
            return true;

        std::cout
            << "The module has not been verified in this session.\n";

        if (!confirm("Download, verify and install the signed module?"))
            return false;

        return install();
    }

    void portAction(
        const std::string& action,
        bool offerForce)
    {
        const std::string port =
            ask("Port (80, 80/tcp, 8000:8100/tcp): ");

        if (port.empty())
            return;

        const std::string source =
            ask("Only from IP/CIDR (Enter = anywhere): ");

        std::vector<std::string> args = { action, port };

        if (!source.empty())
        {
            args.push_back("--from");
            args.push_back(source);
        }

        if (!ensureInstalled())
            return;

        std::string output;
        const int rc = run(commandLine(args), output);

        std::cout << output;

        if (!output.empty() && output.back() != '\n')
            std::cout << '\n';

        if (rc == 3 && offerForce &&
            confirm("This port is protected. Force anyway?"))
        {
            args.push_back("--force");
            call(args);
        }
    }

    void protectedMenu()
    {
        call({ "protect", "list" });

        const std::string action =
            ask("add / remove / Enter = back: ");

        if (action != "add" && action != "remove")
            return;

        const std::string port = ask("Port (e.g. 22/tcp): ");

        if (!port.empty())
            call({ "protect", action, port });
    }

    static bool downloadToFile(
        const std::string& url,
        const std::string& path)
    {
        return URLDownloadToFileA(
            nullptr,
            url.c_str(),
            path.c_str(),
            0,
            nullptr) == S_OK;
    }

    static bool readBinaryFile(
        const std::string& path,
        std::string& data,
        size_t maxSize)
    {
        data.clear();

        std::ifstream file(path, std::ios::binary);

        if (!file)
            return false;

        file.seekg(0, std::ios::end);

        const std::streamoff size = file.tellg();

        if (size < 0 ||
            static_cast<unsigned long long>(size) > maxSize)
        {
            return false;
        }

        file.seekg(0, std::ios::beg);

        data.resize(static_cast<size_t>(size));

        if (!data.empty())
        {
            file.read(
                &data[0],
                static_cast<std::streamsize>(data.size()));

            if (!file ||
                file.gcount() !=
                static_cast<std::streamsize>(data.size()))
            {
                data.clear();
                return false;
            }
        }

        return true;
    }

    static bool verifyEd25519(
        const std::string& manifest,
        const std::string& signature)
    {
        if (signature.size() != kMaxSignatureSize ||
            manifest.empty())
        {
            return false;
        }

        EVP_PKEY* rawKey = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519,
            nullptr,
            kPublicKey,
            sizeof(kPublicKey));

        if (!rawKey)
        {
            std::cerr
                << "OpenSSL could not create the Ed25519 public key.\n";
            return false;
        }

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>
            key(rawKey, EVP_PKEY_free);

        EVP_MD_CTX* rawContext = EVP_MD_CTX_new();

        if (!rawContext)
            return false;

        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>
            context(rawContext, EVP_MD_CTX_free);

        if (EVP_DigestVerifyInit(
            context.get(),
            nullptr,
            nullptr,
            nullptr,
            key.get()) != 1)
        {
            return false;
        }

        return EVP_DigestVerify(
            context.get(),
            reinterpret_cast<const unsigned char*>(
                signature.data()),
            signature.size(),
            reinterpret_cast<const unsigned char*>(
                manifest.data()),
            manifest.size()) == 1;
    }

    // Проверяет поля манифеста и извлекает SHA-256.
    // Это ограниченная проверка JSON через regex.
    static bool getExpectedScriptHash(
        const std::string& manifest,
        std::string& expectedHash)
    {
        expectedHash.clear();

        if (manifest.find("\"format\"") == std::string::npos ||
            manifest.find("\"ServerGuardModuleManifest\"") ==
            std::string::npos ||
            !std::regex_search(
                manifest,
                std::regex(
                    R"REGEX("version"\s*:\s*1(?:\s*[,}]))REGEX")) ||
            manifest.find("\"algorithm\"") == std::string::npos ||
            manifest.find("\"Ed25519\"") == std::string::npos)
        {
            return false;
        }

        const std::regex pathPattern(
            R"REGEX("path"\s*:\s*"firewall_manager\.py")REGEX");

        const std::regex entryPattern(
            R"REGEX("path"\s*:\s*"firewall_manager\.py"\s*,\s*"sha256"\s*:\s*"([0-9a-fA-F]{64})")REGEX");

        size_t count = 0;

        for (std::sregex_iterator it(
            manifest.begin(), manifest.end(), pathPattern),
            end;
            it != end;
            ++it)
        {
            ++count;
        }

        if (count != 1)
            return false;

        std::smatch match;

        if (!std::regex_search(manifest, match, entryPattern))
            return false;

        expectedHash = match[1].str();

        std::transform(
            expectedHash.begin(),
            expectedHash.end(),
            expectedHash.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });

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
            return {};

        std::ostringstream result;
        result << std::hex << std::setfill('0');

        for (unsigned int i = 0; i < digestLength; ++i)
        {
            result << std::setw(2)
                << static_cast<unsigned int>(digest[i]);
        }

        return result.str();
    }

    static std::string base64(const std::string& input)
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
            const unsigned int value =
                static_cast<unsigned char>(input[i]) << 16;

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

    bool uploadVerifiedScript(
        const std::string& script,
        const std::string& remotePath)
    {
        if (script.empty() || script.size() > kMaxScriptSize)
            return false;

        const std::string tempBase64 = "/tmp/.sg_fw.b64";
        std::string output;

        const std::string encoded = base64(script);

        if (run(
            "umask 077; : > " + q(tempBase64),
            output,
            false) != 0)
        {
            return false;
        }

        const size_t chunkSize = 6000;

        for (size_t pos = 0; pos < encoded.size(); pos += chunkSize)
        {
            const std::string chunk =
                encoded.substr(pos, chunkSize);

            if (run(
                "printf %s " + q(chunk) +
                " >> " + q(tempBase64),
                output,
                false) != 0)
            {
                run("rm -f " + q(tempBase64), output, false);
                return false;
            }
        }

        const int rc = run(
            "base64 -d " + q(tempBase64) +
            " > " + q(remotePath) +
            " && chmod 600 " + q(remotePath),
            output,
            false);

        run("rm -f " + q(tempBase64), output, false);

        return rc == 0;
    }

    bool install()
    {
        std::string output;

        if (run("command -v python3", output, false) != 0)
        {
            std::cout
                << "python3 is not installed on the server.\n"
                << "Run: sudo apt update && sudo apt install -y python3\n";
            return false;
        }

        char tempDirectory[MAX_PATH] = {};

        if (!GetTempPathA(MAX_PATH, tempDirectory))
        {
            std::cout
                << "Cannot determine Windows temp directory.\n";
            return false;
        }

        char manifestPath[MAX_PATH] = {};
        char signaturePath[MAX_PATH] = {};
        char scriptPath[MAX_PATH] = {};

        if (!GetTempFileNameA(
            tempDirectory, "sgm", 0, manifestPath) ||
            !GetTempFileNameA(
                tempDirectory, "sgs", 0, signaturePath) ||
            !GetTempFileNameA(
                tempDirectory, "sgp", 0, scriptPath))
        {
            std::cout << "Cannot create temporary files.\n";

            if (manifestPath[0])
                DeleteFileA(manifestPath);

            if (signaturePath[0])
                DeleteFileA(signaturePath);

            if (scriptPath[0])
                DeleteFileA(scriptPath);

            return false;
        }

        const auto cleanup = [&]()
            {
                DeleteFileA(manifestPath);
                DeleteFileA(signaturePath);
                DeleteFileA(scriptPath);
            };

        std::cout << "Downloading signed module files...\n";

        if (!downloadToFile(
            ServerGuardConfig::FIREWALL_MANIFEST_URL,
            manifestPath) ||
            !downloadToFile(
                ServerGuardConfig::FIREWALL_SIGNATURE_URL,
                signaturePath) ||
            !downloadToFile(
                ServerGuardConfig::FIREWALL_SCRIPT_URL,
                scriptPath))
        {
            std::cout
                << "Download failed. Installation cancelled.\n";

            cleanup();
            return false;
        }

        std::string manifest;
        std::string signature;
        std::string script;

        if (!readBinaryFile(
            manifestPath, manifest, kMaxManifestSize) ||
            !readBinaryFile(
                signaturePath, signature, kMaxSignatureSize) ||
            !readBinaryFile(
                scriptPath, script, kMaxScriptSize))
        {
            std::cout
                << "Cannot read downloaded files or a size limit was exceeded.\n";

            cleanup();
            return false;
        }

        std::cout << "Checking Ed25519 signature...\n";

        if (!verifyEd25519(manifest, signature))
        {
            std::cout
                << "SECURITY ERROR: Invalid module signature.\n"
                << "Installation cancelled.\n";

            cleanup();
            return false;
        }

        std::cout
            << "Signature valid. Checking manifest structure...\n";

        std::string expectedHash;

        if (!getExpectedScriptHash(manifest, expectedHash))
        {
            std::cout
                << "SECURITY ERROR: Invalid manifest structure "
                << "or missing script hash.\n"
                << "Installation cancelled.\n";

            cleanup();
            return false;
        }

        const std::string actualHash = sha256Hex(script);

        if (actualHash.empty() || actualHash != expectedHash)
        {
            std::cout
                << "SECURITY ERROR: SHA-256 mismatch.\n"
                << "Downloaded module may have been modified.\n"
                << "Installation cancelled.\n";

            cleanup();
            return false;
        }

        std::cout
            << "Ed25519 and SHA-256 verified successfully.\n"
            << "Uploading verified module...\n";

        const std::string tempPython = "/tmp/.sg_fw.py";

        if (!uploadVerifiedScript(script, tempPython))
        {
            std::cout
                << "Could not upload verified module.\n";

            run("rm -f " + q(tempPython), output, false);
            cleanup();
            return false;
        }

        std::cout << "Installing service...\n";

        const int rc = run(
            "python3 " + q(tempPython) +
            " install-service --protect " +
            std::to_string(sshPort_),
            output);

        std::cout << output;

        if (!output.empty() && output.back() != '\n')
            std::cout << '\n';

        run("rm -f " + q(tempPython), output, false);
        cleanup();

        if (rc != 0)
        {
            std::cout
                << "Installation failed (exit code "
                << rc << ").\n";

            installed_ = false;
            return false;
        }

        installed_ = true;

        std::cout
            << "Firewall module installation command completed.\n"
            << "SSH port " << sshPort_
            << " was passed to the installer.\n";

        return true;
    }
};
