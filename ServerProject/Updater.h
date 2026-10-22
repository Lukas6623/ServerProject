
#pragma once

#include "Platform.h"

#ifndef _WIN32

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <sys/stat.h>

namespace upd
{
    inline std::string manifestUrl()
    {
        return "https://serverguard.site/downloads/manifest.json";
    }

    inline std::string allowedPrefix()
    {
        return "https://serverguard.site/";
    }

    inline std::string jsonString(
        const std::string& json,
        const std::string& key)
    {
        size_t k = json.find("\"" + key + "\"");

        if (k == std::string::npos)
            return {};

        size_t colon = json.find(':', k);

        if (colon == std::string::npos)
            return {};

        size_t q1 = json.find('"', colon + 1);

        if (q1 == std::string::npos)
            return {};

        size_t q2 = json.find('"', q1 + 1);

        if (q2 == std::string::npos)
            return {};

        return json.substr(q1 + 1, q2 - q1 - 1);
    }

    inline std::string jsonObject(
        const std::string& json,
        const std::string& key)
    {
        size_t k = json.find("\"" + key + "\"");

        if (k == std::string::npos)
            return {};

        size_t open = json.find('{', k);

        if (open == std::string::npos)
            return {};

        size_t close = json.find('}', open);

        if (close == std::string::npos)
            return {};

        return json.substr(open + 1, close - open - 1);
    }

    inline std::vector<int> parseVersion(const std::string& s)
    {
        std::vector<int> version;
        int current = 0;
        bool hasDigit = false;

        for (char c : s)
        {
            if (c >= '0' && c <= '9')
            {
                current = current * 10 + (c - '0');
                hasDigit = true;
            }
            else if (c == '.')
            {
                version.push_back(hasDigit ? current : 0);
                current = 0;
                hasDigit = false;
            }
            else
            {
                break;
            }
        }

        if (hasDigit)
            version.push_back(current);

        return version;
    }

    inline bool isNewer(
        const std::string& a,
        const std::string& b)
    {
        std::vector<int> x = parseVersion(a);
        std::vector<int> y = parseVersion(b);

        size_t size = std::max(x.size(), y.size());

        x.resize(size, 0);
        y.resize(size, 0);

        return std::lexicographical_compare(
            y.begin(),
            y.end(),
            x.begin(),
            x.end());
    }

    inline std::string detectPackageType()
    {
        if (!plat::findInPath("dpkg").empty())
            return "deb";

        if (!plat::findInPath("pacman").empty())
            return "pacman";

        if (!plat::findInPath("rpm").empty())
            return "rpm";

        return {};
    }

    inline std::string packageExtension(const std::string& type)
    {
        if (type == "deb")
            return ".deb";

        if (type == "rpm")
            return ".rpm";

        return ".pkg.tar.zst";
    }

    inline std::vector<std::string> installCommand(
        const std::string& type,
        const std::string& file)
    {
        std::vector<std::string> command;

        if (!plat::isRoot())
            command.push_back("sudo");

        if (type == "deb")
        {
            if (!plat::findInPath("apt-get").empty())
            {
                command.insert(
                    command.end(),
                    { "apt-get", "install", "-y", file });
            }
            else
            {
                command.insert(
                    command.end(),
                    { "dpkg", "-i", file });
            }
        }
        else if (type == "rpm")
        {
            if (!plat::findInPath("dnf").empty())
            {
                command.insert(
                    command.end(),
                    { "dnf", "install", "-y", file });
            }
            else if (!plat::findInPath("zypper").empty())
            {
                command.insert(
                    command.end(),
                    {
                        "zypper",
                        "--non-interactive",
                        "install",
                        "--allow-unsigned-rpm",
                        file
                    });
            }
            else if (!plat::findInPath("yum").empty())
            {
                command.insert(
                    command.end(),
                    { "yum", "install", "-y", file });
            }
            else
            {
                command.insert(
                    command.end(),
                    { "rpm", "-U", file });
            }
        }
        else
        {
            command.insert(
                command.end(),
                { "pacman", "-U", "--noconfirm", file });
        }

        return command;
    }

    inline std::string readWholeFile(const std::string& path)
    {
        std::ifstream file(path, std::ios::binary);

        if (!file)
            return {};

        return std::string(
            std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>());
    }

    inline void checkAndUpdate(
        const std::string& currentVersion,
        char** argv)
    {
        if (!plat::getEnv("SERVERGUARD_NO_UPDATE").empty() ||
            !plat::getEnv("SERVERGUARD_UPDATED").empty())
        {
            return;
        }

        const std::string exe = plat::exePath();
        std::string manifestFile = plat::makeTempFile("sgman");

        if (manifestFile.empty())
            return;

        bool downloaded = plat::downloadFile(
            manifestUrl(),
            manifestFile,
            64 * 1024);

        std::string manifest = downloaded
            ? readWholeFile(manifestFile)
            : std::string();

        plat::removeFile(manifestFile);

        if (manifest.empty())
        {
            std::cout
                << "[Update] Cannot check for updates (offline?). Starting.\n";
            return;
        }

        std::string latest = jsonString(manifest, "latest");

        if (latest.empty())
        {
            std::cout
                << "[Update] Manifest is invalid. Starting.\n";
            return;
        }

        if (!isNewer(latest, currentVersion))
        {
            std::cout
                << "[Update] ServerGuard "
                << currentVersion
                << " is up to date.\n";
            return;
        }

        std::cout
            << "[Update] New version available: "
            << latest
            << " (current "
            << currentVersion
            << ")\n";

        std::string type = detectPackageType();

        if (type.empty())
        {
            std::cout
                << "[Update] Unknown package manager. Starting.\n";
            return;
        }

        std::string package = jsonObject(manifest, type);
        std::string url = jsonString(package, "url");
        std::string sha = jsonString(package, "sha256");

        std::transform(
            sha.begin(),
            sha.end(),
            sha.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });

        if (url.compare(0, allowedPrefix().size(), allowedPrefix()) != 0 ||
            sha.size() != 64)
        {
            std::cout
                << "[Update] No valid "
                << type
                << " package in manifest. Starting.\n";
            return;
        }

        std::string base = plat::makeTempFile("sgupd");

        if (base.empty())
            return;

        std::string file = base + packageExtension(type);

        if (std::rename(base.c_str(), file.c_str()) != 0)
        {
            plat::removeFile(base);
            return;
        }

        std::cout << "[Update] Downloading " << url << "\n";

        if (!plat::downloadFile(url, file, 300u * 1024u * 1024u))
        {
            std::cout
                << "[Update] Download failed. Starting current version.\n";

            plat::removeFile(file);
            return;
        }

        if (plat::sha256File(file) != sha)
        {
            std::cout
                << "[Update] SHA256 mismatch - package rejected. "
                << "Starting current version.\n";

            plat::removeFile(file);
            return;
        }

        chmod(file.c_str(), 0644);

        if (!plat::isRoot() &&
            plat::findInPath("sudo").empty())
        {
            std::cout
                << "[Update] sudo not found - cannot install. "
                << "Run ServerGuard as root to update.\n";

            plat::removeFile(file);
            return;
        }

        std::cout
            << "[Update] Installing (sudo password may be required)...\n";

        int result = plat::runProcess(installCommand(type, file));

        plat::removeFile(file);

        if (result != 0)
        {
            std::cout
                << "[Update] Installation failed (code "
                << result
                << "). Starting current version.\n";
            return;
        }

        std::cout
            << "[Update] Updated to "
            << latest
            << ". Restarting...\n";

        if (exe.empty() || !plat::restartSelf(exe, argv))
        {
            std::cout
                << "[Update] Restart failed. Please start ServerGuard again.\n";

            std::exit(0);
        }
    }
}

#endif
