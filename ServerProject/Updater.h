#pragma once
// ============================================================
//  Updater.h - auto-update on startup (Linux only).
//  Uses only plat:: helpers from Platform.h.
//
//  Flow: download manifest -> compare version -> download package
//  for this distro -> verify SHA256 -> install via sudo -> restart.
//  On ANY failure the program just starts normally.
//
//  Environment:
//    SERVERGUARD_NO_UPDATE=1   disable the check
//    SERVERGUARD_UPDATED=1     set automatically after restart
// ============================================================

#include "Platform.h"

#ifndef _WIN32

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iterator>

namespace upd
{
    inline std::string manifestUrl()
    {
        return "https://serverguard.site/downloads/manifest.json";
    }

    // Packages may only come from our own site.
    inline std::string allowedPrefix()
    {
        return "https://serverguard.site/";
    }

    // ---- tiny JSON helpers (flat string values only) ----

    inline std::string jsonString(const std::string& json, const std::string& key)
    {
        size_t k = json.find("\"" + key + "\"");
        if (k == std::string::npos) return {};

        size_t colon = json.find(':', k);
        if (colon == std::string::npos) return {};

        size_t q1 = json.find('"', colon + 1);
        if (q1 == std::string::npos) return {};

        size_t q2 = json.find('"', q1 + 1);
        if (q2 == std::string::npos) return {};

        return json.substr(q1 + 1, q2 - q1 - 1);
    }

    // Returns the text inside { } that follows "key".
    // Works for flat objects only (no nested braces inside).
    inline std::string jsonObject(const std::string& json, const std::string& key)
    {
        size_t k = json.find("\"" + key + "\"");
        if (k == std::string::npos) return {};

        size_t open = json.find('{', k);
        if (open == std::string::npos) return {};

        size_t close = json.find('}', open);
        if (close == std::string::npos) return {};

        return json.substr(open + 1, close - open - 1);
    }

    // ---- versions ----

    inline std::vector<int> parseVersion(const std::string& s)
    {
        std::vector<int> v;
        int cur = 0;
        bool has = false;

        for (char c : s)
        {
            if (c >= '0' && c <= '9')
            {
                cur = cur * 10 + (c - '0');
                has = true;
            }
            else if (c == '.')
            {
                v.push_back(has ? cur : 0);
                cur = 0;
                has = false;
            }
            else
            {
                break;
            }
        }

        if (has) v.push_back(cur);

        return v;
    }

    // true if a is newer than b
    inline bool isNewer(const std::string& a, const std::string& b)
    {
        std::vector<int> x = parseVersion(a);
        std::vector<int> y = parseVersion(b);

        size_t n = std::max(x.size(), y.size());
        x.resize(n, 0);
        y.resize(n, 0);

        return std::lexicographical_compare(
            y.begin(), y.end(), x.begin(), x.end());
    }

    // ---- package manager ----

    inline std::string detectPackageType()
    {
        if (!plat::findInPath("dpkg").empty())   return "deb";
        if (!plat::findInPath("pacman").empty()) return "pacman";
        if (!plat::findInPath("rpm").empty())    return "rpm";
        return {};
    }

    inline std::string packageExtension(const std::string& type)
    {
        if (type == "deb") return ".deb";
        if (type == "rpm") return ".rpm";
        return ".pkg.tar.zst";
    }

    inline std::vector<std::string> installCommand(
        const std::string& type, const std::string& file)
    {
        std::vector<std::string> cmd;

        if (!plat::isRoot())
            cmd.push_back("sudo");

        if (type == "deb")
        {
            if (!plat::findInPath("apt-get").empty())
                cmd.insert(cmd.end(), { "apt-get", "install", "-y", file });
            else
                cmd.insert(cmd.end(), { "dpkg", "-i", file });
        }
        else if (type == "rpm")
        {
            if (!plat::findInPath("dnf").empty())
                cmd.insert(cmd.end(), { "dnf", "install", "-y", file });
            else if (!plat::findInPath("zypper").empty())
                cmd.insert(cmd.end(), { "zypper", "--non-interactive",
                                        "install", "--allow-unsigned-rpm", file });
            else if (!plat::findInPath("yum").empty())
                cmd.insert(cmd.end(), { "yum", "install", "-y", file });
            else
                cmd.insert(cmd.end(), { "rpm", "-U", file });
        }
        else
        {
            cmd.insert(cmd.end(), { "pacman", "-U", "--noconfirm", file });
        }

        return cmd;
    }

    inline std::string readWholeFile(const std::string& path)
    {
        std::ifstream f(path, std::ios::binary);
        if (!f) return {};

        return std::string(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());
    }

    // ---- main entry ----
    // If a newer version exists: install it and restart (does not return).
    // In every other case it returns and the program starts normally.

    inline void checkAndUpdate(const std::string& currentVersion, char** argv)
    {
        if (!plat::getEnv("SERVERGUARD_NO_UPDATE").empty() ||
            !plat::getEnv("SERVERGUARD_UPDATED").empty())
            return;

        const std::string exe = plat::exePath();

        // 1. manifest
        std::string manifestFile = plat::makeTempFile("sgman");

        if (manifestFile.empty())
            return;

        bool got = plat::downloadFile(manifestUrl(), manifestFile, 64 * 1024);
        std::string manifest = got ? readWholeFile(manifestFile) : std::string();
        plat::removeFile(manifestFile);

        if (manifest.empty())
        {
            std::cout << "[Update] Cannot check for updates (offline?). Starting.\n";
            return;
        }

        // 2. version
        std::string latest = jsonString(manifest, "latest");

        if (latest.empty())
        {
            std::cout << "[Update] Manifest is invalid. Starting.\n";
            return;
        }

        if (!isNewer(latest, currentVersion))
        {
            std::cout << "[Update] ServerGuard " << currentVersion
                << " is up to date.\n";
            return;
        }

        std::cout << "[Update] New version available: " << latest
            << " (current " << currentVersion << ")\n";

        // 3. package for this distro
        std::string type = detectPackageType();

        if (type.empty())
        {
            std::cout << "[Update] Unknown package manager. Starting.\n";
            return;
        }

        // keys "deb" / "rpm" / "pacman" are unique in the manifest
        std::string pkg = jsonObject(manifest, type);

        std::string url = jsonString(pkg, "url");
        std::string sha = jsonString(pkg, "sha256");

        std::transform(sha.begin(), sha.end(), sha.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (url.compare(0, allowedPrefix().size(), allowedPrefix()) != 0 ||
            sha.size() != 64)
        {
            std::cout << "[Update] No valid " << type
                << " package in manifest. Starting.\n";
            return;
        }

        // 4. download
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
            std::cout << "[Update] Download failed. Starting current version.\n";
            plat::removeFile(file);
            return;
        }

        // 5. verify
        if (plat::sha256File(file) != sha)
        {
            std::cout << "[Update] SHA256 mismatch - package rejected. "
                "Starting current version.\n";
            plat::removeFile(file);
            return;
        }

        chmod(file.c_str(), 0644);   // so apt/dnf running as root can read it

        // 6. install
        if (!plat::isRoot() && plat::findInPath("sudo").empty())
        {
            std::cout << "[Update] sudo not found - cannot install. "
                "Run ServerGuard as root to update.\n";
            plat::removeFile(file);
            return;
        }

        std::cout << "[Update] Installing (sudo password may be required)...\n";

        int rc = plat::runProcess(installCommand(type, file));

        plat::removeFile(file);

        if (rc != 0)
        {
            std::cout << "[Update] Installation failed (code " << rc
                << "). Starting current version.\n";
            return;
        }

        std::cout << "[Update] Updated to " << latest << ". Restarting...\n";

        if (exe.empty() || !plat::restartSelf(exe, argv))
        {
            std::cout << "[Update] Restart failed. Please start ServerGuard again.\n";
            std::exit(0);
        }
    }
}

#endif