
#pragma once

namespace ServerGuardConfig
{
    inline constexpr const char* SECURITY_MANIFEST_URL =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/brute_force_guard/manifest.json";

    inline constexpr const char* SECURITY_SIGNATURE_URL =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/brute_force_guard/manifest.sig";

    inline constexpr const char* SECURITY_SCRIPT_URL =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/brute_force_guard/brute_force_guard.py";

    inline constexpr const char* SECURITY_MAIN_SCRIPT_NAME =
        "brute_force_guard.py";

    inline constexpr const char* FIREWALL_MANIFEST_URL =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/firewall/manifest.json";

    inline constexpr const char* FIREWALL_SIGNATURE_URL =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/firewall/manifest.sig";

    inline constexpr const char* FIREWALL_SCRIPT_URL =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/firewall/firewall_manager.py";

    inline constexpr char SSH_HARDENING_SCRIPT_URL[] =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/ssh_hardening/ssh_hardening.py";

    inline constexpr char SSH_HARDENING_MANIFEST_URL[] =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/ssh_hardening/manifest.json";

    inline constexpr char SSH_HARDENING_SIGNATURE_URL[] =
        "https://raw.githubusercontent.com/Lukas6623/ServerGuard/main/ssh_hardening/manifest.sig";

    inline constexpr char SSH_HARDENING_SCRIPT_PATH[] =
        "/opt/serverguard/ssh_hardening.py";

    inline constexpr char SSH_HARDENING_TEMP_SCRIPT_PATH[] =
        "/opt/serverguard/ssh_hardening.py.update";

    inline constexpr char SSH_HARDENING_TEMP_MANIFEST_PATH[] =
        "/opt/serverguard/ssh_hardening.manifest.json";

    inline constexpr char SSH_HARDENING_TEMP_SIGNATURE_PATH[] =
        "/opt/serverguard/ssh_hardening.manifest.sig";

    inline constexpr char SSH_HARDENING_PUBLIC_KEY_PATH[] =
        "/opt/serverguard/ssh_hardening_public.pem";

    inline constexpr char SSH_HARDENING_PUBLIC_KEY_PEM[] =
        R"SGPEM(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4OdSzkxRiJ2Y3ffqqvY8i3QXIQzQCl+v8UcZlKQICdA=
-----END PUBLIC KEY-----
)SGPEM";
}
