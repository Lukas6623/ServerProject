
#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent

ROOT = next(
    (
        path
        for path in (SCRIPT_DIR, *SCRIPT_DIR.parents)
        if (path / "CMakeLists.txt").is_file()
    ),
    None,
)

if ROOT is None:
    raise RuntimeError(
        "Не найден CMakeLists.txt. "
        "Помести скрипт в корень проекта ServerProject."
    )

DIST = ROOT / "dist"
BUILD_LINUX = ROOT / "build-linux"
BUILD_WINDOWS = ROOT / "build-windows"

LINUX_BIN_DIR = DIST / "linux-x64"
LINUX_BIN = LINUX_BIN_DIR / "ServerGuard"

SNAPCRAFT_FILE = ROOT / "snapcraft.yaml"
UPDATER = ROOT / "packaging" / "linux" / "update-serverguard.sh"

WINDOWS_RUNTIME_DLLS = (
    "libssh2.dll",
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
    "z.dll",
    "zlib1.dll",
)

WINDOWS_OPTIONAL_FILES = (
    "version.txt",
    "ServerGuardUpdater.exe",
)


# ============================================================
# GENERAL UTILITIES
# ============================================================

def run(command, cwd=ROOT):
    command = [str(arg) for arg in command]

    print("\n$", " ".join(command), flush=True)

    subprocess.run(
        command,
        cwd=str(cwd),
        check=True,
    )


def require_command(name):
    if shutil.which(name) is None:
        raise RuntimeError(
            f"Не найдена команда '{name}'. "
            "Установи её и повтори запуск."
        )


def valid_version(version: str) -> bool:
    return re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
        version.strip(),
    ) is not None


def ask_version() -> str:
    while True:
        version = input(
            "Введите версию ServerGuard (например, 1.1.14): "
        ).strip()

        if valid_version(version):
            return version

        print(
            f"Неверный формат версии: {version!r}. "
            "Пример: 1.1.14"
        )


def check_environment():
    if os.name != "posix":
        raise RuntimeError(
            "Запускай этот скрипт в WSL Ubuntu."
        )

    if not (ROOT / "CMakeLists.txt").is_file():
        raise RuntimeError(
            f"Не найден CMakeLists.txt: {ROOT}"
        )

    for tool in ("cmake", "nfpm", "snapcraft", "wslpath", "powershell.exe"):
        require_command(tool)

    print(f"Корень проекта: {ROOT}")
    print(f"Linux build: {BUILD_LINUX}")
    print(f"Windows build: {BUILD_WINDOWS}")
    print(f"Каталог релизов: {DIST}")


def windows_path(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


# ============================================================
# LINUX BUILD
# ============================================================

def build_linux_binary():
    print("\n========== LINUX: CMAKE ==========")

    LINUX_BIN_DIR.mkdir(parents=True, exist_ok=True)

    run([
        "cmake",
        "-S", ROOT,
        "-B", BUILD_LINUX,
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY={LINUX_BIN_DIR}",
    ])

    run([
        "cmake",
        "--build", BUILD_LINUX,
        "--config", "Release",
        "--parallel",
    ])

    candidates = [
        LINUX_BIN,
        BUILD_LINUX / "ServerGuard",
        BUILD_LINUX / "serverguard",
    ]

    found = next(
        (path for path in candidates if path.is_file()),
        None,
    )

    if found is None:
        raise RuntimeError(
            "Linux-бинарник не найден после CMake.\n"
            f"Ожидался файл: {LINUX_BIN}\n"
            "Проверь имя цели в CMakeLists.txt."
        )

    if found != LINUX_BIN:
        shutil.copy2(found, LINUX_BIN)

    LINUX_BIN.chmod(LINUX_BIN.stat().st_mode | 0o111)

    with LINUX_BIN.open("rb") as file:
        if file.read(4) != b"\x7fELF":
            raise RuntimeError(
                f"{LINUX_BIN} не является Linux ELF-бинарником."
            )

    print(f"Linux-бинарник готов: {LINUX_BIN}")


def make_nfpm_config(version: str, config_path: Path):
    if not UPDATER.is_file():
        raise RuntimeError(
            f"Не найден скрипт обновления: {UPDATER}"
        )

    config = f"""name: serverguard
arch: amd64
platform: linux
version: "{version}"
release: "1"
section: admin
priority: optional
maintainer: ServerGuard
description: ServerGuard Linux server security manager
homepage: https://serverguard.site
license: Proprietary

contents:
  - src: "{LINUX_BIN}"
    dst: /usr/bin/serverguard
    file_info:
      mode: 0755

  - src: "{UPDATER}"
    dst: /usr/share/serverguard/update-serverguard.sh
    file_info:
      mode: 0755

overrides:
  deb:
    depends:
      - libc6
      - libstdc++6
      - libssl3
      - libssh2-1

  rpm:
    depends:
      - glibc
      - libstdc++
      - openssl-libs
      - libssh2

  archlinux:
    depends:
      - glibc
      - gcc-libs
      - openssl
      - libssh2
"""

    config_path.write_text(config, encoding="utf-8")


def build_linux_packages(version: str, output: Path):
    print("\n========== LINUX: DEB / RPM / ARCH ==========")

    with tempfile.TemporaryDirectory(
        prefix="serverguard-nfpm-"
    ) as temp:
        config_path = Path(temp) / "nfpm.yaml"
        make_nfpm_config(version, config_path)

        targets = [
            (
                "deb",
                output / f"serverguard_{version}-1_amd64.deb",
            ),
            (
                "rpm",
                output / f"serverguard-{version}-1.x86_64.rpm",
            ),
            (
                "archlinux",
                output
                / f"serverguard-{version}-1-x86_64.pkg.tar.zst",
            ),
        ]

        for packager, target in targets:
            run([
                "nfpm",
                "package",
                "--config", config_path,
                "--packager", packager,
                "--target", target,
            ])

            if not target.is_file() or target.stat().st_size == 0:
                raise RuntimeError(f"Не создан пакет: {target}")

            print(f"Готово: {target.name}")


def ignore_snap_source(directory, names):
    patterns = [
        ".git", ".vs", ".idea", "__pycache__",
        "parts", "stage", "prime", "dist",
        "build*", "x64", "*.snap",
        ".env", "*.pem", "*.key",
        "*.bak", "*.bak-*", "*.old",
        "server.cfg", "servers.cfg",
    ]

    return [
        name
        for name in names
        if any(fnmatch.fnmatch(name, pattern) for pattern in patterns)
    ]


def build_linux_snap(version: str, output: Path):
    print("\n========== LINUX: SNAP ==========")

    if not SNAPCRAFT_FILE.is_file():
        raise RuntimeError(
            f"Не найден snapcraft.yaml: {SNAPCRAFT_FILE}"
        )

    with tempfile.TemporaryDirectory(
        prefix=f"serverguard-snap-{version}-"
    ) as temp:
        stage = Path(temp) / "source"

        shutil.copytree(
            ROOT,
            stage,
            ignore=ignore_snap_source,
        )

        staged_yaml = stage / "snapcraft.yaml"

        text = staged_yaml.read_text(encoding="utf-8")
        text, count = re.subn(
            r"(?m)^version:\s*.*$",
            f'version: "{version}"',
            text,
            count=1,
        )

        if count != 1:
            raise RuntimeError(
                "Не удалось обновить version в snapcraft.yaml."
            )

        staged_yaml.write_text(text, encoding="utf-8")

        run(
            ["snapcraft", "pack", "--destructive-mode"],
            cwd=stage,
        )

        expected = stage / f"serverguard_{version}_amd64.snap"

        if not expected.is_file():
            candidates = list(stage.glob("*.snap"))

            if len(candidates) != 1:
                raise RuntimeError(
                    "Snapcraft не создал ожидаемый пакет."
                )

            expected = candidates[0]

        target = output / f"serverguard_{version}_amd64.snap"
        shutil.copy2(expected, target)

        if target.stat().st_size == 0:
            raise RuntimeError("Создан пустой SNAP-пакет.")

        print(f"Готово: {target.name}")


# ============================================================
# WINDOWS BUILD THROUGH WINDOWS CMAKE / MSVC
# ============================================================

def create_windows_build_script(script_path: Path):
    script = r'''
param(
    [Parameter(Mandatory=$true)][string]$ProjectRoot,
    [Parameter(Mandatory=$true)][string]$BuildDir,
    [Parameter(Mandatory=$true)][string]$StageDir
)

$ErrorActionPreference = "Stop"

function Check-ExitCode([string]$Step) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Step завершился с кодом $LASTEXITCODE"
    }
}

$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$BuildDir = [IO.Path]::GetFullPath($BuildDir)
$StageDir = [IO.Path]::GetFullPath($StageDir)

$CMake = Get-Command cmake.exe -ErrorAction Stop
$CMakePath = $CMake.Source

if (-not (Test-Path (Join-Path $ProjectRoot "CMakeLists.txt"))) {
    throw "Не найден CMakeLists.txt: $ProjectRoot"
}

New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

Write-Host "`n========== WINDOWS: CMAKE CONFIGURE =========="

$ConfigureArgs = @(
    "-S", $ProjectRoot,
    "-B", $BuildDir,
    "-A", "x64",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=$StageDir"
)

$VcpkgToolchain = "C:\vcpkg\scripts\buildsystems\vcpkg.cmake"
if (Test-Path $VcpkgToolchain) {
    $ConfigureArgs += "-DCMAKE_TOOLCHAIN_FILE=$VcpkgToolchain"
}

& $CMakePath @ConfigureArgs
Check-ExitCode "CMake configure"

Write-Host "`n========== WINDOWS: MSVC RELEASE BUILD =========="

& $CMakePath --build $BuildDir --config Release --parallel
Check-ExitCode "CMake build"

$ExeCandidates = @()

$ExeCandidates += Get-ChildItem -Path $StageDir `
    -Filter "ServerGuard.exe" -File -Recurse `
    -ErrorAction SilentlyContinue

$ExeCandidates += Get-ChildItem -Path $BuildDir `
    -Filter "ServerGuard.exe" -File -Recurse `
    -ErrorAction SilentlyContinue

$Exe = $ExeCandidates |
    Where-Object { $_.FullName -notmatch '\\CMakeFiles\\' } |
    Select-Object -First 1

if (-not $Exe) {
    throw "Не найден ServerGuard.exe после сборки. Проверь имя цели CMake."
}

$FinalExe = Join-Path $StageDir "ServerGuard.exe"

if ($Exe.FullName -ne $FinalExe) {
    Copy-Item -LiteralPath $Exe.FullName -Destination $FinalExe -Force
}

Write-Host "Windows EXE: $FinalExe"

# Copy only known runtime DLLs, searching project build outputs,
# vcpkg runtime binaries, and the existing installed application.
$SearchDirs = @(
    $StageDir,
    $BuildDir,
    (Join-Path $ProjectRoot "C:\vcpkg\installed\x64-windows\bin"),
    "C:\vcpkg\installed\x64-windows\bin",
    "C:\Program Files\ServerGuard"
)

$RuntimeNames = @(
    "libssh2.dll",
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
    "z.dll",
    "zlib1.dll"
)

foreach ($Name in $RuntimeNames) {
    $AlreadyThere = Join-Path $StageDir $Name

    if (Test-Path $AlreadyThere) {
        continue
    }

    foreach ($Dir in $SearchDirs) {
        if (-not (Test-Path $Dir -PathType Container)) {
            continue
        }

        $Found = Get-ChildItem -LiteralPath $Dir `
            -Filter $Name -File -Recurse `
            -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if ($Found) {
            Copy-Item -LiteralPath $Found.FullName `
                -Destination $AlreadyThere -Force
            Write-Host "Runtime DLL: $Name"
            break
        }
    }
}

# Include known application support files only when they exist.
foreach ($Name in @("version.txt", "ServerGuardUpdater.exe")) {
    $Target = Join-Path $StageDir $Name

    if (Test-Path $Target) {
        continue
    }

    $Found = $null

    foreach ($Dir in @($ProjectRoot, $BuildDir, "C:\Program Files\ServerGuard")) {
        if (-not (Test-Path $Dir -PathType Container)) {
            continue
        }

        $Found = Get-ChildItem -LiteralPath $Dir `
            -Filter $Name -File -Recurse `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\CMakeFiles\\' } |
            Select-Object -First 1

        if ($Found) {
            break
        }
    }

    if ($Found) {
        Copy-Item -LiteralPath $Found.FullName `
            -Destination $Target -Force
        Write-Host "Support file: $Name"
    }
}

Write-Host "`nWindows build finished."
Get-ChildItem -LiteralPath $StageDir -File |
    Select-Object Name, Length |
    Format-Table -AutoSize
'''

    script_path.write_text(script, encoding="utf-8")


def build_windows_zip(version: str, output: Path):
    print("\n========== WINDOWS: BUILD AND ZIP ==========")

    output.mkdir(parents=True, exist_ok=True)

    zip_path = output / f"ServerGuard-v{version}.zip"

    # Keep intermediate Windows build files outside the release folder.
    stage_parent = DIST / ".windows-staging"
    stage = stage_parent / version
    stage_parent.mkdir(parents=True, exist_ok=True)

    if stage.exists():
        shutil.rmtree(stage)

    stage.mkdir(parents=True)

    win_root = windows_path(ROOT)
    win_build = windows_path(BUILD_WINDOWS)
    win_stage = windows_path(stage)

    ps_script = ROOT / ".build_windows_release_temp.ps1"

    try:
        create_windows_build_script(ps_script)

        run([
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", windows_path(ps_script),
            "-ProjectRoot", win_root,
            "-BuildDir", win_build,
            "-StageDir", win_stage,
        ])

        exe = stage / "ServerGuard.exe"

        if not exe.is_file():
            raise RuntimeError(
                "Windows-сборка не создала ServerGuard.exe."
            )

        with exe.open("rb") as file:
            if file.read(2) != b"MZ":
                raise RuntimeError(
                    "ServerGuard.exe не является Windows PE-файлом."
                )

        # Package only application files; never include PDBs,
        # source code, build directories, or intermediate artifacts.
        allowed = {
            "ServerGuard.exe",
            *WINDOWS_RUNTIME_DLLS,
            *WINDOWS_OPTIONAL_FILES,
        }

        files = sorted(
            p for p in stage.iterdir()
            if p.is_file() and p.name in allowed
        )

        if not any(p.name == "ServerGuard.exe" for p in files):
            raise RuntimeError("В Windows ZIP отсутствует EXE.")

        with zipfile.ZipFile(
            zip_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for file in files:
                archive.write(file, arcname=file.name)

        if not zip_path.is_file() or zip_path.stat().st_size == 0:
            raise RuntimeError("Windows ZIP не создан или пустой.")

        print(f"\nWindows ZIP готов: {zip_path}")
        print("Файлы внутри ZIP:")

        with zipfile.ZipFile(zip_path, "r") as archive:
            for item in archive.infolist():
                print(f"  {item.filename:40} {item.file_size:>10} bytes")

    finally:
        if ps_script.exists():
            ps_script.unlink()

        # Preserve the ZIP but remove temporary staging files.
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


# ============================================================
# MAIN
# ============================================================

def main():
    check_environment()

    version = ask_version()
    output = DIST / version

    if output.exists() and any(output.iterdir()):
        answer = input(
            f"\nПапка {output} уже содержит файлы.\n"
            "Пересобрать эту версию? [y/N]: "
        ).strip().lower()

        if answer not in ("y", "yes", "д", "да"):
            print("Сборка отменена.")
            return

    output.mkdir(parents=True, exist_ok=True)

    print(f"\nВерсия: {version}")
    print(f"Результаты: {output}")

    # Build Windows first so a Windows failure is detected early.
    build_windows_zip(version, output)

    build_linux_binary()
    build_linux_packages(version, output)
    build_linux_snap(version, output)

    print("\n========== RELEASE SUMMARY ==========")

    for package in sorted(output.iterdir()):
        if package.is_file():
            print(
                f"{package.name:55} "
                f"{package.stat().st_size:>10} bytes"
            )

    print(f"\nВсе сборки завершены: {output}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(
            f"\nОШИБКА: команда завершилась с кодом {exc.returncode}.",
            file=sys.stderr,
        )
        sys.exit(exc.returncode)
    except KeyboardInterrupt:
        print("\nСборка прервана пользователем.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"\nОШИБКА: {exc}", file=sys.stderr)
        sys.exit(1)
