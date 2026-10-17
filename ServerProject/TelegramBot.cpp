#include "TelegramBot.h"
#include "TelegramBotInternal.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

// ============================================================================
// Внутренние помощники (виден только в этом .cpp, заголовки менять не нужно).
// Они не используют shellQuote/trim из TelegramBotInternal.h, поэтому не
// зависят от того, как эти функции объявлены.
// ============================================================================
namespace
{
    // Верхняя граница времени выполнения одной удалённой команды
    // (apt-get / pip могут работать долго, но не бесконечно).
    constexpr int  SG_COMMAND_TIMEOUT_SEC = 1200;
    // Короткие служебные проверки (id -u, sudo -n true, sudo -v).
    constexpr int  SG_PROBE_TIMEOUT_SEC = 60;
    // Таймаут блокирующих операций libssh2, мс.
    constexpr long SG_BLOCKING_TIMEOUT_MS = 10000;
    // Сколько ждём, пока канал примет данные stdin (пароль sudo).
    constexpr int  SG_STDIN_WRITE_TIMEOUT_SEC = 10;

    void sgSleepMs(int milliseconds)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }

    std::string sgTrim(const std::string& value)
    {
        const char* whitespace = " \t\r\n";

        const std::size_t first = value.find_first_not_of(whitespace);

        if (first == std::string::npos)
            return std::string();

        const std::size_t last = value.find_last_not_of(whitespace);

        return value.substr(first, last - first + 1);
    }

    // Последняя непустая строка вывода (sudo может напечатать предупреждения
    // ДО результата команды, поэтому нельзя разбирать вывод целиком).
    std::string sgLastLine(const std::string& text)
    {
        const std::size_t end = text.find_last_not_of(" \t\r\n");

        if (end == std::string::npos)
            return std::string();

        std::size_t start = text.find_last_of('\n', end);

        start = (start == std::string::npos) ? 0 : start + 1;

        return sgTrim(text.substr(start, end - start + 1));
    }

    // Ищет строку, которая НАЧИНАЕТСЯ с marker. Возвращает значение после
    // маркера из ПОСЛЕДНЕЙ такой строки. Совпадения в середине строки
    // (например, внутри диагностического сообщения) игнорируются.
    bool sgFindMarker(
        const std::string& text,
        const std::string& marker,
        std::string& value)
    {
        value.clear();

        bool found = false;
        std::size_t position = 0;

        while (position <= text.size())
        {
            const std::size_t eol = text.find('\n', position);

            const std::string line = sgTrim(
                text.substr(
                    position,
                    eol == std::string::npos
                    ? std::string::npos
                    : eol - position));

            if (line.compare(0, marker.size(), marker) == 0)
            {
                value = sgTrim(line.substr(marker.size()));
                found = true;
            }

            if (eol == std::string::npos)
                break;

            position = eol + 1;
        }

        return found;
    }

    bool sgSudoNeedsPassword(const std::string& output)
    {
        return output.find("a password is required") != std::string::npos ||
            output.find("a terminal is required to read the password") != std::string::npos;
    }

    // Временно переводит SSH-сессию в блокирующий режим с таймаутом и
    // восстанавливает прежние настройки при выходе.
    class SgSessionModeGuard
    {
    public:
        explicit SgSessionModeGuard(LIBSSH2_SESSION* s)
            : session(s),
            blocking(libssh2_session_get_blocking(s)),
            timeout(libssh2_session_get_timeout(s))
        {
            libssh2_session_set_blocking(session, 1);
            libssh2_session_set_timeout(session, SG_BLOCKING_TIMEOUT_MS);
        }

        ~SgSessionModeGuard()
        {
            libssh2_session_set_timeout(session, timeout);
            libssh2_session_set_blocking(session, blocking);
        }

        SgSessionModeGuard(const SgSessionModeGuard&) = delete;
        SgSessionModeGuard& operator=(const SgSessionModeGuard&) = delete;

    private:
        LIBSSH2_SESSION* session;
        int blocking;
        long timeout;
    };

    std::string sgDescribeError(
        LIBSSH2_SESSION* session,
        const std::string& what,
        int code)
    {
        char* errorMessage = nullptr;
        int errorLength = 0;

        const int lastCode = libssh2_session_last_error(
            session,
            &errorMessage,
            &errorLength,
            0);

        std::ostringstream text;

        text << what << ". libssh2 error: " << (code != 0 ? code : lastCode);

        if (errorMessage != nullptr && errorLength > 0)
        {
            text << ". Details: "
                << std::string(errorMessage, static_cast<std::size_t>(errorLength));
        }

        return text.str();
    }

    // Выполняет одну команду в новом SSH-канале.
    //  - stdout и stderr объединяются в output;
    //  - stdinData (например, пароль sudo) передаётся в stdin, затем stdin закрывается,
    //    чтобы удалённая команда никогда не ждала ввод;
    //  - код возврата читается только ПОСЛЕ закрытия канала;
    //  - чтение ограничено временем (нет бесконечного цикла на EAGAIN).
    // Возвращает true, если команда была выполнена и получен код возврата
    // (сам код возврата может быть ненулевым). false — ошибка транспорта/таймаут.
    bool sgRunChannel(
        LIBSSH2_SESSION* session,
        const std::string& command,
        const std::string& stdinData,
        int timeoutSec,
        std::string& output,
        int& exitCode)
    {
        output.clear();
        exitCode = -1;

        if (session == nullptr)
        {
            output = "SSH session is invalid.";
            return false;
        }

        SgSessionModeGuard modeGuard(session);

        LIBSSH2_CHANNEL* channel = libssh2_channel_open_session(session);

        if (channel == nullptr)
        {
            output = sgDescribeError(session, "Cannot open SSH channel", 0);
            return false;
        }

        auto release = [&]()
            {
                libssh2_channel_close(channel);
                libssh2_channel_free(channel);
            };

        libssh2_channel_handle_extended_data2(
            channel,
            LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE);

        const int execResult = libssh2_channel_exec(channel, command.c_str());

        if (execResult != 0)
        {
            output = sgDescribeError(session, "Cannot execute remote command", execResult);
            release();
            return false;
        }

        // Передаём stdin (пароль sudo). Ошибка записи не считается фатальной:
        // если удалённая сторона уже закрыла канал, настоящая причина будет
        // в выводе команды, который мы прочитаем ниже.
        std::size_t totalWritten = 0;

        const auto writeDeadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(SG_STDIN_WRITE_TIMEOUT_SEC);

        while (totalWritten < stdinData.size())
        {
            const ssize_t written = libssh2_channel_write(
                channel,
                stdinData.data() + totalWritten,
                stdinData.size() - totalWritten);

            if (written > 0)
            {
                totalWritten += static_cast<std::size_t>(written);
                continue;
            }

            if ((written == LIBSSH2_ERROR_EAGAIN || written == LIBSSH2_ERROR_TIMEOUT) &&
                std::chrono::steady_clock::now() < writeDeadline)
            {
                sgSleepMs(10);
                continue;
            }

            break;
        }

        libssh2_channel_send_eof(channel);

        const int effectiveTimeout = timeoutSec > 0 ? timeoutSec : SG_COMMAND_TIMEOUT_SEC;

        const auto deadline =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(effectiveTimeout);

        char buffer[4096];
        bool timedOut = false;
        bool readError = false;

        while (true)
        {
            const ssize_t bytesRead = libssh2_channel_read(channel, buffer, sizeof(buffer));

            if (bytesRead > 0)
            {
                output.append(buffer, static_cast<std::size_t>(bytesRead));

                if (std::chrono::steady_clock::now() > deadline)
                {
                    timedOut = true;
                    break;
                }

                continue;
            }

            if (bytesRead == LIBSSH2_ERROR_EAGAIN ||
                bytesRead == LIBSSH2_ERROR_TIMEOUT ||
                bytesRead == 0)
            {
                if (libssh2_channel_eof(channel))
                    break;

                if (std::chrono::steady_clock::now() > deadline)
                {
                    timedOut = true;
                    break;
                }

                if (bytesRead != LIBSSH2_ERROR_TIMEOUT)
                    sgSleepMs(10);

                continue;
            }

            output += "\n" + sgDescribeError(
                session,
                "SSH channel read failed",
                static_cast<int>(bytesRead));

            readError = true;
            break;
        }

        if (timedOut)
        {
            output += "\n[timeout after " + std::to_string(effectiveTimeout) + " seconds]";
            release();
            exitCode = -2;
            return false;
        }

        if (readError)
        {
            release();
            return false;
        }

        // Канал закрываем и ждём закрытия ДО чтения кода возврата.
        libssh2_channel_close(channel);
        libssh2_channel_wait_closed(channel);

        exitCode = libssh2_channel_get_exit_status(channel);

        char* exitSignal = nullptr;
        std::size_t exitSignalLength = 0;

        if (libssh2_channel_get_exit_signal(
            channel,
            &exitSignal,
            &exitSignalLength,
            nullptr,
            nullptr,
            nullptr,
            nullptr) == 0 &&
            exitSignal != nullptr &&
            exitSignalLength > 0)
        {
            output += "\n[terminated by signal " +
                std::string(exitSignal, exitSignalLength) + "]";

            if (exitCode == 0)
                exitCode = -3;
        }

        libssh2_channel_free(channel);

        output.erase(
            std::remove(output.begin(), output.end(), '\r'),
            output.end());

        return true;
    }
}

TelegramBot::TelegramBot(LIBSSH2_SESSION* sshSession, const std::string& password)
{
    session = sshSession;
    sudoPassword = password;
    sudoRequired = false;
    sudoAuthenticated = false;
}

// Состояние привилегий:
//   sudoAuthenticated == true  -> права уже определены и подтверждены
//                                 (root, либо sudo работает);
//   sudoRequired == true       -> SSH-пользователь не root, команды с
//                                 useSudo=true нужно выполнять через sudo.
// Если useSudo=true, а права ещё не определены, executeRemote() определяет
// их сам (раньше команда молча выполнялась от обычного пользователя).
bool TelegramBot::executeRemote(
    const std::string& command,
    std::string& output,
    int& exitCode,
    bool useSudo)
{
    output.clear();
    exitCode = -1;

    if (session == nullptr)
    {
        output = "SSH session is invalid.";
        return false;
    }

    if (useSudo && !sudoAuthenticated)
    {
        if (!authenticateSudo())
        {
            output = "Cannot obtain administrator privileges on the remote server.";
            return false;
        }
    }

    const bool elevate = useSudo && sudoRequired;

    if (!elevate)
    {
        // root, либо команде права администратора не нужны.
        if (!sgRunChannel(session, command, std::string(), SG_COMMAND_TIMEOUT_SEC, output, exitCode))
            return false;

        return exitCode == 0;
    }

    // Сначала sudo без пароля (NOPASSWD или действующий кэш sudo).
    // Если sudo отказывает до запуска команды, команда НЕ выполнялась,
    // поэтому повтор с паролем безопасен.
    const std::string quotedCommand = shellQuote(command);

    if (!sgRunChannel(
        session,
        "sudo -n -H bash -c " + quotedCommand,
        std::string(),
        SG_COMMAND_TIMEOUT_SEC,
        output,
        exitCode))
    {
        return false;
    }

    if (exitCode != 0 && sgSudoNeedsPassword(output))
    {
        if (sudoPassword.empty())
        {
            output = "Sudo requires a password, but the sudo password is empty.";
            return false;
        }

        // Пароль идёт через stdin (-S), а не через аргументы команды.
        if (!sgRunChannel(
            session,
            "sudo -S -p '' -H bash -c " + quotedCommand,
            sudoPassword + "\n",
            SG_COMMAND_TIMEOUT_SEC,
            output,
            exitCode))
        {
            return false;
        }
    }

    return exitCode == 0;
}


bool TelegramBot::authenticateSudo()
{
    if (!session)
    {
        std::cout << "ERROR: SSH session is not available.\n";
        return false;
    }

    std::cout << "Checking remote user privileges...\n";

    std::string output;
    int exitCode = -1;

    if (!sgRunChannel(session, "id -u", std::string(), SG_PROBE_TIMEOUT_SEC, output, exitCode) ||
        exitCode != 0)
    {
        sudoAuthenticated = false;
        std::cout << "Cannot determine remote user ID.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    // sudo/sshd могут напечатать предупреждения, поэтому берём последнюю строку.
    const std::string uidText = sgLastLine(output);
    long uid = -1;

    try
    {
        std::size_t used = 0;
        uid = std::stol(uidText, &used);

        if (used != uidText.size())
            uid = -1;
    }
    catch (...)
    {
        uid = -1;
    }

    if (uid < 0)
    {
        sudoAuthenticated = false;
        std::cout << "Cannot parse remote user ID: [" << uidText << "]\n";
        return false;
    }

    // root не нуждается в sudo.
    if (uid == 0)
    {
        sudoRequired = false;
        sudoAuthenticated = true;

        std::cout << "Connected as root. Sudo is not required.\n";
        return true;
    }

    // Не-root пользователь обязан использовать sudo.
    sudoRequired = true;
    sudoAuthenticated = false;

    // 1) sudo без пароля (NOPASSWD, типично для azureuser).
    if (sgRunChannel(session, "sudo -n true", std::string(), SG_PROBE_TIMEOUT_SEC, output, exitCode) &&
        exitCode == 0)
    {
        sudoAuthenticated = true;
        std::cout << "Sudo is available without a password.\n";
        return true;
    }

    const std::string passwordlessOutput = output;

    if (sudoPassword.empty())
    {
        std::cout << "Sudo requires a password, but the sudo password is empty.\n";

        if (!passwordlessOutput.empty())
            std::cout << passwordlessOutput << "\n";

        return false;
    }

    // 2) sudo с паролем через stdin.
    std::cout << "Authenticating sudo...\n";

    if (!sgRunChannel(
        session,
        "sudo -S -p '' -v",
        sudoPassword + "\n",
        SG_PROBE_TIMEOUT_SEC,
        output,
        exitCode))
    {
        std::cout << "Cannot run sudo authentication.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    if (exitCode == 0)
    {
        sudoAuthenticated = true;
        std::cout << "Sudo authentication successful.\n";
        return true;
    }

    std::cout << "Sudo authentication failed. Exit code: "
        << exitCode << "\n";

    if (!output.empty())
        std::cout << output << "\n";

    return false;
}

bool TelegramBot::commandExists(const std::string& command)
{
    std::string output;
    int exitCode = -1;

    std::string remoteCommand = "command -v " + shellQuote(command) + " >/dev/null 2>&1";

    executeRemote(remoteCommand, output, exitCode, false);

    return exitCode == 0;
}

bool TelegramBot::checkRootOrSudo()
{
    std::string output;
    int exitCode = -1;

    if (!executeRemote("id -u", output, exitCode, false))
    {
        std::cout << "Cannot determine remote user.\n";
        return false;
    }

    long uid = -1;

    try
    {
        uid = std::stol(sgLastLine(output));
    }
    catch (...)
    {
        uid = -1;
    }

    if (uid == 0)
    {
        sudoRequired = false;
        sudoAuthenticated = true;
        std::cout << "Remote user is root.\n";
        return true;
    }

    if (!commandExists("sudo"))
    {
        std::cout << "sudo is not installed.\n";
        return false;
    }

    sudoRequired = true;
    sudoAuthenticated = false;

    if (!authenticateSudo())
    {
        std::cout << "Current user cannot use sudo.\n";
        return false;
    }

    return true;
}

bool TelegramBot::createDirectories()
{
    std::cout << "Creating Telegram directories...\n";

    std::string output;
    int exitCode = -1;

    std::string command = "mkdir -p " + shellQuote(TELEGRAM_DIR) + " " + shellQuote(TELEGRAM_QUEUE);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create Telegram directories.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << "Telegram directories created.\n";

    return true;
}

bool TelegramBot::installPythonDependencies()
{
    std::cout << "\nChecking Python environment...\n";

    // Проверка apt-get теперь выполняется ДО попытки что-либо установить.
    if (!commandExists("apt-get"))
    {
        std::cout << "apt-get not found.\n";
        return false;
    }

    std::string output;
    int exitCode = -1;

    const bool packagesPresent =
        commandExists("python3") &&
        commandExists("curl") &&
        commandExists("unzip") &&
        executeRemote("dpkg -s python3-venv python3-pip >/dev/null 2>&1", output, exitCode, false);

    if (!packagesPresent)
    {
        std::cout << "Installing Python3, venv, pip, curl and unzip...\n";

        // apt-get update выполняется один раз; Lock::Timeout ждёт, пока
        // unattended-upgrades освободит блокировку dpkg.
        if (!executeRemote(
            "apt-get update -o DPkg::Lock::Timeout=300 && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=300 "
            "python3 python3-venv python3-pip curl unzip",
            output, exitCode, true))
        {
            std::cout << "Failed to install Python requirements.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }
    }
    else
    {
        std::cout << "Required system packages are already installed.\n";
    }

    std::cout << "Checking Telegram virtual environment...\n";

    std::string venvPython = TELEGRAM_VENV + "/bin/python";

    // venv принадлежит root, поэтому проверки делаются с sudo.
    bool venvExists = executeRemote("test -x " + shellQuote(venvPython), output, exitCode, true);

    if (!venvExists)
    {
        std::cout << "Virtual environment not found.\n";
        std::cout << "Creating virtual environment...\n";

        if (!executeRemote("rm -rf " + shellQuote(TELEGRAM_VENV) + " && python3 -m venv " + shellQuote(TELEGRAM_VENV), output, exitCode, true))
        {
            std::cout << "Failed to create virtual environment.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }

        std::cout << "Virtual environment created.\n";
    }
    else
    {
        std::cout << "Virtual environment already exists.\n";
    }

    output.clear();
    exitCode = -1;

    if (!executeRemote(shellQuote(venvPython) + " --version", output, exitCode, true))
    {
        std::cout << "Virtual environment Python is not working.\n";
        return false;
    }

    if (!output.empty())
        std::cout << output;

    std::cout << "Checking aiogram...\n";

    output.clear();
    exitCode = -1;

    bool aiogramInstalled = executeRemote(shellQuote(venvPython) + " -c \"import aiogram\"", output, exitCode, true);

    if (!aiogramInstalled)
    {
        std::cout << "aiogram is not installed.\n";
        std::cout << "Installing aiogram...\n";

        output.clear();
        exitCode = -1;

        if (!executeRemote(shellQuote(venvPython) + " -m pip install aiogram", output, exitCode, true))
        {
            std::cout << "Failed to install aiogram.\n";

            if (!output.empty())
                std::cout << output << "\n";

            return false;
        }

        std::cout << "aiogram installed.\n";
    }
    else
    {
        std::cout << "aiogram is already installed.\n";
    }

    return true;
}

bool TelegramBot::checkScript()
{
    std::string output;
    int exitCode = -1;

    // Каталог принадлежит root, проверка выполняется с sudo.
    executeRemote("test -f " + shellQuote(TELEGRAM_SCRIPT), output, exitCode, true);

    return exitCode == 0;
}

bool TelegramBot::ensureUnzip()
{
    if (commandExists("unzip"))
        return true;

    std::cout << "unzip is not installed.\n";
    std::cout << "Installing unzip...\n";

    std::string output;
    int exitCode = -1;

    if (!executeRemote(
        "apt-get update -o DPkg::Lock::Timeout=300 && "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -o DPkg::Lock::Timeout=300 unzip",
        output, exitCode, true))
    {
        std::cout << "Cannot install unzip.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    return commandExists("unzip");
}

bool TelegramBot::downloadRepositoryArchive(const std::string& archivePath)
{
    std::cout << "\nDownloading Telegram bot repository...\n";
    std::cout << "Repository:\n"
        << GITHUB_TELEGRAM_REPOSITORY_ZIP << "\n\n";

    std::string output;
    int exitCode = -1;

    const std::string command =
        "rm -f " + shellQuote(archivePath) + " && "
        "curl -fL --silent --show-error "
        "--connect-timeout 15 "
        "--max-time 180 "
        "--retry 3 "
        "--retry-delay 2 "
        "-o " + shellQuote(archivePath) + " "
        + shellQuote(GITHUB_TELEGRAM_REPOSITORY_ZIP)
        + " && "
        "test -s " + shellQuote(archivePath)
        + " && "
        "stat -c '%s' " + shellQuote(archivePath);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Repository download or verification failed.\n";

        if (!output.empty())
            std::cout << output << '\n';

        std::cout << "Exit code: " << exitCode << '\n';
        return false;
    }

    // Размер файла — последняя строка вывода (до неё возможны предупреждения sudo).
    const std::string sizeText = sgLastLine(output);

    try
    {
        const unsigned long long archiveSize =
            std::stoull(sizeText);

        if (archiveSize == 0)
        {
            std::cout << "Downloaded archive is empty.\n";
            return false;
        }

        std::cout << "Repository archive downloaded successfully.\n";
        std::cout << "Archive size: "
            << archiveSize << " bytes.\n";

        return true;
    }
    catch (...)
    {
        std::cout << "Could not determine downloaded archive size.\n";
        std::cout << "Command output: " << output << '\n';
        return false;
    }
}

bool TelegramBot::extractRepository(
    const std::string& archivePath,
    const std::string& extractDirectory,
    std::string& repositoryRoot)
{
    repositoryRoot.clear();

    std::cout << "\nExtracting Telegram bot repository...\n";

    std::string output;
    int exitCode = -1;

    // Проверка целостности архива, распаковка, нормализация владельца и прав,
    // поиск скрипта и определение каталога выполняются в одном вызове с правами
    // администратора. Дерево принадлежит root и недоступно на запись
    // обычному пользователю, поэтому подменить код до его установки нельзя.
    // Путь выводится в отдельных строках-маркерах.
    const std::string command =
        "set -eu; "
        "rm -rf " + shellQuote(extractDirectory) + "; "
        "mkdir -p " + shellQuote(extractDirectory) + "; "
        "unzip -tq " + shellQuote(archivePath) + " >/dev/null; "
        "unzip -q -o " + shellQuote(archivePath) +
        " -d " + shellQuote(extractDirectory) + "; "
        "chown -R root:root " + shellQuote(extractDirectory) + "; "
        "chmod -R u+rwX,go+rX,go-w,a-s " + shellQuote(extractDirectory) + "; "
        "script=$(find " + shellQuote(extractDirectory) +
        " -maxdepth 4 -type f -name 'telegram_bot.py' ! -path '*/__MACOSX/*' "
        "-printf '%d\\t%p\\n' | sort -n | head -n 1 | cut -f2-); "
        "if [ -z \"$script\" ]; then "
        "echo 'ERROR: telegram_bot.py not found after extraction' >&2; "
        "find " + shellQuote(extractDirectory) +
        " -maxdepth 5 -print >&2; "
        "exit 20; "
        "fi; "
        "printf '\\nSERVERGUARD_SCRIPT_PATH=%s\\n' \"$script\"; "
        "printf 'SERVERGUARD_REPOSITORY_ROOT=%s\\n' "
        "\"$(dirname \"$script\")\"";

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Repository extraction or search failed.\n";

        if (!output.empty())
            std::cout << output << '\n';

        std::cout << "Remote exit code: " << exitCode << '\n';
        return false;
    }

    // Маркер принимается только в начале строки, поэтому диагностические
    // сообщения не могут привести к неверному пути.
    std::string foundRoot;

    if (!sgFindMarker(output, "SERVERGUARD_REPOSITORY_ROOT=", foundRoot))
    {
        std::cout << "Could not determine Telegram repository root.\n";

        if (!output.empty())
            std::cout << output << '\n';

        return false;
    }

    if (foundRoot.empty() || foundRoot[0] != '/')
    {
        std::cout << "Repository root is empty or not an absolute path: ["
            << foundRoot << "]\n";
        return false;
    }

    repositoryRoot = foundRoot;

    std::cout << "Repository extracted successfully.\n";
    std::cout << "Repository root:\n" << repositoryRoot << '\n';

    return true;
}

bool TelegramBot::validateRepository(const std::string& repositoryRoot)
{
    std::cout << "\nValidating Telegram repository...\n";
    std::cout << "Repository root: [" << repositoryRoot << "]\n";

    if (repositoryRoot.empty())
    {
        std::cout << "ERROR: repositoryRoot is empty.\n";
        return false;
    }

    const std::string mainScript = repositoryRoot + "/telegram_bot.py";

    std::string output;
    int exitCode = -1;

    // Каталог создан от root (через sudo), поэтому проверка тоже выполняется
    // с правами администратора. Команда всегда завершается кодом 0:
    // результат определяется по маркерам, а не по коду последней команды.
    const std::string checkCommand =
        "if [ -d " + shellQuote(repositoryRoot) + " ]; then "
        "echo 'REPOSITORY_DIRECTORY_EXISTS'; "
        "else echo 'REPOSITORY_DIRECTORY_MISSING'; fi; "
        "if [ -f " + shellQuote(mainScript) + " ]; then "
        "echo 'TELEGRAM_SCRIPT_EXISTS'; "
        "else echo 'TELEGRAM_SCRIPT_MISSING'; fi; "
        "printf 'ACTUAL_ROOT='; "
        "ls -ld " + shellQuote(repositoryRoot) + " 2>&1; "
        "printf '\\nROOT_CONTENTS:\\n'; "
        "ls -la " + shellQuote(repositoryRoot) + " 2>&1; "
        "printf '\\nSCRIPT_SEARCH:\\n'; "
        "find " + shellQuote(repositoryRoot) +
        " -maxdepth 4 -type f -name 'telegram_bot.py' -print 2>&1; "
        "exit 0";

    const bool checkExecuted =
        executeRemote(checkCommand, output, exitCode, true);

    if (!checkExecuted)
    {
        std::cout << "ERROR: Could not execute repository diagnostic command.\n";
        std::cout << "Remote exit code: " << exitCode << "\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << output << "\n";

    std::string ignored;

    if (!sgFindMarker(output, "REPOSITORY_DIRECTORY_EXISTS", ignored))
    {
        std::cout << "ERROR: Repository directory does not exist.\n";
        return false;
    }

    if (!sgFindMarker(output, "TELEGRAM_SCRIPT_EXISTS", ignored))
    {
        std::cout << "ERROR: telegram_bot.py is missing from repository root.\n";
        std::cout << "Expected file:\n" << mainScript << "\n";
        return false;
    }

    std::cout << "Main Telegram bot file found:\n"
        << mainScript << "\n";

    std::cout << "\nChecking Python syntax for repository...\n";

    // Проверка синтаксиса не исполняет код бота (только разбор AST).
    if (!checkPythonSyntax(mainScript))
    {
        std::cout << "ERROR: Python syntax validation failed.\n";
        return false;
    }

    std::cout << "Python syntax validation successful.\n";
    std::cout << "Repository validation successful.\n";

    return true;
}


bool TelegramBot::setRepositoryPermissions()
{
    std::cout << "\nConfiguring Telegram repository permissions...\n";

    std::string output;
    int exitCode = -1;

    // venv и queue пропускаются (-prune): раньше chmod 644 снимал бит
    // исполнения с файлов в venv/bin и менял права файлов очереди.
    // Все файлы принадлежат root, обычный SSH-пользователь не может их изменить.
    const std::string pruneVenvAndQueue =
        "\\( -path " + shellQuote(TELEGRAM_VENV) +
        " -o -path " + shellQuote(TELEGRAM_QUEUE) + " \\) -prune -o ";

    std::string command =
        "find " + shellQuote(TELEGRAM_DIR) + " " + pruneVenvAndQueue +
        "-type d -exec chmod 755 {} + && "
        "find " + shellQuote(TELEGRAM_DIR) + " " + pruneVenvAndQueue +
        "-type f "
        "! -path " + shellQuote(TELEGRAM_CONFIG) + " "
        "! -path " + shellQuote(TELEGRAM_VERIFICATION) + " "
        "! -path " + shellQuote(TELEGRAM_OWNER) + " -exec chmod 644 {} + && "
        "chmod 755 " + shellQuote(TELEGRAM_SCRIPT) + " && "
        "chown -R root:root " + shellQuote(TELEGRAM_DIR);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot configure repository permissions.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    // Секреты: только root.
    command =
        "chmod 600 " + shellQuote(TELEGRAM_CONFIG) + " 2>/dev/null || true; "
        "chmod 600 " + shellQuote(TELEGRAM_VERIFICATION) + " 2>/dev/null || true; "
        "chmod 600 " + shellQuote(TELEGRAM_OWNER) + " 2>/dev/null || true; "
        "chown -R root:root " + shellQuote(TELEGRAM_QUEUE) + " 2>/dev/null || true; "
        "chown -R root:root " + shellQuote(TELEGRAM_VENV) + " 2>/dev/null || true";

    executeRemote(command, output, exitCode, true);

    std::cout << "Repository permissions configured.\n";

    return true;
}

bool TelegramBot::installRepositoryFiles(const std::string& repositoryRoot)
{
    std::cout << "\nInstalling Telegram repository files...\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "find " + shellQuote(repositoryRoot) + " -mindepth 1 -maxdepth 1 "
        "! -name telegram.conf "
        "! -name verification.json "
        "! -name owner.json "
        "! -name queue "
        "! -name venv "
        "-exec cp -a {} " + shellQuote(TELEGRAM_DIR) + "/ \\;";

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot install repository files.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    if (!setRepositoryPermissions())
        return false;

    std::cout << "Telegram repository installed successfully.\n";

    return true;
}

bool TelegramBot::downloadBot()
{
    std::cout << "\nDownloading Telegram bot repository...\n";

    if (!ensureUnzip())
        return false;

    std::string output;
    int exitCode = -1;

    executeRemote("rm -rf " + shellQuote(TELEGRAM_UPDATE_DIR) + " " + shellQuote(TELEGRAM_UPDATE_ZIP), output, exitCode, true);

    if (!downloadRepositoryArchive(TELEGRAM_UPDATE_ZIP))
        return false;

    std::string repositoryRoot;

    if (!extractRepository(TELEGRAM_UPDATE_ZIP, TELEGRAM_UPDATE_DIR, repositoryRoot))
    {
        executeRemote("rm -rf " + shellQuote(TELEGRAM_UPDATE_DIR) + " " + shellQuote(TELEGRAM_UPDATE_ZIP), output, exitCode, true);
        return false;
    }

    if (!validateRepository(repositoryRoot))
    {
        std::cout << "\nTelegram repository validation failed.\n";

        executeRemote("rm -rf " + shellQuote(TELEGRAM_UPDATE_DIR) + " " + shellQuote(TELEGRAM_UPDATE_ZIP), output, exitCode, true);

        return false;
    }

    if (!installRepositoryFiles(repositoryRoot))
    {
        std::cout << "\nFailed to install Telegram repository.\n";

        executeRemote("rm -rf " + shellQuote(TELEGRAM_UPDATE_DIR) + " " + shellQuote(TELEGRAM_UPDATE_ZIP), output, exitCode, true);

        return false;
    }

    executeRemote("rm -rf " + shellQuote(TELEGRAM_UPDATE_DIR) + " " + shellQuote(TELEGRAM_UPDATE_ZIP), output, exitCode, true);

    if (!checkScript())
    {
        std::cout << "Telegram bot script is missing after installation.\n";
        return false;
    }

    if (!checkPythonSyntax(TELEGRAM_SCRIPT))
    {
        std::cout << "Telegram bot Python syntax check failed.\n";
        return false;
    }

    std::cout << "\nTelegram bot repository installed successfully.\n";

    return true;
}

bool TelegramBot::configExists()
{
    std::string output;
    int exitCode = -1;

    // Конфигурация лежит в каталоге root. Проверка без sudo на Azure могла
    // дать ложное "не существует" и привести к повторному запросу токена.
    executeRemote("test -s " + shellQuote(TELEGRAM_CONFIG), output, exitCode, true);

    return exitCode == 0;
}

std::string TelegramBot::readBotToken()
{
    std::string token;

    std::cout << "\n";
    std::cout << "Telegram Bot Token\n";
    std::cout << "------------------\n";
    std::cout << "Enter token: ";

    std::getline(std::cin >> std::ws, token);

    return token;
}

bool TelegramBot::createConfig()
{
    if (configExists())
    {
        std::cout << "\nTelegram configuration already exists.\n";
        std::cout << "Existing bot token will be preserved.\n";
        return true;
    }

    std::cout << "\nConfiguring Telegram bot...\n";

    std::string token = readBotToken();

    if (token.empty())
    {
        std::cout << "Bot token cannot be empty.\n";
        return false;
    }

    std::size_t colon = token.find(':');

    if (colon == std::string::npos || colon == 0 || colon == token.size() - 1)
    {
        std::cout << "Telegram token format looks invalid.\n";
        std::cout << "Expected format:\n";
        std::cout << "123456789:AAxxxxxxxx...\n";
        return false;
    }

    for (unsigned char c : token)
    {
        if (!(std::isalnum(c) || c == ':' || c == '_' || c == '-'))
        {
            std::cout << "Telegram token contains invalid characters.\n";
            return false;
        }
    }

    std::string config = "BOT_TOKEN=" + token + "\n";
    std::string encoded = base64Encode(config);

    // umask 077: файл с токеном никогда не бывает читаемым для других,
    // даже на короткое время до chmod.
    std::string command =
        "umask 077 && echo " + shellQuote(encoded) + " | base64 -d > " + shellQuote(TELEGRAM_CONFIG) +
        " && chmod 600 " + shellQuote(TELEGRAM_CONFIG) +
        " && chown root:root " + shellQuote(TELEGRAM_CONFIG);

    std::string output;
    int exitCode = -1;

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create Telegram configuration.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << "Telegram configuration created.\n";

    return true;
}

bool TelegramBot::createConfig(const std::string& token)
{
    if (token.empty())
    {
        std::cout << "Telegram bot token cannot be empty.\n";
        return false;
    }

    const std::size_t colon = token.find(':');

    if (colon == std::string::npos ||
        colon == 0 ||
        colon == token.size() - 1)
    {
        std::cout << "Telegram token format looks invalid.\n";
        return false;
    }

    for (unsigned char c : token)
    {
        if (!(std::isalnum(c) || c == ':' || c == '_' || c == '-'))
        {
            std::cout << "Telegram token contains invalid characters.\n";
            return false;
        }
    }

    const std::string config = "BOT_TOKEN=" + token + "\n";
    const std::string encoded = base64Encode(config);

    const std::string command =
        "umask 077 && printf '%s' " + shellQuote(encoded) +
        " | base64 -d > " + shellQuote(TELEGRAM_CONFIG) +
        " && chmod 600 " + shellQuote(TELEGRAM_CONFIG) +
        " && chown root:root " + shellQuote(TELEGRAM_CONFIG);

    std::string output;
    int exitCode = -1;

    if (!executeRemote(command, output, exitCode, true) ||
        exitCode != 0)
    {
        std::cout << "Failed to save Telegram configuration.\n";

        if (!output.empty())
            std::cout << output << '\n';

        return false;
    }

    if (!configExists())
    {
        std::cout << "Telegram configuration was not created.\n";
        return false;
    }

    std::cout << "Telegram configuration saved successfully.\n";
    return true;
}


bool TelegramBot::createSystemdService()
{
    std::cout << "\nCreating Telegram systemd service...\n";

    std::string service;

    service += "[Unit]\n";
    service += "Description=ServerGuard Telegram Security Bot\n";
    service += "After=network-online.target\n";
    service += "Wants=network-online.target\n\n";
    service += "[Service]\n";
    service += "Type=simple\n";
    service += "ExecStart=" + TELEGRAM_VENV + "/bin/python " + TELEGRAM_SCRIPT + "\n";
    service += "WorkingDirectory=" + TELEGRAM_DIR + "\n";
    service += "User=root\n";
    service += "Group=root\n";
    service += "Restart=always\n";
    service += "RestartSec=5\n";
    service += "Environment=PYTHONUNBUFFERED=1\n";
    service += "NoNewPrivileges=false\n\n";
    service += "[Install]\n";
    service += "WantedBy=multi-user.target\n";

    std::string encoded = base64Encode(service);

    std::string command = "echo " + shellQuote(encoded) + " | base64 -d > " + shellQuote(TELEGRAM_SERVICE_PATH);

    std::string output;
    int exitCode = -1;

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create Telegram systemd service.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    command = "chmod 644 " + shellQuote(TELEGRAM_SERVICE_PATH) + " && chown root:root " + shellQuote(TELEGRAM_SERVICE_PATH);

    output.clear();
    exitCode = -1;

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot configure service permissions.\n";
        return false;
    }

    std::cout << "Telegram systemd service created.\n";

    return true;
}

bool TelegramBot::reloadSystemd()
{
    std::cout << "\nReloading systemd...\n";

    std::string output;
    int exitCode = -1;

    if (!executeRemote("systemctl daemon-reload", output, exitCode, true))
    {
        std::cout << "systemd reload failed.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << "systemd reloaded.\n";

    return true;
}

bool TelegramBot::startService()
{
    std::cout << "\nStarting Telegram bot...\n";

    std::string output;
    int exitCode = -1;

    if (!executeRemote("systemctl start " + TELEGRAM_SERVICE, output, exitCode, true))
    {
        std::cout << "Failed to start Telegram bot.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << "Telegram bot started.\n";

    return true;
}

bool TelegramBot::serviceExists()
{
    std::string output;
    int exitCode = -1;

    executeRemote("test -f " + shellQuote(TELEGRAM_SERVICE_PATH), output, exitCode, false);

    return exitCode == 0;
}

bool TelegramBot::serviceIsActive()
{
    std::string output;
    int exitCode = -1;

    executeRemote("systemctl is-active --quiet " + TELEGRAM_SERVICE, output, exitCode, false);

    return exitCode == 0;
}

bool TelegramBot::downloadUpdateFile(const std::string& url, const std::string& destination)
{
    std::cout << "Downloading:\n" << url << "\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "curl -fL --silent --show-error "
        "--connect-timeout 15 "
        "--max-time 120 "
        "--retry 2 "
        "--retry-delay 2 "
        "-o " + shellQuote(destination) + " " + shellQuote(url);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Download failed.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    output.clear();
    exitCode = -1;

    if (!executeRemote("test -s " + shellQuote(destination), output, exitCode, true))
    {
        std::cout << "Downloaded file is empty or missing.\n";
        return false;
    }

    std::cout << "Download successful.\n";

    return true;
}

bool TelegramBot::checkPythonSyntax(const std::string& file)
{
    std::cout << "Checking Python syntax:\n" << file << "\n";

    std::string output;
    int exitCode = -1;

    std::string python = TELEGRAM_VENV + "/bin/python";

    // Файлы и venv принадлежат root, поэтому нужен sudo. Используется разбор
    // AST: код бота НЕ исполняется и не импортируется, а py_compile больше не
    // создаёт __pycache__ с файлами root внутри каталога бота.
    const std::string script =
        "import ast,sys; "
        "ast.parse(open(sys.argv[1],encoding=\"utf-8\").read(),sys.argv[1])";

    const std::string command =
        shellQuote(python) + " -c " + shellQuote(script) + " " + shellQuote(file);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Python syntax check FAILED.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << "Python syntax is valid.\n";

    return true;
}

bool TelegramBot::requirementsExists()
{
    std::string output;
    int exitCode = -1;

    std::string requirements = TELEGRAM_DIR + "/requirements.txt";

    executeRemote("test -s " + shellQuote(requirements), output, exitCode, true);

    return exitCode == 0;
}

bool TelegramBot::updateRequirements()
{
    std::cout << "\nUpdating Python libraries from requirements.txt...\n";

    std::string output;
    int exitCode = -1;

    std::string python = TELEGRAM_VENV + "/bin/python";
    std::string requirements = TELEGRAM_DIR + "/requirements.txt";

    std::string command = shellQuote(python) + " -m pip install --upgrade -r " + shellQuote(requirements);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Failed to update Python libraries.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    if (!output.empty())
        std::cout << output;

    std::cout << "Python libraries updated.\n";

    return true;
}

bool TelegramBot::updatePythonLibraries()
{
    std::cout << "\n============================================\n";
    std::cout << "          PYTHON LIBRARY UPDATE\n";
    std::cout << "============================================\n\n";

    if (requirementsExists())
    {
        std::cout << "requirements.txt found.\n";
        return updateRequirements();
    }

    std::cout << "requirements.txt was not found.\n";
    std::cout << "Using aiogram update fallback.\n";

    std::string output;
    int exitCode = -1;

    std::string python = TELEGRAM_VENV + "/bin/python";
    std::string command = shellQuote(python) + " -m pip install --upgrade aiogram";

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Failed to update aiogram.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    if (!output.empty())
        std::cout << output;

    std::cout << "aiogram updated successfully.\n";

    return true;
}

bool TelegramBot::backupTelegramCode()
{
    std::cout << "\nCreating complete Telegram bot backup...\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "rm -rf " + shellQuote(TELEGRAM_CODE_BACKUP) + " && "
        "mkdir -p " + shellQuote(TELEGRAM_CODE_BACKUP) + " && "
        "find " + shellQuote(TELEGRAM_DIR) + " -mindepth 1 -maxdepth 1 "
        "! -name telegram.conf "
        "! -name verification.json "
        "! -name owner.json "
        "! -name queue "
        "! -name venv "
        "! -name .repository_update "
        "-exec cp -a {} " + shellQuote(TELEGRAM_CODE_BACKUP) + "/ \\;";

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot create complete Telegram backup.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << "Complete Telegram bot backup created:\n" << TELEGRAM_CODE_BACKUP << "\n";

    return true;
}

bool TelegramBot::clearTelegramCode()
{
    std::cout << "\nRemoving old Telegram bot code...\n";

    std::string output;
    int exitCode = -1;

    std::string command =
        "find " + shellQuote(TELEGRAM_DIR) + " -mindepth 1 -maxdepth 1 "
        "! -name telegram.conf "
        "! -name verification.json "
        "! -name owner.json "
        "! -name queue "
        "! -name venv "
        "! -name .repository_update "
        "-exec rm -rf {} \\;";

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot remove old Telegram bot code.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    std::cout << "Old Telegram bot code removed.\n";

    return true;
}

bool TelegramBot::restoreTelegramCode()
{
    std::cout << "\nRestoring previous Telegram bot version...\n";

    std::string output;
    int exitCode = -1;

    // Сначала убеждаемся, что резервная копия существует (каталог принадлежит
    // root, поэтому проверка с sudo), и только потом удаляем текущий код.
    // Раньше код удалялся до проверки: если проверка падала, бот оставался
    // без файлов.
    std::string command = "test -d " + shellQuote(TELEGRAM_CODE_BACKUP);

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Telegram backup does not exist.\n";
        return false;
    }

    if (!clearTelegramCode())
    {
        std::cout << "Cannot clear failed Telegram version.\n";
        return false;
    }

    command =
        "find " + shellQuote(TELEGRAM_CODE_BACKUP) + " -mindepth 1 -maxdepth 1 "
        "-exec cp -a {} " + shellQuote(TELEGRAM_DIR) + "/ \\;";

    if (!executeRemote(command, output, exitCode, true))
    {
        std::cout << "Cannot restore Telegram bot backup.\n";

        if (!output.empty())
            std::cout << output << "\n";

        return false;
    }

    setRepositoryPermissions();

    std::cout << "Previous Telegram bot version restored.\n";

    return true;
}

void TelegramBot::showUpdateLogs()
{
    std::cout << "\n";
    std::cout << "============================================\n";
    std::cout << "        TELEGRAM SERVICE LOGS\n";
    std::cout << "============================================\n\n";

    std::string logs;
    int exitCode = -1;

    // Журнал systemd доступен не каждому пользователю, поэтому с sudo.
    executeRemote("journalctl -u " + TELEGRAM_SERVICE + " -n 50 --no-pager", logs, exitCode, true);

    if (!logs.empty())
        std::cout << logs;

    std::cout << "\n";
}

bool TelegramBot::isActive()
{
    return serviceIsActive();
}

void TelegramBot::menu()
{
    while (true)
    {
        std::cout << "\n";
        std::cout << "============================================\n";
        std::cout << "             TELEGRAM BOT\n";
        std::cout << "============================================\n\n";

        bool active = serviceIsActive();

        std::cout << "Telegram bot: " << (active ? "ACTIVE" : "INACTIVE") << "\n\n";
        std::cout << "1. Install / configure bot\n";
        std::cout << "2. Generate verification code\n";
        std::cout << "3. Start bot\n";
        std::cout << "4. Stop bot\n";
        std::cout << "5. Restart bot\n";
        std::cout << "6. Disable automatic startup\n";
        std::cout << "7. Update bot\n";
        std::cout << "8. Check status\n";
        std::cout << "9. Show logs\n";
        std::cout << "10. Remove bot\n";
        std::cout << "0. Back\n\n";
        std::cout << "Select: ";

        std::string choice;
        std::getline(std::cin >> std::ws, choice);

        if (choice == "1")
        {
            install();
            continue;
        }

        if (choice == "2")
        {
            generateCode();
            continue;
        }

        if (choice == "3")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";
                continue;
            }

            if (startService())
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));

                if (serviceIsActive())
                    std::cout << "Telegram bot is ACTIVE.\n";
                else
                    std::cout << "Telegram bot failed to start.\n";
            }

            continue;
        }

        if (choice == "4")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";
                continue;
            }

            if (stopService())
                std::cout << "Telegram bot stopped.\n";

            continue;
        }

        if (choice == "5")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";
                continue;
            }

            restartService();

            std::this_thread::sleep_for(std::chrono::seconds(1));

            if (serviceIsActive())
                std::cout << "Telegram bot is ACTIVE.\n";

            continue;
        }

        if (choice == "6")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";
                continue;
            }

            if (disableService())
                std::cout << "Automatic startup disabled.\n";

            continue;
        }

        if (choice == "7")
        {
            updateBot();
            continue;
        }

        if (choice == "8")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";
                continue;
            }

            std::string output;
            int exitCode = -1;

            executeRemote("systemctl status " + TELEGRAM_SERVICE + " --no-pager", output, exitCode, true);

            std::cout << "\n";

            if (!output.empty())
                std::cout << output;

            continue;
        }

        if (choice == "9")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";
                continue;
            }

            std::string output;
            int exitCode = -1;

            executeRemote("journalctl -u " + TELEGRAM_SERVICE + " -n 50 --no-pager", output, exitCode, true);

            std::cout << "\n";
            std::cout << "============================================\n";
            std::cout << "             TELEGRAM LOGS\n";
            std::cout << "============================================\n\n";

            if (!output.empty())
                std::cout << output;

            std::cout << "\n";

            continue;
        }

        if (choice == "10")
        {
            if (!serviceExists())
            {
                std::cout << "\nTelegram bot is not installed.\n";
                continue;
            }

            std::cout << "\nWARNING: This will remove the Telegram bot.\n";
            std::cout << "Continue? (yes/no): ";

            std::string confirmation;
            std::getline(std::cin >> std::ws, confirmation);

            if (confirmation == "yes")
                removeInstallation();
            else
                std::cout << "Cancelled.\n";

            continue;
        }

        if (choice == "0")
            break;

        std::cout << "Unknown option.\n";
    }
}

bool TelegramBot::webStart()
{
    if (!serviceExists())
        return false;

    return startService();
}

std::string TelegramBot::webStatus()
{
    bool installed = serviceExists();
    bool active = false;
    bool enabled = false;
    bool config = configExists();
    bool script = checkScript();
    bool requirements = requirementsExists();

    if (installed)
    {
        active = serviceIsActive();

        std::string output;
        int exitCode = -1;

        executeRemote("systemctl is-enabled --quiet " + TELEGRAM_SERVICE, output, exitCode, false);

        enabled = (exitCode == 0);
    }

    std::ostringstream json;

    json << "{"
        << "\"installed\":" << (installed ? "true" : "false") << ","
        << "\"active\":" << (active ? "true" : "false") << ","
        << "\"enabled\":" << (enabled ? "true" : "false") << ","
        << "\"config\":" << (config ? "true" : "false") << ","
        << "\"script\":" << (script ? "true" : "false") << ","
        << "\"requirements\":" << (requirements ? "true" : "false") << ","
        << "\"service\":\"" << TELEGRAM_SERVICE << "\","
        << "\"directory\":\"" << TELEGRAM_DIR << "\""
        << "}";

    return json.str();
}

std::string TelegramBot::webLogs()
{
    std::string logs;
    int exitCode = -1;

    executeRemote("journalctl -u " + TELEGRAM_SERVICE + " -n 100 --no-pager", logs, exitCode, true);

    return logs;
}