cmake_minimum_required(VERSION 3.20)

project(ServerProject LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(libssh2 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

set(SERVERPROJECT_SOURCES
    autostart_disable/TelegramBot_DisableAutostart.cpp
    autostart_enable/TelegramBot_EnableAutostart.cpp
    FileGuard.cpp
    generate_code/TelegramBot_GenerateCode.cpp
    handlers/WebServer_Hardening.cpp
    handlers/WebServer_Security.cpp
    handlers/WebServer_ServerStats.cpp
    handlers/WebServer_SshKeyGuard.cpp
    handlers/WebServer_Stop.cpp
    handlers/WebServer_TelegramBot.cpp
    Help.cpp
    install/TelegramBot_Install.cpp
    main.cpp
    remove/TelegramBot_Remove.cpp
    restart/TelegramBot_Restart.cpp
    Security.cpp
    SSHHardening.cpp
    SSHKeyGuard.cpp
    stop/TelegramBot_Stop.cpp
    TelegramBot.cpp
    update/TelegramBot_Update.cpp
    Web.cpp
    WebServer.cpp
)

add_executable(ServerProject ${SERVERPROJECT_SOURCES})

if(TARGET unofficial::libssh2::libssh2)
    target_link_libraries(ServerProject PRIVATE unofficial::libssh2::libssh2)
elseif(TARGET libssh2::libssh2)
    target_link_libraries(ServerProject PRIVATE libssh2::libssh2)
elseif(TARGET libssh2)
    target_link_libraries(ServerProject PRIVATE libssh2)
else()
    message(FATAL_ERROR "libssh2 package was found, but its CMake target is unknown.")
endif()

target_link_libraries(ServerProject PRIVATE OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(ServerProject PRIVATE ws2_32 shell32)
    target_compile_definitions(ServerProject PRIVATE WIN32_LEAN_AND_MEAN)
endif()

