
cmake_minimum_required(VERSION 3.21)

project(ServerGuard VERSION 1.1.13 LANGUAGES CXX)

# ============================================================
# General settings
# ============================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================
# Source files
# Keep this list explicit to avoid including build artifacts
# and accidentally compiling extra files with main() functions.
# ============================================================

set(SG_SOURCES
    FileGuard.cpp
    Help.cpp
    SSHHardening.cpp
    SSHKeyGuard.cpp
    Security.cpp
    TelegramBot.cpp
    Web.cpp
    WebServer.cpp

    autostart_disable/TelegramBot_DisableAutostart.cpp
    autostart_enable/TelegramBot_EnableAutostart.cpp
    generate_code/TelegramBot_GenerateCode.cpp

    handlers/WebServer_Hardening.cpp
    handlers/WebServer_Security.cpp
    handlers/WebServer_ServerStats.cpp
    handlers/WebServer_SshKeyGuard.cpp
    handlers/WebServer_Stop.cpp
    handlers/WebServer_TelegramBot.cpp

    install/TelegramBot_Install.cpp
    main.cpp
    remove/TelegramBot_Remove.cpp
    restart/TelegramBot_Restart.cpp
    stop/TelegramBot_Stop.cpp
    update/TelegramBot_Update.cpp
)

# Fail early if a source file was moved or renamed.
foreach(SG_SOURCE IN LISTS SG_SOURCES)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${SG_SOURCE}")
        message(FATAL_ERROR
            "ServerGuard source file not found: ${SG_SOURCE}")
    endif()
endforeach()

# ============================================================
# Dependencies
# ============================================================

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

if(WIN32)
    # vcpkg installation for Windows x64.
    set(SG_VCPKG_ROOT
        "C:/vcpkg/installed/x64-windows"
        CACHE PATH "vcpkg x64-windows installation")

    set(SG_VCPKG_INCLUDE_DIR "${SG_VCPKG_ROOT}/include")
    set(SG_VCPKG_LIB_DIR "${SG_VCPKG_ROOT}/lib")
    set(SG_VCPKG_DEBUG_LIB_DIR "${SG_VCPKG_ROOT}/debug/lib")
    set(SG_VCPKG_BIN_DIR "${SG_VCPKG_ROOT}/bin")

    if(NOT EXISTS "${SG_VCPKG_INCLUDE_DIR}/libssh2.h")
        message(FATAL_ERROR
            "libssh2.h not found: ${SG_VCPKG_INCLUDE_DIR}")
    endif()

    if(NOT EXISTS "${SG_VCPKG_LIB_DIR}/libssh2.lib")
        message(FATAL_ERROR
            "libssh2.lib not found: ${SG_VCPKG_LIB_DIR}")
    endif()

    add_library(sg_libssh2 UNKNOWN IMPORTED GLOBAL)

    set_target_properties(sg_libssh2 PROPERTIES
        IMPORTED_CONFIGURATIONS "Debug;Release;RelWithDebInfo;MinSizeRel"
        IMPORTED_LOCATION_RELEASE
            "${SG_VCPKG_LIB_DIR}/libssh2.lib"
        IMPORTED_LOCATION_RELWITHDEBINFO
            "${SG_VCPKG_LIB_DIR}/libssh2.lib"
        IMPORTED_LOCATION_MINSIZEREL
            "${SG_VCPKG_LIB_DIR}/libssh2.lib"
        INTERFACE_INCLUDE_DIRECTORIES
            "${SG_VCPKG_INCLUDE_DIR}"
    )

    if(EXISTS "${SG_VCPKG_DEBUG_LIB_DIR}/libssh2.lib")
        set_target_properties(sg_libssh2 PROPERTIES
            IMPORTED_LOCATION_DEBUG
                "${SG_VCPKG_DEBUG_LIB_DIR}/libssh2.lib"
        )
    else()
        set_target_properties(sg_libssh2 PROPERTIES
            MAP_IMPORTED_CONFIG_DEBUG Release
        )
    endif()

else()
    find_path(LIBSSH2_INCLUDE_DIR
        NAMES libssh2.h
        REQUIRED
    )

    find_library(LIBSSH2_LIBRARY
        NAMES ssh2 libssh2
        REQUIRED
    )

    add_library(sg_libssh2 UNKNOWN IMPORTED GLOBAL)

    set_target_properties(sg_libssh2 PROPERTIES
        IMPORTED_LOCATION "${LIBSSH2_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH2_INCLUDE_DIR}"
    )

    find_package(Threads REQUIRED)
endif()

# ============================================================
# Executable
# ============================================================

add_executable(ServerGuard ${SG_SOURCES})

target_include_directories(ServerGuard PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries(ServerGuard PRIVATE
    sg_libssh2
    OpenSSL::Crypto
)

if(MSVC)
    target_compile_options(ServerGuard PRIVATE /utf-8)
endif()

# ============================================================
# Platform-specific libraries and release packaging
# ============================================================

if(WIN32)
    target_link_libraries(ServerGuard PRIVATE
        ws2_32
        crypt32
        bcrypt
        shell32
        urlmon
        wininet
    )

    set(SG_RELEASE_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/dist/windows-x64")

    # Package the executable and required runtime DLLs.
    set(SG_RUNTIME_DLLS
        libssh2.dll
        libcrypto-3-x64.dll
        libssl-3-x64.dll
        z.dll
        legacy.dll
    )

    add_custom_command(TARGET ServerGuard POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${SG_RELEASE_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:ServerGuard>"
            "${SG_RELEASE_DIR}/"
        VERBATIM
    )

    foreach(SG_DLL IN LISTS SG_RUNTIME_DLLS)
        if(EXISTS "${SG_VCPKG_BIN_DIR}/${SG_DLL}")
            add_custom_command(TARGET ServerGuard POST_BUILD
                COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                    "${SG_VCPKG_BIN_DIR}/${SG_DLL}"
                    "${SG_RELEASE_DIR}/"
                VERBATIM
            )
        endif()
    endforeach()

    message(STATUS "ServerGuard target platform: Windows")

else()
    target_link_libraries(ServerGuard PRIVATE
        Threads::Threads
    )

    set(SG_RELEASE_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/dist/linux-x64")

    add_custom_command(TARGET ServerGuard POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${SG_RELEASE_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "$<TARGET_FILE:ServerGuard>"
            "${SG_RELEASE_DIR}/"
        VERBATIM
    )

    # Install rules for Linux packages.
    install(TARGETS ServerGuard
        RUNTIME DESTINATION bin
    )

    if(EXISTS
        "${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/update-serverguard.sh")
        install(PROGRAMS
            "${CMAKE_CURRENT_SOURCE_DIR}/packaging/linux/update-serverguard.sh"
            DESTINATION share/serverguard
        )
    endif()

    message(STATUS "ServerGuard target platform: Linux")
endif()

message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Release output: ${SG_RELEASE_DIR}")
