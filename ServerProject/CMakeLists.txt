cmake_minimum_required(VERSION 3.16)
project(ServerGuard CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Linux packages (Debian/Ubuntu):
#   sudo apt install build-essential cmake libssh2-1-dev libssl-dev curl
# Windows: libssh2 + OpenSSL via vcpkg:
#   vcpkg install libssh2:x64-windows
#   cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

find_package(OpenSSL REQUIRED)

if(WIN32)
    find_package(Libssh2 CONFIG REQUIRED)
    set(SG_SSH2_TARGET Libssh2::libssh2)
else()
    find_library(LIBSSH2_LIB ssh2 REQUIRED)
    find_path(LIBSSH2_INCLUDE_DIR libssh2.h REQUIRED)

    add_library(sg_libssh2 INTERFACE)
    target_link_libraries(sg_libssh2 INTERFACE ${LIBSSH2_LIB})
    target_include_directories(sg_libssh2 INTERFACE ${LIBSSH2_INCLUDE_DIR})

    set(SG_SSH2_TARGET sg_libssh2)
endif()

# Sources live in the project root AND in subfolders (install/, handlers/, ...).
file(GLOB_RECURSE SG_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

# Skip build output folders (build, build-linux, build-cmake, ...) and
# CMake-generated files such as CMakeCXXCompilerId.cpp (it has its own main()).
list(FILTER SG_SOURCES EXCLUDE REGEX "/(build[^/]*|CMakeFiles|x64|\\.git)/")

# Security/install.cpp and Security/update.cpp are excluded on purpose:
# Security.cpp already defines installSecurity()/updateSecurity().
# Remove this line if they turn out to hold code that is NOT in Security.cpp.
list(FILTER SG_SOURCES EXCLUDE REGEX "/Security/")

add_executable(ServerGuard ${SG_SOURCES})
target_include_directories(ServerGuard PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(ServerGuard PRIVATE ${SG_SSH2_TARGET} OpenSSL::Crypto)

if(MSVC)
    target_compile_options(ServerGuard PRIVATE /utf-8)
endif()

if(WIN32)
    target_link_libraries(ServerGuard PRIVATE
        ws2_32 crypt32 shell32 urlmon wininet)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(ServerGuard PRIVATE Threads::Threads)
endif()