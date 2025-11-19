cmake_minimum_required(VERSION 3.15)
project(net-net CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set PKG_CONFIG_PATH for keg-only libpcap
set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/libpcap/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

# pkg-config and modules
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# Find OpenSSL and yaml-cpp early
find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)

# Vendor include dir
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor)

# Core library
add_library(netnet-core STATIC
)

target_include_directories(netnet-core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    PRIVATE
        ${PCAP_INCLUDE_DIRS}
        ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(netnet-core
    PRIVATE
        ${PCAP_LIBRARIES}
        pthread
)

# Main executable (for testing)
add_executable(netnet
)

target_include_directories(netnet
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net
        ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(netnet
    PRIVATE
        netnet-core
        yaml-cpp
        ${SQLITE3_LIBRARIES}
)

# Testing setup (unchanged)
enable_testing()
find_package(GTest REQUIRED)
# ... test targets unchanged ...

# API daemon executable
add_executable(netnet-daemon
)

target_include_directories(netnet-daemon
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net
        ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
        ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(netnet-daemon
    PRIVATE
        netnet-core
        yaml-cpp
        pthread
        ${PCAP_LIBRARIES}
        ${SQLITE3_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
)
