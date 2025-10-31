cmake_minimum_required(VERSION 3.15)
project(net-net CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set PKG_CONFIG_PATH for keg-only libpcap
set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/libpcap/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

# Find libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Core library
add_library(netnet-core
    src/net/PcapAdapter.cpp
)

target_include_directories(netnet-core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net
    PRIVATE
        ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(netnet-core
    PRIVATE
        ${PCAP_LIBRARIES}
        pthread
)

# Main executable (for testing)
add_executable(netnet
    src/main.cpp
)

target_link_libraries(netnet
    PRIVATE
        netnet-core
)