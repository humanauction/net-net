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
        ${CMAKE_CURRENT_SOURCE_DIR}/src
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

# Testing START
enable_testing()

find_package(GTest REQUIRED)

# TEST runner
add_executable(test_runner 
    tests/unit/test_pcap_adapter.cpp
)

target_link_libraries(test_runner
    PRIVATE
        netnet-core
        GTest::GTest
        GTest::Main
)

target_compile_definitions(test_runner
    PRIVATE
        CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME PcapAdapterTests COMMAND test_runner)

# TEST parser
add_executable(test_parser
    tests/unit/test_parser.cpp
    src/core/parser.cpp
)

target_include_directories(test_parser
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

target_link_libraries(test_parser
    PRIVATE
        GTest::GTest
        GTest::Main
)

add_test(NAME ParserTests COMMAND test_parser)

# TEST connection tracker
add_executable(test_connection_tracker
    tests/integration/test_connection_tracker.cpp
    src/core/parser.cpp
    src/core/ConnectionTracker.cpp
)

target_include_directories(test_connection_tracker
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

target_link_libraries(test_connection_tracker
    PRIVATE
    GTest::GTest
    GTest::Main
)

add_test(NAME ConnectionTrackerIntegration COMMAND test_connection_tracker)

# TEST StatsAggregator correctly aggregates flows and maintains history

add_executable(test_stats_aggregator
    tests/unit/test_stats_aggregator.cpp
    src/core/StatsAggregator.cpp
    src/core/parser.cpp
    src/core/ConnectionTracker.cpp
)

target_include_directories(test_stats_aggregator
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

target_link_libraries(test_stats_aggregator
    PRIVATE
    GTest::GTest
    GTest::Main
)

add_test(NAME StatsAggregatorTests COMMAND test_stats_aggregator)

# TEST aggregated metrics: Feed packets (real or synthetic pcap file) through parser and StatsAggregator.

add_executable(test_stats_aggregator_integration
    tests/integration/test_stats_aggregator_integration.cpp
    src/core/StatsAggregator.cpp
    src/core/parser.cpp
)

target_include_directories(test_stats_aggregator_integration
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net
)

target_link_libraries(test_stats_aggregator_integration
    PRIVATE
        GTest::GTest
        GTest::Main
        pcap
)

add_test(NAME StatsAggregatorIntegration COMMAND test_stats_aggregator_integration)