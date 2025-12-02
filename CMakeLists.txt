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

# Find OpenSSL, yaml-cpp, nlohmann_json early
find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(nlohmann_json REQUIRED)

# Find or add cpp-httplib
find_path(HTTPLIB_INCLUDE_DIR httplib.h
    PATHS /usr/local/include /opt/homebrew/include
)
if(NOT HTTPLIB_INCLUDE_DIR)
    message(FATAL_ERROR "httplib.h not found. Install: brew install cpp-httplib")
endif()

include_directories(${HTTPLIB_INCLUDE_DIR})

# Vendor include dir
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor)

# Core library
add_library(netnet-core STATIC
    src/core/ConnectionTracker.cpp
    src/core/parser.cpp
    src/net/PcapAdapter.cpp
    src/core/SessionManager.cpp
    src/core/StatsAggregator.cpp
    src/core/StatsPersistence.cpp
    include/net-net/vendor/bcrypt.cpp
    include/net-net/vendor/uuid_gen.cpp
)

target_include_directories(netnet-core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    PRIVATE
        ${PCAP_INCLUDE_DIRS}
        ${SQLITE3_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor    
)

target_link_libraries(netnet-core
    PRIVATE
        ${PCAP_LIBRARIES}
        ${SQLITE3_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto        
        pthread
)

# Main executable (for testing)
add_executable(netnet
    src/main.cpp
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

# Testing setup
enable_testing()
find_package(GTest REQUIRED)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
)

# Testing source directory
# add_definitions(-DCMAKE_SOURCE_DIR=\"${CMAKE_SOURCE_DIR}\")

# API daemon executable
# Test runner
add_executable(test_runner
    tests/unit/test_pcap_adapter.cpp
)

target_include_directories(test_runner PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(test_runner 
    PRIVATE 
        netnet-core GTest::gtest GTest::gtest_main pthread
)

# TEST Parser
add_executable(test_parser
    tests/unit/test_parser.cpp
    src/core/parser.cpp
)
target_include_directories(test_parser 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_parser 
    PRIVATE 
        GTest::gtest GTest::gtest_main
)

# TEST Connection Tracker
add_executable(test_connection_tracker
    tests/integration/test_connection_tracker.cpp
    src/core/parser.cpp
    src/core/ConnectionTracker.cpp
)
target_include_directories(test_connection_tracker
    PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_connection_tracker 
    PRIVATE 
        GTest::gtest GTest::gtest_main pthread
)

# TEST Stats Aggregator
add_executable(test_stats_aggregator
    tests/unit/test_stats_aggregator.cpp 
    src/core/StatsAggregator.cpp 
    src/core/parser.cpp 
    src/core/ConnectionTracker.cpp
)
target_include_directories(test_stats_aggregator
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_stats_aggregator
    PRIVATE GTest::gtest GTest::gtest_main pthread
)

# TEST Session Management
add_executable(test_session_manager
    tests/unit/test_session_manager.cpp 
    src/core/SessionManager.cpp
    include/net-net/vendor/uuid_gen.cpp
    include/net-net/vendor/bcrypt.cpp
)
target_include_directories(test_session_manager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(test_session_manager 
    PRIVATE 
        GTest::gtest 
        GTest::gtest_main 
        pthread
        ${SQLITE3_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
)

# TEST Aggregator Integration
add_executable(test_stats_aggregator_integration
    tests/integration/test_stats_aggregator_integration.cpp 
    src/core/StatsAggregator.cpp
    src/core/parser.cpp 
    src/core/ConnectionTracker.cpp
)
target_include_directories(test_stats_aggregator_integration 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_stats_aggregator_integration 
    PRIVATE 
        GTest::gtest 
        GTest::gtest_main 
        pthread 
        ${PCAP_LIBRARIES}
)


# API daemon executable
add_executable(netnet-daemon
    # src/core/ConnectionTracker.cpp
    # src/core/parser.cpp
    # src/net/PcapAdapter.cpp
    # src/core/SessionManager.cpp
    # src/core/StatsAggregator.cpp
    # src/core/StatsPersistence.cpp
    src/daemon/NetMonDaemon.cpp
)

target_include_directories(netnet-daemon
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        # ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        # ${CMAKE_CURRENT_SOURCE_DIR}/src/net
        ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
        ${HTTPLIB_INCLUDE_DIR}
        ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(netnet-daemon
    PRIVATE
        netnet-core
        yaml-cpp
        pthread
        nlohmann_json::nlohmann_json
        # ${PCAP_LIBRARIES}
        ${SQLITE3_LIBRARIES}
        # OpenSSL::SSL
        # OpenSSL::Crypto
)

# Unit test: Metrics endpoint
add_executable(test_metrics_endpoint 
    tests/unit/test_metrics_endpoint.cpp
    src/core/StatsAggregator.cpp
    src/core/ConnectionTracker.cpp
    src/core/parser.cpp
)

target_include_directories(test_metrics_endpoint 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(test_metrics_endpoint 
    GTest::gtest_main 
    nlohmann_json::nlohmann_json
    pcap
    pthread
)
add_test(NAME test_metrics_endpoint COMMAND test_metrics_endpoint)

