cmake_minimum_required(VERSION 3.15)
project(net-net CXX)

# =========================
# IMPORTANT: Before running the daemon or tests, generate a config file with the correct interface:
#   make config-ci
# This will create examples/sample-config.ci.yaml with the correct interface name.
# =========================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Generate coverage data
if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# Set PKG_CONFIG_PATH for keg-only libpcap
set(ENV{PKG_CONFIG_PATH} "/usr/local/opt/libpcap/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

# pkg-config and modules
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Find OpenSSL, yaml-cpp, nlohmann_json early
find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(nlohmann_json REQUIRED)
include(FetchContent)

FetchContent_Declare(
    SQLiteCpp
    GIT_REPOSITORY https://github.com/SRombauts/SQLiteCpp.git
    GIT_TAG        3.3.1  # Latest stable version
)

set(SQLITECPP_RUN_CPPLINT OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPCHECK OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(SQLiteCpp)

# Find or add cpp-httplib
find_path(HTTPLIB_INCLUDE_DIR httplib.h
    PATHS ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)
if(NOT HTTPLIB_INCLUDE_DIR)
    message(FATAL_ERROR "httplib.h not found. Install: brew install cpp-httplib")
endif()

# Environment flags
# libxcrypt flags
if(UNIX AND NOT APPLE)
    set(EXTRA_LIBS crypt uuid)
    include_directories(/usr/local/opt/libxcrypt/include)
    link_directories(/usr/local/opt/libxcrypt/lib)
else()
    set(EXTRA_LIBS "")
endif()

# Core library
add_library(netnet-core STATIC
    src/core/ConnectionTracker.cpp
    src/core/Parser.cpp
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
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
    PRIVATE
        ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(netnet-core
    PUBLIC
        SQLiteCpp
        OpenSSL::SSL
        OpenSSL::Crypto
    PRIVATE
        ${PCAP_LIBRARIES}        
        pthread
        ${EXTRA_LIBS}
)

# Main executable (for testing)
add_executable(netnet
    src/main.cpp
)

target_include_directories(netnet
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/net
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(netnet
    PRIVATE 
        netnet-core
        yaml-cpp
        ${EXTRA_LIBS}
)

# Testing setup
enable_testing()
find_package(GTest REQUIRED)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/CMake/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/config.h
)

# Test runner
add_executable(test_runner
    tests/unit/test_pcap_adapter.cpp
)

target_include_directories(test_runner PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(test_runner 
    PRIVATE 
        netnet-core GTest::gtest GTest::gtest_main pthread
        ${EXTRA_LIBS}
)
add_test(NAME test_runner COMMAND test_runner)

# TEST Parser
add_executable(test_parser
    tests/unit/test_parser.cpp
    src/core/Parser.cpp
)
target_include_directories(test_parser 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)
target_link_libraries(test_parser 
    PRIVATE 
        GTest::gtest GTest::gtest_main
        ${EXTRA_LIBS}
)
add_test(NAME test_parser COMMAND test_parser)

# TEST Connection Tracker
add_executable(test_connection_tracker
    tests/integration/test_connection_tracker.cpp
    src/core/Parser.cpp
    src/core/ConnectionTracker.cpp
)
target_include_directories(test_connection_tracker
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)
target_link_libraries(test_connection_tracker 
    PRIVATE 
        GTest::gtest GTest::gtest_main pthread
        ${EXTRA_LIBS}
)
add_test(NAME test_connection_tracker COMMAND test_connection_tracker)

# TEST Stats Aggregator
add_executable(test_stats_aggregator
    tests/unit/test_stats_aggregator.cpp 
    src/core/StatsAggregator.cpp 
    src/core/Parser.cpp 
    src/core/ConnectionTracker.cpp
)
target_include_directories(test_stats_aggregator
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)
target_link_libraries(test_stats_aggregator
    PRIVATE GTest::gtest GTest::gtest_main pthread
    ${EXTRA_LIBS}
)
add_test(NAME test_stats_aggregator COMMAND test_stats_aggregator)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(test_session_manager 
    PRIVATE 
        GTest::gtest 
        GTest::gtest_main 
        pthread
        SQLiteCpp
        OpenSSL::SSL
        OpenSSL::Crypto
        ${EXTRA_LIBS}
)
add_test(NAME test_session_manager COMMAND test_session_manager)

# TEST Aggregator Integration
add_executable(test_stats_aggregator_integration
    tests/integration/test_stats_aggregator_integration.cpp 
    src/core/StatsAggregator.cpp
    src/core/Parser.cpp 
    src/core/ConnectionTracker.cpp
)
target_include_directories(test_stats_aggregator_integration 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/core
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)
target_link_libraries(test_stats_aggregator_integration 
    PRIVATE 
        GTest::gtest 
        GTest::gtest_main 
        pthread 
        ${PCAP_LIBRARIES}
        ${EXTRA_LIBS}
)
add_test(NAME test_stats_aggregator_integration COMMAND test_stats_aggregator_integration)

# TEST Stats Persistence
add_executable(test_stats_persistence
    tests/unit/test_stats_persistence.cpp
)

target_include_directories(test_stats_persistence
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(test_stats_persistence
    PRIVATE
        netnet-core
        GTest::gtest_main
        pthread
        ${EXTRA_LIBS}
)

add_test(NAME test_stats_persistence COMMAND test_stats_persistence)

# ============================================================
# DAEMON LIBRARY (shared between production and testing)
# ============================================================
add_library(netnet-daemon-lib STATIC
    src/daemon/NetMonDaemon.cpp
)

target_include_directories(netnet-daemon-lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(netnet-daemon-lib
    PUBLIC
        netnet-core
        yaml-cpp
        nlohmann_json::nlohmann_json
        pthread
        OpenSSL::SSL
        OpenSSL::Crypto
        ${EXTRA_LIBS}
)

# ============================================================
# PRODUCTION API DAEMON EXECUTABLE
# ============================================================
add_executable(netnet-daemon
    src/daemon/Main.cpp
)

target_link_libraries(netnet-daemon
    PRIVATE
        netnet-daemon-lib
)

# ============================================================
# UNIT TEST: METRICS ENDPOINT
# ============================================================
add_executable(test_metrics_endpoint 
    tests/unit/test_metrics_endpoint.cpp
    src/core/StatsAggregator.cpp
    src/core/ConnectionTracker.cpp
    src/core/Parser.cpp
)

target_include_directories(test_metrics_endpoint 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(test_metrics_endpoint 
    GTest::gtest_main 
    nlohmann_json::nlohmann_json
    pcap
    pthread
    ${EXTRA_LIBS}
)
add_test(NAME test_metrics_endpoint COMMAND test_metrics_endpoint)

# ============================================================
# INTEGRATION TEST: NETMON DAEMON
# ============================================================
add_executable(test_netmon_daemon
    tests/integration/test_netmon_daemon.cpp
)

target_include_directories(test_netmon_daemon
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(test_netmon_daemon
    PRIVATE
        netnet-daemon-lib
        GTest::gtest
        GTest::gtest_main
        ${EXTRA_LIBS}
)

add_test(NAME test_netmon_daemon COMMAND test_netmon_daemon)

# Copy test fixtures to build directory
if(EXISTS ${CMAKE_SOURCE_DIR}/tests/fixtures)
    file(COPY ${CMAKE_SOURCE_DIR}/tests/fixtures
        DESTINATION ${CMAKE_BINARY_DIR}/tests)
endif()

# ============================================================
# INTEGRATION TEST: comprehensive test executables
# ============================================================

add_executable(test_parser_extended 
    tests/unit/test_parser_extended.cpp
)
target_include_directories(test_parser_extended PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_parser_extended 
    PRIVATE 
        netnet-core
        GTest::gtest_main
        pthread
)
add_test(NAME test_parser_extended COMMAND test_parser_extended)

add_executable(test_pcap_adapter_extended 
    tests/unit/test_pcap_adapter_extended.cpp
)
target_include_directories(test_pcap_adapter_extended PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(test_pcap_adapter_extended 
    PRIVATE 
        netnet-core
        GTest::gtest_main
        pthread
)
add_test(NAME test_pcap_adapter_extended COMMAND test_pcap_adapter_extended)

# ============================================================
# INTEGRATION TEST: NETMON ERROR PATHS
# ============================================================
add_executable(test_netmon_error_paths
    tests/integration/test_netmon_error_paths.cpp
)

target_include_directories(test_netmon_error_paths
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(test_netmon_error_paths
    PRIVATE
        netnet-daemon-lib
        GTest::gtest
        GTest::gtest_main
        ${EXTRA_LIBS}
)

add_test(NAME test_netmon_error_paths COMMAND test_netmon_error_paths)

# ============================================================
# INTEGRATION TEST: API ERROR PATHS
# ============================================================
add_executable(test_api_error_paths
    tests/integration/test_api_error_paths.cpp
)

target_include_directories(test_api_error_paths
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/daemon
        ${CMAKE_CURRENT_SOURCE_DIR}/include/net-net/vendor
)

target_link_libraries(test_api_error_paths
    PRIVATE
        netnet-daemon-lib
        GTest::gtest
        GTest::gtest_main
        ${EXTRA_LIBS}
)

add_test(NAME test_api_error_paths COMMAND test_api_error_paths)

# Enable parallel test execution
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.17)
    list(APPEND CMAKE_CTEST_ARGUMENTS "--parallel ${CMAKE_BUILD_PARALLEL_LEVEL}")
endif()

# Set test properties for parallel execution
set_tests_properties(test_netmon_daemon PROPERTIES
    RUN_SERIAL FALSE  # Allow parallel runs
    TIMEOUT 120       # Kill test after 2 minutes
)