cmake_minimum_required(VERSION 3.24)
project(net-net VERSION 0.2.0 LANGUAGES CXX)

# =========================
# IMPORTANT: Before running the daemon or tests, generate a config file with the correct interface:
#   make config-ci
# This will create examples/sample-config.ci.yaml with the correct interface name.
# =========================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)
include(FetchContent)

# Coverage is opt-in: Debug builds must be usable without compiler-specific
# instrumentation, and coverage should never be enabled in a release artifact.
option(NETNET_ENABLE_COVERAGE "Enable compiler coverage instrumentation" OFF)
if(NETNET_ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# libpcap is commonly exposed through pkg-config on Linux. Homebrew marks it
# keg-only, so fall back to stable Homebrew *opt* symlinks (never Cellar
# version paths) on macOS. PCAP_ROOT takes precedence for custom installs.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET libpcap)
endif()

if(NOT PCAP_FOUND)
    set(_netnet_pcap_hints)
    if(DEFINED ENV{PCAP_ROOT})
        list(APPEND _netnet_pcap_hints "$ENV{PCAP_ROOT}")
    endif()
    if(APPLE)
        list(APPEND _netnet_pcap_hints
            /opt/homebrew/opt/libpcap
            /usr/local/opt/libpcap
        )
    endif()
    find_path(PCAP_INCLUDE_DIR
        NAMES pcap/pcap.h
        HINTS ${_netnet_pcap_hints}
        PATH_SUFFIXES include
    )
    find_library(PCAP_LIBRARY
        NAMES pcap libpcap
        HINTS ${_netnet_pcap_hints}
        PATH_SUFFIXES lib
    )
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "libpcap was not found. Install libpcap development files, set "
            "PCAP_ROOT, or make libpcap visible to pkg-config."
        )
    endif()
    set(PCAP_FOUND TRUE)
    set(PCAP_INCLUDE_DIRS "${PCAP_INCLUDE_DIR}")
    set(PCAP_LIBRARIES "${PCAP_LIBRARY}")
endif()

# Host-provided libraries are intentionally discovered through their CMake
# packages. Their minimum versions document the supported security baseline.
find_package(OpenSSL 3.0 REQUIRED)
find_package(yaml-cpp 0.8 REQUIRED)
find_package(nlohmann_json 3.12 REQUIRED)
find_package(GTest 1.17 REQUIRED)

# Third-party source dependencies are pinned to immutable upstream commits.
# See docs/dependency-policy.md before changing a pin.
FetchContent_Declare(
    SQLiteCpp
    GIT_REPOSITORY https://github.com/SRombauts/SQLiteCpp.git
    GIT_TAG        4eb9964c2d71a3c03ebd04291f093a78783f58cf # 3.3.1
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG        4f3f9ef19be83ae97a5d9a059432dc00e445b7ab # v0.58.0
    GIT_SHALLOW    TRUE
)

set(SQLITECPP_RUN_CPPLINT OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPCHECK OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(SQLiteCpp cpp_httplib)

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
        httplib::httplib
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
    TIMEOUT 300       # Kill test after 5 minutes
)

# Set timeout for all tests
set_property(TEST test_netmon_daemon test_parser test_connection_tracker
    test_stats_aggregator test_session_manager test_stats_aggregator_integration
    test_stats_persistence test_metrics_endpoint test_parser_extended
    test_pcap_adapter_extended test_netmon_error_paths test_api_error_paths
    PROPERTY TIMEOUT 180)

# ONLY serialize daemon tests (avoid port conflicts)
set_tests_properties(test_netmon_daemon test_api_error_paths test_netmon_error_paths
    PROPERTIES
        # These suites bind the same test API port. A resource lock prevents
        # collisions while preserving parallel execution for other tests.
        RESOURCE_LOCK netnet-api
)

# Allow other tests to run in parallel
set_tests_properties(test_parser test_connection_tracker test_stats_aggregator
    test_session_manager test_stats_aggregator_integration test_stats_persistence
    test_metrics_endpoint test_parser_extended test_pcap_adapter_extended
    PROPERTIES RUN_SERIAL FALSE
)

# INCREASE timeout ONLY for daemon tests
set_tests_properties(test_netmon_daemon test_api_error_paths test_netmon_error_paths
    PROPERTIES TIMEOUT 300
)

# Keep default 180s for others
set_property(TEST test_parser test_connection_tracker test_stats_aggregator
    PROPERTY TIMEOUT 180
)
