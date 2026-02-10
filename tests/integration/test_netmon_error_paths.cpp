#include <gtest/gtest.h>
#include "daemon/NetMonDaemon.h"
#include <yaml-cpp/yaml.h>

// ============================================================
// ERROR PATH TESTS (Target: NetMonDaemon initialization)
// ============================================================

TEST(NetMonDaemonErrorPaths, InitFailure_MissingApiToken) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    // Missing api.token
    
    EXPECT_THROW({
        NetMonDaemon daemon(config, "test-missing-token");
    }, std::runtime_error);
}

TEST(NetMonDaemonErrorPaths, InitFailure_MissingStatsWindowSize) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["api"]["token"] = "test-token";
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    // Missing stats.window_size
    
    EXPECT_THROW({
        NetMonDaemon daemon(config, "test-missing-window");
    }, std::runtime_error);
}

TEST(NetMonDaemonErrorPaths, InitFailure_MissingDatabasePath) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["api"]["token"] = "test-token";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    // Missing database.path
    
    EXPECT_THROW({
        NetMonDaemon daemon(config, "test-missing-db");
    }, std::runtime_error);
}

TEST(NetMonDaemonErrorPaths, InitFailure_InvalidBpfFilter) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["interface"]["bpf_filter"] = "tcp; DROP TABLE users;";  // SQL injection
    config["api"]["token"] = "test-token";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    
    EXPECT_THROW({
        NetMonDaemon daemon(config, "test-invalid-bpf");
    }, std::runtime_error);
}

TEST(NetMonDaemonErrorPaths, InitFailure_MissingInterfaceAndOfflineFile) {
    YAML::Node config;
    config["api"]["token"] = "test-token";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    // Missing both interface.name AND offline.file
    
    EXPECT_THROW({
        NetMonDaemon daemon(config, "test-no-interface");
    }, std::runtime_error);
}

TEST(NetMonDaemonErrorPaths, InitFailure_InvalidLogFilePath) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["api"]["token"] = "test-token";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    config["logging"]["file"] = "/nonexistent_dir/impossible.log";
    
    EXPECT_THROW({
        NetMonDaemon daemon(config, "test-bad-log");
    }, std::runtime_error);
}

TEST(NetMonDaemonErrorPaths, InitFailure_BpfFilterTooLong) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["interface"]["bpf_filter"] = std::string(300, 'a');  // 300 chars
    config["api"]["token"] = "test-token";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    
    EXPECT_THROW({
        NetMonDaemon daemon(config, "test-long-bpf");
    }, std::runtime_error);
}

TEST(NetMonDaemonErrorPaths, InitSuccess_PrehashedPassword) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["api"]["token"] = "test-token";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    
    // Pre-hashed bcrypt password (should NOT rehash)
    YAML::Node user;
    user["username"] = "admin";
    user["password"] = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
    config["users"].push_back(user);
    
    EXPECT_NO_THROW({
        NetMonDaemon daemon(config, "test-prehashed");
    });
}

TEST(NetMonDaemonErrorPaths, InitSuccess_NoUsers) {
    YAML::Node config;
    config["interface"]["name"] = "lo0";
    config["api"]["token"] = "test-token";
    config["stats"]["window_size"] = 1;
    config["stats"]["history_depth"] = 2;
    config["database"]["path"] = ":memory:";
    // No users section (should warn but not crash)
    
    EXPECT_NO_THROW({
        NetMonDaemon daemon(config, "test-no-users");
    });
}

