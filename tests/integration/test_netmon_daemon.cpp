#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <yaml-cpp/yaml.h>
#include "daemon/NetMonDaemon.h"
#include "httplib.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class NetMonDaemonTest : public ::testing::Test {
protected:
    std::unique_ptr<NetMonDaemon> daemon;
    std::thread daemon_thread;

    // Test configuration
    int test_port = 9999;
    std::string test_host = "localhost";
    std::string api_token = "test-token-12345";
    std::string test_config_path = "test_daemon_config.yaml";

    void SetUp() override {
        // Create test daemon with config
        createTestConfig();

        daemon = std::make_unique<NetMonDaemon>(test_config_path);
        // Start background thread daemon
        daemon_thread = std::thread([this]() {
            daemon->run();
        });

        // Await daemon
        bool ready = false;
        for (int i = 0; i < 50; ++i) {
            httplib::Client client(test_host, test_port);
            client.set_connection_timeout(1,0);
            auto res = client.Post("/login");
            if (res && (res->status == 400 || res->status == 401)) {
                ready = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ASSERT_TRUE(ready) << "ERROR Daemon failed to start.";
    }

    void TearDown() override {

        if (daemon) {
            daemon->stop();
        }
        
        if (daemon_thread.joinable()) {
            daemon_thread.join();
        }

        std::remove(test_config_path.c_str());
        std::remove("test_daemon.db");
        std::remove("test_daemon.db.sessions");
    }
    // Helper: Create test configuration file
    void createTestConfig() {
        YAML::Node config;

        // Interface config
        config["interface"]["name"] = "lo0";
        config["interface"]["promiscuous"] = false;
        config["interface"]["snaplen"] = 65535;
        config["interface"]["timeout_ms"] = 1000;
        config["filter"]["bpf"] = "";
        
        // Stats config
        config["stats"]["window_size"] = 1;
        config["stats"]["history_depth"] = 3;
        
        // Database config
        config["database"]["path"] = "test_daemon.db";
        
        // API config
        config["api"]["enabled"] = true;
        config["api"]["host"] = test_host;
        config["api"]["port"] = test_port;
        config["api"]["token"] = api_token;
        config["api"]["session_expiry"] = 3600;
        
        // User credentials (use bcrypt hash for test password)
        YAML::Node user;
        user["username"] = "test_username";
        user["password"] = "10000$abcd1234$5678efgh";  // Placeholder hash
        user["plaintext"] = "test_password";  // For testing
        config["users"].push_back(user);
        
        // Logging config
        config["logging"]["level"] = "debug";
        config["logging"]["file"] = "";
        config["logging"]["timestamps"] = true;
        
        // Privilege config (don't drop for tests)
        config["privilege"]["drop"] = false;
        
        // Write to file
        std::ofstream fout(test_config_path);
        fout << config;
        fout.close();
    }

    // Make authenticated GET request with API token
    httplib::Result makeAuthenticatedGet(const std::string& path) {
        httplib::Client client(test_host, test_port);
        httplib::Headers headers = {
            {"Authorization", "Bearer " + api_token}
        };
        return client.Get(path, headers);
    }

    // Make authenticated POST request with API token
    httplib::Result makeAuthenticatedPost(const std::string& path, const std::string& body = "") {
        httplib::Client client(test_host, test_port);
        httplib::Headers headers = {
            {"Authorization", "Bearer " + api_token}
        };
        return client.Post(path, headers, body, "application/json");
    }

    // Make request with session token
    httplib::Result makeSessionToken(const std::string& path, const std::string& token) {
        httplib::Client client(test_host, test_port);
        httplib::Headers headers = {
            {"X-Session-Token", token}
        };
        return client.Get(path, headers);
    }
    
    // Login and get session token
    std::string loginUser(const std::string& username, const std::string& password) {
        httplib::Client client(test_host, test_port);

        json body;

        body["username"] = username;
        body["password"] = password;

        auto res = client.Post("/login", body.dump(), "application/json");
        if (!res || res->status != 200) {
            return "";
        }
        
        auto j = json::parse(res->body);
        return j.value("token", "");
    }
};

// =================================
// Test suite
// =================================
