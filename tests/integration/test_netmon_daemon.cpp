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

// TEST Daemon is Running

TEST_F(NetMonDaemonTest, DaemonStartsSuccessfully) {
    EXPECT_TRUE(daemon ->isRunning());
}


// TEST Metrics Endpoint Returns Valid JSON
TEST_F(NetMonDaemonTest, MetricsEndpointReturnsValidJSON) {
    auto res = makeAuthenticatedGet("/metrics");
    
    ASSERT_TRUE(res != nullptr) << "Request failed";
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");
    
    // Parse JSON
    auto j = json::parse(res->body);
    
    // Validate structure
    EXPECT_TRUE(j.contains("timestamp"));
    EXPECT_TRUE(j.contains("window_start"));
    EXPECT_TRUE(j.contains("total_bytes"));
    EXPECT_TRUE(j.contains("total_packets"));
    EXPECT_TRUE(j.contains("bytes_per_second"));
    EXPECT_TRUE(j.contains("protocol_breakdown"));
    EXPECT_TRUE(j.contains("active_flows"));
    
    // Validate types
    EXPECT_TRUE(j["timestamp"].is_number());
    EXPECT_TRUE(j["total_bytes"].is_number());
    EXPECT_TRUE(j["total_packets"].is_number());
    EXPECT_TRUE(j["protocol_breakdown"].is_object());
    EXPECT_TRUE(j["active_flows"].is_array());
}


// TEST Metrics Endpoint Without Auth Returns 401
TEST_F(NetMonDaemonTest, MetricsWithoutAuthReturns401) {
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/metrics");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 401);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("error"));
    EXPECT_EQ(j["error"], "unauthorized");
}

// TEST Login With Valid Credentials Returns Token
TEST_F(NetMonDaemonTest, LoginWithValidCredentialsReturnsToken) {
    httplib::Client client(test_host, test_port);
    
    json body;
    body["username"] = test_username;
    body["password"] = test_password;
    
    auto res = client.Post("/login", body.dump(), "application/json");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("token"));
    EXPECT_TRUE(j.contains("username"));
    EXPECT_TRUE(j.contains("expires_in"));
    EXPECT_EQ(j["username"], test_username);
    EXPECT_GT(j["token"].get<std::string>().length(), 0);
}

// TEST Login With Invalid Credentials Returns 401
TEST_F(NetMonDaemonTest, LoginWithInvalidCredentialsReturns401) {
    httplib::Client client(test_host, test_port);
    
    json body;
    body["username"] = "nonexistent";
    body["password"] = "wrongpass";
    
    auto res = client.Post("/login", body.dump(), "application/json");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 401);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("error"));
}

// TEST Login With Malformed JSON Returns 400
TEST_F(NetMonDaemonTest, LoginWithMalformedJSONReturns400) {
    httplib::Client client(test_host, test_port);
    
    auto res = client.Post("/login", "not valid json", "application/json");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 400);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["error"], "malformed JSON");
}

// TEST Access With Session Token