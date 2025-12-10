#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <yaml-cpp/yaml.h>
#include "daemon/NetMonDaemon.h"
#include "httplib.h"
#include <nlohmann/json.hpp>
#include <filesystem>


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
    std::string test_username = "test_username";
    std::string test_password = "test_password";
    std::string session_token;    

    void SetUp() override {
        // Create YAML config in memory (no file I/O!)
        YAML::Node config = createTestConfigNode();  // ✅ CAPTURE THE RETURN VALUE
    
        // Create daemon with in-memory config
        daemon = std::make_unique<NetMonDaemon>(config, "test-daemon-config");  // ✅ PASS YAML::Node
    
        // Start daemon in background thread
        daemon_thread = std::thread([this]() {
            daemon->run();
        });
    
        // Wait for daemon to be ready
        bool ready = false;
        for (int i = 0; i < 50; ++i) {
            httplib::Client client(test_host, test_port);
            client.set_connection_timeout(1, 0);
            auto res = client.Post("/login");
            if (res && (res->status == 400 || res->status == 401)) {
                ready = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    
        ASSERT_TRUE(ready) << "ERROR: Daemon failed to start within 5 seconds";
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
    YAML::Node createTestConfigNode() {
        YAML::Node config;
        
        // Interface config (offline mode for tests)
        config["interface"]["name"] = "lo0";
        config["interface"]["promiscuous"] = false;
        config["interface"]["snaplen"] = 65535;
        config["interface"]["timeout_ms"] = 1000;
        
        // Use offline mode with the test pcap file
        config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
        config["offline"]["exit_after_read"] = true;
        
        // No BPF filter
        config["filter"]["bpf"] = "";
        
        // Stats config
        config["stats"]["window_size"] = 1;
        config["stats"]["history_depth"] = 3;
        
        // Database config (in-memory SQLite)
        config["database"]["path"] = ":memory:";
        
        // API config
        config["api"]["enabled"] = true;
        config["api"]["host"] = test_host;
        config["api"]["port"] = test_port;
        config["api"]["token"] = api_token;
        config["api"]["session_expiry"] = 3600;
        
        // User credentials (PLAINTEXT - your code will hash them)
        YAML::Node user;
        user["username"] = test_username;
        user["password"] = test_password;  // Plaintext - gets auto-hashed on line 158
        config["users"].push_back(user);
        
        // Logging config
        config["logging"]["level"] = "debug";
        config["logging"]["file"] = "";
        config["logging"]["timestamps"] = true;
        
        // Privilege config (don't drop for tests)
        config["privilege"]["drop"] = false;
        
        return config;
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
    httplib::Result makeSessionGet(const std::string& path, const std::string& token) {
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

// TEST Session Token Authorizes Metrics Access
TEST_F(NetMonDaemonTest, SessionTokenAuthorizesMetricsAccess) {
    // Login to get session token
    std::string token = loginUser(test_username, test_password);
    ASSERT_FALSE(token.empty()) << "Failed to get session token";
    
    // Use session token to access /metrics
    auto res = makeSessionGet("/metrics", token);
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("total_bytes"));
}

// TEST Logout Invalidates Session
TEST_F(NetMonDaemonTest, LogoutInvalidatesSession) {
    // Login
    std::string token = loginUser(test_username, test_password);
    ASSERT_FALSE(token.empty());
    
    // Verify token works
    auto res1 = makeSessionGet("/metrics", token);
    EXPECT_EQ(res1->status, 200);
    
    // Logout
    httplib::Client client(test_host, test_port);
    httplib::Headers headers = {
        {"X-Session-Token", token}
    };
    auto res2 = client.Post("/logout", headers, "", "application/json");
    EXPECT_EQ(res2->status, 200);
    
    // Verify token no longer works
    auto res3 = makeSessionGet("/metrics", token);
    EXPECT_EQ(res3->status, 401);
}

// TEST Control Endpoints
TEST_F(NetMonDaemonTest, ControlStartEndpoint) {
    auto res = makeAuthenticatedPost("/control/start");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["status"], "started");
}

// TEST Control Stop Endpoint
TEST_F(NetMonDaemonTest, ControlStopEndpoint) {
    auto res = makeAuthenticatedPost("/control/stop");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["status"], "stopped");
    
    // Verify daemon actually stopped
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_FALSE(daemon->isRunning());
}

// TEST Control Reload Endpoint
TEST_F(NetMonDaemonTest, ControlReloadEndpoint) {
    auto res = makeAuthenticatedPost("/control/reload");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["status"], "reloaded");
}

// TEST Control Endpoints Require Auth
TEST_F(NetMonDaemonTest, ControlEndpointsRequireAuth) {
    httplib::Client client(test_host, test_port);
    
    auto res1 = client.Post("/control/start");
    EXPECT_EQ(res1->status, 401);
    
    auto res2 = client.Post("/control/stop");
    EXPECT_EQ(res2->status, 401);
    
    auto res3 = client.Post("/control/reload");
    EXPECT_EQ(res3->status, 401);
}

// TEST Rate Limiting on Control Endpoints
TEST_F(NetMonDaemonTest, RateLimitingOnControlEndpoints) {
    // First request succeeds
    auto res1 = makeAuthenticatedPost("/control/start");
    EXPECT_EQ(res1->status, 200);
    
    // Second immediate request is rate-limited
    auto res2 = makeAuthenticatedPost("/control/start");
    EXPECT_EQ(res2->status, 429);
    
    auto j = json::parse(res2->body);
    EXPECT_EQ(j["error"], "rate limit exceeded");
}

// TEST Invalid Endpoint Returns 404
TEST_F(NetMonDaemonTest, InvalidEndpointReturns404) {
    auto res = makeAuthenticatedGet("/api/nonexistent");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 404);
}

// TEST Token Auth Via Query Parameter
TEST_F(NetMonDaemonTest, TokenAuthViaQueryParameter) {
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/metrics?token=" + api_token);
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
}

// TEST Protocol Breakdown In Metrics
TEST_F(NetMonDaemonTest, ProtocolBreakdownInMetrics) {
    // Generate some traffic (if possible in test environment)
    auto res = makeAuthenticatedGet("/metrics");
    
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    auto& breakdown = j["protocol_breakdown"];
    
    // Should have at least the structure (may be empty)
    EXPECT_TRUE(breakdown.is_object());
}

//  TEST Active Flows Array Structure
TEST_F(NetMonDaemonTest, ActiveFlowsArrayStructure) {
    auto res = makeAuthenticatedGet("/metrics");
    
    ASSERT_TRUE(res != nullptr);
    auto j = json::parse(res->body);
    auto& flows = j["active_flows"];
    
    EXPECT_TRUE(flows.is_array());
    
    // If flows exist, validate structure
    if (!flows.empty()) {
        auto& flow = flows[0];
        EXPECT_TRUE(flow.contains("iface"));
        EXPECT_TRUE(flow.contains("src_ip"));
        EXPECT_TRUE(flow.contains("src_port"));
        EXPECT_TRUE(flow.contains("dst_ip"));
        EXPECT_TRUE(flow.contains("dst_port"));
        EXPECT_TRUE(flow.contains("protocol"));
        EXPECT_TRUE(flow.contains("bytes"));
        EXPECT_TRUE(flow.contains("packets"));
        EXPECT_TRUE(flow.contains("state"));
    }
}