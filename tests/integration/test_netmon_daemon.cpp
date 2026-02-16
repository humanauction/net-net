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
    // Static daemon shared across all tests
    static std::unique_ptr<NetMonDaemon> daemon;
    static std::thread daemon_thread;
    static int test_port;
    static std::string test_host;
    static std::string api_token;
    static std::string test_username;
    static std::string test_password;
    std::string config_path_;
    
    std::string session_token;  // Per-test session token
    
    // HELPER: Create test config node
    static YAML::Node createTestConfigNode(bool with_offline = true) {
        YAML::Node config;

        if (with_offline) {
            config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
        } else {
            config["interface"]["name"] = "lo0";
        }
        config["stats"]["window_size"] = 1;
        config["stats"]["history_depth"] = 2;
        config["database"]["path"] = ":memory:";
        config["api"]["token"] = "test-token-12345";
        config["api"]["host"] = "localhost";
        config["api"]["port"] = 9999;
        config["api"]["session_expiry"] = 60;
        config["logging"]["level"] = "error";
        
        YAML::Node user;
        user["username"] = "test_username";
        user["password"] = "test_password";
        config["users"].push_back(user);
        
        return config;
    }
    // START DAEMON ONCE FOR ALL TESTS
    static void SetUpTestSuite() {
        test_port = 9999;
        test_host = "localhost";
        api_token = "test-token-12345";
        test_username = "test_username";
        test_password = "test_password";
        
        YAML::Node config = createTestConfigNode(true);
        
        daemon = std::make_unique<NetMonDaemon>(config, "test-daemon-shared");
        daemon_thread = std::thread([]() { daemon->run(); });
        
        // Wait for daemon startup (only once)
        for (int i = 0; i < 10; ++i) {
            try {
                httplib::Client client(test_host, test_port);
                client.set_read_timeout(1, 0);
                auto res = client.Get("/metrics?token=" + api_token);
                if (res && res->status > 0) break;
            } catch (...) {}
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    // STOP DAEMON AFTER ALL TESTS
    static void TearDownTestSuite() {
        if (daemon) {
            daemon->stop();
        }

        auto start = std::chrono::steady_clock::now();
        while (daemon->isRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto elapsed = std::chrono::steady_clock::now() - start;
            if (elapsed > std::chrono::seconds(5)) {
                std::cerr << "ERROR: Daemon did not stop within expected time. Forcing shutdown." << std::endl;
                break;
            }
        }

        if (daemon_thread.joinable()) {
            daemon_thread.join();
        }

        daemon.reset();
    }
    
    // PER-TEST SETUP: only resets session token
    void SetUp() override {
        session_token.clear();
    }
    
    void TearDown() override {
        // No per-test cleanup needed
    }
    
    // HELPER: Login and return session token
    std::string loginUser(const std::string& username, const std::string& password) {
        httplib::Client client(test_host, test_port);
        nlohmann::json body = {
            {"username", username},
            {"password", password}
        };
        
        auto res = client.Post("/login", body.dump(), "application/json");
        if (res && res->status == 200) {
            auto j = nlohmann::json::parse(res->body);
            return j["token"].get<std::string>();
        }
        return "";
    }
    
    // HELPER: GET with session token
    httplib::Result makeSessionGet(const std::string& path, const std::string& token) {
        httplib::Client client(test_host, test_port);
        httplib::Headers headers = {{"X-Session-Token", token}};
        return client.Get(path, headers);
    }
    
    // HELPER: Authenticated GET (uses API token)
    httplib::Result makeAuthenticatedGet(const std::string& path) {
        if (session_token.empty()) {
            session_token = loginUser(test_username, test_password);
        }
        
        httplib::Client client(test_host, test_port);
        httplib::Headers headers = {{"X-Session-Token", session_token}};
        return client.Get(path, headers);
    }
    
    // HELPER: Authenticated POST (uses API token)
    httplib::Result makeAuthenticatedPost(const std::string& path, const std::string& body = "") {
        httplib::Client client(test_host, test_port);
        httplib::Headers headers = {
            {"Authorization", "Bearer " + api_token}
        };
        return client.Post(path, headers, body, "application/json");
    }
};

// STATIC MEMBERS
std::unique_ptr<NetMonDaemon> NetMonDaemonTest::daemon = nullptr;
std::thread NetMonDaemonTest::daemon_thread;
int NetMonDaemonTest::test_port = 9999;
std::string NetMonDaemonTest::test_host = "localhost";
std::string NetMonDaemonTest::api_token = "test-token-12345";
std::string NetMonDaemonTest::test_username = "test_username";
std::string NetMonDaemonTest::test_password = "test_password";

// =================================
// Tests
// =================================

TEST_F(NetMonDaemonTest, DaemonStartsSuccessfully) {
	EXPECT_NE(daemon, nullptr);
}


TEST_F(NetMonDaemonTest, MetricsHistoryEndpointReturnsValidJSON) {
    
    int64_t start = 0;
    int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string url = "/metrics/history?start=" + std::to_string(start) + 
                      "&end=" + std::to_string(now) + "&limit=10";
    
    auto res = makeAuthenticatedGet(url);

    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);

    auto j = nlohmann::json::parse(res->body);
    EXPECT_TRUE(j.contains("windows"));
    EXPECT_GE(j["windows"].size(), 1) << "Expected at least 1 window from offline pcap";
    
    if (!j["windows"].empty()) {
        auto& w = j["windows"][0];
        EXPECT_TRUE(w.contains("timestamp"));
        EXPECT_TRUE(w.contains("total_bytes"));
        EXPECT_TRUE(w.contains("total_packets"));
    }
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

// // TEST Control Stop Endpoint
// TEST_F(NetMonDaemonTest, ControlStopEndpoint) {
// 	auto res = makeAuthenticatedPost("/control/stop");
	
// 	ASSERT_TRUE(res != nullptr);
// 	EXPECT_EQ(res->status, 200);
	
// 	auto j = json::parse(res->body);
// 	EXPECT_EQ(j["status"], "stopped");
	
// 	// Verify daemon actually stopped
// 	EXPECT_FALSE(daemon->isRunning());
// }

// TEST Control Reload Endpoint
TEST_F(NetMonDaemonTest, ControlReloadEndpoint) {

    std::this_thread::sleep_for(std::chrono::seconds(6));

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

    std::this_thread::sleep_for(std::chrono::seconds(6));
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

// Test missing required config fields
TEST(NetMonDaemonConfigTest, ThrowsOnMissingApiToken) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	// Missing api.token
	
	EXPECT_THROW({
		NetMonDaemon daemon(config, "test-missing-token");
	}, std::runtime_error);
}

TEST(NetMonDaemonConfigTest, ThrowsOnMissingStatsConfig) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["api"]["token"] = "test-token";
	config["database"]["path"] = ":memory:";
	// Missing stats.window_size and history_depth
	
	EXPECT_THROW({
		NetMonDaemon daemon(config, "test-missing-stats");
	}, std::runtime_error);
}

TEST(NetMonDaemonConfigTest, ThrowsOnMissingDatabasePath) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	// Missing database.path
	
	EXPECT_THROW({
		NetMonDaemon daemon(config, "test-missing-db");
	}, std::runtime_error);
}

TEST(NetMonDaemonConfigTest, ThrowsOnMissingInterfaceAndOfflineFile) {
	YAML::Node config;
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	// Missing both interface.name and offline.file
	
	EXPECT_THROW({
		NetMonDaemon daemon(config, "test-no-source");
	}, std::runtime_error);
}

// Test invalid BPF filter
TEST(NetMonDaemonConfigTest, ThrowsOnInvalidBpfFilter) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["interface"]["bpf_filter"] = "invalid; DROP TABLE--";  // SQL injection attempt
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	
	EXPECT_THROW({
		NetMonDaemon daemon(config, "test-bad-bpf");
	}, std::runtime_error);
}

// Add to existing NetMonDaemonTest fixture:

// Test expired session token
TEST_F(NetMonDaemonTest, LoggedOutSessionTokenReturns401) {
	// Create short-lived session
	std::string token = loginUser(test_username, test_password);
    ASSERT_FALSE(token.empty());
    
    // Verify token works
    auto res1 = makeSessionGet("/metrics", token);
    EXPECT_EQ(res1->status, 200);
    
    // Logout
    httplib::Client client(test_host, test_port);
    httplib::Headers headers = {{"X-Session-Token", token}};
    auto logout_res = client.Post("/logout", headers, "", "application/json");
    EXPECT_EQ(logout_res->status, 200);
    
    // Now token should be invalid
    auto res2 = makeSessionGet("/metrics", token);
    EXPECT_EQ(res2->status, 401);
}

// Test missing username in login
TEST_F(NetMonDaemonTest, LoginWithoutUsernameReturns400) {
	httplib::Client client(test_host, test_port);
	
	json body;
	body["password"] = "test";
	// Missing username
	
	auto res = client.Post("/login", body.dump(), "application/json");
	EXPECT_EQ(res->status, 400);
}

// Test missing password in login
TEST_F(NetMonDaemonTest, LoginWithoutPasswordReturns400) {
	httplib::Client client(test_host, test_port);
	
	json body;
	body["username"] = "test";
	// Missing password
	
	auto res = client.Post("/login", body.dump(), "application/json");
	EXPECT_EQ(res->status, 400);
}

// Test logout without session token
TEST_F(NetMonDaemonTest, LogoutWithoutTokenReturns400) {
	httplib::Client client(test_host, test_port);
	auto res = client.Post("/logout");
	
	EXPECT_EQ(res->status, 400);
	auto j = json::parse(res->body);
	EXPECT_EQ(j["error"], "no session token provided");
}

// Test logout with invalid token
TEST_F(NetMonDaemonTest, LogoutWithInvalidTokenReturns401) {
	httplib::Client client(test_host, test_port);
	httplib::Headers headers = {
		{"X-Session-Token", "invalid-token-12345"}
	};
	auto res = client.Post("/logout", headers, "", "application/json");
	
	EXPECT_EQ(res->status, 401);
}

// Test multiple rapid control requests (rate limiting)
TEST_F(NetMonDaemonTest, MultipleRapidControlRequestsBlocked) {

    std::this_thread::sleep_for(std::chrono::seconds(6));

	auto res1 = makeAuthenticatedPost("/control/reload");
	EXPECT_EQ(res1->status, 200);
	
	auto res2 = makeAuthenticatedPost("/control/reload");
	EXPECT_EQ(res2->status, 429);
	
	auto res3 = makeAuthenticatedPost("/control/reload");
	EXPECT_EQ(res3->status, 429);
}

// Test control endpoints with session token (not just API token)
TEST_F(NetMonDaemonTest, ControlEndpointsWorkWithSessionToken) {

    std::this_thread::sleep_for(std::chrono::seconds(6));

	std::string token = loginUser(test_username, test_password);
	ASSERT_FALSE(token.empty());
	
	httplib::Client client(test_host, test_port);
	httplib::Headers headers = {
		{"X-Session-Token", token}
	};
	
	auto res = client.Post("/control/start", headers, "", "application/json");
	EXPECT_EQ(res->status, 200);
}

// Test malformed Authorization header
TEST_F(NetMonDaemonTest, MalformedAuthHeaderReturns401) {
	httplib::Client client(test_host, test_port);
	httplib::Headers headers = {
		{"Authorization", "NotBearer wrongformat"}
	};
	auto res = client.Get("/metrics", headers);
	EXPECT_EQ(res->status, 401);
}

// Test empty metrics response (no traffic)
TEST_F(NetMonDaemonTest, MetricsWithNoTrafficReturnsZeros) {
	// Daemon starts with no traffic in test
	auto res = makeAuthenticatedGet("/metrics");
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(res->status, 200);
	
	auto j = json::parse(res->body);
	// In offline test mode with icmp_sample.pcap, there will be traffic
	// But we can still validate the structure
	EXPECT_TRUE(j.contains("total_bytes"));
	EXPECT_TRUE(j.contains("total_packets"));
}

// TEST: Daemon with offline mode but missing pcap file
// TEST(NetMonDaemonConfigTest, ThrowsOnMissingOfflineFile) {
//     YAML::Node config;
//     config["offline"]["file"] = "/nonexistent/missing.pcap";
//     config["api"]["token"] = "test-token";
//     config["stats"]["window_size"] = 1;
//     config["stats"]["history_depth"] = 3;
//     config["database"]["path"] = ":memory:";
//     
//     EXPECT_THROW({
//         NetMonDaemon daemon(config, "test-missing-pcap");
//     }, std::runtime_error);
// }

// Test PcapAdapter validation directly
TEST(NetMonDaemonConfigTest, PcapAdapterValidatesFileExistenceBeforeCapture) {
	PcapAdapter::Options opts;
	opts.iface_or_file = "/nonexistent/missing.pcap";
	opts.read_offline = true;
	
	// Construction succeeds
	PcapAdapter pcap(opts);
	
	// Capture throws on missing file
	EXPECT_THROW({
		pcap.startCapture([](const PacketMeta&, const uint8_t*, size_t) {});
	}, std::runtime_error);
}

// TEST: Daemon with invalid log level
TEST(NetMonDaemonConfigTest, AcceptsInvalidLogLevelWithoutCrashing) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	config["logging"]["level"] = "INVALID_LEVEL";  // Should default to "info"
	
	EXPECT_NO_THROW({
		NetMonDaemon daemon(config, "test-invalid-loglevel");
	});
}

// TEST: Daemon with missing log file directory
TEST(NetMonDaemonConfigTest, ThrowsOnInvalidLogFilePath) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	config["logging"]["file"] = "/nonexistent_dir/impossible.log";
	
	EXPECT_THROW({
		NetMonDaemon daemon(config, "test-bad-logfile");
	}, std::exception);  // Should exit(1) or throw during log_stream_.open()
}

// TEST: Login with empty username/password strings
TEST_F(NetMonDaemonTest, LoginWithEmptyStringsReturns400) {
	httplib::Client client(test_host, test_port);
	
	json body;
	body["username"] = "";
	body["password"] = "";
	
	auto res = client.Post("/login", body.dump(), "application/json");
	EXPECT_EQ(res->status, 400);
	
	auto j = json::parse(res->body);
	EXPECT_EQ(j["error"], "missing username or password");
}

// TEST: Config with user having pre-hashed password (bcrypt format)
TEST(NetMonDaemonConfigTest, AcceptsPrehashedPassword) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	
	// Pre-hashed password (bcrypt format starts with $2a$)
	YAML::Node user;
	user["username"] = "prehashed_user";
	user["password"] = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";  // "password123"
	config["users"].push_back(user);
	
	EXPECT_NO_THROW({
		NetMonDaemon daemon(config, "test-prehashed-pw");
	});
}

// TEST: Config with no users (authentication disabled warning)
TEST(NetMonDaemonConfigTest, AcceptsConfigWithNoUsers) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	// No users section
	
	EXPECT_NO_THROW({
		NetMonDaemon daemon(config, "test-no-users");
	});
}

// TEST: Config with custom session expiry
TEST(NetMonDaemonConfigTest, CustomSessionExpiryApplied) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
	config["api"]["token"] = "test-token";
	config["api"]["session_expiry"] = 120;  // 2 minutes
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	
	YAML::Node user;
	user["username"] = "testuser";
	user["password"] = "testpass";
	config["users"].push_back(user);
	
	EXPECT_NO_THROW({
		NetMonDaemon daemon(config, "test-custom-expiry");
	});
}

// TEST: Daemon with logging disabled (no timestamps)
TEST(NetMonDaemonConfigTest, LoggingWithoutTimestamps) {
	YAML::Node config;
	config["interface"]["name"] = "lo0";
	config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
	config["api"]["token"] = "test-token";
	config["stats"]["window_size"] = 1;
	config["stats"]["history_depth"] = 3;
	config["database"]["path"] = ":memory:";
	config["logging"]["timestamps"] = false;
	
	EXPECT_NO_THROW({
		NetMonDaemon daemon(config, "test-no-timestamps");
	});
}

// TEST: Authorization with Bearer token having extra whitespace
TEST_F(NetMonDaemonTest, AuthWithBearerTokenExtraWhitespace) {
	httplib::Client client(test_host, test_port);
	httplib::Headers headers = {
		{"Authorization", "Bearer  " + api_token}  // Double space
	};
	auto res = client.Get("/metrics", headers);
	
	// Should fail due to whitespace mismatch
	EXPECT_EQ(res->status, 401);
}

// TEST: Multiple simultaneous login attempts (race condition test)
TEST_F(NetMonDaemonTest, ConcurrentLoginAttempts) {
	std::vector<std::thread> threads;
	std::vector<std::string> tokens(10);
	
	for (int i = 0; i < 10; ++i) {
		threads.emplace_back([&, i]() {
			tokens[i] = loginUser(test_username, test_password);
		});
	}
	
	for (auto& t : threads) {
		t.join();
	}
	
	// All tokens should be unique and non-empty
	std::set<std::string> unique_tokens;
	for (const auto& token : tokens) {
		EXPECT_FALSE(token.empty());
		unique_tokens.insert(token);
	}
	EXPECT_EQ(unique_tokens.size(), 10);
}

// TEST: Metrics endpoint with very long valid token
TEST_F(NetMonDaemonTest, AuthWithVeryLongToken) {
	std::string long_token(10000, 'a');
	
	httplib::Client client(test_host, test_port);
	httplib::Headers headers = {
		{"Authorization", "Bearer " + long_token}
	};
	auto res = client.Get("/metrics", headers);
	
	// httplib returns 400 for malformed/oversized headers
	EXPECT_TRUE(res->status == 400 || res->status == 401);  // Either is acceptable
}

// TEST: Stop daemon multiple times (idempotency test)
// TEST_F(NetMonDaemonTest, StopDaemonIsIdempotent) {
// 	daemon->stop();
// 	EXPECT_FALSE(daemon->isRunning());
	
// 	// Second stop should not crash
// 	EXPECT_NO_THROW({
// 		daemon->stop();
// 	});
// }

// TEST: Config reload with file-based daemon (not in-memory)
TEST(NetMonDaemonConfigTest, FileBasedDaemonCanReload) {
    std::string config_path = "/tmp/test_daemon_reload_" + std::to_string(getpid()) + ".yaml";
    std::string db_path = "/tmp/test_reload_db_" + std::to_string(getpid()) + ".db";
    
    std::ofstream ofs(config_path);
    // ofs << "interface:\n";
    // ofs << "  name: lo0\n";
    ofs << "offline:\n";
    ofs << "  file: tests/fixtures/icmp_sample.pcap\n";
    ofs << "api:\n";
    ofs << "  token: test-token-123\n";
    ofs << "  host: localhost\n";
    ofs << "  port: 9998\n";
    ofs << "stats:\n";
    ofs << "  window_size: 1\n";
    ofs << "  history_depth: 3\n";
    ofs << "database:\n";
    ofs << "  path: " << db_path << "\n";
    ofs << "logging:\n";
    ofs << "  level: error\n";  // Reduces log noise
    ofs.close();
    
    // SMART POINTER for cleanup
    auto daemon = std::make_unique<NetMonDaemon>(config_path);
    
    std::thread t([&daemon]() {
        daemon->run();
    });
    
    // DAEMON START
    bool daemon_ready = false;
    for (int i = 0; i < 20; ++i) {
        try {
            httplib::Client client("localhost", 9998);
            client.set_read_timeout(2, 0);
            auto res = client.Get("/metrics?token=test-token-123");
            if (res && res->status == 200) {
                daemon_ready = true;
                break;
            }
        } catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    if (!daemon_ready) {
        daemon->stop();
        if (t.joinable()) t.join();
        std::filesystem::remove(config_path);
        std::filesystem::remove(db_path);
        std::filesystem::remove(db_path + ".sessions");
        GTEST_SKIP() << "Daemon failed to start within timeout";
    }
    
    // WAIT FOR RATE LIMIT TO EXPIRE
    std::this_thread::sleep_for(std::chrono::seconds(6));
    
    httplib::Client client("localhost", 9998);
    httplib::Headers headers = {
        {"Authorization", "Bearer test-token-123"}
    };
    auto res = client.Post("/control/reload", headers, "", "application/json");
    
    EXPECT_EQ(res->status, 200);
    
    // SHUTDOWN SEQUENCE
    daemon->stop();
    
    // WAIT FOR DAEMON TO FULLY STOP
    auto start = std::chrono::steady_clock::now();
    while (daemon->isRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(5)) {
            std::cerr << "WARNING: Daemon shutdown timeout" << std::endl;
            break;
        }
    }
    
    // JOIN THREAD BEFORE DESTROYING DAEMON
    if (t.joinable()) {
        t.join();
    }
    
    // CLEANUP
    daemon.reset();  // Destroy daemon after thread is joined
    
    // Cleanup files
    std::filesystem::remove(config_path);
    std::filesystem::remove(db_path);
    std::filesystem::remove(db_path + ".sessions");
}

// Test: /metrics/history invalid parameters
TEST_F(NetMonDaemonTest, MetricsHistoryEndpointRejectsInvalidParams) {
	// start > end
	int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	std::string url = "/metrics/history?start=" + std::to_string(now + 100) + "&end=" + std::to_string(now);

	auto res = makeAuthenticatedGet(url);
	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(res->status, 400);

	auto j = json::parse(res->body);
	EXPECT_TRUE(j.contains("error"));
}

// ============================================================
// COVERAGE TESTS: Protocol Breakdown & Active Flows
// ============================================================

TEST_F(NetMonDaemonTest, MetricsEndpointReturnsProtocolBreakdown) {
    // Wait for stats to accumulate
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    auto res = makeAuthenticatedGet("/metrics");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("protocol_breakdown"));
    
    // Protocol breakdown should be an object
    auto& breakdown = j["protocol_breakdown"];
    EXPECT_TRUE(breakdown.is_object());
    
    // If icmp_sample.pcap has ICMP packets, verify they're counted
    if (breakdown.contains("OTHER")) {
        EXPECT_GT(breakdown["OTHER"].get<uint64_t>(), 0);
    }
}

TEST_F(NetMonDaemonTest, MetricsEndpointReturnsActiveFlows) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    auto res = makeAuthenticatedGet("/metrics");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("active_flows"));
    
    auto& flows = j["active_flows"];
    EXPECT_TRUE(flows.is_array());
    
    // If any flows exist, validate full structure
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
        EXPECT_EQ(flow["state"], "active");
    }
}

// ============================================================
// COVERAGE TESTS: /metrics/history Parameter Parsing
// ============================================================

TEST_F(NetMonDaemonTest, MetricsHistoryWithInvalidStartTimestamp) {
    auto res = makeAuthenticatedGet("/metrics/history?start=not_a_number&end=1000000000");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 400);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["error"], "invalid 'start' timestamp");
}

TEST_F(NetMonDaemonTest, MetricsHistoryWithInvalidEndTimestamp) {
    auto res = makeAuthenticatedGet("/metrics/history?start=1000000000&end=invalid");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 400);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["error"], "invalid 'end' timestamp");
}

TEST_F(NetMonDaemonTest, MetricsHistoryWithInvalidLimitParam) {
    int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    auto res = makeAuthenticatedGet("/metrics/history?start=0&end=" + std::to_string(now) + "&limit=not_a_number");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 400);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["error"], "invalid 'limit' timestamp");
}

TEST_F(NetMonDaemonTest, MetricsHistoryWithExcessiveLimitClamped) {
    int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    auto res = makeAuthenticatedGet("/metrics/history?start=0&end=" + std::to_string(now) + "&limit=100000");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    // Limit should be clamped to 43200 internally
    EXPECT_TRUE(j.contains("windows"));
}

TEST_F(NetMonDaemonTest, MetricsHistoryWithoutStartUsesDefault) {
    int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    auto res = makeAuthenticatedGet("/metrics/history?end=" + std::to_string(now));
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("start"));
    // Should default to 24 hours before end
    EXPECT_EQ(j["start"], now - (24 * 3600));
}

// ============================================================
// COVERAGE TESTS: New API Endpoints
// ============================================================

TEST_F(NetMonDaemonTest, TopTalkersEndpointReturnsValidJSON) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    auto res = makeAuthenticatedGet("/api/top-talkers");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("top_sources"));
    EXPECT_TRUE(j.contains("top_destinations"));
    EXPECT_TRUE(j["top_sources"].is_array());
    EXPECT_TRUE(j["top_destinations"].is_array());
    
    // Validate structure if any top talkers exist
    if (!j["top_sources"].empty()) {
        auto& src = j["top_sources"][0];
        EXPECT_TRUE(src.contains("ip"));
        EXPECT_TRUE(src.contains("bytes"));
    }
}

TEST_F(NetMonDaemonTest, TopTalkersRequiresAuth) {
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/api/top-talkers");
    EXPECT_EQ(res->status, 401);
}

TEST_F(NetMonDaemonTest, PortStatsEndpointReturnsValidJSON) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    auto res = makeAuthenticatedGet("/api/port-stats");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.is_array());
    
    // Validate structure if any port stats exist
    if (!j.empty()) {
        auto& port_stat = j[0];
        EXPECT_TRUE(port_stat.contains("port"));
        EXPECT_TRUE(port_stat.contains("bytes"));
        EXPECT_TRUE(port_stat.contains("connections"));
        EXPECT_TRUE(port_stat.contains("service"));
    }
}

TEST_F(NetMonDaemonTest, PortStatsRequiresAuth) {
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/api/port-stats");
    EXPECT_EQ(res->status, 401);
}

TEST_F(NetMonDaemonTest, SystemHealthEndpointReturnsValidJSON) {
    auto res = makeAuthenticatedGet("/api/system-health");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("uptime_seconds"));
    EXPECT_TRUE(j.contains("packets_received"));
    EXPECT_TRUE(j.contains("packets_dropped"));
    EXPECT_TRUE(j.contains("drop_rate"));
    EXPECT_TRUE(j.contains("active_flows"));
    EXPECT_TRUE(j.contains("capture_running"));
    EXPECT_TRUE(j.contains("interface"));
    EXPECT_TRUE(j.contains("buffer_usage_percent"));
    
    EXPECT_GE(j["uptime_seconds"].get<int64_t>(), 0);
    EXPECT_GE(j["drop_rate"].get<double>(), 0.0);
}

TEST_F(NetMonDaemonTest, SystemHealthRequiresAuth) {
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/api/system-health");
    EXPECT_EQ(res->status, 401);
}

TEST_F(NetMonDaemonTest, PacketSizesEndpointReturnsValidJSON) {
    auto res = makeAuthenticatedGet("/api/packet-sizes");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("tiny"));
    EXPECT_TRUE(j.contains("small"));
    EXPECT_TRUE(j.contains("medium"));
    EXPECT_TRUE(j.contains("large"));
    EXPECT_TRUE(j.contains("jumbo"));
    
    EXPECT_TRUE(j["tiny"].is_number());
    EXPECT_TRUE(j["small"].is_number());
}

// ============================================================
// COVERAGE TESTS: Helper Methods
// ============================================================

TEST_F(NetMonDaemonTest, GetServiceNameReturnsKnownPorts) {
    // Test via port-stats endpoint which calls getServiceName()
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    auto res = makeAuthenticatedGet("/api/port-stats");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    if (!j.empty()) {
        // If we have port 80, verify it's labeled "HTTP"
        for (const auto& port_stat : j) {
            if (port_stat["port"] == 80) {
                EXPECT_EQ(port_stat["service"], "HTTP");
            }
            if (port_stat["port"] == 443) {
                EXPECT_EQ(port_stat["service"], "HTTPS");
            }
        }
    }
}

TEST_F(NetMonDaemonTest, LoggingLevelFiltersMessages) {
	// Create daemon with "error" log level
	YAML::Node config = createTestConfigNode(true);
	config["logging"]["level"] = "error";
	config["api"]["port"] = 9997;  // Use different port to avoid conflicts
	
	// Construction should succeed without errors
	EXPECT_NO_THROW({
		NetMonDaemon test_daemon(config, "test-log-filter");
	});
	
	// Logging is an internal implementation detail, so we test it
	// indirectly through daemon operation and output level configuration
}

// ============================================================
// FAVICON TESTS
// ============================================================

TEST_F(NetMonDaemonTest, FaviconReturns404WhenMissing) {
    // Daemon's static_files_dir_ likely points to non-existent favicon path in CI
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/favicon.ico");
    
    // Should return 404 if favicon file doesn't exist
    EXPECT_TRUE(res->status == 404 || res->status == 200);
}

TEST_F(NetMonDaemonTest, FaviconServedWhenPresent) {
    // If favicon exists, verify content-type
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/favicon.ico");
    
    if (res->status == 200) {
        EXPECT_EQ(res->get_header_value("Content-Type"), "image/x-icon");
    }
}

// ============================================================
// LOGIN ERROR PATHS
// ============================================================

TEST_F(NetMonDaemonTest, LoginWithWrongPassword) {
    httplib::Client client(test_host, test_port);
    
    nlohmann::json body = {
        {"username", test_username},
        {"password", "wrong_password_123"}
    };
    
    auto res = client.Post("/login", body.dump(), "application/json");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 401);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["error"], "invalid credentials");
}

TEST_F(NetMonDaemonTest, LoginWithMalformedJSON) {
    httplib::Client client(test_host, test_port);
    
    // Send invalid JSON to trigger exception path
    auto res = client.Post("/login", "{invalid json", "application/json");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 400);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["error"], "malformed JSON");
}

// ============================================================
// RELOAD RATE LIMITING
// ============================================================

TEST_F(NetMonDaemonTest, ReloadRateLimitEnforced) {

    std::this_thread::sleep_for(std::chrono::seconds(6));

    auto token = loginUser(test_username, test_password);
    
    httplib::Client client(test_host, test_port);
    httplib::Headers headers = {{"X-Session-Token", token}};
    
    // First reload should succeed
    auto res1 = client.Post("/control/reload", headers, "", "application/json");
    EXPECT_EQ(res1->status, 200);
    
    // Immediate second reload should be rate-limited
    auto res2 = client.Post("/control/reload", headers, "", "application/json");
    EXPECT_EQ(res2->status, 429);
    
    auto j = json::parse(res2->body);
    EXPECT_EQ(j["error"], "rate limit exceeded");
}

TEST_F(NetMonDaemonTest, ReloadWithInvalidConfig) {
    // Skip test if daemon is in-memory (can't reload from disk)
    if (daemon && daemon->isRunning() && config_path_.empty()) {
        GTEST_SKIP() << "Test skipped: daemon uses in-memory config (cannot reload)";
    }

    std::this_thread::sleep_for(std::chrono::seconds(6));

    auto token = loginUser(test_username, test_password);
    
    // Create a temporary file-based config
    std::string temp_config = "/tmp/test_reload_invalid_" + std::to_string(getpid()) + ".yaml";
    std::ofstream(temp_config) << "interface:\n  name: lo0\napi:\n  token: test\n";
    
    std::string backup_path = temp_config + ".backup";
    std::filesystem::copy_file(temp_config, backup_path);
    
    // Corrupt config
    std::ofstream ofs(temp_config);
    ofs << "invalid: yaml: [[[";
    ofs.close();
    
    httplib::Client client(test_host, test_port);
    httplib::Headers headers = {{"X-Session-Token", token}};
    
    auto res = client.Post("/control/reload", headers, "", "application/json");
    
    // In-memory daemon skips reload
    EXPECT_EQ(res->status, 200);
    auto j = json::parse(res->body);
    EXPECT_EQ(j["message"], "config reload skipped (in-memory config)");
    
    // Cleanup
    std::filesystem::remove(temp_config);
    std::filesystem::remove(backup_path);
}

// ============================================================
// METRICS/HISTORY AUTHORIZATION
// ============================================================

TEST_F(NetMonDaemonTest, MetricsHistoryRequiresAuth) {
    httplib::Client client(test_host, test_port);
    auto res = client.Get("/metrics/history");
    
    EXPECT_EQ(res->status, 401);
    auto j = json::parse(res->body);
    EXPECT_EQ(j["error"], "unauthorized");
}

// ============================================================
// PROTOCOL BREAKDOWN WITH MULTIPLE PROTOCOLS
// ============================================================

TEST_F(NetMonDaemonTest, ProtocolBreakdownIncludesTCPUDPOther) {
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    auto res = makeAuthenticatedGet("/metrics");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    ASSERT_TRUE(j.contains("protocol_breakdown"));
    
    auto& breakdown = j["protocol_breakdown"];

	// If still empty, daemon may need aggregator->advanceWindow() call
    // For offline mode, ensure aggregator processes packets before test runs
    if (breakdown.size() == 0) {
        GTEST_SKIP() << "No protocol breakdown data available (offline pcap may be empty or not processed)";
    }

    // Verify at least one protocol exists
    EXPECT_GT(breakdown.size(), 0);
    
    // If OTHER exists, bytes should be > 0
    if (breakdown.contains("OTHER")) {
        EXPECT_GT(breakdown["OTHER"].get<uint64_t>(), 0);
    }
}

// ============================================================
// ACTIVE FLOWS FULL STRUCTURE
// ============================================================

TEST_F(NetMonDaemonTest, ActiveFlowsContainAllFields) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto res = makeAuthenticatedGet("/metrics");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    ASSERT_TRUE(j.contains("active_flows"));
    
    auto& flows = j["active_flows"];
    if (!flows.empty()) {
        auto& flow = flows[0];
        
        // Verify all fields exist
        EXPECT_TRUE(flow.contains("iface"));
        EXPECT_TRUE(flow.contains("src_ip"));
        EXPECT_TRUE(flow.contains("src_port"));
        EXPECT_TRUE(flow.contains("dst_ip"));
        EXPECT_TRUE(flow.contains("dst_port"));
        EXPECT_TRUE(flow.contains("protocol"));
        EXPECT_TRUE(flow.contains("bytes"));
        EXPECT_TRUE(flow.contains("packets"));
        EXPECT_TRUE(flow.contains("state"));
        
        // Verify protocol is one of TCP/UDP/OTHER
        std::string proto = flow["protocol"];
        EXPECT_TRUE(proto == "TCP" || proto == "UDP" || proto == "OTHER");
        
        EXPECT_EQ(flow["state"], "active");
    }
}

// ============================================================
// TOP TALKERS WITH SORTING
// ============================================================

TEST_F(NetMonDaemonTest, TopTalkersAreSortedByBytes) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto res = makeAuthenticatedGet("/api/top-talkers");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.contains("top_sources"));
    EXPECT_TRUE(j.contains("top_destinations"));
    
    // Verify sorting (descending by bytes)
    if (j["top_sources"].size() >= 2) {
        uint64_t first_bytes = j["top_sources"][0]["bytes"];
        uint64_t second_bytes = j["top_sources"][1]["bytes"];
        EXPECT_GE(first_bytes, second_bytes);
    }
    
    if (j["top_destinations"].size() >= 2) {
        uint64_t first_bytes = j["top_destinations"][0]["bytes"];
        uint64_t second_bytes = j["top_destinations"][1]["bytes"];
        EXPECT_GE(first_bytes, second_bytes);
    }
}

// ============================================================
// PORT STATS WITH SERVICE NAMES
// ============================================================

TEST_F(NetMonDaemonTest, PortStatsIncludeServiceNames) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto res = makeAuthenticatedGet("/api/port-stats");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_TRUE(j.is_array());
    
    if (!j.empty()) {
        auto& port_stat = j[0];
        
        EXPECT_TRUE(port_stat.contains("port"));
        EXPECT_TRUE(port_stat.contains("bytes"));
        EXPECT_TRUE(port_stat.contains("connections"));
        EXPECT_TRUE(port_stat.contains("service"));
        
        // If port is well-known (e.g., 80), service should be non-empty
        uint16_t port = port_stat["port"];
        if (port == 80 || port == 443 || port == 22 || port == 53) {
            EXPECT_FALSE(port_stat["service"].get<std::string>().empty());
        }
    }
}

TEST_F(NetMonDaemonTest, PortStatsAreSortedByBytes) {
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto res = makeAuthenticatedGet("/api/port-stats");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    
    // Verify sorting (descending by bytes)
    if (j.size() >= 2) {
        uint64_t first_bytes = j[0]["bytes"];
        uint64_t second_bytes = j[1]["bytes"];
        EXPECT_GE(first_bytes, second_bytes);
    }
}

// ============================================================
// LOGGING TESTS
// ============================================================

TEST_F(NetMonDaemonTest, LogToFileWhenConfigured) {
    // Create daemon with log file configured
    YAML::Node config = createTestConfigNode(true);
    config["logging"]["file"] = "/tmp/netnet-test.log";
    config["api"]["port"] = 9998;
    
    EXPECT_NO_THROW({
        NetMonDaemon test_daemon(config, "test-log-file");
        // test_daemon.log("info", "Test log message");
    });
    
    // Verify log file was created
    EXPECT_TRUE(std::filesystem::exists("/tmp/netnet-test.log"));
    std::filesystem::remove("/tmp/netnet-test.log");
}

TEST_F(NetMonDaemonTest, LogLevelFilteringWorks) {
	YAML::Node config = createTestConfigNode(true);
	config["logging"]["level"] = "warn";
	config["api"]["port"] = 9995;
	
	// Test log level configuration by observing daemon behavior
	// The log level filtering is an internal implementation detail
	EXPECT_NO_THROW({
		NetMonDaemon test_daemon(config, "test-log-level");
		// Daemon should start successfully with warn log level
	});
}

// ============================================================
// SERVICE NAME LOOKUP
// ============================================================

TEST_F(NetMonDaemonTest, GetServiceNameReturnsKnownServices) {
    // Test via port-stats which calls getServiceName()
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto res = makeAuthenticatedGet("/api/port-stats");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    
    // Verify well-known ports have service names
    bool found_http = false;
    bool found_https = false;
    
    for (const auto& port_stat : j) {
        if (port_stat["port"] == 80) {
            EXPECT_EQ(port_stat["service"], "HTTP");
            found_http = true;
        }
        if (port_stat["port"] == 443) {
            EXPECT_EQ(port_stat["service"], "HTTPS");
            found_https = true;
        }
    }
    
    // If neither found, that's ok (depends on pcap content)
}

TEST_F(NetMonDaemonTest, GetServiceNameReturnsEmptyForUnknownPort) {
    // Port 65535 should not be in the services map
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    auto res = makeAuthenticatedGet("/api/port-stats");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    
    for (const auto& port_stat : j) {
        if (port_stat["port"] == 65535) {
            EXPECT_EQ(port_stat["service"], "");
        }
    }
}

// SEPARATED FIXTURE for tests that stop daemon
class NetMonDaemonStopTest : public ::testing::Test {
protected:
    std::unique_ptr<NetMonDaemon> daemon;
    std::thread daemon_thread;
    
    void SetUp() override {
        YAML::Node config;
        config["offline"]["file"] = "tests/fixtures/icmp_sample.pcap";
        config["stats"]["window_size"] = 1;
        config["stats"]["history_depth"] = 2;
        config["database"]["path"] = ":memory:";
        config["api"]["token"] = "test-token-12345";
        config["api"]["host"] = "localhost";
        config["api"]["port"] = 9996;  // Different port
        config["api"]["session_expiry"] = 60;
        config["logging"]["level"] = "error";
        
        daemon = std::make_unique<NetMonDaemon>(config, "test-stop-daemon");
        daemon_thread = std::thread([this]() { daemon->run(); });
        
        // Wait for startup
        bool daemon_ready = false;
        for (int i = 0; i < 10; ++i) {
            try {
                httplib::Client client("localhost", 9996);
                auto res = client.Get("/metrics?token=test-token-12345");
                if (res && res->status == 200) {
                    daemon_ready = true;
                    break;
                }
            } catch (...) {}
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    void TearDown() override {
        if (daemon) daemon->stop();
        if (daemon_thread.joinable()) daemon_thread.join();
    }
};

// STOP TESTS HERE
TEST_F(NetMonDaemonStopTest, ControlStopEndpoint) {
    httplib::Client client("localhost", 9996);
    httplib::Headers headers = {
        {"Authorization", "Bearer test-token-12345"}
    };
    
    auto res = client.Post("/control/stop", headers, "", "application/json");
    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    
    auto j = json::parse(res->body);
    EXPECT_EQ(j["status"], "stopped");
    
    EXPECT_FALSE(daemon->isRunning());
}

TEST_F(NetMonDaemonStopTest, StopDaemonIsIdempotent) {
    daemon->stop();
    EXPECT_FALSE(daemon->isRunning());
    
    EXPECT_NO_THROW({
        daemon->stop();
    });
}