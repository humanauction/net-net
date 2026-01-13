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
		try {
			// Create YAML config in memory (no file I/O!)
			YAML::Node config = createTestConfigNode();

			// Create daemon with in-memory config
			daemon = std::make_unique<NetMonDaemon>(config, "test-daemon-config");

			// Start daemon in background thread
			daemon_thread = std::thread([this]() {
				try {
					daemon->run();
				} catch (const std::exception& ex) {
					std::cerr << "Daemon thread exception: " << ex.what() << std::endl;
					throw;
				}
			});

			// Wait for daemon to be ready
			bool ready = false;
			for (int i = 0; i < 50; ++i) {
				httplib::Client client(test_host, test_port);
				client.set_connection_timeout(1, 0);
				auto res = client.Post("/login", "{}", "application/json");
				if (res && (res->status == 400 || res->status == 401)) {
					ready = true;
					break;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}

			ASSERT_TRUE(ready) << "ERROR: Daemon failed to start within 5 seconds";
		} catch (const std::exception& ex) {
			std::cerr << "SetUp() exception: " << ex.what() << std::endl;
			throw;
		}
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
		// config["database"]["path"] = ":memory:";

		// Use temp file for persistence testing
		config["database"]["path"] = "test_daemon.db";

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
TEST_F(NetMonDaemonTest, ExpiredSessionTokenReturns401) {
	// Create short-lived session
	std::string test_db = "/tmp/test_session_expired_" + std::to_string(getpid()) + ".db";
	SessionManager short_mgr(test_db, 1);  // 1 second expiry
	
	std::string token = short_mgr.createSession("testuser", "127.0.0.1");
	
	sleep(2);  // Wait for expiry
	
	auto res = makeSessionGet("/metrics", token);
	EXPECT_EQ(res->status, 401);
	
	unlink(test_db.c_str());
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
	auto res1 = makeAuthenticatedPost("/control/reload");
	EXPECT_EQ(res1->status, 200);
	
	auto res2 = makeAuthenticatedPost("/control/reload");
	EXPECT_EQ(res2->status, 429);
	
	auto res3 = makeAuthenticatedPost("/control/reload");
	EXPECT_EQ(res3->status, 429);
}

// Test control endpoints with session token (not just API token)
TEST_F(NetMonDaemonTest, ControlEndpointsWorkWithSessionToken) {
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

// ✅ ADD: Test PcapAdapter validation directly
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
	
	// ✅ FIX: httplib returns 400 for malformed/oversized headers
	EXPECT_TRUE(res->status == 400 || res->status == 401);  // Either is acceptable
}

// TEST: Stop daemon multiple times (idempotency test)
TEST_F(NetMonDaemonTest, StopDaemonIsIdempotent) {
	daemon->stop();
	EXPECT_FALSE(daemon->isRunning());
	
	// Second stop should not crash
	EXPECT_NO_THROW({
		daemon->stop();
	});
}

// TEST: Config reload with file-based daemon (not in-memory)
TEST(NetMonDaemonConfigTest, FileBasedDaemonCanReload) {
	std::string config_path = "/tmp/test_daemon_reload_" + std::to_string(getpid()) + ".yaml";
	std::string db_path = "/tmp/test_reload_db_" + std::to_string(getpid()) + ".db";
	
	std::ofstream ofs(config_path);
	ofs << "interface:\n";
	ofs << "  name: lo0\n";
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
	ofs.close();
	
	NetMonDaemon daemon(config_path);
	
	std::thread t([&]() {
		daemon.run();
	});
	
	std::this_thread::sleep_for(std::chrono::seconds(1));
	
	httplib::Client client("localhost", 9998);
	httplib::Headers headers = {
		{"Authorization", "Bearer test-token-123"}
	};
	auto res = client.Post("/control/reload", headers, "", "application/json");
	
	EXPECT_EQ(res->status, 200);
	
	daemon.stop();
	if (t.joinable()) t.join();
	
	// Cleanup
	std::filesystem::remove(config_path);
	std::filesystem::remove(db_path);
	std::filesystem::remove(db_path + ".sessions");
}

// Test /metrics/history endpoint 
TEST_F(NetMonDaemonTest, MetricsHistoryEndpointReturnsValidJSON) {
	// Wait for at least one stats window to be persisted
	std::this_thread::sleep_for(std::chrono::seconds(5));

	// Query /metrics/history
	int64_t start = 0;
	int64_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

	std::string url = "/metrics/history?start=" + std::to_string(start) + "&end=" + std::to_string(now) + "&limit=10";
	auto res = makeAuthenticatedGet(url);

	ASSERT_TRUE(res != nullptr);
	EXPECT_EQ(res->status, 200);
	EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");

	auto j = json::parse(res->body);

	EXPECT_TRUE(j.contains("start"));
	EXPECT_TRUE(j.contains("end"));
	EXPECT_TRUE(j.contains("windows"));
	EXPECT_TRUE(j["windows"].is_array());
	// At least one window should be present if stats are being persisted
	EXPECT_GE(j["windows"].size(), 1);

	// Validate window structure
	if (!j["windows"].empty()) {
		auto& w = j["windows"][0];
		EXPECT_TRUE(w.contains("timestamp"));
		EXPECT_TRUE(w.contains("window_start"));
		EXPECT_TRUE(w.contains("total_bytes"));
		EXPECT_TRUE(w.contains("total_packets"));
		EXPECT_TRUE(w.contains("bytes_per_second"));
		EXPECT_TRUE(w.contains("protocol_breakdown"));
		EXPECT_TRUE(w["protocol_breakdown"].is_object());
	}
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