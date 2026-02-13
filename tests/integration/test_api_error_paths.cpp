#include <gtest/gtest.h>
#include "daemon/NetMonDaemon.h"
#include "httplib.h"
#include <nlohmann/json.hpp>

class ApiErrorPathsTest : public ::testing::Test {
protected:
    static std::unique_ptr<NetMonDaemon> daemon;
    static std::thread daemon_thread;
    static std::string test_host;
    static int test_port;
    static std::string api_token;
    
    static void SetUpTestSuite() {
        test_host = "localhost";
        test_port = 9997;
        api_token = "test-token";
        
        YAML::Node config;
        config["interface"]["name"] = "lo0";
        config["api"]["token"] = api_token;
        config["api"]["host"] = test_host;
        config["api"]["port"] = test_port;
        config["stats"]["window_size"] = 1;
        config["stats"]["history_depth"] = 2;
        config["database"]["path"] = ":memory:";
        
        YAML::Node user;
        user["username"] = "test";
        user["password"] = "pass";
        config["users"].push_back(user);
        
        daemon = std::make_unique<NetMonDaemon>(config, "api-error-test-shared");
        daemon_thread = std::thread([]() { daemon->run(); });
        
        // Wait for startup (only once)
        for (int i = 0; i < 10; ++i) {
            try {
                httplib::Client client(test_host, test_port);
                auto res = client.Get("/metrics?token=" + api_token);
                if (res && res->status > 0) break;
            } catch (...) {}
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    static void TearDownTestSuite() {
        if (daemon) daemon->stop();
        if (daemon_thread.joinable()) daemon_thread.join();
    }
    
    void SetUp() override {}
    void TearDown() override {}
};

std::unique_ptr<NetMonDaemon> ApiErrorPathsTest::daemon = nullptr;
std::thread ApiErrorPathsTest::daemon_thread;
std::string ApiErrorPathsTest::test_host = "localhost";
int ApiErrorPathsTest::test_port = 9997;
std::string ApiErrorPathsTest::api_token = "test-token";

TEST_F(ApiErrorPathsTest, Login_MissingUsername) {
    httplib::Client client(test_host, test_port);
    nlohmann::json body = {{"password", "test"}};
    
    auto res = client.Post("/login", body.dump(), "application/json");
    EXPECT_EQ(res->status, 400);
}

TEST_F(ApiErrorPathsTest, Login_MissingPassword) {
    httplib::Client client(test_host, test_port);
    nlohmann::json body = {{"username", "test"}};
    
    auto res = client.Post("/login", body.dump(), "application/json");
    EXPECT_EQ(res->status, 400);
}

TEST_F(ApiErrorPathsTest, Login_EmptyCredentials) {
    httplib::Client client(test_host, test_port);
    nlohmann::json body = {{"username", ""}, {"password", ""}};
    
    auto res = client.Post("/login", body.dump(), "application/json");
    EXPECT_EQ(res->status, 400);
}

TEST_F(ApiErrorPathsTest, Login_MalformedJSON) {
    httplib::Client client(test_host, test_port);
    
    auto res = client.Post("/login", "{not valid json", "application/json");
    EXPECT_EQ(res->status, 400);
}

TEST_F(ApiErrorPathsTest, Logout_NoSessionToken) {
    httplib::Client client(test_host, test_port);
    
    auto res = client.Post("/logout");
    EXPECT_EQ(res->status, 400);
}

TEST_F(ApiErrorPathsTest, Logout_InvalidSessionToken) {
    httplib::Client client(test_host, test_port);
    httplib::Headers headers = {{"X-Session-Token", "invalid-token-12345"}};
    
    auto res = client.Post("/logout", headers, "", "application/json");
    EXPECT_EQ(res->status, 401);
}

TEST_F(ApiErrorPathsTest, ControlReload_RateLimitExceeded) {
    httplib::Client client(test_host, test_port);
    httplib::Headers headers = {{"Authorization", "Bearer " + api_token}};
    
    // First request succeeds
    auto res1 = client.Post("/control/reload", headers, "", "application/json");
    EXPECT_EQ(res1->status, 200);
    
    // Second immediate request is rate-limited
    auto res2 = client.Post("/control/reload", headers, "", "application/json");
    EXPECT_EQ(res2->status, 429);
}

TEST_F(ApiErrorPathsTest, MetricsHistory_StartAfterEnd) {
    httplib::Client client(test_host, test_port);
    
    auto res = client.Get("/metrics/history?start=100&end=50&token=" + api_token);
    EXPECT_EQ(res->status, 400);
}

TEST_F(ApiErrorPathsTest, MetricsHistory_InvalidStartTimestamp) {
    httplib::Client client(test_host, test_port);
    
    auto res = client.Get("/metrics/history?start=not_a_number&token=" + api_token);
    EXPECT_EQ(res->status, 400);
}

TEST_F(ApiErrorPathsTest, MetricsHistory_InvalidLimitParameter) {
    httplib::Client client(test_host, test_port);
    
    auto res = client.Get("/metrics/history?limit=invalid&token=" + api_token);
    EXPECT_EQ(res->status, 400);
}