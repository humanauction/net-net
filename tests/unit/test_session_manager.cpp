#include <gtest/gtest.h>
#include "core/SessionManager.h"
#include <unistd.h>
#include <fstream>
#include <regex>
#include <thread>

// Test fixtures for SessionManager tests
class SessionManagerTest : public ::testing::Test {
protected:
    std::string test_db_path_;
    SessionManager* manager_;

        void SetUp() override {
            // Create unique test database in /tmp
            test_db_path_ = "/tmp/test_session_" + std::to_string(getpid()) + ".db";

            // Remove if exists from previous failed test
            unlink(test_db_path_.c_str());
            
            // Create session manager with 3600s expiry
            manager_ = new SessionManager(test_db_path_, 3600);
        }

        void TearDown() override {
            delete manager_;
            unlink(test_db_path_.c_str());
        }
}; 
// TEST createSession() returns valid UUID v4 token
TEST_F(SessionManagerTest, CreateSessionReturnsValidUUID) {
    std::string token = manager_->createSession("testuser", "192.168.1.100");

    // UUID v4 format: 8-4-4-4-12 hex digits separated by hyphens
    // Example: a1b2c3d4-e5f6-47g8-h9i0-j1k2l3m4n5o6
    std::regex uuid_pattern(
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        std::regex::icase
    );

    EXPECT_TRUE(std::regex_match(token, uuid_pattern))
        << "Token does not match UUID v4 format: " << token;

    EXPECT_EQ(token.length(), 36) << "UUID must be 36 characters in length";
}


// TEST 2: createSession() generates unique token
TEST_F(SessionManagerTest, CreateSessionGeneratesUniqueToken) {
    std::string token1 = manager_->createSession("user","192.168.1.1");
    std::string token2 = manager_->createSession("user","192.168.1.2");
    std::string token3 = manager_->createSession("user","192.168.1.3");
    
    EXPECT_NE(token1, token2);
    EXPECT_NE(token1, token3);
    EXPECT_NE(token2, token3);
}


// Test 3: createSession() persists to database
TEST_F(SessionManagerTest, CreateSessionPersistsToDatabase) {
    std::string token = manager_->createSession("admin", "10.0.0.1");
    
    // validate session exists == true
    SessionData data;
    bool valid = manager_->validateSession(token, data);

    ASSERT_TRUE(valid) << "Session should exist in database";
    EXPECT_EQ(data.username, "admin");
    EXPECT_EQ(data.ip_address, "10.0.0.1");
    EXPECT_EQ(data.token, token);
}

// TEST 4: createSession() sets correct timestamps
TEST_F(SessionManagerTest, CreateSessionSetsTimestampsCorrectly) {
    // Truncate to second precision (matching SQLite storage)
    auto now = std::chrono::system_clock::now();
    auto now_seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);

    auto before_create = now_seconds - std::chrono::seconds(1);
    std::string token = manager_->createSession("testuser", "127.0.0.1");
    auto after_create = now_seconds + std::chrono::seconds(1);

    // First validation - timestamps should be set correctly
    SessionData data;
    ASSERT_TRUE(manager_->validateSession(token, data));

    // Truncate retrieved timestamps to seconds for comparison
    auto created_at_seconds = std::chrono::time_point_cast<std::chrono::seconds>(data.created_at);
    auto last_activity_seconds = std::chrono::time_point_cast<std::chrono::seconds>(data.last_activity);

    // created_at should be between before and after timestamps
    EXPECT_GE(created_at_seconds, before_create)
        << "created_at should be >= before_create";
    EXPECT_LE(created_at_seconds, after_create)
        << "created_at should be <= after_create";


    // last_activity should === created_at initially
    EXPECT_EQ(created_at_seconds, last_activity_seconds)
        << "last_activity should equal created_at initially";

    // Sleep for 2 seconds (ensure different second in SQLite)
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Second validation - last_activity should be updated
    SessionData data2;
    ASSERT_TRUE(manager_->validateSession(token, data2));

    auto created_at_seconds2 = std::chrono::time_point_cast<std::chrono::seconds>(data2.created_at);
    auto last_activity_seconds2 = std::chrono::time_point_cast<std::chrono::seconds>(data2.last_activity);
    
    
    // created_at should not change
    EXPECT_EQ(created_at_seconds, created_at_seconds2)
        << "created_at should never change";

    // last_activity should allow ±1s tolerance 
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(
        last_activity_seconds2 - last_activity_seconds).count();

        EXPECT_GE(diff, 1)
            << "last_activity should advance by at least 1 second, got: " << diff << "s";
        EXPECT_LE(diff, 3)
            << "last_activity should advance by at least 3 seconds, got: " << diff << "s";
}

// TEST 5: createSession() accepts special characters in username
TEST_F(SessionManagerTest, CreateSessionAcceptsSpecialCharacters) {
    std::string token = manager_->createSession("user@example.com", "192.168.1.1");

    SessionData data;
    ASSERT_TRUE(manager_->validateSession(token, data));
    EXPECT_EQ(data.username, "user@example.com");
}

//TEST 6: createSession() accepts IPv6 addresses
TEST_F(SessionManagerTest, CreateSessionAcceptsIPv6) {
    std::string token = manager_->createSession("testuser", "2001:0db8:85a3::8a2e:0370:7334");

    SessionData data;
    ASSERT_TRUE(manager_->validateSession(token, data));
    EXPECT_EQ(data.ip_address, "2001:0db8:85a3::8a2e:0370:7334");
}

