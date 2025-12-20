#include <gtest/gtest.h>
#include "core/SessionManager.h"

#include <unistd.h>
#include <regex>
#include <sqlite3.h>
#include <chrono>
#include <cstdio>
#include <string>
#include <sys/stat.h>
#include <cstdint>
#include <filesystem>
namespace fs = std::filesystem;

// Helper: RAII cleanup guard
struct ScopeExit {
    std::function<void()> fn;
    bool dismissed = false;
    ScopeExit(std::function<void()> f) : fn(f) {}
    ~ScopeExit() { if (!dismissed && fn) fn(); }
    void dismiss() { dismissed = true; }
};

// Helper: get current Unix timestamp
static int64_t now_sec() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
}

// Helper: execute raw SQL on a sqlite3* handle
static void exec_sql_raw(sqlite3* db, const char* sql) {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string error = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        throw std::runtime_error("SQL error: " + error);
    }
}

// Helper: manually set last_activity timestamp in DB
static void set_last_activity(const std::string& db_path, const std::string& token, int64_t ts) {
    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        throw std::runtime_error("Failed to open DB for set_last_activity");
    }
    ScopeExit cleanup([&] { sqlite3_close(db); });

    std::string sql = "UPDATE sessions SET last_activity = " + std::to_string(ts) +
                      " WHERE token = '" + token + "';";
    exec_sql_raw(db, sql.c_str());
}

// ✅ Test fixture with test_db_path_ member
class SessionManagerTest : public ::testing::Test {
protected:
    std::unique_ptr<SessionManager> manager_;
    std::string test_db_path_;  // ✅ ADD THIS

    void SetUp() override {
        test_db_path_ = "test_sessions_" + std::to_string(getpid()) + ".db";
        
        // Remove if exists
        if (fs::exists(test_db_path_)) {
            fs::remove(test_db_path_);
        }
        
        manager_ = std::make_unique<SessionManager>(test_db_path_, 3600);
    }

    void TearDown() override {
        manager_.reset();
        
        // Cleanup test DB files
        if (fs::exists(test_db_path_)) {
            fs::remove(test_db_path_);
        }
        
        std::string wal_file = test_db_path_ + "-wal";
        std::string shm_file = test_db_path_ + "-shm";
        
        if (fs::exists(wal_file)) fs::remove(wal_file);
        if (fs::exists(shm_file)) fs::remove(shm_file);
    }
};

// Standalone tests that DON'T use the fixture
class SessionManagerStandaloneTest : public ::testing::Test {};

TEST_F(SessionManagerStandaloneTest, ConstructorThrowsWhenDbPathCannotBeOpened) {
    EXPECT_THROW({
        SessionManager mgr("/dev/null/impossible.db", 3600);
    }, SQLite::Exception);
}

TEST_F(SessionManagerStandaloneTest, ConstructorThrowsWhenDbIsReadOnly) {
    const std::string readonly_db = "readonly_test.db";
    
    {
        SessionManager temp(readonly_db, 3600);
    }
    
    chmod(readonly_db.c_str(), 0444);
    
    EXPECT_THROW({
        SessionManager mgr(readonly_db, 3600);
    }, SQLite::Exception);
    
    chmod(readonly_db.c_str(), 0644);
    fs::remove(readonly_db);
    fs::remove(readonly_db + "-wal");
    fs::remove(readonly_db + "-shm");
}

// ✅ Now this test can access test_db_path_
TEST_F(SessionManagerTest, ValidateSessionReturnsTrueEvenIfLastActivityUpdateIsBusy) {
    const std::string token = manager_->createSession("locktest", "127.0.0.1");

    const int64_t forced_old_ts = now_sec() - 100;
    set_last_activity(test_db_path_, token, forced_old_ts);

    const auto forced_old_tp =
        std::chrono::time_point_cast<std::chrono::seconds>(
            std::chrono::system_clock::from_time_t(forced_old_ts));

    {
        sqlite3* db2 = nullptr;
        ASSERT_EQ(sqlite3_open(test_db_path_.c_str(), &db2), SQLITE_OK);
        sqlite3_busy_timeout(db2, 0);

        ScopeExit cleanup([&] {
            if (!db2) return;
            sqlite3_exec(db2, "ROLLBACK;", nullptr, nullptr, nullptr);
            sqlite3_close(db2);
            db2 = nullptr;
        });

        exec_sql_raw(db2, "BEGIN EXCLUSIVE;");
        
        std::string lock_sql = "UPDATE sessions SET last_activity = last_activity WHERE token = '" + token + "';";
        exec_sql_raw(db2, lock_sql.c_str());

        SessionData out{};
        EXPECT_TRUE(manager_->validateSession(token, out));

        const auto out_last_tp =
            std::chrono::time_point_cast<std::chrono::seconds>(out.last_activity);

        EXPECT_EQ(out_last_tp, forced_old_tp);

        ASSERT_EQ(sqlite3_exec(db2, "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_close(db2), SQLITE_OK);
        db2 = nullptr;
        cleanup.dismiss();
    }

    SessionData out2{};
    ASSERT_TRUE(manager_->validateSession(token, out2));
    const auto out2_last_tp =
        std::chrono::time_point_cast<std::chrono::seconds>(out2.last_activity);

    // ✅ FIX: Compare time_point to time_point, NOT to int64_t
    EXPECT_GT(out2_last_tp, forced_old_tp);
}

// TEST createSession() returns valid UUID v4 token
TEST_F(SessionManagerTest, CreateSessionReturnsValidUUID) {
    std::string token = manager_->createSession("testuser", "192.168.1.100");

    std::regex uuid_pattern(
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        std::regex::icase
    );

    EXPECT_TRUE(std::regex_match(token, uuid_pattern))
        << "Token does not match UUID v4 format: " << token;

    EXPECT_EQ(token.length(), 36) << "UUID must be 36 characters in length";
}

// TEST createSession() generates unique token
TEST_F(SessionManagerTest, CreateSessionGeneratesUniqueToken) {
    std::string token1 = manager_->createSession("user","192.168.1.1");
    std::string token2 = manager_->createSession("user","192.168.1.2");
    std::string token3 = manager_->createSession("user","192.168.1.3");

    EXPECT_NE(token1, token2);
    EXPECT_NE(token1, token3);
    EXPECT_NE(token2, token3);
}

// TEST createSession() persists to database
TEST_F(SessionManagerTest, CreateSessionPersistsToDatabase) {
    std::string token = manager_->createSession("admin", "10.0.0.1");

    SessionData data{};
    bool valid = manager_->validateSession(token, data);

    ASSERT_TRUE(valid) << "Session should exist in database";
    EXPECT_EQ(data.username, "admin");
    EXPECT_EQ(data.ip_address, "10.0.0.1");
    EXPECT_EQ(data.token, token);
}

// TEST createSession() sets correct timestamps, validateSession updates last_activity
TEST_F(SessionManagerTest, CreateSessionSetsTimestampsCorrectly) {
    // Truncate to second precision (matching typical SQLite storage)
    auto now = std::chrono::system_clock::now();
    auto now_seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);

    auto before_create = now_seconds - std::chrono::seconds(1);
    std::string token = manager_->createSession("testuser", "127.0.0.1");
    auto after_create = now_seconds + std::chrono::seconds(2);

    SessionData data{};
    ASSERT_TRUE(manager_->validateSession(token, data));

    auto created_at_seconds = std::chrono::time_point_cast<std::chrono::seconds>(data.created_at);
    auto last_activity_seconds = std::chrono::time_point_cast<std::chrono::seconds>(data.last_activity);

    EXPECT_GE(created_at_seconds, before_create);
    EXPECT_LE(created_at_seconds, after_create);

    // last_activity should === created_at initially
    EXPECT_EQ(created_at_seconds, last_activity_seconds);

    // Force last_activity far in the past, then validate to ensure it updates (no sleeps).
    const int64_t forced_old_ts = now_sec() - 100;
    set_last_activity(test_db_path_, token, forced_old_ts);

    SessionData data2{};
    ASSERT_TRUE(manager_->validateSession(token, data2));

    auto created_at_seconds2 = std::chrono::time_point_cast<std::chrono::seconds>(data2.created_at);
    auto last_activity_seconds2 = std::chrono::time_point_cast<std::chrono::seconds>(data2.last_activity);

    EXPECT_EQ(created_at_seconds, created_at_seconds2) << "created_at should never change";

    // Stable check: last_activity should move forward relative to the forced-old DB value.
    const auto forced_old_tp =
        std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::from_time_t(forced_old_ts));
    EXPECT_GT(last_activity_seconds2, forced_old_tp)
        << "last_activity should be updated to 'now' and therefore be > forced-old timestamp";
}

// TEST createSession() accepts special characters in username
TEST_F(SessionManagerTest, CreateSessionAcceptsSpecialCharacters) {
    std::string token = manager_->createSession("user@example.com", "192.168.1.1");

    SessionData data{};
    ASSERT_TRUE(manager_->validateSession(token, data));
    EXPECT_EQ(data.username, "user@example.com");
}

// TEST createSession() accepts IPv6 addresses
TEST_F(SessionManagerTest, CreateSessionAcceptsIPv6) {
    std::string token = manager_->createSession("testuser", "2001:0db8:85a3::8a2e:0370:7334");

    SessionData data{};
    ASSERT_TRUE(manager_->validateSession(token, data));
    EXPECT_EQ(data.ip_address, "2001:0db8:85a3::8a2e:0370:7334");
}

// ADDITION: validateSession() rejects unknown tokens
TEST_F(SessionManagerTest, ValidateUnknownTokenReturnsFalse) {
    SessionData out{};
    EXPECT_FALSE(manager_->validateSession("does-not-exist", out));
}

// TEST validateSession() rejects expired sessions (no sleep; direct timestamp)
TEST_F(SessionManagerTest, ValidateSessionRejectsExpired) {
    std::string test_db = "/tmp/test_session_expired_" + std::to_string(getpid()) + ".db";
    unlink(test_db.c_str());
    SessionManager short_manager(test_db, 1);  // 1 second expiry

    std::string token = short_manager.createSession("testuser", "127.0.0.1");

    // Prove it exists first.
    SessionData data{};
    EXPECT_TRUE(short_manager.validateSession(token, data));

    // Force expiry beyond limit.
    set_last_activity(test_db, token, now_sec() - 2);

    SessionData data2{};
    EXPECT_FALSE(short_manager.validateSession(token, data2))
        << "Session should be invalid after expiry period";

    unlink(test_db.c_str());
}

// TEST validateSession() accepts sessions exactly at expiry boundary
TEST_F(SessionManagerTest, ExpiryBoundaryExactlyAtLimitIsStillValid) {
    std::string test_db = "/tmp/test_session_boundary_" + std::to_string(getpid()) + ".db";
    unlink(test_db.c_str());
    SessionManager sm(test_db, 10);

    const std::string token = sm.createSession("bob", "10.0.0.1");

    set_last_activity(test_db, token, now_sec() - 10);

    SessionData out{};
    EXPECT_TRUE(sm.validateSession(token, out));

    unlink(test_db.c_str());
}

// TEST validateSession() accepts sessions just inside expiry boundary
TEST_F(SessionManagerTest, ExpiryNearBoundaryIsStillValid) {
    std::string test_db = "/tmp/test_session_boundary2_" + std::to_string(getpid()) + ".db";
    unlink(test_db.c_str());
    SessionManager sm(test_db, 10);

    const std::string token = sm.createSession("bob", "10.0.0.1");
    set_last_activity(test_db, token, now_sec() - 9);

    SessionData out{};
    EXPECT_TRUE(sm.validateSession(token, out));

    unlink(test_db.c_str());
}

// TEST cleanupExpired() keeps sessions with last_activity exactly at cutoff, deletes strictly older
TEST_F(SessionManagerTest, CleanupBoundaryKeepsEqualCutoffDeletesStrictlyOlder) {
    std::string test_db = "/tmp/test_session_cleanup_boundary_" + std::to_string(getpid()) + ".db";
    unlink(test_db.c_str());
    SessionManager sm(test_db, 10);

    const std::string keep_equal = sm.createSession("keep", "10.0.0.10");
    const std::string drop_old   = sm.createSession("drop", "10.0.0.11");

    const int64_t t0 = now_sec();
    const int64_t cutoff = t0 - 10;

    set_last_activity(test_db, keep_equal, cutoff);     // equal cutoff => should remain
    set_last_activity(test_db, drop_old,   cutoff - 1); // older than cutoff => should be deleted

    sm.cleanupExpired();

    SessionData a{}, b{};
    EXPECT_TRUE(sm.validateSession(keep_equal, a));
    EXPECT_FALSE(sm.validateSession(drop_old, b));

    unlink(test_db.c_str());
}

// TEST deleteSession() removes session
TEST_F(SessionManagerTest, DeleteSessionRemovesSession) {
    std::string token = manager_->createSession("testuser", "127.0.0.1");

    SessionData data{};
    ASSERT_TRUE(manager_->validateSession(token, data))
        << "Session should exist before deletion";

    manager_->deleteSession(token);

    SessionData data2{};
    EXPECT_FALSE(manager_->validateSession(token, data2))
        << "Session should not exist after deletion";
}

// TEST cleanupExpired() removes old sessions (no sleep; direct timestamp)
TEST_F(SessionManagerTest, CleanupExpiredRemovesOldSessions) {
    std::string test_db = "/tmp/test_session_cleanup_" + std::to_string(getpid()) + ".db";
    unlink(test_db.c_str());
    SessionManager short_manager(test_db, 1);

    std::string token1 = short_manager.createSession("user1", "192.168.1.1");
    std::string token2 = short_manager.createSession("user2", "192.168.1.2");

    SessionData data{};
    ASSERT_TRUE(short_manager.validateSession(token1, data));
    ASSERT_TRUE(short_manager.validateSession(token2, data));

    set_last_activity(test_db, token1, now_sec() - 5);
    set_last_activity(test_db, token2, now_sec() - 5);

    short_manager.cleanupExpired();

    EXPECT_FALSE(short_manager.validateSession(token1, data));
    EXPECT_FALSE(short_manager.validateSession(token2, data));

    unlink(test_db.c_str());
}

// TEST cleanupExpired() removes expired but keeps recent
TEST_F(SessionManagerTest, CleanupExpiredRemovesOldButKeepsRecent) {
    std::string test_db = "/tmp/test_session_cleanup_keep_" + std::to_string(getpid()) + ".db";
    unlink(test_db.c_str());
    SessionManager sm(test_db, 10);

    const std::string keep = sm.createSession("eve", "10.0.0.4");
    const std::string drop = sm.createSession("frank", "10.0.0.5");

    set_last_activity(test_db, keep, now_sec());
    set_last_activity(test_db, drop, now_sec() - 100);

    sm.cleanupExpired();

    SessionData out_keep{};
    SessionData out_drop{};
    EXPECT_TRUE(sm.validateSession(keep, out_keep));
    EXPECT_FALSE(sm.validateSession(drop, out_drop));

    unlink(test_db.c_str());
}
