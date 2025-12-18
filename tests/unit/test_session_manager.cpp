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
#include <stdexcept>
#include <memory>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

// Scope guard (keep ABOVE any function that uses ScopeExit)
template <class F>
class ScopeExit {
public:
    explicit ScopeExit(F f) : f_(std::move(f)), active_(true) {}
    ~ScopeExit() { if (active_) f_(); }
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;
    void dismiss() { active_ = false; }
private:
    F f_;
    bool active_;
};

// Seconds since epoch (matches typical SQLite INTEGER seconds usage)
static int64_t now_sec() {
    const auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
}

// Helper to set last_activity timestamp directly in DB for a given token
static void set_last_activity(const std::string& db_path, const std::string& token, int64_t ts) {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(db_path.c_str(), &db), SQLITE_OK);
    ScopeExit cleanup_db([&] {
        if (db) sqlite3_close(db);
        db = nullptr;
    });

    const char* sql = "UPDATE sessions SET last_activity = ? WHERE token = ?";
    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr), SQLITE_OK);
    ScopeExit cleanup_stmt([&] {
        if (stmt) sqlite3_finalize(stmt);
        stmt = nullptr;
    });

    ASSERT_EQ(sqlite3_bind_int64(stmt, 1, ts), SQLITE_OK);
    ASSERT_EQ(sqlite3_bind_text(stmt, 2, token.c_str(), -1, SQLITE_TRANSIENT), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
}

static void exec_sql_raw(sqlite3* db, const char* sql) {
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "";
        sqlite3_free(err);
        FAIL() << "sqlite3_exec failed rc=" << rc << " err=" << msg << " sql=" << sql;
    }
}

static fs::path unique_db_path(const std::string& prefix) {
    const auto now_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    return fs::temp_directory_path() / (prefix + "-" + std::to_string(getpid()) + "-" + std::to_string(now_ns) + ".db");
}

// Test fixtures for SessionManager tests
class SessionManagerTest : public ::testing::Test {
protected:
    std::string test_db_path_;
    std::unique_ptr<SessionManager> manager_;

    void SetUp() override {
        test_db_path_ = unique_db_path("test_session").string();
        unlink(test_db_path_.c_str());
        manager_ = std::make_unique<SessionManager>(test_db_path_, 3600);
    }

    void TearDown() override {
        manager_.reset();
        unlink(test_db_path_.c_str());
    }
};
}

// =====================================
//  Test Cases
// =====================================

// TEST Constructor throws when DB path cannot be opened
TEST(SessionManagerStandaloneTest, ConstructorThrowsWhenDbPathCannotBeOpened) {
    const std::string bad_dir = "/tmp/netnet-no-such-dir-" + std::to_string(getpid());
    const std::string db_path = bad_dir + "/sessions.db";

    // Directory does not exist => sqlite3_open should fail => constructor throws.
    EXPECT_THROW({ SessionManager sm(db_path, 10); }, std::runtime_error);
}


// TEST Constructor throws when DB is read-only
TEST(SessionManagerStandaloneTest, ConstructorThrowsWhenDbIsReadOnly) {
    const std::string db_path = "/tmp/netnet-readonly-" + std::to_string(getpid()) + ".db";
    unlink(db_path.c_str());

    // Create an empty file, then make it read-only.
    {
        std::FILE* f = std::fopen(db_path.c_str(), "w");
        ASSERT_NE(f, nullptr);
        std::fclose(f);
    }
    ASSERT_EQ(chmod(db_path.c_str(), 0444), 0);

    // initDatabase() will attempt CREATE TABLE and should fail on read-only db => throws.
    EXPECT_THROW({ SessionManager sm(db_path, 10); }, std::runtime_error);

    // Cleanup
    ASSERT_EQ(chmod(db_path.c_str(), 0644), 0);
    unlink(db_path.c_str());
}

// TEST validateSession() returns true even if last_activity UPDATE is blocked
TEST_F(SessionManagerTest, ValidateSessionReturnsTrueEvenIfLastActivityUpdateIsBusy) {
    const std::string token = manager_->createSession("locktest", "127.0.0.1");

    const int64_t forced_old_ts = now_sec() - 100;
    set_last_activity(test_db_path_, token, forced_old_ts);

    const auto forced_old_tp =
        std::chrono::time_point_cast<std::chrono::seconds>(
            std::chrono::system_clock::from_time_t(forced_old_ts));

    // Hold a write lock in a separate connection so the UPDATE in validateSession() fails.
    {
        sqlite3* db2 = nullptr;
        ASSERT_EQ(sqlite3_open(test_db_path_.c_str(), &db2), SQLITE_OK);

        ScopeExit cleanup([&] {
            if (!db2) return;
            sqlite3_exec(db2, "ROLLBACK;", nullptr, nullptr, nullptr);
            sqlite3_close(db2);
            db2 = nullptr;
        });

        exec_sql_raw(db2, "BEGIN IMMEDIATE;");

        SessionData out{};
        EXPECT_TRUE(manager_->validateSession(token, out));

        const auto out_last_tp =
            std::chrono::time_point_cast<std::chrono::seconds>(out.last_activity);

        // last_activity should NOT change because the UPDATE is blocked.
        EXPECT_EQ(out_last_tp, forced_old_tp);

        // Explicitly release the lock *before* leaving the scope (deterministic).
        ASSERT_EQ(sqlite3_exec(db2, "ROLLBACK;", nullptr, nullptr, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_close(db2), SQLITE_OK);
        db2 = nullptr;
        cleanup.dismiss();
    }

    // Now that the lock is gone, validateSession() should be able to update last_activity.
    SessionData out2{};
    ASSERT_TRUE(manager_->validateSession(token, out2));
    const auto out2_last_tp =
        std::chrono::time_point_cast<std::chrono::seconds>(out2.last_activity);

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
    const auto test_db = unique_db_path("test_session_boundary").string();
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
    const auto test_db = unique_db_path("test_session_boundary").string();
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
