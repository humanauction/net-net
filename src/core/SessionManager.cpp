#include "core/SessionManager.h"
#include "../../include/net-net/vendor/uuid_gen.h"
#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>
#include <stdexcept>
#include <ctime>
#include <iostream>
#include <thread>

// Constructor
SessionManager::SessionManager(const std::string& db_path, int expiry_seconds)
    : db_path_(db_path), expiry_seconds_(expiry_seconds) {
    
    db_ = std::make_unique<SQLite::Database>(db_path_, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE);

    // Enable WAL mode for concurrency
    db_->exec("PRAGMA journal_mode=WAL;");
    db_->exec("PRAGMA busy_timeout=5000;");

    // ✅ ADD: Test write access to detect read-only databases
    try {
        db_->exec("CREATE TABLE IF NOT EXISTS _write_test (id INTEGER);");
        db_->exec("DROP TABLE _write_test;");
    } catch (const SQLite::Exception& e) {
        throw SQLite::Exception("Database is read-only or cannot be written to");
    }

    // Create sessions table if it doesn't exist
    db_->exec(R"(
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_activity INTEGER NOT NULL
        )
    )");

    // Index for faster expiry cleanup
    db_->exec("CREATE INDEX IF NOT EXISTS idx_last_activity ON sessions(last_activity);");
}

SessionManager::~SessionManager() {
    // SQLiteCpp unique_ptr handles cleanup automatically
}

std::string SessionManager::createSession(const std::string& username, const std::string& client_ip) {
    std::string token = uuid_gen::generate();
    auto now = std::chrono::system_clock::now();
    int64_t timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    const int MAX_RETRIES = 5;
    for (int attempt = 0; attempt < MAX_RETRIES; ++attempt) {
        try {
            SQLite::Statement insert(*db_, 
                "INSERT INTO sessions (token, username, client_ip, created_at, last_activity) "
                "VALUES (?, ?, ?, ?, ?)");

            insert.bind(1, token);
            insert.bind(2, username);
            insert.bind(3, client_ip);
            insert.bind(4, timestamp);
            insert.bind(5, timestamp);

            insert.exec();
            return token;

        } catch (const SQLite::Exception& e) {
            std::string err_msg = e.what();
            if (err_msg.find("database is locked") != std::string::npos ||
                err_msg.find("SQLITE_BUSY") != std::string::npos) {
                
                std::this_thread::sleep_for(std::chrono::milliseconds(50 * (attempt + 1)));
                continue;
            }
            throw;
        }
    }

    throw std::runtime_error("Failed to create session after " + std::to_string(MAX_RETRIES) + " attempts (database locked)");
}

bool SessionManager::validateSession(const std::string& token, SessionData& out_data) {
    try {
        SQLite::Statement query(*db_, 
            "SELECT username, created_at, last_activity, client_ip FROM sessions WHERE token = ?");
        query.bind(1, token);

        if (query.executeStep()) {
            std::string username = query.getColumn(0).getText();
            int64_t created_at = query.getColumn(1).getInt64();
            int64_t last_activity = query.getColumn(2).getInt64();
            std::string client_ip = query.getColumn(3).getText();

            auto now = std::chrono::system_clock::now();
            int64_t now_timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

            // Check if expired
            if (now_timestamp - last_activity > expiry_seconds_) {
                return false;
            }

            // ✅ FIXED: Track whether update succeeded
            int64_t final_last_activity = last_activity;  // Default to old value
            
            try {
                SQLite::Statement update(*db_, "UPDATE sessions SET last_activity = ? WHERE token = ?");
                update.bind(1, now_timestamp);
                update.bind(2, token);
                update.exec();
                final_last_activity = now_timestamp;  // Update succeeded
            } catch (const SQLite::Exception& e) {
                if (e.getErrorCode() == SQLITE_BUSY || e.getErrorCode() == SQLITE_LOCKED) {
                    std::cerr << "validateSession: last_activity update skipped (db busy)" << std::endl;
                    // Keep final_last_activity at old value
                } else {
                    throw;
                }
            }

            // Populate output data
            out_data.token = token;
            out_data.username = username;
            out_data.created_at = std::chrono::system_clock::from_time_t(created_at);
            out_data.last_activity = std::chrono::system_clock::from_time_t(final_last_activity);
            out_data.ip_address = client_ip;

            return true;
        }

        return false;  // Token not found

    } catch (const SQLite::Exception& e) {
        std::cerr << "validateSession error: " << e.what() << std::endl;
        return false;
    }
}

void SessionManager::deleteSession(const std::string& token) {
    try {
        SQLite::Statement del(*db_, "DELETE FROM sessions WHERE token = ?");
        del.bind(1, token);
        del.exec();
    } catch (const SQLite::Exception& e) {
        std::cerr << "deleteSession error: " << e.what() << std::endl;
    }
}

void SessionManager::cleanupExpired() {
    auto now = std::chrono::system_clock::now();
    int64_t cutoff = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() - expiry_seconds_;

    try {
        SQLite::Statement del(*db_, "DELETE FROM sessions WHERE last_activity < ?");
        del.bind(1, cutoff);
        del.exec();
    } catch (const SQLite::Exception& e) {
        std::cerr << "cleanupExpired error: " << e.what() << std::endl;
    }
}