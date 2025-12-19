#include "core/SessionManager.h"
#include "../../include/net-net/vendor/uuid_gen.h"
#include <stdexcept>
#include <ctime>
#include <iostream>

// Constructor: Opens SQLite database and initializes session table
// db_path: Path to SQLite database file (e.g., "/tmp/netnet_sessions.db")
// expiry_seconds: How long sessions remain valid without activity (default: 3600s = 1 hour)
SessionManager::SessionManager(const std::string& db_path, int expiry_seconds) : db_(nullptr), expiry_seconds_(expiry_seconds) {
    // Open database connection
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error("Failed to open session database: " + std::string(sqlite3_errmsg(db_)));
    }

    // Enable write-ahead logging (WAL) for better concurrency
    char* err_msg = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err_msg);
    if (err_msg) {
        std::cerr << "WAL mode warning: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
    
    // Add busy timeout to prevent "database is locked" errors
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, &err_msg);
    if (err_msg) {
        std::cerr << "Busy timeout warning: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }

    // Create sessions table if none exists
    initDatabase();
}

// Destructor: Clean up database connection
SessionManager::~SessionManager() {
    if (db_) {
        sqlite3_close(db_);
    }
}

// Creates the sessions table and index for efficient expired session cleanup
void SessionManager::initDatabase() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_activity INTEGER NOT NULL,
            ip_address TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_last_activity ON sessions(last_activity);
    )";

    char* err_msg = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::string error = "Failed to create sessions table: " + std::string(err_msg);
        sqlite3_free(err_msg);
        throw std::runtime_error(error);
    }

    // Check column count by actually counting rows from PRAGMA
    const char* check_sql = "PRAGMA table_info(sessions);";
    sqlite3_stmt* check_stmt = nullptr;

    if (sqlite3_prepare_v2(db_, check_sql, -1, &check_stmt, nullptr) == SQLITE_OK) {
        int column_count = 0;
        while (sqlite3_step(check_stmt) == SQLITE_ROW) {
            column_count++;  // Count each row = each column
        }
        sqlite3_finalize(check_stmt);

        // If column count is not 5, drop and recreate
        if (column_count != 5) {
            std::cerr << "Schema mismatch detected (" << column_count << " columns, expected 5). Recreating table." << std::endl;
            sqlite3_exec(db_, "DROP TABLE IF EXISTS sessions;", nullptr, nullptr, &err_msg);
            sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
            if (err_msg) {
                std::cerr << "Error recreating table: " << err_msg << std::endl;
                sqlite3_free(err_msg);
            }
        }
    }
}

// Creates a new session after successful login
// username: Authenticated user
// ip: Client IP address for forensic trail
// Returns: UUID session token to send to client
std::string SessionManager::createSession(const std::string& username, const std::string& ip) {
    // GENERATE RANDOM UUID TOKEN (V4. 36-char string)
    std::string token = uuid_gen::generate();

    // Get current time as Unix timestamp (seconds since epoch)
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

    // Prepare parameterized SQL insert (prevents SQL injection)
    const char* sql = "INSERT INTO sessions (token, username, created_at, last_activity, ip_address) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare insert session statement: " + std::string(sqlite3_errmsg(db_)));
    }

    // Bind parameters to placeholders (? in SQL)
    // SQLITE_TRANSIENT tells SQLite to make a copy of the string data
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, timestamp);  // created_at
    sqlite3_bind_int64(stmt, 4, timestamp);  // last_activity (same as created_at initially)
    sqlite3_bind_text(stmt, 5, ip.c_str(), -1, SQLITE_TRANSIENT);
    
    // Execute the insert
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert new session: " + std::string(sqlite3_errmsg(db_)));
    }
    sqlite3_finalize(stmt);
    return token; // Return token to send to client (via JSON response)
}

// Validates a session token and updates last_activity timestamp
// token: Session token from client's Authorization header
// out_data: Output parameter - filled with session details if valid
// Returns: true if session exists and hasn't expired, false otherwise

bool SessionManager::validateSession(const std::string& token, SessionData& out_data) {
    // Query Session by Token
    const char* sql = "SELECT username, created_at, last_activity, ip_address FROM sessions WHERE token = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false; // DB error
    }
    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);

    bool valid = false;
    int64_t old_last_activity = 0;  // Store the OLD last_activity
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        old_last_activity = sqlite3_column_int64(stmt, 2);
        
        // Get current time INSIDE the if block (not at function start)
        auto now = std::chrono::system_clock::now();
        auto now_timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        // Check for expired session (current time - last_activity > expiry_seconds)
        if (now_timestamp - old_last_activity <= expiry_seconds_) {
            // Session is valid - populate output data
            out_data.token = token;
            out_data.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            out_data.created_at = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 1));
            out_data.ip_address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));

            valid = true;
            
            // Finalize SELECT before UPDATE
            sqlite3_finalize(stmt);
            
            // Update last_activity to NOW (not the old now_timestamp from function start)
            const char* update_sql = "UPDATE sessions SET last_activity = ? WHERE token = ?";
            sqlite3_stmt* update_stmt = nullptr;
            if (sqlite3_prepare_v2(db_, update_sql, -1, &update_stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_int64(update_stmt, 1, now_timestamp);
                sqlite3_bind_text(update_stmt, 2, token.c_str(), -1, SQLITE_TRANSIENT);
                
                if (sqlite3_step(update_stmt) == SQLITE_DONE) {
                    // Update succeeded - set last_activity to the NEW timestamp
                    out_data.last_activity = std::chrono::system_clock::from_time_t(now_timestamp);
                } else {
                    // Update failed - use OLD timestamp
                    std::cerr << "UPDATE failed: " << sqlite3_errmsg(db_) << std::endl;
                    out_data.last_activity = std::chrono::system_clock::from_time_t(old_last_activity);
                }
                sqlite3_finalize(update_stmt);
            } else {
                std::cerr << "Failed to prepare UPDATE: " << sqlite3_errmsg(db_) << std::endl;
                out_data.last_activity = std::chrono::system_clock::from_time_t(old_last_activity);
            }
        } else {
            // Session expired
            sqlite3_finalize(stmt);
        }
    } else {
        // Session not found
        sqlite3_finalize(stmt);
    }

    return valid;
}

// Deletes a session (called on logout)
// token: Session token to invalidate
void SessionManager::deleteSession(const std::string& token) {
    const char* sql = "DELETE FROM sessions WHERE token = ?";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

// Removes expired sessions from database (should be called periodically)
// Deletes all sessions where (current_time - last_activity) > expiry_seconds
void SessionManager::cleanupExpired() {
    auto now = std::chrono::system_clock::now();
    auto cutoff = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() - expiry_seconds_;

    const char* sql = "DELETE FROM sessions WHERE last_activity < ?";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, cutoff);  // Only bind the cutoff timestamp
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}