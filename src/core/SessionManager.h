#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <string>
#include <memory>
#include <SQLiteCpp/SQLiteCpp.h>
#include <chrono>

struct SessionData {
std::string token;
std::string username;
std::chrono::system_clock::time_point created_at;
std::chrono::system_clock::time_point last_activity;
std::string ip_address;    
};

class SessionManager {
public:
    SessionManager(const std::string& db_path, int expiry_seconds = 3600);
    ~SessionManager();
    // Create new session, returns token
    std::string createSession(const std::string& username, const std::string& client_ip);
    // Validate session token, update last_activity if valid
    bool validateSession(const std::string& token, SessionData& out_data);
    // Delete session (logout)
    void deleteSession(const std::string& token);
    // Cleanup expired sessions
    void cleanupExpired();

private:
    std::unique_ptr<SQLite::Database> db_;
    std::string db_path_;
    int expiry_seconds_;
};

#endif // SESSION_MANAGER_H