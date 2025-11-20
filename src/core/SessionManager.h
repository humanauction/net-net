#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <string>
#include <sqlite3.h>
#include <chrono>

struct SessionData {
std::string ;
std::string ;
std::chrono::;
std::chrono::;
std::string ;    
};

class SessionManager {
public:

// Create new session, returns token

// Validate session token, update last_activity if valid

// Delete session (logout)

// Cleanup expired sessions

private:

};

#endif // SESSION_MANAGER_H