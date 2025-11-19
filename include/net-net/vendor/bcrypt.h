#ifndef BCRYPT_H
#define BCRYPT_H

#include <string>

namespace bcrypt {
    // Hash password with bcrypt (work factor 12)
    std::string hash(const std::string& password);

    // Verify password against bcrypt hash
    bool verify(const std::string& password, const std::string& hash);
}

#endif // BCRYPT_H