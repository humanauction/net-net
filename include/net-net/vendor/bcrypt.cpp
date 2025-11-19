#include "bcrypt.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace bcrypt {

// Simple bcrypt-like implementation using PBKDF2 (OpenSSL)
std::string hash(const std::string& password) {
    const int iterations = 10000; // Work factor equivalent
    const int salt_len = 16;
    const int hash_len = 32;

    unsigned char salt[salt_len]; 
    unsigned char hash[hash_len];
    // Generate random salt
    if (RAND_bytes(salt, salt_len) != 1) {
        throw std::runtime_error("No salt generated");
    }
    // Derive key using PBKDF2
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, salt_len, iterations, EVP_sha256(),hash_len, hash) != 1) {
        throw std::runtime_error("Failed to hash password");
    }
    
    // Encode as: iterations$salt$hash (hex)
    std::ostringstream oss;
    oss << iterations << "$";
    for (int i = 0; i < salt_len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }
    oss << "$";
    for (int i = 0; i < hash_len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

    // Parse stored hash: iterations$salt$hash

    // Decode salt from hex

    // Hash the input password with same salt
   
    
        throw std::runtime_error("");
    // Compare computed hash with stored hash

} // namespace bcrypt