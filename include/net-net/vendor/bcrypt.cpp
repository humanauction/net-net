#include "bcrypt.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#ifdef __linux__
#include <crypt.h>
#endif
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>

namespace bcrypt {

// Simple bcrypt-like implementation using PBKDF2 (OpenSSL)
std::string hash(const std::string& password) {
    const int iterations = 10000; // Work factor equivalent
    const int salt_len = 16;
    const int hash_len = 32;

    std::vector<unsigned char> salt(salt_len);
    std::vector<unsigned char> computed_hash(hash_len);
    // Generate random salt
    if (RAND_bytes(salt.data(), salt_len) != 1) {
        throw std::runtime_error("No salt generated");
    }
    // Derive key using PBKDF2
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt_len, iterations, EVP_sha256(),hash_len, computed_hash.data()) != 1) {
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
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)computed_hash[i];
    }
    return oss.str();
}

bool verify(const std::string& password, const std::string& stored_hash) {
    // Check if this is a standard bcrypt hash ($2a$/$2b$/$2y$)
    if (stored_hash.length() >= 4 && 
        (stored_hash.substr(0, 4) == "$2a$" ||
         stored_hash.substr(0, 4) == "$2b$" ||
         stored_hash.substr(0, 4) == "$2y$")) {
        
        // Use system bcrypt (crypt_r on Linux, bcrypt on OpenBSD/macOS)
        #ifdef __APPLE__
        #elif defined(__linux__)
            struct crypt_data data;
            data.initialized = 0;
            char* result = crypt_r(password.c_str(), stored_hash.c_str(), &data);
            return result && stored_hash == result;
        #else
            throw std::runtime_error("Standard bcrypt not supported on this platform - use PBKDF2 format or install libcrypt");
        #endif
    }
    
    // Fall back to custom PBKDF2 format (iterations$salt$hash)
    size_t pos1 = stored_hash.find('$');
    size_t pos2 = stored_hash.find('$', pos1 + 1);    

    if (pos1 == std::string::npos || pos2 == std::string::npos) {
        return false;
    }
    int iterations = std::stoi(stored_hash.substr(0, pos1));
    std::string salt_hex = stored_hash.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string hash_hex = stored_hash.substr(pos2 +1);

    // Decode salt from hex
    const int salt_len = salt_hex.length() / 2;
    std::vector<unsigned char> salt(salt_len);
    for (int i =0; i < salt_len; i++) {
        salt[i] = std::stoi(salt_hex.substr(i * 2, 2), nullptr, 16);
    }

    // Hash the input password with same salt
    const int hash_len = hash_hex.length() / 2;
    std::vector<unsigned char> computed_hash(hash_len);

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt_len, iterations, EVP_sha256(), hash_len, computed_hash.data()) != 1) {
        return false;
    }

    // Compare computed hash with stored hash
    std::ostringstream oss;
    for (int i = 0; i < hash_len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)computed_hash[i];
    }
    return oss.str() == hash_hex;
}

} // namespace bcrypt