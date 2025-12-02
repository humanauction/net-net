#include "uuid_gen.h"
#ifdef __APPLE__
#include <uuid/uuid.h>
#endif
#include <sstream>
#include <stdexcept>

namespace uuid_gen {

std::string generate() {
#ifdef __APPLE__
    uuid_t uuid;
    uuid_generate_random(uuid);

    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);

    return std::string(uuid_str);
#elif defined(__linux__)
    uuid_t uuid;
    uuid_generate_random(uuid);

    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);

    return std::string(uuid_str);
#else
    throw std::runtime_error("UUID generation not supported on this platform");
#endif
}

} // namespace uuid_gen