#include "uuid_gen.h"
#include <uuid/uuid.h>
#include <sstream>

namespace uuid_gen {

std::string generate() {
    uuid_t uuid;
    uuid_generate_random(uuid);
    
    char uuid_str[37]; // UUID string is 36 chars + null terminator
    uuid_unparse_lower(uuid, uuid_str);
    
    return std::string(uuid_str);
}

} // namespace uuid_gen