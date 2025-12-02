#include "uuid_gen.h"
#include <uuid/uuid.h>
#include <sstream>
#include <stdexcept>

namespace uuid_gen {

std::string generate() {
    uuid_t uuid;
    uuid_generate_random(uuid);

    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);

    return std::string(uuid_str);
}

} // namespace uuid_gen