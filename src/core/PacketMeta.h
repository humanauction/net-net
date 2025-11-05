#pragma once
#include <string>
#include <cstdint>
#include <chrono>

// Metadata from capture adapter
struct PacketMeta {
    std::chrono::system_clock::time_point timestamp;
    std::string iface;
    uint32_t cap_len;
    uint32_t orig_len;
};