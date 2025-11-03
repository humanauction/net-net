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

// Layer 3 (network) info
struct NetworkInfo {
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol; // 6=TCP, 17=UDP, 1=ICMP
    bool ipv6 = false;
};
// Layer 4 (transport) info
struct TransportInfo {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    uint8_t tcp_flags = 0; // Only for TCP
};

// Parsed packet structure
struct ParsedPacket {
    PacketMeta meta;
    NetworkInfo network;
    TransportInfo transport;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

bool parsePacket(const uint8_t* data, size_t len, PacketMeta meta, ParsedPacket& out);