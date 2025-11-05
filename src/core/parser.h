#pragma once
#include <string>
#include <cstdint>
#include <chrono>
#include "PacketMeta.h"

// Layer 2 (data link) info
struct DataLinkInfo {
    std::string src_mac;
    std::string dst_mac;
    uint16_t ethertype = 0;
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
    DataLinkInfo datalink;
    NetworkInfo network;
    TransportInfo transport;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

bool parsePacket(const uint8_t* data, size_t len, const PacketMeta& meta, ParsedPacket& out) {
    // TODO: Implement actual parsing logic here.
    // For now, assume parsing always successful if data is not null and len > 0.
    bool success = (data != nullptr && len > 0);
    if (success) {
        out.meta = meta;
        // TO DO: out.network, out.transport, etc. here.
        return true;
    }
    return false;   
}