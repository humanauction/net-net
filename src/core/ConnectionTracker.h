#pragma once
#include <string>
#include <cstdint>
#include <chrono>
#include <unordered_map>
#include <memory>

// FlowKey: iface, protocol, src_ip, src_port, dst_ip, dst_port
struct FlowKey {
    std::string iface;
    uint8_t protocol;  // 6=TCP, 17=UDP, 1=ICMP
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;

    bool operator==(const FlowKey& other) const;
};

namespace std {
    template<>
    struct hash<FlowKey> {
        size_t operator()(const FlowKey& k) const;
    };
}

// FlowStats: first_seen, last_seen, bytes/pkts c2s and s2c, state
struct FlowStats {
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    
    uint64_t bytes_c2s = 0;
    uint64_t pkts_c2s = 0;
    uint64_t bytes_s2c = 0;
    uint64_t pkts_s2c = 0;
    
    enum State { NEW, ESTABLISHED, CLOSING, CLOSED } state = NEW;
};

// Forward declare ParsedPacket (defined in Parser.h)
struct ParsedPacket;

class ConnectionTracker {
public:
    ConnectionTracker();
    ~ConnectionTracker();

    // Stage 2: ingest ParsedPacket from Parser
    void ingest(const ParsedPacket& packet);
    
    // Stage 2: getActiveConnections
    std::unordered_map<FlowKey, FlowStats> getActiveConnections() const;
    
    // Cleanup idle flows
    void cleanupIdle(std::chrono::seconds timeout = std::chrono::seconds(300));

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};