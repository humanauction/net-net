#pragma once
#include <chrono>
#include <unordered_map>
#include <vector>
#include <memory>
#include "core/ConnectionTracker.h"
#include "core/Parser.h"
#include <mutex>

// Aggregated stats for a time window
struct AggregatedStats {
    std::chrono::system_clock::time_point window_start;
    std::chrono::seconds window_size;
    std::unordered_map<FlowKey, FlowStats> flows;
    // TODO Add more fields here (e.g. totals, protocol breakdown)
    // total bytes, packets
    uint64_t total_bytes = 0;
    uint64_t total_packets = 0;
    // protocol breakdown
    std::unordered_map<uint8_t, uint64_t> protocol_bytes;
    std::unordered_map<uint8_t, uint64_t> protocol_packets;

    AggregatedStats() = default;
};

struct PacketSizeDistribution {
    uint64_t tiny = 0;    // 0-64 bytes
    uint64_t small = 0;   // 65-128 bytes
    uint64_t medium = 0;  // 129-512 bytes
    uint64_t large = 0;   // 513-1024 bytes
    uint64_t jumbo = 0;   // 1025+ bytes
};

class StatsAggregator {
public:
    StatsAggregator(std::chrono::seconds window_size, size_t history_depth);
// Ingest a ParsedPacket (from parser)
    void ingest(const ParsedPacket& packet);
// Advance to next window (called periodically)
    void advanceWindow();
// Get stats for current window
    const AggregatedStats& currentStats() const;
// Get stats history (rolling buffer)
    std::vector<AggregatedStats> history() const;
    void recordPacketSize(size_t size);
    PacketSizeDistribution getPacketSizeDistribution() const;


private:
    struct Impl {
        size_t count = 0;
        std::chrono::seconds window_size;
        size_t history_depth;
        std::vector<AggregatedStats> stats_history;
        size_t head = 0;
        AggregatedStats current;
        std::chrono::system_clock::time_point last_packet_ts;
    };
    std::unique_ptr<Impl> impl_;
    mutable std::mutex size_mutex_;
    PacketSizeDistribution packet_sizes_;
};