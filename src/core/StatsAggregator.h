#pragma once
#include <chrono>
#include <unordered_map>
#include <vector>
#include "ConnectionTracker.h"
#include "parser.h"

// Aggregated stats for a time window
struct AggregatedStats {
    std::chrono::system_clock::time_point window_start;
    std::unordered_map<FlowKey, FlowStats> flows;
    // TODO Add more fields here (e.g. totals, protocol breakdown)
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


private:
    struct Impl {
        size_t count = 0;
        std::chrono::seconds window_size;
        size_t history_depth;
        std::vector<AggregatedStats> stats_history;
        size_t head = 0;
        AggregatedStats current;
    };
    std::unique_ptr<Impl> impl_;
};