#include "StatsAggregator.h"

struct StatsAggregator::Impl {
    std::chrono::seconds window_size;
    size_t history_depth;
    std::vector<AggregatedStats> stats_history;
    AggregatedStats current;

    Impl(std::chrono::seconds win, size_t depth)
    : window_size(win), history_depth(depth) {
        current.window_start = std::chrono::system_clock::now();
    }
};

StatsAggregator::StatsAggregator(std::chrono::seconds window_size, size_t history_depth)
    : impl_(std::make_unique<Impl>(window_size, history_depth)) {}

void StatsAggregator::ingest(const ParsedPacket& packet) {
    // TODO: Update current.flows and other stats
}

void StatsAggregator::advanceWindow() {
    impl_->stats_history.push_back(impl_->current);
    if (impl_->stats_history.size() > impl_->history_depth)
        impl_->stats_history.erase(impl_->stats_history.begin());
    impl_->current = AggregatedStats{};
    impl_->current.window_start = std::chrono::system_clock::now();
}
const AggregatedStats& StatsAggregator::currentStats() const {
    return impl_->current;
}

const std::vector<AggregatedStats>& StatsAggregator::history() const {
    return impl_->stats_history;
}