#include "StatsAggregator.h"
#include "parser.h"

struct StatsAggregator::Impl {
    std::chrono::seconds window_size;
    size_t history_depth;
    std::vector<AggregatedStats> stats_history;
    size_t head = 0;
    AggregatedStats current;

    Impl(std::chrono::seconds win, size_t depth)
        : window_size(win), history_depth(depth), stats_history(depth) {
        current.window_start = std::chrono::system_clock::now();
    }
};

void StatsAggregator::advanceWindow() {
    impl_->stats_history[impl_->head] = impl_->current;
    impl_->head = (impl_->head + 1) % impl_->history_depth;
    impl_->current = AggregatedStats{};
    impl_->current.window_start = std::chrono::system_clock::now();
}

// To get history in order:
std::vector<AggregatedStats> StatsAggregator::history() const {
    std::vector<AggregatedStats> ordered;
    for (size_t i = 0; i < impl_->history_depth; ++i) {
        size_t idx = (impl_->head + i) % impl_->history_depth;
        ordered.push_back(impl_->stats_history[idx]);
    }
    return ordered;
}

const AggregatedStats& StatsAggregator::currentStats() const {
    return impl_->current;
}