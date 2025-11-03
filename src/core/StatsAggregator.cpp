#include "StatsAggregator.h"
#include "parser.h"

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
    // Build FlowKey from packet
    FlowKey key;
    key.iface = packet.meta.iface;
    key.protocol = packet.transport.protocol;
    key.src_ip = packet.network.src_ip;
    key.src_port = packet.transport.src_port;
    key.dst_ip = packet.network.dst_ip;
    key.dst_port = packet.transport.dst_port;

    auto& stats = impl_->current.flows[key];
    auto now = packet.meta.timestamp;

    if (stats.pkts_c2s == 0 && stats.pkts_s2c == 0) {
        stats.first_seen = now;
        stats.state = FlowStats::NEW;
    }
    stats.last_seen = now;

    // Direction: c2s or s2c (same logic as ConnectionTracker - ergo inefficient? REVISIT ME)
    bool is_c2s = (key.src_ip < key.dst_ip) ||
                  (key.src_ip == key.dst_ip && key.src_port < key.dst_port);

    if (is_c2s) {
        stats.bytes_c2s += packet.meta.cap_len;
        stats.pkts_c2s++;
    } else {
        stats.bytes_s2c += packet.meta.cap_len;
        stats.pkts_s2c++;
    }

    // State transitions for TCP
    if (packet.transport.protocol == 6) {
        if (packet.transport.tcp_flags & 0x02) { // SYN
            stats.state = FlowStats::NEW;
        } else if (packet.transport.tcp_flags & 0x10) { // ACK
            if (stats.state == FlowStats::NEW) {
                stats.state = FlowStats::ESTABLISHED;
            }
        } else if (packet.transport.tcp_flags & 0x01) { // FIN
            stats.state = FlowStats::CLOSING;
        }
    } else {
        if (stats.state == FlowStats::NEW) {
            stats.state = FlowStats::ESTABLISHED;
        }
    }
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