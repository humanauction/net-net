#include "core/StatsAggregator.h"
#include "core/Parser.h"


StatsAggregator::StatsAggregator(std::chrono::seconds window_size, size_t history_depth)
    
    : impl_(std::make_unique<Impl>()) {
    impl_->window_size = window_size;
    impl_->history_depth = history_depth;
    impl_->stats_history.resize(history_depth);
    impl_->head = 0;
    impl_->current.window_start = std::chrono::system_clock::now();
}

void StatsAggregator::advanceWindow() {
    impl_->stats_history[impl_->head] = impl_->current;
    impl_->head = (impl_->head + 1) % impl_->history_depth;
    impl_->count++;

    impl_->current = AggregatedStats();
    impl_->current.window_start = std::chrono::system_clock::now();
}

// Circular Buffer: get ordered history
std::vector<AggregatedStats> StatsAggregator::history() const {
    std::vector<AggregatedStats> ordered;
    for (size_t i = 0; i < impl_->count; ++i) {
        size_t idx = (impl_->head + i) % impl_->history_depth;
        ordered.push_back(impl_->stats_history[idx]);
    }
    return ordered;
}

const AggregatedStats& StatsAggregator::currentStats() const {
    if (impl_->count == 0) {
        return impl_->current;
    }
    size_t last_window = (impl_->head + impl_->history_depth - 1) % impl_->history_depth;
    return impl_->stats_history[last_window];
}

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

    // Direction: c2s or s2c
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
