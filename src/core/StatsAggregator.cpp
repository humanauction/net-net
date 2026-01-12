#include "core/StatsAggregator.h"
#include "core/Parser.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstring>
#include <tuple>

namespace {

struct ParsedIp {
    int family = AF_UNSPEC;                 // AF_INET / AF_INET6 / AF_UNSPEC
    std::array<unsigned char, 16> bytes{};  // big enough for IPv6
    size_t len = 0;
};

static ParsedIp parse_ip(const std::string& s) {
    ParsedIp out{};

    in_addr v4{};
    if (::inet_pton(AF_INET, s.c_str(), &v4) == 1) {
        out.family = AF_INET;
        out.len = 4;
        std::memcpy(out.bytes.data(), &v4, 4);
        return out;
    }

    in6_addr v6{};
    if (::inet_pton(AF_INET6, s.c_str(), &v6) == 1) {
        out.family = AF_INET6;
        out.len = 16;
        std::memcpy(out.bytes.data(), &v6, 16);
        return out;
    }

    return out; // AF_UNSPEC
}

// True if (ip_a, port_a) is "less than or equal to" (ip_b, port_b) in a stable, numeric-aware way.
static bool endpoint_leq(const std::string& ip_a, uint16_t port_a,
                         const std::string& ip_b, uint16_t port_b) {
    const auto a = parse_ip(ip_a);
    const auto b = parse_ip(ip_b);

    // Numeric compare when both parse and share same family/size.
    if (a.family != AF_UNSPEC && b.family != AF_UNSPEC && a.family == b.family && a.len == b.len) {
        const int cmp = std::memcmp(a.bytes.data(), b.bytes.data(), a.len);
        if (cmp != 0) return cmp < 0;
        return port_a <= port_b;
    }

    // Prefer parsed IPs over unparsed for stability.
    if (a.family != AF_UNSPEC && b.family == AF_UNSPEC) return true;
    if (a.family == AF_UNSPEC && b.family != AF_UNSPEC) return false;

    // Fallback: string compare (should be rare if inputs are real IPs).
    if (ip_a != ip_b) return ip_a < ip_b;
    return port_a <= port_b;
}

} // namespace

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

    size_t num_windows = (impl_->count == 0) ? 0 : std::min(impl_->count, impl_->history_depth);
    
    for (size_t i = 0; i < num_windows; ++i) {
        size_t idx = (impl_->head + impl_->history_depth - num_windows + i) % impl_->history_depth;
        ordered.push_back(impl_->stats_history[idx]);
    }
    return ordered;
}

const AggregatedStats& StatsAggregator::currentStats() const {
    return impl_->current;
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

    // Direction: c2s or s2c (numeric IP compare; stable fallback)
    const bool is_c2s = endpoint_leq(
        key.src_ip, key.src_port,
        key.dst_ip, key.dst_port
    );

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

    // Protocol breakdown (by protocol number)
    uint8_t proto = packet.transport.protocol;

    impl_->current.protocol_bytes[proto] += packet.meta.cap_len;
    impl_->current.protocol_packets[proto] += 1;

    // Update totals
    impl_->current.total_bytes +=  packet.meta.cap_len;
    impl_->current.total_packets +=1; 
    
}
