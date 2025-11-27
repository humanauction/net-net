#include "core/ConnectionTracker.h"
#include "core/parser.h"
#include <mutex>
#include <shared_mutex>

bool FlowKey::operator==(const FlowKey& other) const {
    return iface == other.iface &&
           protocol == other.protocol &&
           src_ip == other.src_ip &&
           src_port == other.src_port &&
           dst_ip == other.dst_ip &&
           dst_port == other.dst_port;
}

size_t std::hash<FlowKey>::operator()(const FlowKey& k) const {
    size_t h1 = std::hash<std::string>()(k.iface); 
    size_t h2 = std::hash<uint8_t>()(k.protocol);
    size_t h3 = std::hash<std::string>()(k.src_ip);
    size_t h4 = std::hash<uint16_t>()(k.src_port);
    size_t h5 = std::hash<std::string>()(k.dst_ip);
    size_t h6 = std::hash<uint16_t>()(k.dst_port);
    return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4) ^ (h6 << 5);
}

struct ConnectionTracker::Impl {
    std::unordered_map<FlowKey, FlowStats> flows;
    mutable std::shared_mutex mutex;
};

ConnectionTracker::ConnectionTracker() : impl_(std::make_unique<Impl>()) {}

ConnectionTracker::~ConnectionTracker() = default;

void ConnectionTracker::ingest(const ParsedPacket& packet) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);

    // Build FlowKey from ParsedPacket
    FlowKey key;
    key.iface = packet.meta.iface;
    key.protocol = packet.transport.protocol;
    key.src_ip = packet.network.src_ip;
    key.src_port = packet.transport.src_port;
    key.dst_ip = packet.network.dst_ip;
    key.dst_port = packet.transport.dst_port;

    auto& stats = impl_->flows[key];
    auto now = packet.meta.timestamp;

    if (stats.pkts_c2s == 0 && stats.pkts_s2c == 0) {
        stats.first_seen = now;
        stats.state = FlowStats::NEW;
    }

    stats.last_seen = now;

    // Determine direction: c2s or s2c
    // Simple heuristic: lower IP/port is "client"
    bool is_c2s = (key.src_ip < key.dst_ip) ||
                  (key.src_ip == key.dst_ip && key.src_port < key.dst_port);

    if (is_c2s) {
        stats.bytes_c2s += packet.meta.cap_len;
        stats.pkts_c2s++;
    } else {
        stats.bytes_s2c += packet.meta.cap_len;
        stats.pkts_s2c++;        
    }

    // Update state based on TCP flags if available
    if (packet.transport.protocol == 6) { // TCP
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
        // UDP/ICMP: assume established after first packet
        if (stats.state == FlowStats::NEW) {
            stats.state = FlowStats::ESTABLISHED;
        }
    }
}

std::unordered_map<FlowKey, FlowStats> ConnectionTracker::getActiveConnections() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    return impl_->flows;
}

void ConnectionTracker::cleanupIdle(std::chrono::seconds timeout) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    auto now = std::chrono::system_clock::now();

    for (auto it = impl_->flows.begin(); it != impl_->flows.end();) {
        if (now - it->second.last_seen > timeout) {
            it = impl_->flows.erase(it);
        } else {
            ++it;
        }
    }
}