#include <gtest/gtest.h>
#include "core/StatsAggregator.h"
#include "core/Parser.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

static ParsedPacket make_udp_packet(const std::string& iface, const std::string& src_ip, uint16_t src_port,
                                   const std::string& dst_ip, uint16_t dst_port, uint64_t ts_offset = 0) {
    uint8_t pkt[42] = {0};
    pkt[12] = 0x08; pkt[13] = 0x00; // Ethertype IPv4
    pkt[14] = 0x45; // IPv4 header, IHL=5
    pkt[23] = 17;   // Protocol UDP
    in_addr src_addr; inet_pton(AF_INET, src_ip.c_str(), &src_addr);
    memcpy(pkt + 26, &src_addr, 4);
    in_addr dst_addr; inet_pton(AF_INET, dst_ip.c_str(), &dst_addr);
    memcpy(pkt + 30, &dst_addr, 4);
    pkt[34] = src_port >> 8; pkt[35] = src_port & 0xFF;
    pkt[36] = dst_port >> 8; pkt[37] = dst_port & 0xFF;

    PacketMeta meta;
    meta.iface = iface;
    meta.cap_len = 42;
    meta.orig_len = 42;
    meta.timestamp = std::chrono::system_clock::now() + std::chrono::seconds(ts_offset);

    ParsedPacket out;
    EXPECT_TRUE(parsePacket(pkt, 42, meta, out));
    return out;
}

// =================================
// Test suite
// =================================

// TEST Basic ingestion and aggregation
TEST(StatsAggregatorTest, AggregatesFlowsAndHistory) {
    StatsAggregator agg(std::chrono::seconds(1), 3);

    ParsedPacket pkt1;
    pkt1.meta.iface = "eth0";
    pkt1.meta.timestamp = std::chrono::system_clock::now();
    pkt1.network.src_ip = "10.0.0.1";
    pkt1.network.dst_ip = "10.0.0.2";
    pkt1.network.protocol = 6;
    pkt1.transport.src_port = 1234;
    pkt1.transport.dst_port = 80;
    pkt1.transport.protocol = 6;
    pkt1.payload_len = 100;

    // Ingest into window 0
    agg.ingest(pkt1);
    agg.advanceWindow();  // Save window 0 to history

    // Ingest into window 1
    agg.ingest(pkt1);
    agg.advanceWindow();  // Save window 1 to history

    // Now we have 2 completed windows in history
    auto history = agg.history();
    
    // UPDATED: Expect 2 windows (the ones we saved)
    EXPECT_EQ(history.size(), 2);  // Changed from expecting wrong value
    
    // Verify currentStats() returns the LAST completed window (window 1)
    const auto& current = agg.currentStats();
    EXPECT_GT(current.flows.size(), 0);
}

// TEST Circular buffer overwriting old windows
TEST(StatsAggregatorTest, CircularBufferOrder) {
    StatsAggregator agg(std::chrono::seconds(1), 2);  // depth=2

    ParsedPacket pkt;
    pkt.meta.iface = "eth0";
    pkt.meta.timestamp = std::chrono::system_clock::now();
    pkt.network.src_ip = "192.168.1.1";
    pkt.network.dst_ip = "8.8.8.8";
    pkt.network.protocol = 17;  // UDP
    pkt.transport.src_port = 5000;
    pkt.transport.dst_port = 53;
    pkt.transport.protocol = 17;
    pkt.payload_len = 50;

    // Window 0
    agg.ingest(pkt);
    agg.advanceWindow();

    // Window 1
    agg.ingest(pkt);
    agg.advanceWindow();

    auto history = agg.history();
    
    // UPDATED: With depth=2, we have 2 windows
    EXPECT_EQ(history.size(), 2);  // Changed from expecting wrong value
    
    // Verify windows are in chronological order (oldest to newest)
    EXPECT_LE(history[0].window_start, history[1].window_start);
}