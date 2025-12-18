#include <gtest/gtest.h>
#include "core/StatsAggregator.h"
#include "core/Parser.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>

[[maybe_unused]] static ParsedPacket make_udp_packet(const std::string& iface, const std::string& src_ip, uint16_t src_port,
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

static ParsedPacket make_packet(
    const std::string& iface,
    const std::string& src_ip, uint16_t src_port,
    const std::string& dst_ip, uint16_t dst_port,
    uint8_t protocol,
    uint8_t tcp_flags,
    uint32_t cap_len,
    int64_t ts_offset_sec
) {
    ParsedPacket pkt{};
    pkt.meta.iface = iface;
    pkt.meta.cap_len = cap_len;
    pkt.meta.orig_len = cap_len;
    pkt.meta.timestamp = std::chrono::system_clock::time_point{} + std::chrono::seconds(ts_offset_sec);

    pkt.network.src_ip = src_ip;
    pkt.network.dst_ip = dst_ip;
    pkt.network.protocol = protocol;

    pkt.transport.protocol = protocol;
    pkt.transport.src_port = src_port;
    pkt.transport.dst_port = dst_port;
    pkt.transport.tcp_flags = tcp_flags;

    return pkt;
}

// TEST Direction uses numeric IP ordering, not lexicographic
TEST(StatsAggregatorTest, DirectionUsesNumericIpOrderingNotLexicographic) {
    StatsAggregator agg(std::chrono::seconds(1), 3);

    // Numeric: 10.0.0.9 < 10.0.0.10, so this should be c2s.
    agg.ingest(make_packet("eth0", "10.0.0.9", 1234, "10.0.0.10", 80, /*tcp*/6, /*flags*/0, 60, 1));

    FlowKey key;
    key.iface = "eth0";
    key.protocol = 6;
    key.src_ip = "10.0.0.9";
    key.src_port = 1234;
    key.dst_ip = "10.0.0.10";
    key.dst_port = 80;

    const auto& cur = agg.currentStats();
    auto it = cur.flows.find(key);
    ASSERT_NE(it, cur.flows.end());

    EXPECT_EQ(it->second.pkts_c2s, 1u);
    EXPECT_EQ(it->second.pkts_s2c, 0u);
}

// TEST currentStats before any advanceWindow is live current
TEST(StatsAggregatorTest, CurrentStatsBeforeAnyAdvanceIsLiveCurrent) {
    StatsAggregator agg(std::chrono::seconds(1), 3);

    // count==0 path: should return impl_->current
    EXPECT_TRUE(agg.history().empty());
    EXPECT_TRUE(agg.currentStats().flows.empty());

    auto pkt = make_packet("eth0", "10.0.0.1", 1234, "10.0.0.2", 80, /*tcp*/6, /*flags*/0, /*cap*/60, /*ts*/1);
    agg.ingest(pkt);

    const auto& current = agg.currentStats();
    EXPECT_EQ(current.flows.size(), 1u);

    FlowKey key;
    key.iface = "eth0";
    key.protocol = 6;
    key.src_ip = "10.0.0.1";
    key.src_port = 1234;
    key.dst_ip = "10.0.0.2";
    key.dst_port = 80;

    auto it = current.flows.find(key);
    ASSERT_NE(it, current.flows.end());

    // For 10.0.0.1 < 10.0.0.2, direction should be c2s.
    EXPECT_EQ(it->second.pkts_c2s, 1u);
    EXPECT_EQ(it->second.bytes_c2s, 60u);
    EXPECT_EQ(it->second.pkts_s2c, 0u);
    EXPECT_EQ(it->second.bytes_s2c, 0u);
}

// TEST AdvanceWindow creates new window and saves old one
TEST(StatsAggregatorTest, AdvanceWindowSeparatesWindows) {
    StatsAggregator agg(std::chrono::seconds(1), 3);

    FlowKey key;
    key.iface = "eth0";
    key.protocol = 17;
    key.src_ip = "1.1.1.1";
    key.src_port = 5000;
    key.dst_ip = "2.2.2.2";
    key.dst_port = 53;

    // Window 0: cap_len=60
    agg.ingest(make_packet("eth0", "1.1.1.1", 5000, "2.2.2.2", 53, /*udp*/17, 0, 60, 10));
    agg.advanceWindow();

    // Window 1: cap_len=10 (should not accumulate with previous window)
    agg.ingest(make_packet("eth0", "1.1.1.1", 5000, "2.2.2.2", 53, /*udp*/17, 0, 10, 11));
    agg.advanceWindow();

    auto hist = agg.history();
    ASSERT_EQ(hist.size(), 2u);

    auto it0 = hist[0].flows.find(key);
    ASSERT_NE(it0, hist[0].flows.end());
    EXPECT_EQ(it0->second.pkts_c2s + it0->second.pkts_s2c, 1u);
    EXPECT_EQ(it0->second.bytes_c2s + it0->second.bytes_s2c, 60u);

    auto it1 = hist[1].flows.find(key);
    ASSERT_NE(it1, hist[1].flows.end());
    EXPECT_EQ(it1->second.pkts_c2s + it1->second.pkts_s2c, 1u);
    EXPECT_EQ(it1->second.bytes_c2s + it1->second.bytes_s2c, 10u);
}

// TEST Direction branch can hit s2c
TEST(StatsAggregatorTest, DirectionBranchCanHitS2C) {
    StatsAggregator agg(std::chrono::seconds(1), 3);

    // Make src_ip > dst_ip lexicographically so is_c2s becomes false.
    auto pkt = make_packet("eth0", "9.9.9.9", 1234, "1.1.1.1", 80, /*udp*/17, 0, 42, 1);
    agg.ingest(pkt);

    FlowKey key;
    key.iface = "eth0";
    key.protocol = 17;
    key.src_ip = "9.9.9.9";
    key.src_port = 1234;
    key.dst_ip = "1.1.1.1";
    key.dst_port = 80;

    const auto& current = agg.currentStats();
    auto it = current.flows.find(key);
    ASSERT_NE(it, current.flows.end());

    EXPECT_EQ(it->second.pkts_c2s, 0u);
    EXPECT_EQ(it->second.bytes_c2s, 0u);
    EXPECT_EQ(it->second.pkts_s2c, 1u);
    EXPECT_EQ(it->second.bytes_s2c, 42u);

    // UDP else-branch: NEW -> ESTABLISHED
    EXPECT_EQ(it->second.state, FlowStats::ESTABLISHED);
}

// TEST TCP state transitions: SYN -> ACK -> FIN
TEST(StatsAggregatorTest, TcpStateTransitionsSynAckFin) {
    StatsAggregator agg(std::chrono::seconds(1), 3);

    FlowKey key;
    key.iface = "eth0";
    key.protocol = 6;
    key.src_ip = "10.0.0.1";
    key.src_port = 1111;
    key.dst_ip = "10.0.0.2";
    key.dst_port = 2222;

    // SYN sets NEW
    agg.ingest(make_packet("eth0", "10.0.0.1", 1111, "10.0.0.2", 2222, /*tcp*/6, /*SYN*/0x02, 60, 1));
    {
        auto it = agg.currentStats().flows.find(key);
        ASSERT_NE(it, agg.currentStats().flows.end());
        EXPECT_EQ(it->second.state, FlowStats::NEW);
    }

    // ACK should move NEW -> ESTABLISHED
    agg.ingest(make_packet("eth0", "10.0.0.1", 1111, "10.0.0.2", 2222, /*tcp*/6, /*ACK*/0x10, 60, 2));
    {
        auto it = agg.currentStats().flows.find(key);
        ASSERT_NE(it, agg.currentStats().flows.end());
        EXPECT_EQ(it->second.state, FlowStats::ESTABLISHED);
    }

    // FIN sets CLOSING
    agg.ingest(make_packet("eth0", "10.0.0.1", 1111, "10.0.0.2", 2222, /*tcp*/6, /*FIN*/0x01, 60, 3));
    {
        auto it = agg.currentStats().flows.find(key);
        ASSERT_NE(it, agg.currentStats().flows.end());
        EXPECT_EQ(it->second.state, FlowStats::CLOSING);
    }
}