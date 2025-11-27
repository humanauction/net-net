#include <gtest/gtest.h>
#include "core/StatsAggregator.h"
#include "core/parser.h"
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

TEST(StatsAggregatorTest, AggregatesFlowsAndHistory) {
    StatsAggregator agg(std::chrono::seconds(1), 2);

    auto pkt1 = make_udp_packet("eth0", "10.0.0.1", 1234, "10.0.0.2", 5678);
    auto pkt2 = make_udp_packet("eth0", "10.0.0.1", 1234, "10.0.0.2", 5678, 1);
    auto pkt3 = make_udp_packet("eth1", "192.168.1.1", 1111, "192.168.1.2", 2222);

    agg.ingest(pkt1);
    agg.ingest(pkt2);
    agg.ingest(pkt3);

    const auto& stats = agg.currentStats();
    EXPECT_EQ(stats.flows.size(), 2);

    agg.advanceWindow();
    EXPECT_EQ(agg.history().size(), 1);

    agg.ingest(pkt1);
    agg.advanceWindow();
    EXPECT_EQ(agg.history().size(), 2);

    agg.ingest(pkt3);
    agg.advanceWindow();
    EXPECT_EQ(agg.history().size(), 2); // history_depth = 2, oldest dropped
}

TEST(StatsAggregatorTest, CircularBufferOrder) {
    StatsAggregator agg(std::chrono::seconds(1),(2));

    auto pkt1 = make_udp_packet("eth0", "10.0.0.1", 1234, "10.0.0.2", 5678);
    agg.ingest(pkt1);
    agg.advanceWindow();

    auto pkt2 = make_udp_packet("eth1", "192.168.1.1", 1111, "192.168.1.2", 2222);
    agg.ingest(pkt2);
    agg.advanceWindow();

    auto pkt3 = make_udp_packet("eth0", "10.0.0.1", 1234, "10.0.0.2", 5678);
    agg.ingest(pkt3);
    agg.advanceWindow();

    // Check contents of history[0][1] for expected flows
    auto history = agg.history();
    EXPECT_EQ(history.size(), 2);
}