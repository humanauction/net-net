#include <gtest/gtest.h>
#include "core/parser.h"
#include "core/ConnectionTracker.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>


// Helper: build a synthetic TCP packet and parse it
static ParsedPacket make_tcp_packet(const std::string& iface, const std::string& src_ip, uint16_t src_port,
                                   const std::string& dst_ip, uint16_t dst_port, uint8_t flags, uint64_t ts_offset = 0) {
    uint8_t pkt[54] = {0};
    pkt[12] = 0x08; pkt[13] = 0x00; // Ethertype IPv4
    pkt[14] = 0x45; // IPv4 header, IHL=5
    pkt[23] = 6;    // Protocol TCP
    // src_ip
    in_addr src_addr; inet_pton(AF_INET, src_ip.c_str(), &src_addr);
    memcpy(pkt + 26, &src_addr, 4);
    // dst_ip
    in_addr dst_addr; inet_pton(AF_INET, dst_ip.c_str(), &dst_addr);
    memcpy(pkt + 30, &dst_addr, 4);
    // TCP header
    pkt[34] = src_port >> 8; pkt[35] = src_port & 0xFF;
    pkt[36] = dst_port >> 8; pkt[37] = dst_port & 0xFF;
    pkt[46] = 0x50; // Data offset
    pkt[47] = flags; // TCP flags

    PacketMeta meta;
    meta.iface = iface;
    meta.cap_len = 54;
    meta.orig_len = 54;
    meta.timestamp = std::chrono::system_clock::now() + std::chrono::seconds(ts_offset);

    ParsedPacket out;
    EXPECT_TRUE(parsePacket(pkt, 54, meta, out));
    return out;
}

TEST(ConnectionTrackerIntegration, FlowAssemblyAndCounters) {
    ConnectionTracker tracker;

    // Simulate packets on two interfaces
    auto pkt1 = make_tcp_packet("eth0", "10.0.0.1", 12345, "10.0.0.2", 80, 0x02); // SYN
    auto pkt2 = make_tcp_packet("eth0", "10.0.0.1", 12345, "10.0.0.2", 80, 0x10, 1); // ACK
    auto pkt3 = make_tcp_packet("eth1", "192.168.1.10", 5555, "192.168.1.20", 443, 0x02); // SYN

    tracker.ingest(pkt1);
    tracker.ingest(pkt2);
    tracker.ingest(pkt3);

    auto flows = tracker.getActiveConnections();
    ASSERT_EQ(flows.size(), 2);

    // Check per-flow counters
    for (const auto& kv : flows) {
        const auto& key = kv.first;
        const auto& stats = kv.second;
        if (key.iface == "eth0") {
            EXPECT_EQ(stats.pkts_c2s + stats.pkts_s2c, 2);
            EXPECT_EQ(stats.bytes_c2s + stats.bytes_s2c, 108); // 2 packets * 54 bytes
        } else if (key.iface == "eth1") {
            EXPECT_EQ(stats.pkts_c2s + stats.pkts_s2c, 1);
            EXPECT_EQ(stats.bytes_c2s + stats.bytes_s2c, 54);
        }
    }
}
