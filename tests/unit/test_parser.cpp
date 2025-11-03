#include <gtest/gtest.h>
#include "parser.h"

TEST(ParserTest, ParseIPv4TCP) {
    // Synthetic Ethernet+IPv4+TCP packet (minimal, not real traffic)
    uint8_t pkt[54] = {0};
    pkt[12] = 0x08; pkt[13] = 0x00; // Ethertype IPv4
    pkt[14] = 0x45; // IPv4 header, IHL=5
    pkt[23] = 6;    // Protocol TCP
    pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 1; // src_ip
    pkt[30] = 192; pkt[31] = 168; pkt[32] = 1; pkt[33] = 2; // dst_ip
    pkt[34] = 0x00; pkt[35] = 0x50; // src_port 80
    pkt[36] = 0x01; pkt[37] = 0xbb; // dst_port 443
    pkt[47] = 0x02; // TCP SYN

    PacketMeta meta;
    meta.iface = "lo0";
    meta.cap_len = 54;
    meta.orig_len = 54;

    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 54, meta, out));
    EXPECT_EQ(out.network.src_ip, "192.168.1.1");
    EXPECT_EQ(out.network.dst_ip, "192.168.1.2");
    EXPECT_EQ(out.transport.src_port, 80);
    EXPECT_EQ(out.transport.dst_port, 443);
    EXPECT_EQ(out.transport.tcp_flags, 0x02);
}

TEST(ParserTest, ParseInvalidPacket) {
    uint8_t pkt[10] = {0};
    PacketMeta meta;
    ParsedPacket out;
    EXPECT_FALSE(parsePacket(pkt, 10, meta, out));
}