#include <gtest/gtest.h>
#include "parser.h"

TEST(ParserTest, ParseIPv4TCP) {
    uint8_t pkt[54] = {0};
    // Set MAC addresses
    pkt[0] = 0xaa; pkt[1] = 0xbb; pkt[2] = 0xcc; pkt[3] = 0xdd; pkt[4] = 0xee; pkt[5] = 0xff; // dst_mac
    pkt[6] = 0x11; pkt[7] = 0x22; pkt[8] = 0x33; pkt[9] = 0x44; pkt[10] = 0x55; pkt[11] = 0x66; // src_mac
    pkt[12] = 0x08; pkt[13] = 0x00; // Ethertype IPv4
    pkt[14] = 0x45; // IPv4 header, IHL=5
    pkt[23] = 6;    // Protocol TCP
    pkt[26] = 192; pkt[27] = 168; pkt[28] = 1; pkt[29] = 1; // src_ip
    pkt[30] = 192; pkt[31] = 168; pkt[32] = 1; pkt[33] = 2; // dst_ip

    // TCP header starts at offset 34
    pkt[34] = 0x00; pkt[35] = 0x50; // src_port 80
    pkt[36] = 0x01; pkt[37] = 0xbb; // dst_port 443
    pkt[46] = 0x50; // Data offset (5) << 4, no flags
    pkt[47] = 0x02; // TCP flags (SYN)

    PacketMeta meta;
    meta.iface = "lo0";
    meta.cap_len = 54;
    meta.orig_len = 54;

    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 54, meta, out));
    EXPECT_EQ(out.datalink.src_mac, "11:22:33:44:55:66");
    EXPECT_EQ(out.datalink.dst_mac, "aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(out.datalink.ethertype, 0x0800);
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