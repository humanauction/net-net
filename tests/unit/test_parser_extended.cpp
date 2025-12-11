#include <gtest/gtest.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include "core/Parser.h"

class ParserExtendedTest : public ::testing::Test {
protected:
    void createEthernetHeader(uint8_t* buf, uint16_t ethertype) {
        memset(buf, 0, 14);
        buf[0] = 0xaa; buf[1] = 0xbb; buf[2] = 0xcc;
        buf[3] = 0xdd; buf[4] = 0xee; buf[5] = 0xff;
        buf[6] = 0x11; buf[7] = 0x22; buf[8] = 0x33;
        buf[9] = 0x44; buf[10] = 0x55; buf[11] = 0x66;
        buf[12] = (ethertype >> 8) & 0xff;
        buf[13] = ethertype & 0xff;
    }

    void createIPv4Header(uint8_t* buf, uint8_t proto, 
                          const char* src, const char* dst) {
        memset(buf, 0, 20);
        buf[0] = 0x45;
        buf[9] = proto;
        inet_pton(AF_INET, src, buf + 12);
        inet_pton(AF_INET, dst, buf + 16);
    }
};

TEST_F(ParserExtendedTest, ParseICMPPacket) {
    uint8_t pkt[54];
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 1, "192.168.1.1", "8.8.8.8");
    
    pkt[34] = 8;  // ICMP Echo Request
    pkt[35] = 0;
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 54;
    meta.orig_len = 54;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 54, meta, out));
    
    EXPECT_EQ(out.network.src_ip, "192.168.1.1");
    EXPECT_EQ(out.network.dst_ip, "8.8.8.8");
    EXPECT_EQ(out.network.protocol, 1); // ICMP
}

TEST_F(ParserExtendedTest, ParseTruncatedPacket) {
    uint8_t pkt[10];
    createEthernetHeader(pkt, 0x0800);
    
    PacketMeta meta;
    ParsedPacket out;
    
    EXPECT_FALSE(parsePacket(pkt, 10, meta, out));
}

TEST_F(ParserExtendedTest, ParseZeroLengthPacket) {
    uint8_t pkt[1];
    PacketMeta meta;
    ParsedPacket out;
    
    EXPECT_FALSE(parsePacket(pkt, 0, meta, out));
}

TEST_F(ParserExtendedTest, ParseUDPPacket) {
    uint8_t pkt[42];
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 17, "172.16.0.1", "172.16.0.2");
    
    pkt[34] = 0x00; pkt[35] = 0x35; // Src port 53
    pkt[36] = 0x04; pkt[37] = 0xD2; // Dst port 1234
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 42;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 42, meta, out));
    
    EXPECT_EQ(out.transport.protocol, 17);
    EXPECT_EQ(out.transport.src_port, 53);
    EXPECT_EQ(out.transport.dst_port, 1234);
}

TEST_F(ParserExtendedTest, ParseTCPHighPorts) {
    uint8_t pkt[54];
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 6, "10.0.0.1", "10.0.0.2");
    
    pkt[34] = 0xFF; pkt[35] = 0xFF; // 65535
    pkt[36] = 0xFF; pkt[37] = 0xFF; // 65535
    pkt[46] = 0x50;
    pkt[47] = 0x02;
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 54;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 54, meta, out));
    
    EXPECT_EQ(out.transport.protocol, 6);
    EXPECT_EQ(out.transport.src_port, 65535);
    EXPECT_EQ(out.transport.dst_port, 65535);
}



