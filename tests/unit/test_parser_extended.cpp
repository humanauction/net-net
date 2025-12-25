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

    void createIPv6Header(uint8_t* buf, uint8_t next_header,
                          const char* src, const char* dst) {
        memset(buf, 0, 40);
        buf[0] = 0x60; // Version 6
        buf[6] = next_header;
        inet_pton(AF_INET6, src, buf + 8);
        inet_pton(AF_INET6, dst, buf + 24);
    }
};


// ============================================================
// NEW TESTS FOR BRANCH COVERAGE
// ============================================================



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
    uint8_t pkt[20];
    createEthernetHeader(pkt, 0x0800);
    memset(pkt + 14, 0, 6);
    
    PacketMeta meta;
    ParsedPacket out;
    
    EXPECT_FALSE(parsePacket(pkt, 20, meta, out));
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

// Test IPv6 + TCP
TEST_F(ParserExtendedTest, ParseIPv6TCPPacket) {
    uint8_t pkt[74]; // 14 eth + 40 ipv6 + 20 tcp
    createEthernetHeader(pkt, 0x86DD); // IPv6 ethertype
    createIPv6Header(pkt + 14, 6, "2001:db8::1", "2001:db8::2");
    
    // TCP header at offset 54
    pkt[54] = 0x00; pkt[55] = 0x50; // src port 80
    pkt[56] = 0x01; pkt[57] = 0xbb; // dst port 443
    pkt[66] = 0x50; // Data offset
    pkt[67] = 0x02; // SYN flag
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 74;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 74, meta, out));
    
    EXPECT_EQ(out.network.src_ip, "2001:db8::1");
    EXPECT_EQ(out.network.dst_ip, "2001:db8::2");
    EXPECT_EQ(out.network.protocol, 6);
    EXPECT_EQ(out.transport.src_port, 80);
    EXPECT_EQ(out.transport.dst_port, 443);
    EXPECT_EQ(out.transport.tcp_flags, 0x02);
}

// Test IPv6 + UDP
TEST_F(ParserExtendedTest, ParseIPv6UDPPacket) {
    uint8_t pkt[62]; // 14 eth + 40 ipv6 + 8 udp
    createEthernetHeader(pkt, 0x86DD);
    createIPv6Header(pkt + 14, 17, "fe80::1", "fe80::2");
    
    // UDP header at offset 54
    pkt[54] = 0x00; pkt[55] = 0x35; // src port 53
    pkt[56] = 0x04; pkt[57] = 0xD2; // dst port 1234
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 62;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 62, meta, out));
    
    EXPECT_EQ(out.network.src_ip, "fe80::1");
    EXPECT_EQ(out.network.dst_ip, "fe80::2");
    EXPECT_EQ(out.transport.protocol, 17);
    EXPECT_EQ(out.transport.src_port, 53);
    EXPECT_EQ(out.transport.dst_port, 1234);
}

// Test IPv6 + ICMP
TEST_F(ParserExtendedTest, ParseIPv6ICMPPacket) {
    uint8_t pkt[62]; // 14 eth + 40 ipv6 + 8 icmp
    createEthernetHeader(pkt, 0x86DD);
    createIPv6Header(pkt + 14, 58, "::1", "::1"); // ICMPv6 = 58
    
    pkt[54] = 128; // ICMPv6 Echo Request
    pkt[55] = 0;
    
    PacketMeta meta;
    meta.iface = "lo";
    meta.cap_len = 62;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 62, meta, out));
    
    EXPECT_EQ(out.network.src_ip, "::1");
    EXPECT_EQ(out.network.dst_ip, "::1");
    EXPECT_EQ(out.network.protocol, 58);
    EXPECT_EQ(out.transport.icmp_type, 128);
    EXPECT_EQ(out.transport.icmp_code, 0);
}

// Test ICMP with different types
TEST_F(ParserExtendedTest, ParseICMPDestinationUnreachable) {
    uint8_t pkt[54];
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 1, "8.8.8.8", "192.168.1.1");
    
    pkt[34] = 3;  // ICMP Destination Unreachable
    pkt[35] = 1;  // Host Unreachable
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 54;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 54, meta, out));
    
    EXPECT_EQ(out.network.protocol, 1);
    EXPECT_EQ(out.transport.icmp_type, 3);
    EXPECT_EQ(out.transport.icmp_code, 1);
}

// Test TCP truncated (less than 20 bytes)
TEST_F(ParserExtendedTest, ParseTCPTruncated) {
    uint8_t pkt[48]; // 14 eth + 20 ipv4 + 14 bytes (not enough for TCP)
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 6, "10.0.0.1", "10.0.0.2");
    memset(pkt + 34, 0, 14);
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 48;
    
    ParsedPacket out;
    EXPECT_FALSE(parsePacket(pkt, 48, meta, out));
}

// Test UDP truncated (less than 8 bytes)
TEST_F(ParserExtendedTest, ParseUDPTruncated) {
    uint8_t pkt[40]; // 14 eth + 20 ipv4 + 6 bytes (not enough for UDP)
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 17, "172.16.0.1", "172.16.0.2");
    memset(pkt + 34, 0, 6);
    
    PacketMeta meta;
    meta.iface = "eth0";
    meta.cap_len = 40;
    
    ParsedPacket out;
    EXPECT_FALSE(parsePacket(pkt, 40, meta, out));
}

// Test ICMP truncated
TEST_F(ParserExtendedTest, ParseICMPTruncated) {
    uint8_t pkt[35]; // 14 eth + 20 ipv4 + 1 byte (not enough for ICMP)
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 1, "192.168.1.1", "8.8.8.8");
    pkt[34] = 8;
    
    PacketMeta meta;
    meta.cap_len = 35;
    
    ParsedPacket out;
    EXPECT_FALSE(parsePacket(pkt, 35, meta, out));
}

// Test non-IP ethertype (ARP)
TEST_F(ParserExtendedTest, ParseARPPacket) {
    uint8_t pkt[42];
    createEthernetHeader(pkt, 0x0806); // ARP
    memset(pkt + 14, 0, 28);
    
    PacketMeta meta;
    meta.cap_len = 42;
    
    ParsedPacket out;
    EXPECT_FALSE(parsePacket(pkt, 42, meta, out));
}

// Test unknown IP protocol
TEST_F(ParserExtendedTest, ParseUnknownIPProtocol) {
    uint8_t pkt[34];
    createEthernetHeader(pkt, 0x0800);
    createIPv4Header(pkt + 14, 253, "10.0.0.1", "10.0.0.2"); // Reserved protocol
    
    PacketMeta meta;
    meta.cap_len = 34;
    
    ParsedPacket out;
    ASSERT_TRUE(parsePacket(pkt, 34, meta, out));
    EXPECT_EQ(out.network.protocol, 253);
    EXPECT_EQ(out.transport.protocol, 0); // Should default to 0
}



