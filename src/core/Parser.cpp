#include <cstring>
#include "core/parser.h"
#include <netinet/in.h>
#include <arpa/inet.h>

// Helper: parse Ethernet, IPv4, IPv6, TCP, UDP, ICMP
bool parsePacket(const uint8_t* data, size_t len, const PacketMeta& meta, ParsedPacket& out) {
    if (len < 14) return false; // Ethernet header

    // Ethernet
    uint16_t ethertype = (data[12] << 8 | data[13]);
    char src_mac[18], dst_mac[18]; // <-- Only declare once, at the top of the function
    snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             data[6], data[7], data[8], data[9], data[10], data[11]);
    snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3], data[4], data[5]);
    out.datalink.src_mac = src_mac;
    out.datalink.dst_mac = dst_mac;
    out.datalink.ethertype = ethertype;
    size_t offset = 14;

    // IPv4
    if (ethertype == 0x0800 && len >= offset + 20) {
        out.network.ipv6 = false;
        const uint8_t* iphdr = data + offset;
        out.network.src_ip = inet_ntoa(*(in_addr*)(iphdr +12));
        out.network.dst_ip = inet_ntoa(*(in_addr*)(iphdr +16));
        out.network.protocol = iphdr[9];
        offset += (iphdr[0] & 0x0F) * 4;

        //TCP
        if (out.network.protocol == 6 && len >= offset + 20) {
            const uint8_t* tcphdr = data + offset;
            out.transport.protocol = 6;
            out.transport.src_port = ntohs(*(uint16_t*)(tcphdr));
            out.transport.dst_port = ntohs(*(uint16_t*)(tcphdr + 2));
            out.transport.tcp_flags = tcphdr[13];
            offset += ((tcphdr[12] >> 4) & 0xF) * 4;
        }
        //UDP
        else if (out.network.protocol == 17 && len >= offset + 8) {
            const uint8_t* udphdr = data + offset;
            out.transport.protocol = 17;
            out.transport.src_port = ntohs(*(uint16_t*)(udphdr));
            out.transport.dst_port = ntohs(*(uint16_t*)(udphdr + 2));
            offset += 8;
        }
        // ICMP
        else if (out.network.protocol == 1 && len >= offset +4) {
                out.transport.protocol = 1;
                offset +=4;
        }
    }
    // IPv6
    else if (ethertype == 0x86DD && len >= offset + 40) {
        out.network.ipv6 = true;
        const uint8_t* ip6hdr = data + offset;
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ip6hdr + 8, src, sizeof(src));
        inet_ntop(AF_INET6, ip6hdr + 24, dst, sizeof(dst));
        out.network.src_ip = src;
        out.network.dst_ip = dst;
        out.network.protocol = ip6hdr[6];
        offset += 40;
        // Only basic parsing for TCP/UDP/ICMPv6 here
    } else {
        return false;
    }

    out.meta = meta;
    out.payload = data + offset;
    out.payload_len = (offset < len) ? (len - offset) : 0;
    return true;   
}