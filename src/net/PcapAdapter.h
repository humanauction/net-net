#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <chrono>
#include <memory>
#include "../core/PacketMeta.h"

using PacketCallback = std::function<void(const PacketMeta&, const uint8_t*, size_t)>;

class PcapAdapter {
public:
    struct Options{
        std::string iface_or_file;
        // BPF filter expression (see examples below)
        // Examples:
        //   "tcp"                      - TCP traffic only
        //   "tcp port 80"              - HTTP traffic
        //   "tcp port 80 or tcp port 443" - HTTP/HTTPS
        //   "udp port 53"              - DNS queries
        //   "host 192.168.1.1"         - Traffic to/from IP
        //   "net 192.168.0.0/16"       - Traffic in subnet
        //   "not tcp port 22"          - Everything except SSH
        //   "icmp"                     - ICMP (ping) only
        //   "tcp[tcpflags] & (tcp-syn) != 0" - TCP SYN packets
        // Full syntax: https://www.tcpdump.org/manpages/pcap-filter.7.html
        std::string bpf_filter;
        bool promiscuous = true;
        int snaplen = 65535;
        int timeout_ms = 1000;
        bool read_offline = false;
    };

    explicit PcapAdapter(const Options& opts);
    ~PcapAdapter();
    
    PcapAdapter(const PcapAdapter&) = delete;
    PcapAdapter& operator=(const PcapAdapter&) = delete;

    // Stage 1 API
    // Start capture; throws std::runtime_error on fatal setup error.
    void startCapture(PacketCallback cb);
    // Stop capture.
    void stopCapture();
    // Throws std::runtime_error if filter is invalid
    // Examples:
    //   setFilter("tcp port 443");  // Switch to HTTPS only
    //   setFilter("");              // Remove filter (capture all)
    void setFilter(const std::string& bpf);
    // Source name can be interface or file
    std::string source() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    friend void pcap_bridge(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);
};

