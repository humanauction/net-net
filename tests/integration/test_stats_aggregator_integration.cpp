#include <gtest/gtest.h>
#include <pcap.h>
#include "core/ConnectionTracker.h"
#include "core/StatsAggregator.h"
#include "core/Parser.h"

TEST(StatsAggregatorIntegrationTest, AggregatesSyntheticFlows) {
    StatsAggregator agg(std::chrono::seconds(1), 5);

    // Create 10 synthetic packets for a single flow
    for (int i = 0; i < 10; i++) {
        ParsedPacket pkt;
        
        // Set metadata
        pkt.meta.iface = "eth0";
        pkt.meta.cap_len = 54;
        pkt.meta.orig_len = 54;
        pkt.meta.timestamp = std::chrono::system_clock::now();

        // Set network layer info
        pkt.network.src_ip = "10.0.0.1";
        pkt.network.dst_ip = "10.0.0.2";
        pkt.network.protocol = 6; // TCP
        pkt.network.ipv6 = false;

        // Set transport layer info
        pkt.transport.src_port = 1234;
        pkt.transport.dst_port = 80;
        pkt.transport.protocol = 6; // TCP
        pkt.transport.tcp_flags = 0x18; // ACK + PSH

        // Set payload info
        pkt.payload_len = 54;
        
        agg.ingest(pkt);
    }

    agg.advanceWindow();
    const auto& history = agg.history();
    ASSERT_FALSE(history.empty()) << "No history available after advancing window";
    const AggregatedStats& stats = history.back();

    // Verify the flow was aggregated
    FlowKey key;
    key.iface = "eth0";
    key.protocol = 6;
    key.src_ip = "10.0.0.1";
    key.src_port = 1234;
    key.dst_ip = "10.0.0.2";
    key.dst_port = 80;

    auto it = stats.flows.find(key);
    ASSERT_TRUE(it != stats.flows.end()) << "Expected flow not found in aggregated stats";
    EXPECT_EQ(it->second.pkts_c2s, 10);
    EXPECT_EQ(it->second.bytes_c2s, 10 * 54);
}

// Optional: Keep the pcap test but make it skip if file is missing
TEST(StatsAggregatorIntegrationTest, AggregatesPcapReplay) {
    StatsAggregator agg(std::chrono::seconds(1), 5);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("tests/fixtures/sample.pcap", errbuf);
    
    // Skip this test if pcap doesn't exist
    if (!handle) {
        GTEST_SKIP() << "sample.pcap not found: " << errbuf;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int ret;
    int packet_count = 0;
    
    while ((ret = pcap_next_ex(handle, &header, &data)) > 0) {
        PacketMeta meta;
        meta.iface = "eth0";
        meta.cap_len = header->caplen;
        meta.orig_len = header->len;
        meta.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                         std::chrono::microseconds(header->ts.tv_usec);

        ParsedPacket pkt;
        if (parsePacket(data, header->caplen, meta, pkt)) {
            packet_count++;
            agg.ingest(pkt);
        }
    }
    pcap_close(handle);

    agg.advanceWindow();
    const auto& history = agg.history();
    ASSERT_FALSE(history.empty()) << "No history available after advancing window";
    const AggregatedStats& stats = history.back();
    
    // Verify something was parsed 
    ASSERT_GT(packet_count, 0) << "No packets were parsed from pcap file";
    ASSERT_GT(stats.flows.size(), 0) << "No flows were aggregated";
}

TEST(StatsAggregatorIntegrationTest, DebugFlowKey) {
    StatsAggregator agg(std::chrono::seconds(1), 5);

    ParsedPacket pkt;
    pkt.meta.iface = "eth0";
    pkt.meta.cap_len = 54;
    pkt.meta.timestamp = std::chrono::system_clock::now();
    pkt.network.src_ip = "10.0.0.1";
    pkt.network.dst_ip = "10.0.0.2";
    pkt.network.protocol = 6;
    pkt.transport.src_port = 1234;
    pkt.transport.dst_port = 80;
    pkt.transport.protocol = 6;
    pkt.transport.tcp_flags = 0x18;
    pkt.payload_len = 54;

    agg.ingest(pkt);

    const auto& stats = agg.currentStats();
    
    std::cout << "Total flows: " << stats.flows.size() << std::endl;
    
    for (const auto& [key, flow] : stats.flows) {
        std::cout << "Stored FlowKey:" << std::endl;
        std::cout << "  iface: '" << key.iface << "'" << std::endl;
        std::cout << "  protocol: " << (int)key.protocol << std::endl;
        std::cout << "  src_ip: '" << key.src_ip << "'" << std::endl;
        std::cout << "  src_port: " << key.src_port << std::endl;
        std::cout << "  dst_ip: '" << key.dst_ip << "'" << std::endl;
        std::cout << "  dst_port: " << key.dst_port << std::endl;
        std::cout << "  pkts_c2s: " << flow.pkts_c2s << std::endl;
        std::cout << "  bytes_c2s: " << flow.bytes_c2s << std::endl;
    }
    
    // Try to find it
    FlowKey lookup_key;
    lookup_key.iface = "eth0";
    lookup_key.protocol = 6;
    lookup_key.src_ip = "10.0.0.1";
    lookup_key.src_port = 1234;
    lookup_key.dst_ip = "10.0.0.2";
    lookup_key.dst_port = 80;
    
    std::cout << "\nLooking for FlowKey:" << std::endl;
    std::cout << "  iface: '" << lookup_key.iface << "'" << std::endl;
    std::cout << "  protocol: " << (int)lookup_key.protocol << std::endl;
    std::cout << "  src_ip: '" << lookup_key.src_ip << "'" << std::endl;
    std::cout << "  src_port: " << lookup_key.src_port << std::endl;
    std::cout << "  dst_ip: '" << lookup_key.dst_ip << "'" << std::endl;
    std::cout << "  dst_port: " << lookup_key.dst_port << std::endl;
    
    auto it = stats.flows.find(lookup_key);
    std::cout << "\nFound: " << (it != stats.flows.end() ? "YES" : "NO") << std::endl;
}