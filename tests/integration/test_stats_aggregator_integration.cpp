#include <gtest/gtest.h>
#include "core/ConnectionTracker.h"
#include "core/StatsAggregator.h"
#include "core/Parser.h"
#include <pcap/pcap.h>
#include <vector>
#include <string>

TEST(StatsAggregatorIntegrationTest, AggregatesPcapReplay) {
    StatsAggregator agg(std::chrono::seconds(1), 5);

    // Open sample pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("tests/fixtures/sample.pcap", errbuf);
    ASSERT_TRUE(handle != nullptr) << "Failed to open pcap file: " << errbuf;

    struct pcap_pkthdr* header;
    const u_char* data;
    int ret;
    while ((ret = pcap_next_ex(handle, &header, &data)) > 0) {
        PacketMeta meta;
        meta.iface = "eth0";
        meta.cap_len = header->caplen;
        meta.orig_len = header->len;
        meta.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                         std::chrono::microseconds(header->ts.tv_usec);

        ParsedPacket pkt;
        if (parsePacket(data, header->caplen, meta, pkt)) {
            agg.ingest(pkt);
        }
    }
    pcap_close(handle);

    // Advance window to flush stats
    agg.advanceWindow();
    // Check that some flows were aggregated
    const auto& stats = agg.currentStats();
    FlowKey key;
    key.iface = "eth0";
    key.protocol = 6; // TCP
    key.src_ip = "10.0.0.1";
    key.src_port = 1234;
    key.dst_ip = "10.0.0.2";
    key.dst_port = 80;

    auto it = stats.flows.find(key);
    ASSERT_TRUE(it != stats.flows.end());
    EXPECT_EQ(it->second.pkts_c2s, 10);      // 10 pkts. Adjust to match pcap
    EXPECT_EQ(it->second.bytes_c2s, 10 * 54); // 10 * 54 bytes. Adjust to match pcap
}