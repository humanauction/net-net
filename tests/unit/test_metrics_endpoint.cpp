#include <gtest/gtest.h>
#include "../../src/core/StatsAggregator.h"
#include "../../src/core/ConnectionTracker.h"
#include "../../src/core/parser.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <thread>
#include <vector>

using json = nlohmann::json;

class MetricsEndpointTest : public ::testing::Test {
protected:
    std::unique_ptr<StatsAggregator> aggregator;
    std::unique_ptr<ConnectionTracker> tracker;
    
    void SetUp() override {
        // 10-second window, 60 history depth
        aggregator = std::make_unique<StatsAggregator>(std::chrono::seconds(10), 60);
        tracker = std::make_unique<ConnectionTracker>();
    }
    
    void TearDown() override {
        aggregator.reset();
        tracker.reset();
    }
    
    // Helper: Create a parsed packet
    ParsedPacket createPacket(const std::string& src_ip, uint16_t src_port,
                              const std::string& dst_ip, uint16_t dst_port,
                              uint8_t protocol, uint32_t length,
                              const std::string& iface = "en0") {
        ParsedPacket pkt;
        
        // PacketMeta
        pkt.meta.timestamp = std::chrono::system_clock::now();
        pkt.meta.iface = iface;
        pkt.meta.cap_len = length;
        pkt.meta.orig_len = length;
        
        // DataLinkInfo (Ethernet)
        pkt.datalink.src_mac = "00:00:00:00:00:00";
        pkt.datalink.dst_mac = "00:00:00:00:00:00";
        pkt.datalink.ethertype = 0x0800;  // IPv4
        
        // NetworkInfo (IPv4)
        pkt.network.src_ip = src_ip;
        pkt.network.dst_ip = dst_ip;
        pkt.network.protocol = protocol;  // 6=TCP, 17=UDP, 1=ICMP
        pkt.network.ipv6 = false;
        
        // TransportInfo (TCP/UDP)
        pkt.transport.src_port = src_port;
        pkt.transport.dst_port = dst_port;
        pkt.transport.protocol = protocol;
        if (protocol == 6) {  // TCP
            pkt.transport.tcp_flags = 0x18;  // PSH+ACK
        }
        
        return pkt;
    }
    
    // Helper: Generate metrics JSON (mimics NetMonDaemon::handleMetrics)
    json generateMetricsJSON() {
        auto stats = aggregator->currentStats();
        auto flows = tracker->getActiveConnections();
        
        json j;
        j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        j["window_start"] = std::chrono::duration_cast<std::chrono::seconds>(
            stats.window_start.time_since_epoch()
        ).count();
        
        // Calculate totals and protocol breakdown
        uint64_t total_bytes = 0;
        uint64_t total_packets = 0;
        std::unordered_map<std::string, uint64_t> proto_breakdown;
        
        for (const auto& [key, flow_stats] : flows) {
            uint64_t flow_bytes = flow_stats.bytes_c2s + flow_stats.bytes_s2c;
            uint64_t flow_packets = flow_stats.pkts_c2s + flow_stats.pkts_s2c;
            
            total_bytes += flow_bytes;
            total_packets += flow_packets;
            
            // Protocol name
            std::string proto_name;
            if (key.protocol == 6) proto_name = "TCP";
            else if (key.protocol == 17) proto_name = "UDP";
            else if (key.protocol == 1) proto_name = "ICMP";
            else proto_name = "OTHER";
            
            proto_breakdown[proto_name] += flow_bytes;
        }
        
        j["total_bytes"] = total_bytes;
        j["total_packets"] = total_packets;
        
        // Calculate bytes per second (simplified)
        j["bytes_per_second"] = total_bytes / 10;  // Assume 10-second window
        
        // Protocol breakdown
        j["protocol_breakdown"] = json::object();
        for (const auto& [proto, bytes] : proto_breakdown) {
            j["protocol_breakdown"][proto] = bytes;
        }
        
        // Active flows (sorted by bytes descending)
        std::vector<std::pair<FlowKey, FlowStats>> sorted_flows(flows.begin(), flows.end());
        std::sort(sorted_flows.begin(), sorted_flows.end(),
                  [](const auto& a, const auto& b) {
                      uint64_t a_bytes = a.second.bytes_c2s + a.second.bytes_s2c;
                      uint64_t b_bytes = b.second.bytes_c2s + b.second.bytes_s2c;
                      return a_bytes > b_bytes;
                  });
        
        j["active_flows"] = json::array();
        for (const auto& [key, flow_stats] : sorted_flows) {
            json flow_json;
            flow_json["src_ip"] = key.src_ip;
            flow_json["src_port"] = key.src_port;
            flow_json["dst_ip"] = key.dst_ip;
            flow_json["dst_port"] = key.dst_port;
            
            std::string proto_name;
            if (key.protocol == 6) proto_name = "TCP";
            else if (key.protocol == 17) proto_name = "UDP";
            else if (key.protocol == 1) proto_name = "ICMP";
            else proto_name = "OTHER";
            flow_json["protocol"] = proto_name;
            
            flow_json["bytes"] = flow_stats.bytes_c2s + flow_stats.bytes_s2c;
            flow_json["packets"] = flow_stats.pkts_c2s + flow_stats.pkts_s2c;
            j["active_flows"].push_back(flow_json);
        }
        
        return j;
    }
};

// Test 1: Protocol breakdown calculation accuracy
TEST_F(MetricsEndpointTest, ProtocolBreakdownAccuracy) {
    // Add TCP traffic (900 bytes)
    auto tcp1 = createPacket("192.168.1.1", 12345, "8.8.8.8", 443, 6, 300);
    auto tcp2 = createPacket("192.168.1.1", 12346, "8.8.8.8", 443, 6, 300);
    auto tcp3 = createPacket("192.168.1.1", 12347, "8.8.8.8", 443, 6, 300);
    
    tracker->ingest(tcp1);
    tracker->ingest(tcp2);
    tracker->ingest(tcp3);
    aggregator->ingest(tcp1);
    aggregator->ingest(tcp2);
    aggregator->ingest(tcp3);
    
    // Add UDP traffic (600 bytes)
    auto udp1 = createPacket("192.168.1.1", 53, "8.8.8.8", 53, 17, 200);
    auto udp2 = createPacket("192.168.1.1", 54, "8.8.8.8", 53, 17, 200);
    auto udp3 = createPacket("192.168.1.1", 55, "8.8.8.8", 53, 17, 200);
    
    tracker->ingest(udp1);
    tracker->ingest(udp2);
    tracker->ingest(udp3);
    aggregator->ingest(udp1);
    aggregator->ingest(udp2);
    aggregator->ingest(udp3);
    
    // Add ICMP traffic (500 bytes)
    auto icmp1 = createPacket("192.168.1.1", 0, "8.8.8.8", 0, 1, 250);
    auto icmp2 = createPacket("192.168.1.1", 0, "8.8.8.8", 0, 1, 250);
    
    tracker->ingest(icmp1);
    tracker->ingest(icmp2);
    aggregator->ingest(icmp1);
    aggregator->ingest(icmp2);
    
    auto j = generateMetricsJSON();
    
    ASSERT_TRUE(j.contains("protocol_breakdown"));
    EXPECT_EQ(j["protocol_breakdown"]["TCP"], 900);
    EXPECT_EQ(j["protocol_breakdown"]["UDP"], 600);
    EXPECT_EQ(j["protocol_breakdown"]["ICMP"], 500);
    EXPECT_EQ(j["total_bytes"], 2000);
}

// Test 2: Empty flows handling
TEST_F(MetricsEndpointTest, EmptyFlowsHandling) {
    auto j = generateMetricsJSON();
    
    ASSERT_TRUE(j.contains("active_flows"));
    EXPECT_TRUE(j["active_flows"].is_array());
    EXPECT_EQ(j["active_flows"].size(), 0);
    EXPECT_EQ(j["total_bytes"], 0);
    EXPECT_EQ(j["total_packets"], 0);
}

// Test 3: JSON structure validation
TEST_F(MetricsEndpointTest, JSONStructureValidation) {
    auto pkt = createPacket("192.168.1.1", 12345, "8.8.8.8", 443, 6, 1000);
    tracker->ingest(pkt);
    aggregator->ingest(pkt);
    
    auto j = generateMetricsJSON();
    
    // Top-level fields
    EXPECT_TRUE(j.contains("timestamp"));
    EXPECT_TRUE(j.contains("window_start"));
    EXPECT_TRUE(j.contains("total_bytes"));
    EXPECT_TRUE(j.contains("total_packets"));
    EXPECT_TRUE(j.contains("bytes_per_second"));
    EXPECT_TRUE(j.contains("protocol_breakdown"));
    EXPECT_TRUE(j.contains("active_flows"));
    
    // Type validation
    EXPECT_TRUE(j["timestamp"].is_number());
    EXPECT_TRUE(j["total_bytes"].is_number());
    EXPECT_TRUE(j["total_packets"].is_number());
    EXPECT_TRUE(j["protocol_breakdown"].is_object());
    EXPECT_TRUE(j["active_flows"].is_array());
    
    // Flow structure validation
    ASSERT_GT(j["active_flows"].size(), 0);
    auto flow = j["active_flows"][0];
    EXPECT_TRUE(flow.contains("src_ip"));
    EXPECT_TRUE(flow.contains("src_port"));
    EXPECT_TRUE(flow.contains("dst_ip"));
    EXPECT_TRUE(flow.contains("dst_port"));
    EXPECT_TRUE(flow.contains("protocol"));
    EXPECT_TRUE(flow.contains("bytes"));
    EXPECT_TRUE(flow.contains("packets"));
}

// Test 4: Active flows sorting by bytes (descending)
TEST_F(MetricsEndpointTest, FlowsSortedByBytes) {
    auto pkt1 = createPacket("192.168.1.1", 10001, "8.8.8.8", 443, 6, 5000);
    auto pkt2 = createPacket("192.168.1.2", 10002, "8.8.8.8", 443, 6, 100);
    auto pkt3 = createPacket("192.168.1.3", 10003, "8.8.8.8", 443, 6, 2500);
    
    tracker->ingest(pkt1);
    tracker->ingest(pkt2);
    tracker->ingest(pkt3);
    aggregator->ingest(pkt1);
    aggregator->ingest(pkt2);
    aggregator->ingest(pkt3);
    
    auto j = generateMetricsJSON();
    
    ASSERT_EQ(j["active_flows"].size(), 3);
    
    // Verify descending order
    EXPECT_EQ(j["active_flows"][0]["bytes"], 5000);
    EXPECT_EQ(j["active_flows"][1]["bytes"], 2500);
    EXPECT_EQ(j["active_flows"][2]["bytes"], 100);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}