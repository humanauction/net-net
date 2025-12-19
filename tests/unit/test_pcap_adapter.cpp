#include <gtest/gtest.h>
#include "../../src/net/PcapAdapter.h"
#include <thread>
#include <chrono>
#include <atomic>

// =================================
// Test suite
// =================================

TEST(PcapAdapterTest, ConstructorValid) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "lo0";
    opts.promiscuous = false;
    
    EXPECT_NO_THROW({
        PcapAdapter adapter(opts);
        EXPECT_EQ(adapter.source(), "lo0");
    });
}

TEST(PcapAdapterTest, OfflineMode) {
    std::atomic<int> packet_count{0};
    
    PcapAdapter::Options opts;
    opts.iface_or_file = "tests/fixtures/icmp_sample.pcap";
    opts.read_offline = true;
    
    PcapAdapter adapter(opts);
    
    auto callback = [&packet_count](const PacketMeta&, const u_char*, size_t) {
        packet_count++;
    };
    
    adapter.startCapture(callback);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    adapter.stopCapture();

    EXPECT_EQ(packet_count.load(), 128) << "Expected 128 packets in icmp_sample.pcap, got " << packet_count.load();
}

TEST(PcapAdapterTest, InvalidInterface) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "nonexistent999";
    opts.read_offline = false;
    
    PcapAdapter adapter(opts);
    EXPECT_THROW(adapter.startCapture([](auto,auto,auto){}), std::runtime_error);
}

TEST(PcapAdapterTest, InvalidOptions) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "";
    
    EXPECT_THROW({
        PcapAdapter adapter(opts);
    }, std::invalid_argument);
    
    opts.iface_or_file = "lo0";
    opts.snaplen = -1;
    
    EXPECT_THROW({
        PcapAdapter adapter(opts);
    }, std::invalid_argument);
}

TEST(PcapAdapterTest, BpfFilterValid) {
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("icmp"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp port 82"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("host 192.168.1.1"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("udp and port 53"));
}

TEST(PcapAdapterTest, BpfFilterInvalidCharacters) {
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("icmp; rm -rf /"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp | nc 1.2.3.4 4444"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("udp && evil"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("host 192.168.1.1$"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("`shutdown`"));
}

TEST(PcapAdapterTest, BpfFilterTooLong) {
    std::string long_filter(257, 'a');
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter(long_filter));
}