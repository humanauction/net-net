#include <gtest/gtest.h>
#include "PcapAdapter.h"
#include <thread>
#include <chrono>

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
    opts.iface_or_file = CMAKE_SOURCE_DIR "/tests/fixtures/sample.pcap";
    opts.read_offline = true;
    
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