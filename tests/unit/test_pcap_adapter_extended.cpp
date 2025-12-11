#include <gtest/gtest.h>
#include <filesystem>
#include <thread>
#include <chrono>
#include "net/PcapAdapter.h"

// =================================
// Test suite
// =================================

// TEST invalid interface name
TEST(PcapAdapterExtendedTest, InvalidInterface) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "nonexistent_interface_xyz123";
    
    PcapAdapter adapter(opts);
    
    EXPECT_THROW(
        adapter.startCapture([](auto, auto, auto) {}),
        std::runtime_error
    );
}

// TEST invalid BPF filter syntax
TEST(PcapAdapterExtendedTest, InvalidBPFFilter) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "lo0";
    opts.bpf_filter = "invalid syntax !!!";
    
    PcapAdapter adapter(opts);
    
    EXPECT_THROW(
        adapter.startCapture([](auto, auto, auto) {}),
        std::runtime_error
    );
}

// TEST BPF filter with SQL injection attempt
TEST(PcapAdapterExtendedTest, BPFFilterWithSQLInjection) {
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp; DROP TABLE users;"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp | rm -rf /"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp && evil"));
}

// TEST BPF filter with shell metacharacters
TEST(PcapAdapterExtendedTest, BPFFilterWithShellMetacharacters) {
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp`shutdown`"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp$(reboot)"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp&& || cat /etc/passwd"));
}

// TEST excessively long BPF filter
TEST(PcapAdapterExtendedTest, BPFFilterTooLong) {
    std::string long_filter(300, 'a');
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter(long_filter));
}

// TEST valid BPF filter expressions
TEST(PcapAdapterExtendedTest, ValidBPFFilters) {
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("icmp"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp port 80"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("host 192.168.1.1"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("net 10.0.0.0/8"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp[13] & 2 != 0"));
}

// TEST stop capture before start
TEST(PcapAdapterExtendedTest, StopBeforeStart) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "lo0";
    
    PcapAdapter adapter(opts);
    EXPECT_NO_THROW(adapter.stopCapture());
}

// TEST promiscuous mode option
TEST(PcapAdapterExtendedTest, PromiscuousModeOption) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "lo0";
    opts.promiscuous = true;
    
    EXPECT_NO_THROW(PcapAdapter adapter(opts));
}

// TEST custom snaplen
TEST(PcapAdapterExtendedTest, CustomSnaplen) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "lo0";
    opts.snaplen = 1500;
    
    EXPECT_NO_THROW(PcapAdapter adapter(opts));
}

// TEST invalid snaplen
TEST(PcapAdapterExtendedTest, InvalidSnaplen) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "lo0";
    opts.snaplen = -1;
    
    EXPECT_THROW(PcapAdapter adapter(opts), std::invalid_argument);
    
    opts.snaplen = 100000;
    EXPECT_THROW(PcapAdapter adapter(opts), std::invalid_argument);
}

// TEST custom timeout
TEST(PcapAdapterExtendedTest, CustomTimeout) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "lo0";
    opts.timeout_ms = 500;
    
    EXPECT_NO_THROW(PcapAdapter adapter(opts));
}

// TEST nonexistent pcap file
TEST(PcapAdapterExtendedTest, NonexistentPcapFile) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "nonexistent.pcap";
    opts.read_offline = true;
    
    PcapAdapter adapter(opts);
    
    EXPECT_THROW(
        adapter.startCapture([](auto, auto, auto) {}),
        std::runtime_error
    );
}

// TEST empty interface name
TEST(PcapAdapterExtendedTest, EmptyInterfaceName) {
    PcapAdapter::Options opts;
    opts.iface_or_file = "";
    
    EXPECT_THROW(PcapAdapter adapter(opts), std::invalid_argument);
}