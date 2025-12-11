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
    // Note: "&&" is valid BPF logical AND, not shell command chaining
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp and udp"));  // Valid BPF
}

// TEST BPF filter with shell metacharacters
TEST(PcapAdapterExtendedTest, BPFFilterWithShellMetacharacters) {
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp`shutdown`"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp$(reboot)"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp; cat /etc/passwd"));
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

// TEST valid advanced BPF filters
TEST(PcapAdapterExtendedTest, ValidAdvancedBPFFilters) {
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp[13] & 2 != 0"));  // SYN flag
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("ip[0] & 0xf0"));     // IP version
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("udp[8:2] = 53"));    // DNS port
}

// TEST dangerous shell injection patterns are blocked
TEST(PcapAdapterExtendedTest, BlockDangerousShellPatterns) {
    // Command separators
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp; reboot"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp\nreboot"));
    
    // Command substitution
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp`whoami`"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp$(whoami)"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp${PATH}"));
    
    // Pipes and redirects
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp | cat /etc/passwd"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp >> /tmp/pwned"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp << EOF"));
    
    // Escapes
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp\\nmalicious"));
}

// TEST SQL keywords in various positions
TEST(PcapAdapterExtendedTest, BlockSQLKeywords) {
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("DROP TABLE users"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("tcp drop table"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("DELETE FROM sessions"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("INSERT INTO logs"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("UPDATE users SET"));
    EXPECT_FALSE(PcapAdapter::isValidBpfFilter("UNION SELECT password"));
}

// TEST legitimate BPF operators that might look suspicious
TEST(PcapAdapterExtendedTest, AllowLegitimateOperators) {
    // BPF logical operators (not shell operators)
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp and udp"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp or icmp"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("not tcp"));
    
    // Bitwise AND in BPF (different from shell &&)
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("tcp[13] & 2"));
    
    // Comparison operators
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("port > 1024"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("len < 100"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("vlan = 10"));
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("ip[2:2] != 0"));
}

// TEST edge cases with special characters
TEST(PcapAdapterExtendedTest, EdgeCasesWithSpecialChars) {
    // IPv6 addresses with colons
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("host 2001:db8::1"));
    
    // CIDR notation
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("net 192.168.0.0/16"));
    
    // Port ranges
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("portrange 1000-2000"));
    
    // Complex expressions with parentheses
    EXPECT_TRUE(PcapAdapter::isValidBpfFilter("(tcp or udp) and port 53"));
}