#include <gtest/gtest.h>

#include "../core/StatsPersistence.h"

#include <chrono>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

static fs::path unique_temp_path(const std::string& prefix) {
    const auto now_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    return fs::temp_directory_path() / (prefix + "-" + std::to_string(now_ns));
}

static int64_t to_epoch_seconds(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(
        tp.time_since_epoch()).count();
}

static FlowKey make_key(std::string iface,
                        uint8_t proto,
                        std::string src_ip,
                        uint16_t src_port,
                        std::string dst_ip,
                        uint16_t dst_port) {
    FlowKey k;
    k.iface = std::move(iface);
    k.protocol = proto;
    k.src_ip = std::move(src_ip);
    k.src_port = src_port;
    k.dst_ip = std::move(dst_ip);
    k.dst_port = dst_port;
    return k;
}

// ===============================
// TEST SUITE
// ===============================

// TEST: Open DB and create schema
TEST(StatsPersistenceTest, OpensDbAndCreatesSchema) {
    const fs::path db_path = unique_temp_path("netnet-stats-open") += ".sqlite";

    ASSERT_NO_THROW({
        StatsPersistence sp(db_path.string());
        auto history = sp.loadHistory(10);
        EXPECT_TRUE(history.empty());
    });

    std::error_code ec;
    fs::remove(db_path, ec);
}

// TEST Save and load round trip
TEST(StatsPersistenceTest, SaveAndLoadSingleWindowRoundTrip) {
    const fs::path db_path = unique_temp_path("netnet-stats-roundtrip") += ".sqlite";
    StatsPersistence sp(db_path.string());

    AggregatedStats in;
    in.window_start = std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}};

    FlowStats fs1;
    fs1.pkts_c2s = 3;
    fs1.pkts_s2c = 7;
    fs1.bytes_c2s = 111;
    fs1.bytes_s2c = 222;

    const FlowKey k1 = make_key("eth0", 6, "10.0.0.1", 1234, "10.0.0.2", 80);
    in.flows.emplace(k1, fs1);

    sp.saveWindow(in);

    auto out = sp.loadHistory(10);
    ASSERT_EQ(out.size(), 1u);

    const auto& loaded = out[0];
    EXPECT_EQ(to_epoch_seconds(loaded.window_start), 1700000000);

    ASSERT_EQ(loaded.flows.size(), 1u);
    auto it = loaded.flows.find(k1);
    ASSERT_NE(it, loaded.flows.end());

    EXPECT_EQ(it->second.pkts_c2s, 3);
    EXPECT_EQ(it->second.pkts_s2c, 7);
    EXPECT_EQ(it->second.bytes_c2s, 111);
    EXPECT_EQ(it->second.bytes_s2c, 222);

    std::error_code ec;
    fs::remove(db_path, ec);
}

// TEST Load history with max_windows
TEST(StatsPersistenceTest, LoadHistoryMaxWindowsWorksWhenOneFlowPerWindow) {
    const fs::path db_path = unique_temp_path("netnet-stats-maxwindows") += ".sqlite";
    StatsPersistence sp(db_path.string());

    // Window A (older)
    AggregatedStats a;
    a.window_start = std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}};
    {
        FlowStats fs;
        fs.pkts_c2s = 1; fs.pkts_s2c = 0;
        fs.bytes_c2s = 10; fs.bytes_s2c = 0;
        a.flows.emplace(make_key("eth0", 17, "1.1.1.1", 1111, "2.2.2.2", 2222), fs);
    }
    sp.saveWindow(a);

    // Window B (newer)
    AggregatedStats b;
    b.window_start = std::chrono::system_clock::time_point{std::chrono::seconds{1700000100}};
    {
        FlowStats fs;
        fs.pkts_c2s = 2; fs.pkts_s2c = 0;
        fs.bytes_c2s = 20; fs.bytes_s2c = 0;
        b.flows.emplace(make_key("eth0", 17, "3.3.3.3", 3333, "4.4.4.4", 4444), fs);
    }
    sp.saveWindow(b);

    auto out = sp.loadHistory(1);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(to_epoch_seconds(out[0].window_start), 1700000100);

    std::error_code ec;
    fs::remove(db_path, ec);
}

// TEST Save window with no flows does not crash
TEST(StatsPersistenceTest, SaveWindowWithNoFlowsDoesNotCrash) {
    const fs::path db_path = unique_temp_path("netnet-stats-empty") += ".sqlite";
    StatsPersistence sp(db_path.string());

    AggregatedStats empty;
    empty.window_start = std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}};

    ASSERT_NO_THROW(sp.saveWindow(empty));

    std::error_code ec;
    fs::remove(db_path, ec);
}

// TEST Open fails when path is a directory
TEST(StatsPersistenceTest, OpenFailsWhenPathIsDirectory) {
    const fs::path dir_path = unique_temp_path("netnet-stats-dir");

    std::error_code ec;
    fs::create_directories(dir_path, ec);
    ASSERT_TRUE(fs::exists(dir_path));

    EXPECT_THROW(
        {
            StatsPersistence sp(dir_path.string());
        },
        std::runtime_error);

    fs::remove_all(dir_path, ec);
}

// TEST Load history with multiple flows in newest window
TEST(StatsPersistenceTest, LoadHistoryOneWindowReturnsAllFlowsFromNewestWindow) {
    const fs::path db_path = unique_temp_path("netnet-stats-multiflow") += ".sqlite";
    StatsPersistence sp(db_path.string());

    // Older window with 2 flows
    AggregatedStats older;
    older.window_start = std::chrono::system_clock::time_point{std::chrono::seconds{1700000000}};
    {
        FlowStats f1; f1.pkts_c2s = 1; f1.pkts_s2c = 1; f1.bytes_c2s = 10; f1.bytes_s2c = 11;
        FlowStats f2; f2.pkts_c2s = 2; f2.pkts_s2c = 2; f2.bytes_c2s = 20; f2.bytes_s2c = 22;
        older.flows.emplace(make_key("eth0", 6, "10.0.0.1", 1111, "10.0.0.2", 80), f1);
        older.flows.emplace(make_key("eth0", 6, "10.0.0.3", 3333, "10.0.0.4", 443), f2);
    }
    sp.saveWindow(older);

    // Newer window with 2 flows
    AggregatedStats newer;
    newer.window_start = std::chrono::system_clock::time_point{std::chrono::seconds{1700000100}};
    FlowKey n1 = make_key("eth0", 17, "1.1.1.1", 53, "8.8.8.8", 53);
    FlowKey n2 = make_key("eth0", 17, "9.9.9.9", 5353, "224.0.0.251", 5353);
    {
        FlowStats f1; f1.pkts_c2s = 3; f1.pkts_s2c = 4; f1.bytes_c2s = 30; f1.bytes_s2c = 40;
        FlowStats f2; f2.pkts_c2s = 5; f2.pkts_s2c = 6; f2.bytes_c2s = 50; f2.bytes_s2c = 60;
        newer.flows.emplace(n1, f1);
        newer.flows.emplace(n2, f2);
    }
    sp.saveWindow(newer);

    auto out = sp.loadHistory(1);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(to_epoch_seconds(out[0].window_start), 1700000100);

    // The key assertion: BOTH flows from the newest window are present.
    ASSERT_EQ(out[0].flows.size(), 2u);
    EXPECT_NE(out[0].flows.find(n1), out[0].flows.end());
    EXPECT_NE(out[0].flows.find(n2), out[0].flows.end());

    std::error_code ec;
    fs::remove(db_path, ec);
}