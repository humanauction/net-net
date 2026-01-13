#include "core/StatsPersistence.h"
#include "core/StatsAggregator.h"
#include <sqlite3.h>
#include <iostream>
#include <map>
#include <vector>

StatsPersistence::StatsPersistence(const std::string& db_path)
    : db_path_(db_path), db_(nullptr) {

    if (sqlite3_open(db_path_.c_str(), &db_) != SQLITE_OK) {
        std::string error = db_ ? sqlite3_errmsg(db_) : "error unknown";
        if (db_) sqlite3_close(db_);
        throw std::runtime_error("Failed to open database: " + error);
    }

    // Add WAL mode and busy timeout
    char* err_msg = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err_msg);
    if (err_msg) {
        std::cerr << "WAL mode warning: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
    
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, &err_msg);
    if (err_msg) {
        std::cerr << "Busy timeout warning: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }

    createSchema();
}

StatsPersistence::~StatsPersistence() {
    if(db_) {
        sqlite3_close(db_);
    }
}

void StatsPersistence::createSchema() {
    const char* schema =R"(
        CREATE TABLE IF NOT EXISTS agg_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start INTEGER NOT NULL,
            iface TEXT NOT NULL,
            protocol INTEGER NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            pkts_c2s INTEGER DEFAULT 0,
            pkts_s2c INTEGER DEFAULT 0,
            bytes_c2s INTEGER DEFAULT 0,
            bytes_s2c INTEGER DEFAULT 0
        );
        
        CREATE INDEX IF NOT EXISTS idx_window_start ON agg_stats(window_start);
    )";
    
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, schema, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        std::string error = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to create schema: " + error);
    }
}
    

void StatsPersistence::saveWindow(const AggregatedStats& stats) {
    
    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    const char* insert_sql =
        "INSERT INTO agg_stats(window_start, iface, protocol, src_ip, src_port, dst_ip, dst_port, pkts_c2s, pkts_s2c, bytes_c2s, bytes_s2c) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db_) << std::endl;
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return;
    }

    for (const auto& kv : stats.flows) {
        const FlowKey& key = kv.first;
        const FlowStats& fs = kv.second;

        sqlite3_bind_int64(stmt, 1, std::chrono::duration_cast<std::chrono::seconds>(stats.window_start.time_since_epoch()).count());
        sqlite3_bind_text(stmt, 2, key.iface.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, key.protocol);
        sqlite3_bind_text(stmt, 4, key.src_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, key.src_port);
        sqlite3_bind_text(stmt, 6, key.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, key.dst_port);
        sqlite3_bind_int(stmt, 8, fs.pkts_c2s);
        sqlite3_bind_int(stmt, 9, fs.pkts_s2c);
        sqlite3_bind_int(stmt, 10, fs.bytes_c2s);
        sqlite3_bind_int(stmt, 11, fs.bytes_s2c);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db_) << std::endl;
        }
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_exec(db_, "END TRANSACTION;", nullptr, nullptr, nullptr);

    std::cerr << "[DEBUG] saveWindow: flows=" << stats.flows.size() << ", window_start=" << std::chrono::duration_cast<std::chrono::seconds>(stats.window_start.time_since_epoch()).count() << std::endl;
    
}

std::vector<AggregatedStats> StatsPersistence::loadHistory(size_t max_windows) {
    std::vector<AggregatedStats> history;

    const char* select_sql =
        "WITH recent AS ("
        "SELECT DISTINCT window_start "
        "FROM agg_stats "
        " ORDER BY window_start DESC "
        "LIMIT ?"
        ") "
        "SELECT a.window_start, a.iface, a.protocol, a.src_ip, a.src_port, a.dst_ip, a.dst_port, "
        "       a.pkts_c2s, a.pkts_s2c, a.bytes_c2s, a.bytes_s2c "
        "FROM agg_stats a "
        "JOIN recent r ON a.window_start = r.window_start "
        "ORDER BY a.window_start DESC;";

    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare select statement: " << sqlite3_errmsg(db_) << std::endl;
        return history;
    }
    sqlite3_bind_int(stmt, 1, static_cast<int>(max_windows));

    std::map<int64_t, AggregatedStats, std::greater<int64_t>> windows;
    
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t window_start = sqlite3_column_int64(stmt, 0);
        std::string iface = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int protocol = sqlite3_column_int(stmt, 2);
        std::string src_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        int src_port = sqlite3_column_int(stmt, 4);
        std::string dst_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        int dst_port = sqlite3_column_int(stmt, 6);
        int pkts_c2s = sqlite3_column_int(stmt, 7);
        int pkts_s2c = sqlite3_column_int(stmt, 8);
        int bytes_c2s = sqlite3_column_int(stmt, 9);
        int bytes_s2c = sqlite3_column_int(stmt, 10);

        FlowKey key{
            iface,
            static_cast<uint8_t>(protocol),
            src_ip,
            static_cast<uint16_t>(src_port),
            dst_ip,
            static_cast<uint16_t>(dst_port)
        };
        FlowStats fs;
        fs.pkts_c2s = pkts_c2s;
        fs.pkts_s2c = pkts_s2c;
        fs.bytes_c2s = bytes_c2s;
        fs.bytes_s2c = bytes_s2c;

        auto& agg = windows[window_start];
        agg.window_start = std::chrono::system_clock::time_point(std::chrono::seconds(window_start));
        agg.flows[key] = fs;
    }
    if (rc != SQLITE_DONE) {
        std::cerr << "Error while reading rows: " << sqlite3_errmsg(db_) << std::endl;
    }
    sqlite3_finalize(stmt);

    for (auto& kv : windows) {
        history.push_back(std::move(kv.second));
    }
    return history;
}

std::vector<AggregatedStats> StatsPersistence::loadHistoryRange(
    int64_t start_timestamp,
    int64_t end_timestamp,
    size_t limit
) {
    std::vector<AggregatedStats> result;

    std::string sql = R"(
        WITH selected AS (
            SELECT DISTINCT window_start
            FROM agg_stats
            WHERE window_start BETWEEN ? AND ?
            ORDER BY window_start DESC
            LIMIT ?
        )
        SELECT a.window_start, a.iface, a.protocol, a.src_ip, a.src_port, a.dst_ip, a.dst_port,
               a.pkts_c2s, a.pkts_s2c, a.bytes_c2s, a.bytes_s2c
        FROM agg_stats a
        JOIN selected s ON a.window_start = s.window_start
        ORDER BY a.window_start DESC
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

    if (rc != SQLITE_OK) {
        std::cerr << "[StatsPersistence] Failed to prepare range query: "
                  << sqlite3_errmsg(db_) << std::endl;
        return result;
    }

    sqlite3_bind_int64(stmt, 1, start_timestamp);
    sqlite3_bind_int64(stmt, 2, end_timestamp);
    sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(limit));

    std::map<int64_t, AggregatedStats, std::greater<int64_t>> windows;

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t window_start = sqlite3_column_int64(stmt, 0);
        std::string iface = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int protocol = sqlite3_column_int(stmt, 2);
        std::string src_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        int src_port = sqlite3_column_int(stmt, 4);
        std::string dst_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        int dst_port = sqlite3_column_int(stmt, 6);
        int pkts_c2s = sqlite3_column_int(stmt, 7);
        int pkts_s2c = sqlite3_column_int(stmt, 8);
        int bytes_c2s = sqlite3_column_int(stmt, 9);
        int bytes_s2c = sqlite3_column_int(stmt, 10);

        FlowKey key{
            iface,
            static_cast<uint8_t>(protocol),
            src_ip,
            static_cast<uint16_t>(src_port),
            dst_ip,
            static_cast<uint16_t>(dst_port)
        };
        FlowStats fs;
        fs.pkts_c2s = pkts_c2s;
        fs.pkts_s2c = pkts_s2c;
        fs.bytes_c2s = bytes_c2s;
        fs.bytes_s2c = bytes_s2c;

        auto& agg = windows[window_start];
        agg.window_start = std::chrono::system_clock::time_point(std::chrono::seconds(window_start));
        agg.flows[key] = fs;
    }
    sqlite3_finalize(stmt);

    // Aggregate totals for each window
    for (auto& [window_start, agg] : windows) {
        uint64_t total_bytes = 0, total_packets = 0;
        std::unordered_map<uint8_t, uint64_t> proto_bytes;
        std::unordered_map<uint8_t, uint64_t> proto_packets;

        for (const auto& [key, fs] : agg.flows) {
            uint64_t bytes = fs.bytes_c2s + fs.bytes_s2c;
            uint64_t packets = fs.pkts_c2s + fs.pkts_s2c;
            total_bytes += bytes;
            total_packets += packets;
            proto_bytes[key.protocol] += bytes;
            proto_packets[key.protocol] += packets;
        }
        agg.total_bytes = total_bytes;
        agg.total_packets = total_packets;
        agg.protocol_bytes = proto_bytes;
        agg.protocol_packets = proto_packets;

        result.push_back(std::move(agg));
    }
    return result;
}

void StatsPersistence::cleanupOldRecords(int retention_days) {
    int64_t cutoff_timestamp = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now() - std::chrono::hours(24 * retention_days)
    );
    
    std::string sql = "DELETE FROM agg_stats WHERE window_start < ?";
    
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "[StatsPersistence] Failed to prepare cleanup: " 
                  << sqlite3_errmsg(db_) << std::endl;
        return;
    }
    
    sqlite3_bind_int64(stmt, 1, cutoff_timestamp);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "[StatsPersistence] Cleanup failed: " 
                  << sqlite3_errmsg(db_) << std::endl;
    } else {
        int deleted = sqlite3_changes(db_);
        std::cout << "[StatsPersistence] Cleanup removed " << deleted 
                  << " old records (retention: " << retention_days << " days)" << std::endl;
    }

    sqlite3_finalize(stmt);
}