#include "StatsPersistence.h"
#include <sqlite3.h>
#include <iostream>

StatsPersistence::StatsPersistence(const std::string& db_path)
    : db_path_(db_path) {
    // TODO: Open DB, create table if not exists
    sqlite3* db;
    if (sqlite3_open(db_path_.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }
    const char* create_table_sql =
        "CREATE TABLE IF NOT EXISTS agg_stats ("
        "window_start INTEGER,"
        "iface TEXT,"
        "protocol INTEGER,"
        "src_ip TEXT,"
        "src_port INTEGER,"
        "dst_ip TEXT,"
        "dst_port INTEGER,"
        "pkts_c2s INTEGER,"
        "pkts_s2c INTEGER,"
        "bytes_c2s INTEGER,"
        "bytes_s2c INTEGER"
        ");";
        sqlite3_exec(db, create_table_sql, nullptr, nullptr, nullptr);
        sqlite3_close(db);
}

void StatsPersistence::saveWindow(const AggregatedStats& stats) {
    sqlite3* db;
    if (sqlite3_open(db_path_.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    const char* insert_sql =
        "INSERT INTO agg_stats(window_start, iface, protocol, src_ip, src_port, dst_ip, dst_port, pkts_c2s, pkts_s2c, bytes_c2s, bytes_s2c) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
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
            std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
        }
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_exec(db, "END TRANSACTION;", nullptr, nullptr, nullptr);
    sqlite3_close(db);
}

std::vector<AggregatedStats> StatsPersistence::loadHistory(size_t max_windows) {
    std::vector<AggregatedStats> history;
    sqlite3* db;
    if (sqlite3_open(db_path_.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return history;
    }
    const char* select_sql =
        "SELECT window_start, iface, protocol, src_ip, src_port, dst_ip, dst_port, pkts_c2s, pkts_s2c, bytes_c2s, bytes_s2c "
        "FROM agg_stats ORDER BY window_start DESC LIMIT ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare select statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return history;
    }
    sqlite3_bind_int(stmt, 1, static_cast<int>(max_windows));

    std::unordered_map<int64_t, AggregatedStats> windows;
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
        std::cerr << "Error while reading rows: " << sqlite3_errmsg(db) << std::endl;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    for (auto& kv : windows) {
        history.push_back(std::move(kv.second));
    }
    return history;
}