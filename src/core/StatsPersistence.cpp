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
    // TODO: Serialize stats and insert into SQLite
}

std::vector<AggregatedStats> StatsPersistence::loadHistory(size_t max_windows) {
    // TODO: Query and deserialize stats from SQLite
    return {};
}