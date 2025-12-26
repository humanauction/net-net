#pragma once
#include <string>
#include <vector>
#include "core/StatsAggregator.h"


struct sqlite3; // Forward declaration
class StatsPersistence {
public:
    explicit StatsPersistence(const std::string& db_path);
    ~StatsPersistence();

    void saveWindow(const AggregatedStats& stats);
    std::vector<AggregatedStats> loadHistory(size_t max_windows = 100);

// Time-range query for historical API
    std::vector<AggregatedStats> loadHistoryRange(
        int64_t start_timestamp,
        int64_t end_timestamp,
        size_t limit = 1440
);

    void cleanupOldRecords(int retention_days = 7);

private:
    std::string db_path_;
    sqlite3* db_;
    void createSchema();
};