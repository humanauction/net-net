#pragma once
#include <string>
#include <vector>
#include "core/StatsAggregator.h"

class StatsPersistence {
public:
    explicit StatsPersistence(const std::string& db_path);
    ~StatsPersistence();

    void saveWindow(const AggregatedStats& stats);
    std::vector<AggregatedStats> loadHistory(size_t max_window);

private:
    std::string db_path_;
    sqlite3* db_;
    void createSchema();
    // TODO Database connection goes here
};