#pragma once
#include <string>
#include <vector>
#include "StatsAggregator.h"

class StatsPersistence {
public:
    StatsPersistence(const std::string& db_path);
    void saveWindow(const AggregatedStats& stats);
    std::vector<AggregatedStats> loadHistory(size_t max_window);
private:
    std::string db_path_;
    // TODO Database connection goes here
};