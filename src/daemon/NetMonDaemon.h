#pragma once
#include <string>
#include <memory>
#include "core/StatsAggregator.h"
#include "core/StatsPersistence.h"
#include "net/PcapAdapter.h"
// add more here as/when we need/make it (e.g. config, threading, API, etc...)

class NetMonDaemon {
public:
    NetMonDaemon(const std::string& config_path);
    void run();
    void stop();
private:
    std::string config_path_;
    std::unique_ptr<PcapAdapter> pcap_;
    std::unique_ptr<StatsAggregator> aggregator_;
    std::unique_ptr<StatsPersistence> persistence_;
    // add more here as/when we make/need it
};