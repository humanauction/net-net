#pragma once
#include <string>
#include <memory>
// #include <mutex>
#include "core/StatsAggregator.h"
#include "core/StatsPersistence.h"
#include "net/PcapAdapter.h"
#include "httplib.h"
#include <shared_mutex>
#include <chrono>
#include <unordered_map>
// add more here as/when we need/make it (e.g. config, threading, API, etc...)

class NetMonDaemon {
public:
    NetMonDaemon(const std::string& config_path);
    void run();
    void stop();
    void setRunning(bool value) { running_ = value; }
    bool isRunning() const { return running_.load(); }
    static void signalHandler(int signum);
private:
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_control_request_;
    const std::chrono::seconds control_rate_limit_{2};
    bool isAuthorized(const httplib::Request& req) const;
    void logAuthFailure(const httplib::Request& req) const;
    mutable std::shared_mutex reload_mutex;
    std::atomic<bool> running_{false};
    static std::atomic<bool> running_signal_;
    std::string config_path_;
    std::thread api_thread_;
    std::string api_token_;
    std::unique_ptr<PcapAdapter> pcap_;
    std::unique_ptr<StatsAggregator> aggregator_;
    std::unique_ptr<StatsPersistence> persistence_;
    httplib::Server svr_;
};