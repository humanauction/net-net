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
#include <fstream>
#include <cstdint>
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
    void log(const std::string& level, const std::string& msg);
    bool shouldLog(const std::string& level);
    mutable std::shared_mutex reload_mutex;
    std::atomic<bool> running_{false};
    static std::atomic<bool> running_signal_;
    std::string config_path_;
    std::thread api_thread_;
    std::string api_token_;
    std::string api_host_;
    std::uint16_t api_port_;
    std::unique_ptr<PcapAdapter> pcap_;
    std::unique_ptr<StatsAggregator> aggregator_;
    std::unique_ptr<StatsPersistence> persistence_;
    httplib::Server svr_;
    std::string log_file_;   
    std::string log_level_;
    bool log_timestamps_ = true;
    std::ofstream log_stream_;
};

 