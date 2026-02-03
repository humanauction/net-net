#pragma once
#include <string>
#include <memory>
#include <atomic>
#include <yaml-cpp/yaml.h>
#include <shared_mutex>
#include <chrono>
#include <unordered_map>
#include <fstream>
#include <cstdint>
#include <map>
#include <thread>
#include "../core/SessionManager.h"
#include "../core/StatsAggregator.h"
#include "../core/StatsPersistence.h"
#include "../net/PcapAdapter.h"
#include "httplib.h"

// add more here as/when we need/make it (e.g. config, threading, API, etc...)

class NetMonDaemon {
public:
    NetMonDaemon(const std::string& config_path);
    NetMonDaemon(const YAML::Node& config, const std::string& config_name = "in-memory-config");

    ~NetMonDaemon();

    void run();
    void stop();
    void setRunning(bool value) { running_ = value; }
    bool isRunning() const { return running_.load(); }
    static void signalHandler(int signum);
private:
    void initializeFromConfig(const YAML::Node& config);
    void log(const std::string& level, const std::string& msg) const;
    void setupApiRoutes();
    void startServer();
    void stopServer();
    bool isAuthorized(const httplib::Request& req);
    void logAuthFailure(const httplib::Request& req) const;
    bool shouldLog(const std::string& level) const;
    bool checkRateLimit(const httplib::Request& req, httplib::Response& res, const std::string& endpoint);
    bool validateSession(const httplib::Request& req, httplib::Response& res) const;
    static std::string getServiceName(uint16_t port);
    
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_control_request_;
    const std::chrono::seconds control_rate_limit_{2};
    mutable std::shared_mutex reload_mutex;
    mutable std::ofstream log_stream_;
    std::atomic<bool> running_{false};
    static std::atomic<bool> running_signal_;
    std::string config_path_;
    std::string config_name_;
    std::thread api_thread_;
    std::string api_token_;
    std::string api_host_;
    std::uint16_t api_port_;
    std::map<std::string, std::string> user_credentials_;
    std::unique_ptr<PcapAdapter> pcap_;
    PcapAdapter::Options opts_;
    std::unique_ptr<StatsAggregator> aggregator_;
    std::unique_ptr<StatsPersistence> persistence_;
    httplib::Server svr_;
    std::string log_file_;
    std::string log_level_;
    bool log_timestamps_ = true;
    std::unique_ptr<SessionManager> session_manager_;
    int session_expiry_ = 3600;
    std::chrono::steady_clock::time_point start_time_;
};