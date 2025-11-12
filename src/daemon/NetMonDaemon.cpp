#include "NetMonDaemon.h"
#include <iostream>
#include <yaml-cpp/yaml.h>
#include <thread>
#include <chrono>
#include "httplib.h" // For HTTP server (if needed)
#include <sstream>


NetMonDaemon::NetMonDaemon(const std::string& config_path)
    : config_path_(config_path)
{
    // TODO: Load config, initialize PcapAdapter, StatsAggregator, StatsPersistence
    YAML::Node config = YAML::LoadFile(config_path_);
    if (!config["interface"] || !config["interface"]["name"]) {
        throw std::runtime_error("Missing required 'interface.name' in config");
    }
    if (!config["api"] || !config["api"]["token"]) {
        throw std::runtime_error("Config missing 'api.token' required");
    }
    api_token_ = config["api"]["token"].as<std::string>();
    
    std::string iface_or_file = config["interface"]["name"].as<std::string>();
    std::string bpf_filter = config["interface"] && config["interface"]["bpf_filter"] ? config["interface"]["bpf_filter"].as<std::string>() : "";
    bool promiscuous = config["interface"] && config["interface"]["promiscuous"] ? config["interface"]["promiscuous"].as<bool>() : true;
    int snaplen = config["interface"]["snaplen"].as<int>();
    int timeout = config["interface"]["timeout_ms"].as<int>();
    bool read_offline = config["offline"] && config["offline"]["file"];
    std::string offline_file = read_offline ? config["offline"]["file"].as<std::string>() : "";
    
    // Initialize PcapAdapter
    PcapAdapter::Options opts;
    opts.iface_or_file = iface_or_file;      // string: interface or file path
    opts.bpf_filter    = bpf_filter;         // string: BPF filter expression
    opts.promiscuous   = promiscuous;        // bool: promiscuous mode
    opts.snaplen       = snaplen;            // int: snapshot length
    opts.timeout_ms    = timeout;            // int: timeout in ms
    opts.read_offline  = read_offline;       // bool: offline mode

    pcap_ = std::make_unique<PcapAdapter>(opts);
    
    // Initialize StatsAggregator
    if (!config["stats"] || !config["stats"]["window_size"] || !config["stats"]["history_depth"]) {
        throw std::runtime_error("Missing required 'stats.window_size' or 'stats.history_depth' in config");
    }
    int window_size = config["stats"] && config["stats"]["window_size"] ? config["stats"]["window_size"].as<int>() : 1;
    int history_depth = config["stats"] && config["stats"]["history_depth"] ? config["stats"]["history_depth"].as<int>() : 1;
    aggregator_ = std::make_unique<StatsAggregator>(std::chrono::seconds(window_size), history_depth);
    
    // Initialize StatsPersistence
    if (!config["database"] || !config["database"]["path"]) {
        throw std::runtime_error("Missing required 'database.path' in config");
    }
    std::string db_path = config["database"]["path"].as<std::string>();
    persistence_ = std::make_unique<StatsPersistence>(db_path);

    std::cout << "NetMonDaemon initialized with config: " << config_path_ << std::endl;
}

void NetMonDaemon::run()
{
    running_ = true;
    std::cout << "NetMonDaemon is running..." << std::endl;

    // Start REST API server
    api_thread_ = std::thread([this]() {
        svr_.Get("/metrics", [this](const httplib::Request& req, httplib::Response& res) {
            // TODO: Serialize stats to JSON and set res.body
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            auto stats = aggregator_->currentStats();
            std::ostringstream oss;
            oss << "{";
            oss << "\"window_start\":" <<std::chrono::duration_cast<std::chrono::seconds>(stats.window_start.time_since_epoch()).count() << ",";
            oss << "\"flows\":[";
            bool first = true;
            for (const auto& kv : stats.flows) {
                if (!first) oss << ",";
                first = false;
                const auto& key = kv.first;
                const auto& val = kv.second;
                oss << "{";
                oss << "\"iface\":\"" << key.iface << "\",";
                oss << "\"protocol\":" << key.protocol << ",";
                oss << "\"src_ip\":\"" << key.src_ip << "\",";
                oss << "\"src_port\":" << key.src_port << ",";
                oss << "\"dst_ip\":\"" << key.dst_ip << "\",";
                oss << "\"dst_port\":" << key.dst_port << ",";
                oss << "\"bytes_c2s\":" << val.bytes_c2s << ",";
                oss << "\"pkts_c2s\":" << val.pkts_c2s << ",";
                oss << "\"bytes_s2c\":" << val.bytes_s2c << ",";
                oss << "\"pkts_s2c\":" << val.pkts_s2c;
                oss << "}";
            }
            oss << "]";
            oss << "}";
            res.set_content(oss.str(), "application/json");
        });

        svr_.Post("/control/start", [this](const httplib::Request& req, httplib::Response& res) {
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            running_ = true;
            res.set_content("{\"status\":\"started\"}", "application/json");
        });

        svr_.Post("/control/stop", [this](const httplib::Request& req, httplib::Response& res) {
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            running_ = false;
            res.set_content("{\"status\":\"stopped\"}", "application/json");
        });

        svr_.Post("/control/reload", [this](const httplib::Request& req, httplib::Response& res) {
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            try {
                std::lock_guard<std::shared_mutex> lock(reload_mutex);
                YAML::Node config = YAML::LoadFile(config_path_);
                // Re-load token
                if (!config["api"] || !config["api"]["token"]) throw std::runtime_error("Missing api.token");
                api_token_ = config["api"]["token"].as<std::string>();

                // Re-init PcapAdapter
                std::string iface_or_file = config["interface"]["name"].as<std::string>();
                std::string bpf_filter = config["interface"]["bpf_filter"] ? config["interface"]["bpf_filter"].as<std::string>() : "";
                bool promiscuous = config["interface"]["promiscuous"] ? config["interface"]["promiscuous"].as<bool>() : true;
                int snaplen = config["interface"]["snaplen"].as<int>();
                int timeout = config["interface"]["timeout_ms"].as<int>();
                bool read_offline = config["offline"] && config["offline"]["file"];
                std::string offline_file = read_offline ? config["offline"]["file"].as<std::string>() : "";
                PcapAdapter::Options opts;
                opts.iface_or_file = iface_or_file;      // string: interface or file path
                opts.bpf_filter    = bpf_filter;         // string: BPF filter expression
                opts.promiscuous   = promiscuous;        // bool: promiscuous mode
                opts.snaplen       = snaplen;            // int: snapshot length
                opts.timeout_ms    = timeout;            // int: timeout in ms
                opts.read_offline  = read_offline;       // bool: offline mode

                pcap_ = std::make_unique<PcapAdapter>(opts);

                // Re-init StatsAggregator
                int window_size = config["stats"]["window_size"].as<int>();
                int history_depth = config["stats"]["history_depth"].as<int>();
                aggregator_ = std::make_unique<StatsAggregator>(std::chrono::seconds(window_size), history_depth);

                // Re-init StatsPersistence
                std::string db_path = config["database"]["path"].as<std::string>();
                persistence_ = std::make_unique<StatsPersistence>(db_path);

                std::cout << "[INFO] Config reloaded successfully at " 
                          << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) 
                          << std::endl;

                res.set_content("{\"status\":\"reloaded\"}", "application/json");
            } catch (const std::exception& ex) {
                std::cerr << "[ERROR] Reload failed: " << ex.what() << std::endl;
                res.status = 500;
                res.set_content(std::string("{\"error\":\"") + ex.what() + "\"}", "application/json");
            }
        });

        svr_.listen("0.0.0.0", 8080);
    });

    // Start packet capture with a callback that feeds packets to StatsAggregator
    pcap_->startCapture([this](const PacketMeta& meta, const uint8_t* data, size_t len) {
        ParsedPacket pkt;
        if (parsePacket(data, len, meta, pkt)) {
            aggregator_->ingest(pkt);
        }
        // TO DO: handle parse errors/logging
    });
    //  Main loop
    while(running_.load()) {
        // Periodically call advanceWindow() and persist stats
        aggregator_->advanceWindow();
        auto stats = aggregator_->currentStats();
        persistence_->saveWindow(stats);
        // Sleep (or break) logic here
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    pcap_->stopCapture();
    std::cout << "✅ Capture complete! API server will remain running for 500 seconds to allow pending requests." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(500));
    
    // During manual testing use:
    std::cout << "Capture complete! Press Ctrl+C to exit." << std::endl;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // When running_ is set to false (e.g., via /control/stop), exit and clean up
    // stop();
}

void NetMonDaemon::stop()
{
    running_ = false;
    std::cout << "NetMonDaemon is stopping..." << std::endl;
    // TODO: shutdown logic here
    // Stop API server and join thread
    // (cpp-httplib stops when svr.stop() is called)
    svr_.stop();
    if (api_thread_.joinable()) api_thread_.join();
}

bool NetMonDaemon::isAuthorized(const httplib::Request& req) const {
    auto auth = req.get_header_value("Authorization");
    std::string prefix = "Bearer ";
    if (auth.rfind(prefix, 0) == 0 && auth.substr(prefix.size()) == api_token_) {
        return true;
    }
    if (req.has_param("token") && req.get_param_value("token") == api_token_) {
        return true;
    }
    return false;
}

void NetMonDaemon::logAuthFailure(const httplib::Request& req) const {
    std::cerr << "[AUTH FAIL] " << req.method << " " << req.path;
    auto auth = req.get_header_value("Authorization");
    if (!auth.empty()) std::cerr << " (Authorization header present)";
    if (req.has_param("token")) std::cerr << " (token param present)";
    std::cerr << std::endl;
}

int main(int argc, char* argv[]) {
    // Check for config path argument
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config_path.yaml>" << std::endl;
        return 1;
    }
    std::string config_path = argv[1];
    NetMonDaemon daemon(config_path);
    daemon.run();
    return 0;
}