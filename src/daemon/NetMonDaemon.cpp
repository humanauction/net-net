#include "NetMonDaemon.h"
#include <iostream>
#include <yaml-cpp/yaml.h>
#include <thread>
#include <chrono>
#include "httplib.h" // For HTTP server (if needed)


NetMonDaemon::NetMonDaemon(const std::string& config_path)
    : config_path_(config_path)
{
    // TODO: Load config, initialize PcapAdapter, StatsAggregator, StatsPersistence
    YAML::Node config = YAML::LoadFile(config_path_);
    if (!config["interface"] || !config["interface"]["name"]) {
        throw std::runtime_error("Missing required 'interface.name' in config");
    }
    std::string iface_or_file = config["interface"]["name"].as<std::string>();
    std::string bpf_filter = config["interface"] && config["interface"]["bpf_filter"] ? config["interface"]["bpf_filter"].as<std::string>() : "";
    bool promiscuous = config["interface"] && config["interface"]["promiscuous"] ? config["interface"]["promiscuous"].as<bool>() : true;
    int snaplen = config["interface"]["snaplen"].as<int>();
    int timeout = config["interface"]["timeout_ms"].as<int>();
    bool read_offline = config["offline"] && config["offline"]["file"];
    std::string offline_file = read_offline ? config["offline"]["file"].as<std::string>() : "";
    
    // Initialize PcapAdapter
    pcap_ = std::make_unique<PcapAdapter>(iface_or_file, bpf_filter, promiscuous, snaplen, timeout, read_offline);
    
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
    // TODO: Main loop, capture packets, aggregate stats, persist windows
    running_ = true;
    std::cout << "NetMonDaemon is running..." << std::endl;

    // Start REST API server
    api_thread_ = std::thread([this]() {
        svr_.Get("/metrics", [this](const httplib::Request&, httplib::Response& res) {
            // TODO: Serialize stats to JSON and set res.body
            res.set_content("{}", "application/json");
        });
        svr_.listen("0.0.0.0", 8080); // Listen on port 8080
        // TODO: Add endpoints here 
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