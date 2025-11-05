#include "NetMonDaemon.h"
#include <iostream>
#include <yaml-cpp/yaml.h>
#include "PcapAdapter.h"


NetMonDaemon::NetMonDaemon(const std::string& config_path)
    : config_path_(config_path)
{
    // TODO: Load config, initialize PcapAdapter, StatsAggregator, StatsPersistence
    YAML::Node config = YAML::LoadFile(config_path_);
    std::string iface = config["interface"]["name"].as<std::string>();
    int snaplen = config["interface"]["snaplen"].as<int>();
    int timeout = config["interface"]["timeout_ms"].as<int>();
    std::string offline_file = config["offline"] ? config["offline"]["file"].as<std::string>() : "";
    // Initialize PcapAdapter
    pcap_ = std::make_unique<PcapAdapter>(iface, snaplen, timeout, offline_file);
    // Initialize StatsAggregator
    int window_size = config["stats"]["window_size"].as<int>();
    int history_depth = config["stats"]["history_depth"].as<int>();
    aggregator_ = std::make_unique<StatsAggregator>(std::chrono::seconds(window_size), history_depth);
    // TODO: Initialize StatsPersistence
    if (config["database"]) {

    }

    std::cout << "NetMonDaemon initialized with config: " << config_path_ << std::endl;
}

void NetMonDaemon::run()
{
    std::cout << "NetMonDaemon is running..." << std::endl;
    // TODO: Main loop, capture packets, aggregate stats, persist windows
}

void NetMonDaemon::stop()
{
    std::cout << "NetMonDaemon is stopping..." << std::endl;
    // TODO: shutdown logic here
}