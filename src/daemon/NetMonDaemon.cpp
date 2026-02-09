#include "NetMonDaemon.h"
#include <iostream>
#include <iomanip>
#include <yaml-cpp/yaml.h>
#include <thread>
#include <string>
#include <chrono>
#include "httplib.h"
#include <sstream>
#include <csignal>
#include "net/PcapAdapter.h"
#include "core/Parser.h"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <nlohmann/json.hpp>
#include "core/SessionManager.h"
#include "../../include/net-net/vendor/bcrypt.h"
#include "core/StatsAggregator.h"
#include "core/StatsPersistence.h"



// ===================================================================
// CONSTRUCTORS
// ===================================================================

// In-memory constructor (testing use)
NetMonDaemon::NetMonDaemon(const YAML::Node& config, const std::string& config_name)
    : config_path_(""), config_name_(config_name), running_(false)  // INITIALIZE config_name_
{
    log("info", "Loading configuration from memory: " + config_name);
    initializeFromConfig(config);
}

// File-based constructor (production use)
NetMonDaemon::NetMonDaemon(const std::string& config_path)
    : config_path_(config_path), config_name_(""), running_(false)  // INITIALIZE config_name_ (empty for file-based)
{
    log("info", "Loading configuration from: " + config_path);
    
    YAML::Node config;
    try {
        config = YAML::LoadFile(config_path_);
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("Failed to load config file: " + std::string(e.what()));
    }
    
    initializeFromConfig(config);
}

// ===================================================================
// COMMON INITIALIZATION (used by both constructors)
// ===================================================================

void NetMonDaemon::initializeFromConfig(const YAML::Node& config) {
    /*
     * Initialization Order (CRITICAL - do not reorder):
     * 1. Initialize logging
     * 2. Validate API token
     * 3. Initialize PcapAdapter (offline or live)
     * 4. Initialize StatsAggregator
     * 5. Initialize StatsPersistence (database)
     * 6. Load and hash user credentials
     * 7. Initialize SessionManager
     */

    // 1. Logging Level and File Configuration
    if (config["logging"]) {
        log_level_ = config["logging"]["level"] ? config["logging"]["level"].as<std::string>() : "info";
        log_file_ = config["logging"]["file"] ? config["logging"]["file"].as<std::string>() : "";
        log_timestamps_ = config["logging"]["timestamps"] ? config["logging"]["timestamps"].as<bool>() : true;
        if (!log_file_.empty()) {
            log_stream_.open(log_file_, std::ios::app);
            if (!log_stream_) {
                throw std::runtime_error("Could not open log file: " + log_file_);
            }
        }
    }

    // 2. API token check (required)
    if (!config["api"] || !config["api"]["token"]) {
        throw std::runtime_error("Config missing 'api.token' required");
    }
    api_token_ = config["api"]["token"].as<std::string>();
    api_host_ = config["api"]["host"] ? config["api"]["host"].as<std::string>() : "localhost";
    api_port_ = config["api"]["port"] ? config["api"]["port"].as<uint16_t>() : 8082;

    // 3. PcapAdapter - Prioritize offline mode
    bool read_offline = config["offline"] && config["offline"]["file"];
    std::string iface_or_file;
    bool promiscuous = true;
    int snaplen = 65535;
    int timeout = 1000;
    std::string bpf_filter;

    if (read_offline) {
        iface_or_file = config["offline"]["file"].as<std::string>();
        log("info", "Running in offline mode with file: " + iface_or_file);
    } else if (config["interface"] && config["interface"]["name"]) {
        iface_or_file = config["interface"]["name"].as<std::string>();
        bpf_filter = config["interface"]["bpf_filter"] ? config["interface"]["bpf_filter"].as<std::string>() : "";
        promiscuous = config["interface"]["promiscuous"] ? config["interface"]["promiscuous"].as<bool>() : true;
        snaplen = config["interface"]["snaplen"] ? config["interface"]["snaplen"].as<int>() : 65535;
        timeout = config["interface"]["timeout_ms"] ? config["interface"]["timeout_ms"].as<int>() : 1000;
        log("info", "Running in live mode on interface: " + iface_or_file);
        
        // BPF filter validation
        if (!bpf_filter.empty() && !PcapAdapter::isValidBpfFilter(bpf_filter)) {
            throw std::runtime_error("Invalid BPF filter: contains forbidden characters or is too long");
        }
    } else {
        throw std::runtime_error("Missing required 'offline.file' or 'interface.name' in config");
    }

    // Initialize PcapAdapter
    PcapAdapter::Options opts;
    opts.iface_or_file = iface_or_file;
    opts.bpf_filter    = bpf_filter;
    opts.promiscuous   = promiscuous;
    opts.snaplen       = snaplen;
    opts.timeout_ms    = timeout;
    opts.read_offline  = read_offline;

    opts_ = opts;
    
    pcap_ = std::make_unique<PcapAdapter>(opts);

    // 4. StatsAggregator
    if (!config["stats"] || !config["stats"]["window_size"] || !config["stats"]["history_depth"]) {
        throw std::runtime_error("Missing required 'stats.window_size' or 'stats.history_depth' in config");
    }
    int window_size = config["stats"]["window_size"].as<int>();
    int history_depth = config["stats"]["history_depth"].as<int>();
    aggregator_ = std::make_unique<StatsAggregator>(std::chrono::seconds(window_size), history_depth);

    // 5. StatsPersistence (database)
    if (!config["database"] || !config["database"]["path"]) {
        throw std::runtime_error("Missing required 'database.path' in config");
    }
    std::string db_path = config["database"]["path"].as<std::string>();
    persistence_ = std::make_unique<StatsPersistence>(db_path);

    // 6. Load user credentials and hash passwords
    if (config["users"]) {
        for (const auto& user : config["users"]) {
            std::string username = user["username"].as<std::string>();
            std::string password = user["password"].as<std::string>();

            // Check if password is already in PBKDF2/bcrypt format (contains '$')
            if (password.find('$') != std::string::npos) {
                // Already hashed - store as-is
                user_credentials_[username] = password;
            } else {
                // Plaintext password - hash it (development/testing only)
                log("warn", "Plaintext password detected for: " + username + " - hashing now");
                user_credentials_[username] = bcrypt::hash(password);
            }

            log("info", "Loaded user: " + username);
        }   
    } else {
        log("warn", "Authentication disabled - no users defined in config");
    }

    // 7. Initialize session manager
    std::string session_db_path = db_path + ".sessions";
    
    if (config["api"]["session_expiry"]) {
        session_expiry_ = config["api"]["session_expiry"].as<int>();
    }
    session_manager_ = std::make_unique<SessionManager>(session_db_path, session_expiry_);

    log("info", "Session manager initialized (expiry: " + std::to_string(session_expiry_) + "s)");
    log("info", "NetMonDaemon initialized successfully");
}

// ===================================================================
// DESTRUCTOR
// ===================================================================

NetMonDaemon::~NetMonDaemon() {
    stop();
}

// ===================================================================
// RUN METHOD
// ===================================================================

void NetMonDaemon::run() {
    running_.store(true);
    start_time_ = std::chrono::steady_clock::now();
    log("info", "NetMonDaemon is running...");
    
    std::thread capture_thread([this]() {
        try {
            pcap_->startCapture([this](const PacketMeta& meta, const uint8_t* data, size_t len) {
                ParsedPacket pkt;
                if (parsePacket(data, len, meta, pkt)) {
                    std::cerr << "[DEBUG] Parsed packet: " << pkt.network.src_ip << " -> " << pkt.network.dst_ip << std::endl;
                    aggregator_->ingest(pkt);
                    std::cerr << "[DEBUG] Ingested packet at " << pkt.meta.timestamp.time_since_epoch().count() << std::endl;
                }
            });
        } catch (const std::exception& ex) {
            log("error", "Capture failed: " + std::string(ex.what()));
        }
    });

    std::thread cleanup_thread([this]() {
        while (running_.load() && running_signal_.load()) {
            // calc: time until next midnight UTC
            auto now = std::chrono::system_clock::now();
            auto now_t = std::chrono::system_clock::to_time_t(now);
            std::tm* now_tm = std::gmtime(&now_t);

            // next midnight UDC
            std::tm next_midnight = *now_tm;
            next_midnight.tm_hour = 0;
            next_midnight.tm_min = 0;
            next_midnight.tm_sec = 0;
            next_midnight.tm_mday += 1;

            auto next_midnight_tp = std::chrono::system_clock::from_time_t(std::mktime(&next_midnight));
            auto sleep_duration = next_midnight_tp - now;
            
            // sleep until midnight, check every 60 seconds if daemon stops
            auto sleep_minutes = std::chrono::duration_cast<std::chrono::minutes>(sleep_duration).count();
            for (int i = 0; i < sleep_minutes && running_.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::minutes(1));
            }
            if (!running_.load()) break;

            // cleanup
            log("info", "Running daily database cleanup (7-day retention)...");
            persistence_->cleanupOldRecords(7);
        }
    });

    startServer();

    log("info", "API server ready...");
    if (capture_thread.joinable()) capture_thread.join();

    if (opts_.read_offline) {
        aggregator_->advanceWindow();
        persistence_->saveWindow(aggregator_->history().back());
        log("info", "Offline mode: forced stats window persisted after capture.");
    }

    // API running until told to stop
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    log("info", "Daemon shutting down...");
    if (cleanup_thread.joinable()) cleanup_thread.join();
    stopServer();
}

// ===================================================================
// SETUP API ROUTES
// ===================================================================

void NetMonDaemon::setupApiRoutes() {
    auto add_cors = [](httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, X-Session-Token, Authorization");
    };

    // Handle preflight for all routes
    svr_.Options(R"(.*)", [add_cors](const httplib::Request& /*req*/, httplib::Response& res) {
        add_cors(res);
        res.status = 204;
    });

    svr_.Get("/metrics", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);
        if (!isAuthorized(req)) {
            logAuthFailure(req);
            res.status = 401;
            res.set_content("{\"error\":\"unauthorized\"}", "application/json");
            return;
        }

        auto stats = aggregator_->currentStats();

        // Calculate totals
        uint64_t total_bytes = 0;
        uint64_t total_packets = 0;
        std::map<std::string, uint64_t> protocol_bytes;

        for (const auto& kv : stats.flows) {
            const auto& val = kv.second;
            uint64_t flow_bytes = val.bytes_c2s + val.bytes_s2c;
            uint64_t flow_packets = val.pkts_c2s + val.pkts_s2c;

            total_bytes += flow_bytes;            
            total_packets += flow_packets;
            
            // Protocol breakdown
            std::string proto = (kv.first.protocol == 6 ? "TCP" :
                                kv.first.protocol == 17 ? "UDP" : "OTHER");
            protocol_bytes[proto] += flow_bytes;
        }

        std::ostringstream oss;
        oss << "{";
        oss << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() << ",";
        oss << "\"window_start\":" << std::chrono::duration_cast<std::chrono::seconds>(
            stats.window_start.time_since_epoch()).count() << ",";
        oss << "\"total_bytes\":" << total_bytes << ",";
        oss << "\"total_packets\":" << total_packets << ",";
        oss << "\"bytes_per_second\":" << (total_bytes / std::max(1, 
            static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now() - stats.window_start).count()))) << ",";
        
        // Protocol breakdown
        oss << "\"protocol_breakdown\":{";
        bool first_proto = true;
        for (const auto& proto : protocol_bytes) {
            if (!first_proto) oss << ",";
            first_proto = false;
            oss << "\"" << proto.first << "\":" << proto.second;
        }
        oss << "},";

        oss << "\"active_flows\":[";
        bool first = true;
        for (const auto& kv : stats.flows) {
            if (!first) oss << ",";
            first = false;
            const auto& key = kv.first;
            const auto& val = kv.second;
            oss << "{";
            oss << "\"iface\":\"" << key.iface << "\",";
            oss << "\"src_ip\":\"" << key.src_ip << "\",";
            oss << "\"src_port\":" << key.src_port << ",";
            oss << "\"dst_ip\":\"" << key.dst_ip << "\",";
            oss << "\"dst_port\":" << key.dst_port << ",";
            oss << "\"protocol\":\"" << (key.protocol == 6 ? "TCP" : key.protocol == 17 ? "UDP" : "OTHER") << "\",";
            oss << "\"bytes\":" << (val.bytes_c2s + val.bytes_s2c) << ",";
            oss << "\"packets\":" << (val.pkts_c2s + val.pkts_s2c) << ",";
            oss << "\"state\":\"active\"";
            oss << "}";
        }
        oss << "]";
        oss << "}";

        res.set_content(oss.str(), "application/json");
    });

    svr_.Post("/login", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);
        try {
            auto j = nlohmann::json::parse(req.body);
            std::string username = j.value("username", "");
            std::string password = j.value("password", "");
            if (username.empty() || password.empty()) {
                log("warn", "Login attempt with missing credentials");
                res.status = 400;
                res.set_content("{\"error\":\"missing username or password\"}", "application/json");
                return;
            }
            auto it = user_credentials_.find(username);
            if (it == user_credentials_.end()) {
                log("warn", "User does not exist: " + username);
                res.status = 401;
                res.set_content("{\"error\":\"invalid credentials\"}", "application/json");
                return;
            }
            if (!bcrypt::verify(password, it->second)) {
                log("warn", "Login attempt failed for: " + username);
                res.status = 401;
                res.set_content("{\"error\":\"invalid credentials\"}", "application/json");
                return;
            }
            std::string client_ip = req.remote_addr;
            std::string token = session_manager_->createSession(username, client_ip);
            log("info", "User logged in: " + username + " from " + client_ip);
            nlohmann::json resp = {
                {"token", token},
                {"username", username},
                {"expires_in", session_expiry_}
            };
            res.set_content(resp.dump(), "application/json");
        } catch (const nlohmann::json::parse_error&) {
            log("warn", "Malformed JSON in login request");
            res.status = 400;
            res.set_content("{\"error\":\"malformed JSON\"}", "application/json");
            return;
        } catch (const std::exception& ex) {
            log("error", "Login request processing failed: " + std::string(ex.what()));
            res.status = 500;
            res.set_content("{\"error\":\"internal server error\"}", "application/json");
        }
    });

    svr_.Post("/logout", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);
        auto session_token = req.get_header_value("X-Session-Token");
        
        if (session_token.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"no session token provided\"}", "application/json");
            return;
        }

        SessionData session_data;
        if (session_manager_->validateSession(session_token, session_data)) {
            session_manager_->deleteSession(session_token);
            log("info", "User logged out: " + session_data.username);
            res.set_content("{\"status\":\"logged out\"}", "application/json");
        } else {
            res.status = 401;
            res.set_content("{\"error\":\"invalid session\"}", "application/json");
        }
    });

    svr_.Post("/control/start", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);
        if (!isAuthorized(req)) {
            logAuthFailure(req);
            res.status = 401;
            res.set_content("{\"error\":\"unauthorized\"}", "application/json");
            return;
        }
        auto now = std::chrono::steady_clock::now();
        auto& last = last_control_request_["/control/start"];
        if (now - last < control_rate_limit_) {
            res.status = 429;
            res.set_content("{\"error\":\"rate limit exceeded\"}", "application/json");
            return;
        }
        last = now;
        running_.store(true); // atomic store
        res.set_content("{\"status\":\"started\"}", "application/json");
    });

    svr_.Post("/control/stop", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);
        if (!isAuthorized(req)) {
            logAuthFailure(req);
            res.status = 401;
            res.set_content("{\"error\":\"unauthorized\"}", "application/json");
            return;
        }
        auto now = std::chrono::steady_clock::now();
        auto& last = last_control_request_["/control/stop"];
        if (now - last < control_rate_limit_) {
            res.status = 429;
            res.set_content("{\"error\":\"rate limit exceeded\"}", "application/json");
            return;
        }
        last = now;
        stop(); // Only stop via explicit API
        res.set_content("{\"status\":\"stopped\"}", "application/json");
    });

    svr_.Post("/control/reload", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);
        // Check auth + rate limit
        if (!checkRateLimit(req, res, "/control/reload")) {
            return;
        }

        // Check if using in-memory config
        if (config_path_.empty()) {
            log("warn", "RELOAD SKIPPED - Daemon using in-memory config: " + 
                (config_name_.empty() ? "unknown" : config_name_));

            nlohmann::json j;
            j["status"] = "reloaded";
            j["message"] = "config reload skipped (in-memory config)";
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Reload from file
        try {
            std::lock_guard<std::shared_mutex> lock(reload_mutex);
            YAML::Node config = YAML::LoadFile(config_path_);
            initializeFromConfig(config);
            log("info", "SUCCESS, config reloaded from: " + config_path_);
            res.set_content("{\"status\":\"reloaded\"}", "application/json");
        } catch (const std::exception& ex) {
            log("error", "Reload failed: " + std::string(ex.what()));
            res.status = 500;
            res.set_content(std::string("{\"error\":\"") + ex.what() + "\"}", "application/json");
        }
    });

    svr_.Get("/metrics/history", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
        add_cors(res);
        if (!isAuthorized(req)) {
            logAuthFailure(req);
            res.status = 401;
            res.set_content("{\"error\":\"unauthorized\"}", "application/json");
            return;
        }

        // Parse query params
        int64_t start_ts = 0;
        int64_t end_ts = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        size_t limit = 1220;

        // Parse start param
        if (req.has_param("start")) {
            try {
                start_ts = std::stoll(req.get_param_value("start"));
            } catch (...) {
                res.status = 400;
                res.set_content("{\"error\":\"invalid 'start' timestamp\"}", "application/json");
                return;
            }
        } else {
            start_ts = end_ts - (24 * 3600);
        }

        // Parse end param
        if (req.has_param("end")) {
            try {
                end_ts = std::stoll(req.get_param_value("end"));
            } catch (...) {
                res.status = 400;
                res.set_content("{\"error\":\"invalid 'end' timestamp\"}", "application/json");
                return;
            }
        }

        // Parse limit param
        if (req.has_param("limit")) {
            try {
                limit = std::stoll(req.get_param_value("limit"));
                if (limit > 43200) {
                    limit = 43200;
                }
            } catch (...) {
                res.status = 400;
                res.set_content("{\"error\":\"invalid 'limit' timestamp\"}", "application/json");
                return;
            }
        }

        // Validate timestamp range
        if (start_ts >= end_ts) {
            res.status = 400;
            res.set_content("{\"error\":\"start must be before end\"}", "application/json");
            return;
        }

        // Query Database
        auto history = persistence_->loadHistoryRange(start_ts, end_ts, limit);


        // Build json response
        nlohmann::json response;
        response["start"] = start_ts;
        response["end"] = end_ts;
        response["count"] = history.size();

        nlohmann::json windows = nlohmann::json::array();
        for (const auto& stats : history) {
            nlohmann::json window;

            int64_t window_ts = std::chrono::system_clock::to_time_t(stats.window_start);
            window["timestamp"] = window_ts;
            window["window_start"] = window_ts;
            window["total_bytes"] = stats.total_bytes;
            window["total_packets"] = stats.total_packets;

            // Calculation for bytes_per_second (assume 60-sec window)
            uint64_t total_bytes = 0;
            for (const auto& [proto, bytes] : stats.protocol_bytes) {
                total_bytes += bytes;
            }

            int window_duration = 60; // default fallback
            if (stats.window_size > std::chrono::seconds(0)) {
                window_duration = static_cast<int>(stats.window_size.count());
            }
            if (window_duration <= 0) window_duration = 60; // prevent div by zero
            window["bytes_per_second"] = total_bytes / window_duration;

            // Protocol breakdown
            nlohmann::json proto_breakdown = nlohmann::json::object();
            for (const auto& [proto, bytes] : stats.protocol_bytes) {
                if (bytes > 0) {
                    proto_breakdown[std::to_string(proto)] = bytes;
                }
            }
            window["protocol_breakdown"] = proto_breakdown;  
            
            // active flows not stored in historical data (too large)
            window["active_flows"] = nlohmann::json::array();

            windows.push_back(window);

            }

            response["windows"] = windows;
            res.set_content(response.dump(), "application/json");
        });

        // GET /api/top-talkers - Top bandwidth consumers
        svr_.Get("/api/top-talkers", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
            add_cors(res);
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            
            auto stats = aggregator_->currentStats();
            
            // Aggregate by source IP
            std::unordered_map<std::string, uint64_t> src_bytes;
            std::unordered_map<std::string, uint64_t> dst_bytes;
            
            for (const auto& [key, val] : stats.flows) {
                uint64_t total_bytes = val.bytes_c2s + val.bytes_s2c;
                src_bytes[key.src_ip] += total_bytes;
                dst_bytes[key.dst_ip] += total_bytes;
            }
            
            // Convert to sorted vectors
            std::vector<std::pair<std::string, uint64_t>> top_sources(src_bytes.begin(), src_bytes.end());
            std::vector<std::pair<std::string, uint64_t>> top_destinations(dst_bytes.begin(), dst_bytes.end());
            
            std::sort(top_sources.begin(), top_sources.end(), 
                [](const auto& a, const auto& b) { return a.second > b.second; });
            std::sort(top_destinations.begin(), top_destinations.end(),
                [](const auto& a, const auto& b) { return a.second > b.second; });
            
            nlohmann::json response;
            response["top_sources"] = nlohmann::json::array();
            response["top_destinations"] = nlohmann::json::array();
            
            for (size_t i = 0; i < std::min(top_sources.size(), size_t(10)); ++i) {
                response["top_sources"].push_back({
                    {"ip", top_sources[i].first},
                    {"bytes", top_sources[i].second}
                });
            }
            
            for (size_t i = 0; i < std::min(top_destinations.size(), size_t(10)); ++i) {
                response["top_destinations"].push_back({
                    {"ip", top_destinations[i].first},
                    {"bytes", top_destinations[i].second}
                });
            }
            
            res.set_content(response.dump(), "application/json");
        });
        
        // GET /api/port-stats - Port activity statistics
        svr_.Get("/api/port-stats", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
            add_cors(res);
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            
            auto stats = aggregator_->currentStats();
            
            std::unordered_map<uint16_t, uint64_t> port_bytes;
            std::unordered_map<uint16_t, uint64_t> port_connections;
            
            for (const auto& [key, val] : stats.flows) {
                uint64_t total_bytes = val.bytes_c2s + val.bytes_s2c;
                port_bytes[key.dst_port] += total_bytes;
                port_connections[key.dst_port]++;
            }
            
            std::vector<std::tuple<uint16_t, uint64_t, uint64_t>> ports;
            for (const auto& [port, bytes] : port_bytes) {
                ports.emplace_back(port, bytes, port_connections[port]);
            }
            
            std::sort(ports.begin(), ports.end(),
                [](const auto& a, const auto& b) { return std::get<1>(a) > std::get<1>(b); });
            
            nlohmann::json response = nlohmann::json::array();
            for (size_t i = 0; i < std::min(ports.size(), size_t(20)); ++i) {
                response.push_back({
                    {"port", std::get<0>(ports[i])},
                    {"bytes", std::get<1>(ports[i])},
                    {"connections", std::get<2>(ports[i])},
                    {"service", getServiceName(std::get<0>(ports[i]))}
                });
            }
            
            res.set_content(response.dump(), "application/json");
        });
        
        // GET /api/system-health - Daemon health metrics
        svr_.Get("/api/system-health", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
            add_cors(res);
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            
            auto now = std::chrono::steady_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();
            
            // Get flow count from current stats
            auto stats = aggregator_->currentStats();
            // PcapAdapter stats
            auto pcap_stats = pcap_->getStats();
            
            nlohmann::json response = {
                {"uptime_seconds", uptime},
                {"packets_received", pcap_stats.packets_received},
                {"packets_dropped", pcap_stats.packets_dropped},
                {"drop_rate", pcap_stats.packets_received > 0 ? (double)pcap_stats.packets_dropped / pcap_stats.packets_received * 100 : 0.0},
                {"active_flows", stats.flows.size()},
                {"capture_running", running_.load()},
                {"interface", pcap_->source()},
                {"buffer_usage_percent", 0.0}  // TODO: Not implemented yet
            };
            
            res.set_content(response.dump(), "application/json");
        });
        
        // GET /api/packet-sizes Packet size distribution 
        svr_.Get("/api/packet-sizes", [this, add_cors](const httplib::Request& req, httplib::Response& res) {
            add_cors(res);
            if (!isAuthorized(req)) {
                logAuthFailure(req);
                res.status = 401;
                res.set_content("{\"error\":\"unauthorized\"}", "application/json");
                return;
            }
            
            // StatsAggregator track packet sizes yet
            auto dist  = aggregator_->getPacketSizeDistribution();
            
            // Return zeros for now
            nlohmann::json response = {
                {"tiny", dist.tiny},    // 0-64 bytes
                {"small", dist.small},   // 65-128 bytes
                {"medium", dist.medium},  // 129-512 bytes
                {"large", dist.large},   // 513-1024 bytes
                {"jumbo", dist.jumbo}    // 1025+ bytes
            };
            
            res.set_content(response.dump(), "application/json");
        });
}

void NetMonDaemon::startServer() {
    log("info", "Starting API server on " + api_host_ + ":" + std::to_string(api_port_));

    setupApiRoutes();

    api_thread_ = std::thread([this]() {
        svr_.listen(api_host_, api_port_);
    });

    // Await server response
    auto start = std::chrono::steady_clock::now();
    while (!svr_.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        // Timeout after 5 seconds
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(5)) {
            throw std::runtime_error("API server failed to start within 5 seconds");
        }
    }
    
    log("info", "API server is now listening");
}

void NetMonDaemon::stopServer() {
    log("info", "Stopping API server...");
    svr_.stop();
    if (api_thread_.joinable()) api_thread_.join();
}

// ===================================================================
// HELPER METHODS
// ===================================================================

bool NetMonDaemon::isAuthorized(const httplib::Request& req) {
    // Check for API token in Authorization header (Bearer token)
    auto auth_header = req.get_header_value("Authorization");
    if (!auth_header.empty() && auth_header.find("Bearer ") == 0) {
        std::string token = auth_header.substr(7); // Remove "Bearer "
        if (token == api_token_) {
            return true;
        }
    }

    // Check for API token in query parameter (?token=...)
    auto token_param = req.get_param_value("token");
    if (!token_param.empty() && token_param == api_token_) {
        return true;
    }

    // Check for session token in X-Session-Token header
    auto session_token = req.get_header_value("X-Session-Token");
    if (!session_token.empty()) {
        SessionData session_data;
        if (session_manager_->validateSession(session_token, session_data)) {
            return true;
        }
    }

    return false;
}

bool NetMonDaemon::checkRateLimit(const httplib::Request& req, httplib::Response& res, const std::string& endpoint) {
    // Check authorization
    if (!isAuthorized(req)) {
        logAuthFailure(req);
        res.status = 401;
        res.set_content("{\"error\":\"unauthorized\"}", "application/json");
        return false;
    }

    // check rate limit
    auto now = std::chrono::steady_clock::now();
    auto& last = last_control_request_[endpoint];
    if (now - last < control_rate_limit_) {
        res.status = 429;
        res.set_content("{\"error\":\"rate limit exceeded\"}", "application/json");
        return false;
    }
    last = now;
    return true;
}

void NetMonDaemon::stop() {
    if (!running_.exchange(false)) {
        log("warn", "NetMonDaemon is already stopped");
        return;
    }
    
    log("info", "NetMonDaemon is stopping...");
    if (pcap_) pcap_->stopCapture();
}

void NetMonDaemon::logAuthFailure(const httplib::Request& req) const {
    log("warn", "AUTH FAIL: " + req.method + " " + req.path + " from " + req.remote_addr);
}

void NetMonDaemon::log(const std::string& level, const std::string& msg) const {
    if (shouldLog(level)) {
        std::ostringstream oss;
        if (log_timestamps_) {
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            oss << "[" << std::put_time(std::localtime(&now), "%F %T") << "] ";
        }
        oss << "[" << level << "] " << msg << std::endl;
        if (log_stream_.is_open()) {
            log_stream_ << oss.str();
            log_stream_.flush();
        } else {
            std::cout << oss.str();
        }
    }
}

bool NetMonDaemon::shouldLog(const std::string& level) const {
    static const std::map<std::string, int> levels = {
        {"debug", 0}, {"info", 1}, {"warn", 2}, {"error", 3}
    };
    int configured = levels.count(log_level_) ? levels.at(log_level_) : 1;
    int current = levels.count(level) ? levels.at(level) : 1;
    return current >= configured;
}

std::string NetMonDaemon::getServiceName(uint16_t port) {
    static const std::unordered_map<uint16_t, std::string> services = {
        {20, "FTP-DATA"}, {21, "FTP"}, {22, "SSH"}, {23, "TELNET"},
        {25, "SMTP"}, {53, "DNS"}, {67, "DHCP"}, {68, "DHCP"},
        {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"}, {443, "HTTPS"},
        {445, "SMB"}, {993, "IMAPS"}, {995, "POP3S"}, {1433, "MSSQL"},
        {3306, "MySQL"}, {3389, "RDP"}, {5432, "PostgreSQL"},
        {5900, "VNC"}, {6379, "Redis"}, {8080, "HTTP-ALT"},
        {8443, "HTTPS-ALT"}, {27017, "MongoDB"}
    };
    
    auto it = services.find(port);
    return it != services.end() ? it->second : "";
}

// ===================================================================
// SIGNAL HANDLING
// ===================================================================

std::atomic<bool> NetMonDaemon::running_signal_{true};

void NetMonDaemon::signalHandler(int signum) {
    std::cout << "\n[INFO] Signal (" << signum << ") received. Shutting down..." << std::endl;
    running_signal_ = false;
}