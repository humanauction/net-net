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



// ===================================================================
// CONSTRUCTORS
// ===================================================================

// In-memory constructor (testing use)
NetMonDaemon::NetMonDaemon(const YAML::Node& config, const std::string& config_name)
    : config_path_(""), config_name_(config_name), running_(false)  // ✅ INITIALIZE config_name_
{
    log("info", "Loading configuration from memory: " + config_name);
    initializeFromConfig(config);
}

// File-based constructor (production use)
NetMonDaemon::NetMonDaemon(const std::string& config_path)
    : config_path_(config_path), config_name_(""), running_(false)  // ✅ INITIALIZE config_name_ (empty for file-based)
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
                log("error", "Could not open log file: " + log_file_);
                exit(1);
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
    log("info", "NetMonDaemon is running...");
    
    // Start packet capture
    std::thread capture_thread([this]() {
        try {
            pcap_->startCapture([this](const PacketMeta& meta, const uint8_t* data, size_t len) {
                ParsedPacket pkt;
                if (parsePacket(data, len, meta, pkt)) {
                    aggregator_->ingest(pkt);
                }
            });
        } catch (const std::exception& ex) {
            log("error", "Capture failed: " + std::string(ex.what()));
        }
    });
    
    // Start API server
    startServer();
    
    

    // Live mode: keep server running until stop() is called
    log("info", "API server ready...");
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Cleanup
    log("info", "Daemon shutting down...");
        // Wait for capture to complete
    if (capture_thread.joinable()) {
        capture_thread.join();
    }

    stopServer();
    running_.store(false);
}

// ===================================================================
// SETUP API ROUTES
// ===================================================================

void NetMonDaemon::setupApiRoutes() {
    // GET /metrics - Current stats
    svr_.Get("/metrics", [this](const httplib::Request& req, httplib::Response& res) {
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

    // POST /login - Authenticate and create session
    svr_.Post("/login", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            nlohmann::json json_body;
            try {
                json_body = nlohmann::json::parse(req.body);
            } catch (const nlohmann::json::parse_error& e) {
                log("warn", "Malformed JSON in login request: " + std::string(e.what()));
                res.status = 400;
                res.set_content("{\"error\":\"malformed JSON\"}", "application/json");
                return;
            }
            
            std::string username = json_body.value("username", "");
            std::string password = json_body.value("password", "");
            
            if (username.empty() || password.empty()) {
                log("warn", "Login attempt with missing credentials");
                res.status = 400;
                res.set_content("{\"error\":\"missing username or password\"}", "application/json");
                return;
            }

            // Validate credentials
            auto it = user_credentials_.find(username);
            if (it == user_credentials_.end()) {
                log("warn", "User does not exist: " + username);
                res.status = 401;
                res.set_content("{\"error\":\"invalid credentials\"}", "application/json");
                return;
            }

            // Verify password against bcrypt hash
            if (!bcrypt::verify(password, it->second)) {
                log("warn", "Login attempt failed for: " + username);
                res.status = 401;
                res.set_content("{\"error\":\"invalid credentials\"}", "application/json");
                return;
            }

            // Create session
            std::string client_ip = req.remote_addr;
            std::string token = session_manager_->createSession(username, client_ip);

            log("info", "User logged in: " + username + " from " + client_ip);

            std::ostringstream oss;
            oss << "{";
            oss << "\"token\":\"" << token << "\",";
            oss << "\"username\":\"" << username << "\",";
            oss << "\"expires_in\":" << session_expiry_;
            oss << "}";

            res.set_content(oss.str(), "application/json");
        } catch (const std::exception& ex) {
            log("error", "Login request processing failed: " + std::string(ex.what()));
            res.status = 500;
            res.set_content("{\"error\":\"internal server error\"}", "application/json");
        }
    });

    // POST /logout - Invalidate session
    svr_.Post("/logout", [this](const httplib::Request& req, httplib::Response& res) {
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

    // POST /control/start - Start capture
    svr_.Post("/control/start", [this](const httplib::Request& req, httplib::Response& res) {
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
        running_ = true;
        res.set_content("{\"status\":\"started\"}", "application/json");
    });

    // POST /control/stop - Stop capture
    svr_.Post("/control/stop", [this](const httplib::Request& req, httplib::Response& res) {
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
        running_ = false;
        res.set_content("{\"status\":\"stopped\"}", "application/json");
    });

    // POST /control/reload - Reload config
    svr_.Post("/control/reload", [this](const httplib::Request& req, httplib::Response& res) {
        // Check auth + rate limit
        if (!checkRateLimit(req, res, "/control/reload")) {
            return;  // Response already set by checkRateLimit()
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
    if (api_thread_.joinable()) {
        api_thread_.join();
    }
}

// ===================================================================
// HELPER METHODS
// ===================================================================

bool NetMonDaemon::checkRateLimit(const httplib::Request& req, httplib::Response& res, const std::string& endpoint) {
    // Check authorization first
    if (!isAuthorized(req)) {
        logAuthFailure(req);
        res.status = 401;
        res.set_content("{\"error\":\"unauthorized\"}", "application/json");
        return false;
    }

    // Then check rate limit
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
    if (!running_.load()) return;
    
    log("info", "NetMonDaemon is stopping...");
    running_.store(false);
    
    // stop capture
    if (pcap_) {
        pcap_->stopCapture();
    }

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

// ===================================================================
// SIGNAL HANDLING
// ===================================================================

std::atomic<bool> NetMonDaemon::running_signal_{true};

void NetMonDaemon::signalHandler(int signum) {
    std::cout << "\n[INFO] Signal (" << signum << ") received. Shutting down..." << std::endl;
    running_signal_ = false;
}