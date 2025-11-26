#include "NetMonDaemon.h"
#include <iostream>
#include <iomanip>
#include <yaml-cpp/yaml.h>
#include <thread>
#include <string>
#include <chrono>
#include "httplib.h" // For HTTP server
#include <sstream>
#include <csignal>
#include "net/PcapAdapter.h"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <nlohmann/json.hpp>
#include "core/SessionManager.h"
#include "../../include/net-net/vendor/bcrypt.h"

NetMonDaemon::NetMonDaemon(const std::string& config_path)
    : config_path_(config_path)
{
    /*
     * Initialization Order (CRITICAL - do not reorder):
     * 1. Load config (YAML)
     * 2. Initialize logging
     * 3. Validate API token
     * 4. Initialize database/persistence
     * 5. Load and hash user credentials (requires file access)
     * 6. Initialize SessionManager (requires database access)
     * 7. Initialize PcapAdapter (requires root for live capture)
     * 
     * Then in run():
     * 8. Start packet capture (requires root)
     * 9. Drop privileges (AFTER capture device is open)
     * 10. Start API server (runs as unprivileged user)
     */

    
    log("info", "Loading configuration from: " + config_path);

    YAML::Node config = YAML::LoadFile(config_path_);
    // Logging Level and File Configuration
    if (config["logging"]) {
        log_level_ = config["logging"]["level"] ? config["logging"]["level"].as<std::string>() : "info";
        log_file_ = config["logging"]["file"] ? config["logging"]["file"].as<std::string>() : "";
        log_timestamps_ = config["logging"]["timestamps"] ? config["logging"]["timestamps"].as<bool>() : true;
        if (!log_file_.empty()) {
            log_stream_.open(log_file_, std::ios::app);
            if (!log_stream_) {
                log("error", "[ERROR] Could not open log file: " + log_file_);
                exit(1);
            }
        }
    }
    // API token check
    if (!config["api"] || !config["api"]["token"]) {
        throw std::runtime_error("Config missing 'api.token' required");
    }
    api_token_ = config["api"]["token"].as<std::string>();
    api_host_ = config["api"]["host"] ? config["api"]["host"].as<std::string>() : "localhost";
    api_port_ = config["api"]["port"] ? config["api"]["port"].as<uint16_t>() : 8082;

    // Prioritize offline mode
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
        if (!bpf_filter.empty() && !isValidBpfFilter(bpf_filter)) {
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
    pcap_ = std::make_unique<PcapAdapter>(opts);

    // StatsAggregator
    if (!config["stats"] || !config["stats"]["window_size"] || !config["stats"]["history_depth"]) {
        throw std::runtime_error("Missing required 'stats.window_size' or 'stats.history_depth' in config");
    }
    int window_size = config["stats"]["window_size"].as<int>();
    int history_depth = config["stats"]["history_depth"].as<int>();
    aggregator_ = std::make_unique<StatsAggregator>(std::chrono::seconds(window_size), history_depth);

    // StatsPersistence
    if (!config["database"] || !config["database"]["path"]) {
        throw std::runtime_error("Missing required 'database.path' in config");
    }
    std::string db_path = config["database"]["path"].as<std::string>();
    persistence_ = std::make_unique<StatsPersistence>(db_path);

    // Load user credentials and hash passwords
    if (config["users"]) {
        for (const auto& user : config["users"]) {
            std::string username = user["username"].as<std::string>();
            std::string password = user["password"].as<std::string>();

            // Check if password is already in PBKDF2 format (iterations$salt$hash)
            if (password.find('$') != std::string::npos) {
                // Already hashed (PBKDF2 or bcrypt format) - store as-is
                user_credentials_[username] = password;
            } else {
                // Plaintext password - hash it (INSECURE - development only)
                log("warn", "Plaintext password detected for: " + username + " - hashing now");
                user_credentials_[username] = bcrypt::hash(password);
            }

            log("info", "Loaded User: " + username);
        }   
    } else {
        log("warn", "authentication disabled - no user defined in config");
    }

    // Initialize session manager
    std::string session_db_path = db_path + ".sessions";
    
    if (config["api"]["session_expiry"]) {
        session_expiry_ = config["api"]["session_expiry"].as<int>();
    }
    session_manager_ = std::make_unique<SessionManager>(session_db_path, session_expiry_);

    log("info", "Session manager initialized (expiry: " + std::to_string(session_expiry_) + "s)");

    log("info", "NetMonDaemon initialized with config: " + config_path_);
}

void NetMonDaemon::run()
{
    running_ = true;
    log("info", "NetMonDaemon is running...");

    // Start packet capture BEFORE dropping privileges
    pcap_->startCapture([this](const PacketMeta& meta, const uint8_t* data, size_t len) {
        ParsedPacket pkt;
        if (parsePacket(data, len, meta, pkt)) {
            aggregator_->ingest(pkt);
        }
    });

    // Drop privileges AFTER capture device is open
    YAML::Node config = YAML::LoadFile(config_path_);
    if (config["privilege"] && config["privilege"]["drop"] && config["privilege"]["drop"].as<bool>()) {
        std::string user = config["privilege"]["user"] ? config["privilege"]["user"].as<std::string>() : "nobody";
        std::string group = config["privilege"]["group"] ? config["privilege"]["group"].as<std::string>() : "nobody";
        struct passwd* pw = getpwnam(user.c_str());
        struct group* gr = getgrnam(group.c_str());
        if (!pw || !gr) {
            log("error", "[ERROR] Invalid user/group for privilege drop");
            exit(1);
        }
        if (setgid(gr->gr_gid) != 0 || setuid(pw->pw_uid) != 0) {
            log("error", "[ERROR] Failed to drop privileges");
            exit(1);
        }
        log("info", "Dropped privileges to " + user + ":" + group);
    }

    // Start REST API server
    svr_.Get("/metrics", [this](const httplib::Request& req, httplib::Response& res) {
        if (!isAuthorized(req)) {
            logAuthFailure(req);
            res.status = 401;
            res.set_content("{\"error\":\"unauthorized\"}", "application/json");
            return;
        }

        auto stats = aggregator_->currentStats();

        // Calculate totals
        uint64_t total_bytes =0;
        uint64_t total_packets =0;
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

    // TODO: Login endpoint - authenticate user and create session
    svr_.Post("/login", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            // Parse JSON properly
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
            log("debug", "=== PASSWORD VERIFICATION DEBUG ===");
            log("debug", "Username: " + username);
            log("debug", "Password: [" + password + "]");
            log("debug", "Password length: " + std::to_string(password.length()));
            log("debug", "Stored hash: [" + it->second + "]");
            log("debug", "Stored hash length: " + std::to_string(it->second.length()));
            
            bool verify_result = bcrypt::verify(password, it->second);
            log("debug", "bcrypt::verify() returned: " + std::string(verify_result ? "TRUE" : "FALSE"));
            
            if (!verify_result) {
                log("warn", "Login attempt failed for: " + username);
                res.status = 401;
                res.set_content("{\"error\":\"invalid credentials\"}", "application/json");
                return;
            }

            // Get client IP for session tracking
            std::string client_ip = req.remote_addr;

            // Create session
            try {
                std::string token = session_manager_->createSession(username, client_ip);

                log("info", "Logged in user: " + username + "from " + client_ip);
                // Return session token
                std::ostringstream oss;
                oss << "{";
                oss << "\"token\":\"" << token << "\",";
                oss << "\"username\":\"" << username << "\",";
                oss << "\"expires_in\":" << session_expiry_;
                oss << "}";

                res.set_content(oss.str(), "application/json");
            } catch (std::exception& ex) {
                log("error", "Create Session FAILED: " + std::string(ex.what()));
                res.status = 500;
                res.set_content("{\"error\":\"session creation failed\"}", "application/json");
            }
        } catch (const std::exception& ex) {
            log("error", "Login request processing failed: " + std::string(ex.what()));
            res.status = 500;
            res.set_content("{\"error\":\"internal server error\"}", "application/json");
        }
    });
    // Logout endpoint - invalidate session
    svr_.Post("/logout", [this](const httplib::Request& req, httplib::Response& res) {
        auto session_token = req.get_header_value("X-Session-Token");
        
        if (session_token.empty()) {
            res.status = 400;
            res.set_content("{\"error\":\"no session token provided\"}", "application/json");
            return;
        }
        // Validate session exists before deleting
        SessionData session_data;
        if (session_manager_->validateSession(session_token, session_data)) {
            session_manager_->deleteSession(session_token);
            log("info", "Logged out USER: " + session_data.username);
            res.set_content("{\"status\":\"logged out\"}", "application/json");
        } else {
            res.status = 401;
            res.set_content("{\"error\":\"session invalid\"}", "application/json");
        }              
    });

    // Start/Stop/Reload control endpoints
    svr_.Post("/control/start", [this](const httplib::Request& req, httplib::Response& res) {
        if (!isAuthorized(req)) {
            logAuthFailure(req);
            res.status = 401;
            res.set_content("{\"error\":\"unauthorized\"}", "application/json");
            return;
        }
        auto now = std::chrono::steady_clock::now();
        auto& last =  last_control_request_["/control/start"];
        if (now - last < control_rate_limit_) {
            res.status= 429;
            res.set_content("{\"error\":\"rate limit exceeded\"}", "application/json");
            return;
        }
        last = now;
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
        auto now = std::chrono::steady_clock::now();
        auto& last =  last_control_request_["/control/stop"];
        if (now - last < control_rate_limit_) {
            res.status= 429;
            res.set_content("{\"error\":\"rate limit exceeded\"}", "application/json");
            return;
        }
        last = now;
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

            log("info", "Config reloaded successfully at " + std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())));

            res.set_content("{\"status\":\"reloaded\"}", "application/json");
        } catch (const std::exception& ex) {
            log("error", "[ERROR] Reload failed: " + std::string(ex.what()));
            res.status = 500;
            res.set_content(std::string("{\"error\":\"") + ex.what() + "\"}", "application/json");
        }
    });

    // Serve static dashboard files
    svr_.set_mount_point("/", "./www");

    api_thread_ = std::thread([this]() {
        std::cout << "[INFO] Starting API server on " << api_host_ << ":" << api_port_ << std::endl;
        svr_.listen(api_host_, api_port_);
    });

    // 
    int cleanup_counter = 0;
    while (NetMonDaemon::running_signal_ && isRunning()) {
        aggregator_->advanceWindow();
        auto stats = aggregator_->currentStats();
        persistence_->saveWindow(stats);

        // Cleanup expired sessions every 60 seconds
        if (++cleanup_counter % 60 == 0) {
            session_manager_->cleanupExpired();
            log("debug", "Expired sessions CLEANED");
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    pcap_->stopCapture();
    log("info", "Capture complete! API server will remain running for 100 seconds.");
    for (int i = 0; i < 100 && NetMonDaemon::running_signal_; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // When running_ is set to false (e.g., via /control/stop), exit and clean up
    stop();
}

void NetMonDaemon::stop()
{
    running_ = false;
    log("info", "NetMonDaemon is stopping...");
    // TODO: shutdown logic here
    // Stop API server and join thread
    // (cpp-httplib stops when svr.stop() is called)
    svr_.stop();
    if (api_thread_.joinable()) api_thread_.join();
}

bool NetMonDaemon::isAuthorized(const httplib::Request& req) {
    // Check for API token (Bearer or query param)
    auto auth = req.get_header_value("Authorization");
    std::string prefix = "Bearer ";
    if (auth.rfind(prefix, 0) == 0 && auth.substr(prefix.size()) == api_token_) {
        return true;
    }
    if (req.has_param("token") && req.get_param_value("token") == api_token_) {
        return true;
    }
    // Check for session token (X-Session-Token header)
    auto session_token = req.get_header_value("X-Session-Token");

    if (!session_token.empty()) {
        SessionData session_data;
        if (session_manager_->validateSession(session_token, session_data)) {
            // Session is valid and has been refreshed
            return true;
        }
    }

    return false;
}

void NetMonDaemon::logAuthFailure(const httplib::Request& req) const {
    std::cerr << "[AUTH FAIL] " + req.method + " " + req.path << std::endl;
    auto auth = req.get_header_value("Authorization");
    if (!auth.empty()) std::cerr << "error" << " (Authorization header present)";
    if (req.has_param("token")) std::cerr << "error" << " (token param present)";
    std::cerr << "error" << std::endl;
}

int main(int argc, char* argv[]) {
    std::string config_path;
    for (int i = 1; i < argc -1; ++i) {
        if (std::string(argv[i]) == "--config") {
            config_path = argv[i + 1];
            break;
        }
    }
    if (config_path.empty()) {
        std::cerr << "Usage: " << argv[0] << " --config <config_path.yaml>" << std::endl;
        return 1;
    }

    std::signal(SIGINT, NetMonDaemon::signalHandler);
    NetMonDaemon daemon(config_path);
    daemon.setRunning(true);
    daemon.run();
    return 0;
}

std::atomic<bool> NetMonDaemon::running_signal_{true};

void NetMonDaemon::signalHandler(int signum) {
    std::cout << "\n[INFO] Signal (" + std::to_string(signum) + ") received. Shutting down..." << std::endl;
    running_signal_ = false;
}

// Logging helper
void NetMonDaemon::log(const std::string& level, const std::string& msg) {
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

bool NetMonDaemon::shouldLog(const std::string& level) {
    static const std::map<std::string, int> levels = {
        {"debug", 0}, {"info", 1}, {"warn", 2}, {"error", 3}
    };
    int configured = levels.count(log_level_) ? levels.at(log_level_) : 1;
    int current = levels.count(level) ? levels.at(level) : 1;
    return current >= configured;
}