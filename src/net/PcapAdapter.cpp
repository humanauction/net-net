#include "PcapAdapter.h"
#include <pcap/pcap.h>
#include <thread>
#include <stdexcept>
#include <mutex>
#include <shared_mutex>
#include <regex>

struct PcapAdapter::Impl {
    Options opts;
    pcap_t* handle = nullptr;
    std::thread worker;
    PacketCallback callback;
    std::atomic<bool> running{false};
    std::string source_name;
    std::shared_mutex filter_mtx;
};

void pcap_bridge(u_char* user, const struct pcap_pkthdr* hdr, const u_char* data) {
    auto* impl = reinterpret_cast<PcapAdapter::Impl*>(user);
    if (!impl->callback) return;

    PacketMeta meta;
    meta.timestamp = std::chrono::system_clock::from_time_t(hdr->ts.tv_sec);
    meta.timestamp += std::chrono::microseconds(hdr->ts.tv_usec);
    meta.cap_len = hdr->caplen;
    meta.orig_len = hdr->len;
    meta.iface = impl->source_name;

    impl->callback(meta, data, hdr->caplen);
}

PcapAdapter::PcapAdapter(const Options& opts)
    : impl_(std::make_unique<Impl>()) {
    // Validate options
    if (opts.iface_or_file.empty()) {
        throw std::invalid_argument("Interface or file path cannot be empty");
    }
    if (opts.snaplen <= 0 || opts.snaplen > 65535) {
        throw std::invalid_argument("Snaplen must be between 1 and 65535");
    }
    if (opts.timeout_ms < 0) {
        throw std::invalid_argument("Timeout cannot be negative");
    }
    impl_->opts = opts;
    impl_->source_name = opts.iface_or_file;
}

PcapAdapter::~PcapAdapter() {
    stopCapture();
    if (impl_ && impl_->handle) {
        pcap_close(impl_->handle);
        impl_->handle = nullptr;
    }
    // Don't delete impl_ - unique_ptr handles it
}

void PcapAdapter::startCapture(PacketCallback cb) {
    if (impl_->running.load()) {
        throw std::runtime_error("Capture already running");
    }
    impl_->callback = cb;

    char errbuf[PCAP_ERRBUF_SIZE];
    if (impl_->opts.read_offline) {
        impl_->handle = pcap_open_offline(impl_->opts.iface_or_file.c_str(), errbuf);
    } else {
        impl_->handle = pcap_open_live(
            impl_->opts.iface_or_file.c_str(),
            impl_->opts.snaplen,
            impl_->opts.promiscuous ? 1 : 0,
            impl_->opts.timeout_ms,
            errbuf
        );
    }

    if (!impl_->handle) {
        throw std::runtime_error(std::string("pcap_open failed: ") + errbuf);
    }

    if (!impl_->opts.bpf_filter.empty()) {
        struct bpf_program prog{};
        if (pcap_compile(impl_->handle, &prog, impl_->opts.bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::string error = std::string("pcap_compile failed: ") + pcap_geterr(impl_->handle);
            pcap_close(impl_->handle);
            impl_->handle = nullptr;
            throw std::runtime_error(error);
        }
        if (pcap_setfilter(impl_->handle, &prog) == -1) {
            std::string error = std::string("pcap_setfilter failed: ") + pcap_geterr(impl_->handle);
            pcap_freecode(&prog);
            pcap_close(impl_->handle);
            impl_->handle = nullptr;
            throw std::runtime_error(error);
        }
        pcap_freecode(&prog);
    }

    impl_->running.store(true);
    impl_->worker = std::thread([this]() {
        int ret = pcap_loop(impl_->handle, 0, ::pcap_bridge, reinterpret_cast<u_char*>(impl_.get()));
        impl_->running.store(false);
        (void)ret; // suppress unused variable warning
    });
}

void PcapAdapter::stopCapture() {
    if (!impl_->running.load()) {
        if (impl_->worker.joinable()) {
            impl_->worker.join();
        }
        return;
    }

    pcap_breakloop(impl_->handle);

    if (impl_->worker.joinable()) {
        impl_->worker.join();
    }

    impl_->running.store(false);
}

void PcapAdapter::setFilter(const std::string& bpf) {
    std::shared_lock<std::shared_mutex> lock(impl_->filter_mtx);
    if (!impl_->handle) {
        throw std::runtime_error("pcap handle not open");
    }

    struct bpf_program prog{};
    if (pcap_compile(impl_->handle, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        throw std::runtime_error(std::string("pcap_compile failed: ") + pcap_geterr(impl_->handle));
    }

    if (pcap_setfilter(impl_->handle, &prog) == -1) {
        pcap_freecode(&prog);
        throw std::runtime_error(std::string("pcap_setfilter failed: ") + pcap_geterr(impl_->handle));
    }

    pcap_freecode(&prog);
}

std::string PcapAdapter::source() const noexcept {
    return impl_->source_name;
}

bool PcapAdapter::isValidBpfFilter(const std::string& filter) {
    // Check length
    if (filter.empty() || filter.length() > 256) {
        return false;
    }

    
    // Step 1: Allow BPF syntax using regex
    // Valid: tcp, udp, icmp, host, port, src, dst, and, or, not, net
    // Valid symbols: () [] / : . , = > < ! - & (bitwise AND for BPF)
    // Allow spaces and underscores
    static const std::regex safe_bpf(R"(^[a-zA-Z0-9 _\(\)\[\]\/:\.\,\=\>\<\!\-\&]*$)");
    
    if (!std::regex_match(filter, safe_bpf)) {
        return false;
    }
    
    // Step 2: Block ONLY dangerous shell metacharacters
    static const std::vector<std::string> forbidden = {
        ";",      // Command separator
        "|",      // Pipe
        "`",      // Command substitution
        "$(",     // Command substitution
        "${",     // Variable expansion
        ">>",     // Redirect append
        "<<",     // Here document
        "\n",     // Newline
        "\r",     // Carriage return
        "\\",     // Escape (could bypass other checks)
    };
    
    for (const auto& bad : forbidden) {
        if (filter.find(bad) != std::string::npos) {
            return false;
        }
    }

    static const std::vector<std::string> blacklisted_words = {
        "evil", "DROP", "DELETE", "INSERT", "UPDATE", "SELECT", 
        "UNION", "exec", "system", "rm", "sudo"
    };

    for (const auto& keyword : blacklisted_words) {
        if (filter.find(keyword) != std::string::npos) {
            return false;
        }
    }
    
    // Step 3: Reject SQL injection attempts
    std::string lower = filter;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    static const std::vector<std::string> sql_keywords = {
        "drop", "delete", "insert", "update", "union", "exec", "script"
    };
    
    for (const auto& keyword : sql_keywords) {
        if (lower.find(keyword) != std::string::npos) {
            return false;
        }
    }
    
    // All checks passed
    return true;
}

PcapAdapter::Stats PcapAdapter::getStats() const {
    Stats stats;
    if (impl_->handle) {
        struct pcap_stat ps;
        if (pcap_stats(impl_->handle, &ps) == 0) {
            stats.packets_received = ps.ps_recv;
            stats.packets_dropped = ps.ps_drop;
        }
    }
    return stats;
}