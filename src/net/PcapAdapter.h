#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <chrono>
#include <memory>


struct PacketMeta {
    std::chrono::system_clock::time_point timestamp;
    std::string iface;
    uint32_t cap_len;
    uint32_t orig_len;
};

using PacketCallback = std::function<void(const PacketMeta& meta, const uint8_t* data, size_t)>;

class PcapAdapter {
public:
    struct Options{
        std::string iface_or_file;
        std::string bpf_filter;
        bool promiscuous = true;
        int snaplen = 65535;
        int timeout_ms = 1000;
        bool read_offline = false;
    };

    explicit PcapAdapter(const Options& opts);
    ~PcapAdapter();
    
    PcapAdapter(const PcapAdapter&) = delete;
    PcapAdapter& operator=(const PcapAdapter&) = delete;

    // Stage 1 API
    // Start capture; throws std::runtime_error on fatal setup error.
    void startCapture(PacketCallback cb);
    // Stop capture.
    void stopCapture();
    // Apply BPF filter at runtime; throws on error.
    void setFilter(const std::string& bpf);

    // Source name can be interface or file
    std::string source() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
};

