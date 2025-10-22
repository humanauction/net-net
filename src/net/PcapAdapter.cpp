#include "PcapAdapter.h"
#include <pcap/pcap.h>
#include <thread>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <mutex>
#include <memory>

struct PcapAdapter::Impl {
    Options opts;
    pcap_t* handle = nullptr;
    std::thread worker;
    PacketCallBack callback;
    std::atomic<bool> running{false};
    std::string source_name;
    std::mutex filter_mtx;
};

static void pcap_bridge(u_char* user, const struct pcap_pkthdr* hdr, const u_char* data) {
    auto* impl = reinterpret_cast<PcapAdapter::Impl*>(user);
    if (!impl->callback) return;
    PacketMetaData meta;
    meta.timestamp = std::chrono::system_clock::from_time_t(hdr->ts.tv_sec);
    meta.timestamp += std::chrono::microseconds(hdr->ts.tv_usec);
    meta.cap_len = hdr->caplen;
    meta.orig_len = hdr->len;
    meta.iface = impl->source_name;
    impl->callback(meta, data, hdr->caplen);
}

PcapAdapter::PcapAdapter(const Options& opts) 
    : pImpl(std::make_unique<Impl>(Impl{opts})) {
    pImpl->source_name = opts.iface_or_file;
}

PcapAdapter::~PcapAdapter(){
    stop();
    if (pImpl && pImpl->handle) {
        pcap_close(pImpl->handle);
        pImpl->handle = nullptr;
    }
    // Don't delete pImpl - unique_ptr handles it
}

void PcapAdapter::start(PacketCallBack cb) {
    if (pImpl->running.load()) throw std::runtime_error("Capture already running");
    pImpl->callback = cb;

    char errbuff[PCAP_ERRBUF_SIZE];
    if (pImpl->opts.read_offline) {
        pImpl->handle = pcap_open_offline(pImpl->opts.iface_or_file.c_str(), errbuff);
    } else {
        pImpl->handle = pcap_open_live(
            pImpl->opts.iface_or_file.c_str(),
            pImpl->opts.snaplen,
            pImpl->opts.promiscuous ? 1 : 0,
            pImpl->opts.timeout_ms,
            errbuff
        );
    }

    if (!pImpl->handle) {
        throw std::runtime_error(std::string("pcap_open failed: ") + errbuff);
    }

    if (!pImpl->opts.bpf_filter.empty()) {
        struct bpf_program prog{};
        if (pcap_compile(pImpl->handle, &prog, pImpl->opts.bpf_filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::string error = std::string("pcap_compile failed: ") + pcap_geterr(pImpl->handle);
            pcap_close(pImpl->handle);
            pImpl->handle = nullptr;
            throw std::runtime_error(error);
        }
        if (pcap_setfilter(pImpl->handle, &prog) == -1) {
            std::string error = std::string("pcap_setfilter failed: ") + pcap_geterr(pImpl->handle);
            pcap_freecode(&prog);
            pcap_close(pImpl->handle);
            pImpl->handle = nullptr;
            throw std::runtime_error(std::string("pcap_compile failed: ") + pcap_geterr(pImpl->handle));
        }
        pcap_freecode(&prog);
    }
    
    pImpl->running.store(true);
    pImpl->worker = std::thread([this]() {
        // pcap_loop will call our static callback
        int ret = pcap_loop(pImpl->handle, 0, ::pcap_bridge, reinterpret_cast<u_char*>(pImpl));
        // if pcap_loop returns, set running to false
        pImpl->running.store(false);
        (void)ret; // suppress unused variable warning
    });
}

void PcapAdapter::stop() {
    if (!pImpl->running.load()) {
        if (pImpl->worker.joinable()) {
            pImpl->worker.join();
        }
        return;
    }
    pcap_breakloop(pImpl->handle);
    if (pImpl->worker.joinable()) {
        pImpl->worker.join();
    }
    pImpl->running.store(false);
}

void PcapAdapter::setFilter(const std::string& bpf) {
    std::lock_guard<std::mutex> lock(pImpl->filter_mtx);
    if (!pImpl->handle) throw std::runtime_error("pcap handle not open");
    struct bpf_program prog{};
    if (pcap_compile(pImpl->handle, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        throw std::runtime_error(std::string("pcap_compile failed: ") + pcap_geterr(pImpl->handle));
    }
    if (pcap_setfilter(pImpl->handle, &prog) == -1) {
        pcap_freecode(&prog);
        throw std::runtime_error(std::string("pcap_setfilter failed: ") + pcap_geterr(pImpl->handle));
    }
    pcap_freecode(&prog);
}