#include "net/PcapAdapter.h"
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <cstdlib>

std::atomic<bool> running{true};

void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ", stopping..." << std::endl;
    running.store(false);
}

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -i INTERFACE    Capture from network interface (e.g., en0)\n"
              << "  -r FILE         Read from pcap file (offline mode)\n"
              << "  -f FILTER       BPF filter expression\n"
              << "  -s SNAPLEN      Snapshot length (default: 65535)\n"
              << "  -p              Enable promiscuous mode\n"
              << "  -h              Show this help message\n"
              << "  --no-signals    Disable signal handling (for tests)\n\n"
              << "Examples:\n"
              << "  " << prog_name << " -i en0                    # Capture from en0\n"
              << "  " << prog_name << " -i en0 -f \"tcp port 80\"   # Capture HTTP traffic\n"
              << "  " << prog_name << " -r sample.pcap            # Read from file\n";
}

int main(int argc, char* argv[]) {
    PcapAdapter::Options opts;
    // Use struct defaults: promiscuous=true, snaplen=65535, etc.
    bool offline_mode = false;
    bool enable_signals = true;
    int offline_packet_limit = -1; // -1 means no limit

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "-i" && i + 1 < argc) {
            opts.iface_or_file = argv[++i];
            offline_mode = false;
        } else if (arg == "-r" && i + 1 < argc) {
            opts.iface_or_file = argv[++i];
            offline_mode = true;
        } else if (arg == "-f" && i + 1 < argc) {
            opts.bpf_filter = argv[++i];
        } else if (arg == "-s" && i + 1 < argc) {
            opts.snaplen = std::stoi(argv[++i]);
        } else if (arg == "-p") {
            opts.promiscuous = true;
        } else if (arg == "--no-signals") {
            enable_signals = false;
        } else if (arg == "--offline-limit" && i + 1 < argc) {
            offline_packet_limit = std::stoi(argv[++i]);
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    // Default to loopback if no interface or file specified
    if (opts.iface_or_file.empty()) {
        opts.iface_or_file = "lo0";
        std::cout << "No interface specified, using default: lo0" << std::endl;
    }

    opts.read_offline = offline_mode;

    // Setup signal handler unless disabled (for tests)
    if (enable_signals) {
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
    }

    try {
        PcapAdapter adapter(opts);

        std::cout << "Starting capture from: " << adapter.source() << std::endl;
        if (!opts.bpf_filter.empty()) {
            std::cout << "BPF Filter: " << opts.bpf_filter << std::endl;
        }

        uint64_t packet_count = 0;
        bool stop_requested = false;
        adapter.startCapture([&](const PacketMeta& meta, const uint8_t* data, size_t len) {
            packet_count++;

            // Print packet summary every 100 packets
            if (packet_count % 100 == 0) {
                std::cout << "Captured " << packet_count << " packets..." << std::endl;
            }

            // For offline mode, stop after processing all packets or limit
            if (offline_mode && offline_packet_limit > 0 && packet_count >= static_cast<uint64_t>(offline_packet_limit)) {
                running.store(false);
                stop_requested = true;
            }
        });

        // Main loop
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (offline_mode && stop_requested) break;
        }

        adapter.stopCapture();
        std::cout << "\nTotal packets captured: " << packet_count << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}