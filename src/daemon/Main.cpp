#include "NetMonDaemon.h"
#include <csignal>
#include <iostream>

// ===================================================================
// MAIN ENTRY POINT
// ===================================================================

int main(int argc, char* argv[]) {
    std::string config_path;
    for (int i = 1; i < argc - 1; ++i) {
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