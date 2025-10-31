#include "PcapAdapter.h"
#include <iostream>

int main() {
    PcapAdapter::Options opts;
    opts.iface_or_file = "en0";
    opts.promiscuous = true;

    try {
        PcapAdapter adapter(opts);
        std::cout << "source: " << adapter.source() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}