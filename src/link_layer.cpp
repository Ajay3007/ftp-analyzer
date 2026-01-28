#include "link_layer.h"
#include <net/ethernet.h>
#include <iostream>

int LinkLayer::detectOffset(pcap_t* handle) {

    int dl = pcap_datalink(handle);

    if (dl == DLT_EN10MB) {
        std::cout << "[+] Ethernet capture" << std::endl;
        return sizeof(struct ether_header);
    }

    if (dl == DLT_NULL) {
        std::cout << "[+] Loopback capture" << std::endl;
        return 4;
    }

    std::cerr << "Unsupported datalink: " << dl << std::endl;
    return -1;
}
