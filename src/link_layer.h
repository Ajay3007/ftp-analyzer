#pragma once

#include <pcap.h>

class LinkLayer {
public:
    static int detectOffset(pcap_t* handle);
};
