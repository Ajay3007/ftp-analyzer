#pragma once

#include <pcap.h>
#include "session_manager.h"

class PcapReader {
public:
    static bool process(const char* file,
                        SessionMap& sessions,
                        uint16_t& data_port);
};
