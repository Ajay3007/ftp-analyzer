#pragma once

#include <string>
#include <cstdint>

class FTPParser {
public:

    // Passive IPv4
    static bool parsePASV(const std::string& msg,
                          uint16_t& port);

    // Passive IPv6
    static bool parseEPSV(const std::string& msg,
                          uint16_t& port);

    // Active IPv4
    static bool parsePORT(const std::string& msg,
                          uint16_t& port);

    // Active IPv6
    static bool parseEPRT(const std::string& msg,
                          uint16_t& port);
};
