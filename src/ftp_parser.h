#pragma once

#include <string>
#include <cstdint>

class FTPParser {
public:
    static bool parsePASV(const std::string& msg, uint16_t& port);
};
