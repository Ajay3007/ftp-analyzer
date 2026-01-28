#include "ftp_parser.h"
#include <regex>

bool FTPParser::parsePASV(const std::string& s, uint16_t& port) {

    std::regex r("\\((\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)\\)");
    std::smatch m;

    if (std::regex_search(s, m, r)) {

        int p1 = std::stoi(m[5]);
        int p2 = std::stoi(m[6]);

        port = p1 * 256 + p2;
        return true;
    }

    return false;
}
