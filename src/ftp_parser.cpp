#include "ftp_parser.h"

#include <regex>
#include <iostream>


/* ================= PASV ================= */

bool FTPParser::parsePASV(const std::string& s,
                          uint16_t& port) {

    std::regex r(
        "\\((\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)\\)");

    std::smatch m;

    if (std::regex_search(s, m, r)) {

        int p1 = std::stoi(m[5]);
        int p2 = std::stoi(m[6]);

        port = p1 * 256 + p2;

        std::cout << "[+] PASV Port: "
                  << port << std::endl;

        return true;
    }

    return false;
}


/* ================= EPSV ================= */

bool FTPParser::parseEPSV(const std::string& s,
                          uint16_t& port) {

    std::regex r("\\(\\|\\|\\|(\\d+)\\|\\)");

    std::smatch m;

    if (std::regex_search(s, m, r)) {

        port = std::stoi(m[1]);

        std::cout << "[+] EPSV Port: "
                  << port << std::endl;

        return true;
    }

    return false;
}


/* ================= PORT ================= */

bool FTPParser::parsePORT(const std::string& s,
                          uint16_t& port) {

    std::regex r(
        "PORT (\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)");

    std::smatch m;

    if (std::regex_search(s, m, r)) {

        int p1 = std::stoi(m[5]);
        int p2 = std::stoi(m[6]);

        port = p1 * 256 + p2;

        std::cout << "[+] PORT (Active) Port: "
                  << port << std::endl;

        return true;
    }

    return false;
}


/* ================= EPRT ================= */

bool FTPParser::parseEPRT(const std::string& s,
                          uint16_t& port) {

    std::regex r("EPRT \\|.\\|.*\\|(\\d+)\\|");

    std::smatch m;

    if (std::regex_search(s, m, r)) {

        port = std::stoi(m[1]);

        std::cout << "[+] EPRT (Active) Port: "
                  << port << std::endl;

        return true;
    }

    return false;
}
