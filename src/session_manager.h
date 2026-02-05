#pragma once

#include <vector>
#include <map>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <string>

/* ================================
 * TCP Segment
 * ================================ */
struct Segment {
    uint32_t seq;
    std::vector<uint8_t> data;
};

/* ================================
 * IP Address (IPv4 + IPv6)
 * ================================ */
struct IPAddress {

    bool is_v6 = false;

    union {
        uint32_t v4;
        struct in6_addr v6;
    };

    bool operator<(const IPAddress& o) const {

        if (is_v6 != o.is_v6)
            return is_v6 < o.is_v6;

        if (!is_v6)
            return v4 < o.v4;

        return memcmp(&v6, &o.v6, sizeof(v6)) < 0;
    }
};

/* ================================
 * FTP Session State
 * ================================ */
struct FtpSession {

    enum State {
        CONNECTED,
        PASV_SET,
        TRANSFERRING,
        DONE
    };

    State state = CONNECTED;

    uint16_t data_port = 0;
    std::string filename;
};

/* ================================
 * Connection Key
 * ================================ */
struct ConnKey {

    IPAddress src_ip;
    IPAddress dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    std::string filename;

    bool operator<(const ConnKey& o) const {

        return std::tie(src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        filename)
            < std::tie(o.src_ip,
                       o.dst_ip,
                       o.src_port,
                       o.dst_port,
                       o.filename);
    }
};

/* ================================
 * Control Session Key
 * ================================ */
struct ControlKey {

    IPAddress client_ip;
    uint16_t client_port;

    bool operator<(const ControlKey& o) const {

        return std::tie(client_ip, client_port) <
               std::tie(o.client_ip, o.client_port);
    }
};

using SessionMap = std::map<ConnKey, std::vector<Segment>>;
using ControlMap = std::map<ControlKey, FtpSession>;
