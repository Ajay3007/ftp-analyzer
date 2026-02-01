#pragma once

#include <vector>
#include <map>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>   // in6_addr
#include <string>


/* ================================
 * TCP Segment Structure
 * ================================ */
struct Segment {
    uint32_t seq;
    std::vector<uint8_t> data;
};


/* ================================
 * Unified IP Address (IPv4 + IPv6)
 * ================================ */
struct IPAddress {

    bool is_v6;   // false = IPv4, true = IPv6

    union {
        uint32_t v4;        // IPv4 address
        struct in6_addr v6; // IPv6 address
    };

    /* Compare two IP addresses */
    bool operator<(const IPAddress& o) const {

        // IPv4 always comes before IPv6
        if (is_v6 != o.is_v6)
            return is_v6 < o.is_v6;

        // Both IPv4
        if (!is_v6)
            return v4 < o.v4;

        // Both IPv6
        return memcmp(&v6, &o.v6, sizeof(v6)) < 0;
    }
};


/* ================================
 * Connection Key (IPv4 + IPv6)
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
 * Session Map
 * ================================ */
using SessionMap = std::map<ConnKey, std::vector<Segment>>;
