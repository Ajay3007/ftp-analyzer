#pragma once

#include <vector>
#include <map>
#include <cstdint>

struct Segment {
    uint32_t seq;
    std::vector<uint8_t> data;
};

struct ConnKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator<(const ConnKey& o) const {
        return std::tie(src_ip, dst_ip, src_port, dst_port) <
               std::tie(o.src_ip, o.dst_ip, o.src_port, o.dst_port);
    }
};

using SessionMap = std::map<ConnKey, std::vector<Segment>>;
