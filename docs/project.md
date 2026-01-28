# FTP PCAP Analyzer (Refactored Architecture)

This document contains the refactored multi-file architecture for the FTP PCAP reconstruction tool.
Each section corresponds to a file in the recommended project structure.

---

## 📁 Project Structure

```
ftp-analyzer/
│
├── src/
│   ├── main.cpp
│   ├── pcap_reader.cpp
│   ├── pcap_reader.h
│   ├── link_layer.cpp
│   ├── link_layer.h
│   ├── ftp_parser.cpp
│   ├── ftp_parser.h
│   ├── tcp_reassembly.cpp
│   ├── tcp_reassembly.h
│   └── session_manager.h
│
└── CMakeLists.txt
```

---

# ===================== src/session_manager.h =====================

```cpp
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
```

---

# ===================== src/link_layer.h =====================

```cpp
#pragma once

#include <pcap.h>

class LinkLayer {
public:
    static int detectOffset(pcap_t* handle);
};
```

---

# ===================== src/link_layer.cpp =====================

```cpp
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
```

---

# ===================== src/ftp_parser.h =====================

```cpp
#pragma once

#include <string>
#include <cstdint>

class FTPParser {
public:
    static bool parsePASV(const std::string& msg, uint16_t& port);
};
```

---

# ===================== src/ftp_parser.cpp =====================

```cpp
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
```

---

# ===================== src/tcp_reassembly.h =====================

```cpp
#pragma once

#include "session_manager.h"
#include <string>

class TCPReassembly {
public:
    static void reassemble(const SessionMap& sessions,
                           const std::string& outfile);
};
```

---

# ===================== src/tcp_reassembly.cpp =====================

```cpp
#include "tcp_reassembly.h"
#include <fstream>
#include <algorithm>
#include <iostream>

void TCPReassembly::reassemble(const SessionMap& sessions,
                              const std::string& outfile) {

    if (sessions.empty()) {
        std::cout << "No data found" << std::endl;
        return;
    }

    auto& vec = sessions.begin()->second;

    std::vector<Segment> data = vec;

    std::sort(data.begin(), data.end(),
              [](auto& a, auto& b) {
                  return a.seq < b.seq;
              });

    std::ofstream out(outfile, std::ios::binary);

    uint32_t next = data[0].seq;

    for (auto& s : data) {

        if (s.seq < next)
            continue;

        out.write((char*)s.data.data(),
                  s.data.size());

        next = s.seq + s.data.size();
    }

    out.close();

    std::cout << "[+] Reconstructed: "
              << outfile << std::endl;
}
```

---

# ===================== src/pcap_reader.h =====================

```cpp
#pragma once

#include <pcap.h>
#include "session_manager.h"

class PcapReader {
public:
    static bool process(const char* file,
                        SessionMap& sessions,
                        uint16_t& data_port);
};
```

---

# ===================== src/pcap_reader.cpp =====================

```cpp
#include "pcap_reader.h"
#include "link_layer.h"
#include "ftp_parser.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>

bool PcapReader::process(const char* file,
                         SessionMap& sessions,
                         uint16_t& data_port) {

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle =
        pcap_open_offline(file, errbuf);

    if (!handle) {
        std::cerr << errbuf << std::endl;
        return false;
    }

    int offset = LinkLayer::detectOffset(handle);

    if (offset < 0)
        return false;

    struct pcap_pkthdr* header;
    const u_char* packet;

    int ret;

    while ((ret = pcap_next_ex(handle,
                              &header,
                              &packet)) >= 0) {

        auto ip =
            (struct ip*)(packet + offset);

        if (ip->ip_p != IPPROTO_TCP)
            continue;

        uint32_t ip_len = ip->ip_hl * 4;

        auto tcp =
            (struct tcphdr*)(packet + offset + ip_len);

        uint32_t tcp_len = tcp->th_off * 4;

        uint32_t pos = offset + ip_len + tcp_len;

        if (pos >= header->caplen)
            continue;

        uint32_t payload_len = header->caplen - pos;
        const u_char* payload = packet + pos;

        uint16_t src_port = ntohs(tcp->th_sport);
        uint16_t dst_port = ntohs(tcp->th_dport);

        /* Control Channel */

        if (src_port == 21 || dst_port == 21) {

            std::string msg((char*)payload,
                            payload_len);

            if (msg.find("227") != std::string::npos) {

                FTPParser::parsePASV(msg,
                                     data_port);
            }
        }

        /* Data Channel */

        if (data_port == 0)
            continue;

        if (src_port == data_port ||
            dst_port == data_port) {

            ConnKey key{
                ip->ip_src.s_addr,
                ip->ip_dst.s_addr,
                src_port,
                dst_port
            };

            Segment seg;

            seg.seq = ntohl(tcp->th_seq);

            seg.data.assign(payload,
                            payload + payload_len);

            sessions[key].push_back(seg);
        }
    }

    pcap_close(handle);
    return true;
}
```

---

# ===================== src/main.cpp =====================

```cpp
#include "pcap_reader.h"
#include "tcp_reassembly.h"

#include <iostream>

int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cout << "Usage: " << argv[0]
                  << " <pcap> <output>" << std::endl;
        return 1;
    }

    SessionMap sessions;
    uint16_t data_port = 0;

    if (!PcapReader::process(argv[1],
                             sessions,
                             data_port)) {

        return 1;
    }

    TCPReassembly::reassemble(sessions,
                              argv[2]);

    return 0;
}
```

---

# ===================== CMakeLists.txt =====================

```cmake
cmake_minimum_required(VERSION 3.10)
project(ftp_analyzer)

set(CMAKE_CXX_STANDARD 17)

find_package(PCAP REQUIRED)

include_directories(${PCAP_INCLUDE_DIRS} src)

add_executable(ftp_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/link_layer.cpp
    src/ftp_parser.cpp
    src/tcp_reassembly.cpp
)

target_link_libraries(ftp_analyzer
    ${PCAP_LIBRARIES}
)
```

---

# ✅ Build Instructions

```bash
mkdir build
cd build
cmake ..
make
```

Binary:

```
./ftp_analyzer <pcap> <output>
```

---

# 🎯 Result

This refactored architecture separates concerns and enables easy extension for:

* IPv6
* Active FTP
* Multi-session
* Retransmission handling
* CLI filters

Each feature can now be implemented in isolated modules.
