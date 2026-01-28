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
