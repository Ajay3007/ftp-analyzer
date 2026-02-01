#include "tcp_reassembly.h"

#include <fstream>
#include <algorithm>
#include <iostream>
#include <sstream>


void TCPReassembly::reassemble(const SessionMap& sessions,
                              const std::string& outfile) {

    if (sessions.empty()) {

        std::cout << "No data found" << std::endl;
        return;
    }

    int index = 1;


    /* Process Each TCP Session */

    for (const auto& pair : sessions) {

        const auto& vec = pair.second;

        if (vec.empty())
            continue;

        std::vector<Segment> data = vec;

        std::sort(data.begin(),
                  data.end(),
                  [](auto& a, auto& b) {
                      return a.seq < b.seq;
                  });


        /* Generate Output Filename */

        std::ostringstream name;

        name << outfile << "_" << pair.first.filename;


        std::string filename = name.str();


        /* Write File */

        std::ofstream out(filename,
                          std::ios::binary);

        uint32_t next = data[0].seq;

        for (auto& s : data) {

            if (s.seq < next)
                continue;

            out.write(
                (char*)s.data.data(),
                s.data.size());

            next = s.seq + s.data.size();
        }

        out.close();

        std::cout << "[+] Reconstructed: "
                  << filename << std::endl;

        index++;
    }
}
