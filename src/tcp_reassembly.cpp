#include "tcp_reassembly.h"

#include <fstream>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <map>


void TCPReassembly::reassemble(const SessionMap& sessions,
                              const std::string& outfile) {

    if (sessions.empty()) {

        std::cout << "No data found" << std::endl;
        return;
    }


    for (const auto& pair : sessions) {

        const auto& vec = pair.second;

        if (vec.empty())
            continue;


        /* ============================
         * Sort Segments
         * ============================ */

        std::vector<Segment> segs = vec;

        std::sort(segs.begin(),
                  segs.end(),
                  [](const Segment& a,
                     const Segment& b) {

                      return a.seq < b.seq;
                  });


        /* ============================
         * Reassembly Buffer
         * ============================ */

        std::map<uint32_t,
                 std::vector<uint8_t>> buffer;


        uint32_t base_seq = segs[0].seq;


        /* ============================
         * Insert Segments
         * ============================ */

        for (const auto& s : segs) {

            buffer[s.seq] = s.data;
        }


        /* ============================
         * Generate Output Filename
         * ============================ */

        std::ostringstream name;

        name << outfile << "_"
             << pair.first.filename;

        std::string filename = name.str();


        /* ============================
         * Write Stream
         * ============================ */

        std::ofstream out(filename,
                          std::ios::binary);


        uint32_t expected = base_seq;


        for (auto& it : buffer) {

            uint32_t seq = it.first;
            auto& data = it.second;


            /* Skip old/retransmitted data */
            if (seq < expected) {

                uint32_t diff =
                    expected - seq;

                if (diff >= data.size())
                    continue;

                out.write(
                    (char*)data.data() + diff,
                    data.size() - diff);

                expected +=
                    data.size() - diff;

                continue;
            }


            /* Gap detected */
            if (seq > expected) {

                uint32_t gap =
                    seq - expected;

                std::vector<char> zeros(
                    gap, 0);

                out.write(zeros.data(),
                          gap);

                expected += gap;
            }


            /* Write data */
            out.write(
                (char*)data.data(),
                data.size());

            expected += data.size();
        }


        out.close();


        std::cout << "[+] Reconstructed: "
                  << filename << std::endl;
    }
}
