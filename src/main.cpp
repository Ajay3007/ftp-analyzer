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
