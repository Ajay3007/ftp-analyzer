#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <algorithm>
#include <regex>

using namespace std;

/* ================= TCP Segment ================= */

struct Segment {
    uint32_t seq;
    vector<uint8_t> data;
};

/* ================= Connection Key ================= */

struct ConnKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    // Define how to compare this ConnKey with another ConnKey.
    // ConnKey is used as a key in a map. In C++, std::map needs to know:
    // “How do I compare two keys?” Because C++ wouldn’t know how to sort keys in map.
    bool operator<(const ConnKey& o) const {
        return tie(src_ip, dst_ip, src_port, dst_port) <
               tie(o.src_ip, o.dst_ip, o.src_port, o.dst_port);
    }
};

/* ================= Globals ================= */

map<ConnKey, vector<Segment>> tcp_streams;

uint16_t ftp_data_port = 0;

int g_link_offset = 0;

/* ================= PASV Parser ================= */

bool parsePASV(const string& s, uint16_t& port) {

    regex r("\\((\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)\\)");
    smatch m;   // Match object -> A container that holds matched pieces.

    if (regex_search(s, m, r)) {    // Search inside string s using regex r. If found → store result in m.

        int p1 = stoi(m[5]);
        int p2 = stoi(m[6]);

        port = p1 * 256 + p2;

        return true;
    }

    return false;
}

/* ================= Packet Handler ================= */

void handlePacket(const u_char* packet, uint32_t len) {

    /* IP */

    auto ip =
        (struct ip*)(packet + g_link_offset);

    if (ip->ip_p != IPPROTO_TCP)
        return;

    uint32_t ip_len = ip->ip_hl * 4;

    /* TCP */

    auto tcp =
        (struct tcphdr*)(packet +
                         g_link_offset +
                         ip_len);

    uint32_t tcp_len = tcp->th_off * 4;

    uint32_t offset =
        g_link_offset +
        ip_len +
        tcp_len;

    if (offset >= len)
        return;

    uint32_t payload_len = len - offset;

    const u_char* payload =
        packet + offset;

    /* IP + Ports */

    uint32_t src_ip =
        ip->ip_src.s_addr;

    uint32_t dst_ip =
        ip->ip_dst.s_addr;

    uint16_t src_port =
        ntohs(tcp->th_sport);

    uint16_t dst_port =
        ntohs(tcp->th_dport);

    /* ========== FTP CONTROL ========== */

    if (src_port == 21 || dst_port == 21) {

        if (payload_len == 0)
            return;

        // Take payload_len bytes starting at payload, treat them as characters, and make a C++ string.
        string msg((char*)payload,
                   payload_len);    

        if (msg.find("227") != string::npos) {

            uint16_t port;

            if (parsePASV(msg, port)) {

                ftp_data_port = port;

                cout << "[+] PASV Data Port: "
                     << port << endl;
            }
        }
    }

    /* ========== DATA CHANNEL ========== */

    if (ftp_data_port == 0)
        return;

    if (src_port == ftp_data_port ||
        dst_port == ftp_data_port) {

        if (payload_len == 0)
            return;

        ConnKey key{    // brace `{}` initialization to create and initialize objects
            src_ip,
            dst_ip,
            src_port,
            dst_port
        };

        Segment seg;

        // Convert TCP sequence number to machine format and store it.
        seg.seq =
            ntohl(tcp->th_seq); // Network → Host conversion (32-bit)

        seg.data.assign(payload,
                        payload + payload_len); // Copy packet bytes into seg.data.

        tcp_streams[key].push_back(seg);    // Add this packet segment to its TCP connection list
    }
}

/* ================= Reassembly ================= */

void reassemble(const string& outfile) {

    if (tcp_streams.empty()) {

        cout << "No data found\n";
        return;
    }

    // Single file transfer -> take first session only
    auto& vec =
        tcp_streams.begin()->second; // Get the vector of segments of first connection.

    // Sort by seg.seq ascending
    sort(vec.begin(), vec.end(),
         [](auto& a, auto& b) {
             return a.seq < b.seq;
         });

    // ios::binary -> Write raw bytes. No modification.
    ofstream out(outfile, ios::binary);     // Opens output file

    uint32_t next = vec[0].seq; // first packet seq

    for (auto& s : vec) {   // For every Segment in vec.

        if (s.seq < next)   // This handles TCP retransmissions
            continue;   // Skips duplicate packets

        out.write((char*)s.data.data(),
                  s.data.size());   // Writes TCP data in correct order

        next = s.seq + s.data.size();
    }

    out.close();    // Flushes buffer and closes file.

    cout << "[+] Reconstructed: "
         << outfile << endl;
}

/* ================= MAIN ================= */

int main(int argc, char* argv[]) {

    if (argc != 3) {

        cout << "Usage: " << argv[0]
             << " <pcap> <output>\n";

        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle =
        pcap_open_offline(argv[1], errbuf);

    if (!handle) {

        cout << "PCAP Error: "
             << errbuf << endl;

        return 1;
    }

    /* Detect link layer */

    int dl = pcap_datalink(handle);

    if (dl == DLT_EN10MB) {

        g_link_offset =
            sizeof(struct ether_header);

        cout << "[+] Ethernet capture\n";
    }
    else if (dl == DLT_NULL) {

        g_link_offset = 4;

        cout << "[+] Loopback capture\n";
    }
    else {

        cout << "Unsupported datalink: "
             << dl << endl;

        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    int ret;

    while ((ret = pcap_next_ex(
                handle,
                &header,
                &packet)) >= 0) {

        handlePacket(packet,
                     header->caplen);   // header->caplen : Number of bytes captured.
    }

    pcap_close(handle);     // Closes file and frees memory.

    reassemble(argv[2]);

    return 0;
}
