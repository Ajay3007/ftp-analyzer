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
