#include "pcap_reader.h"
#include "link_layer.h"
#include "ftp_parser.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <iostream>
#include <cstring>


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

        if (header->caplen <= offset)
            continue;

        const u_char* net = packet + offset;

        /* ===============================
         * Detect IP Version
         * =============================== */

        uint8_t version = net[0] >> 4;

        bool is_ipv6 = false;

        uint32_t ip_len = 0;

        IPAddress src_ip{};
        IPAddress dst_ip{};

        const struct tcphdr* tcp = nullptr;


        /* ===============================
         * IPv4
         * =============================== */

        if (version == 4) {

            const struct ip* ip4 =
                (const struct ip*)net;

            if (ip4->ip_p != IPPROTO_TCP)
                continue;

            ip_len = ip4->ip_hl * 4;

            src_ip.is_v6 = false;
            dst_ip.is_v6 = false;

            src_ip.v4 = ip4->ip_src.s_addr;
            dst_ip.v4 = ip4->ip_dst.s_addr;

            tcp = (const struct tcphdr*)
                (net + ip_len);
        }

        /* ===============================
         * IPv6
         * =============================== */

        else if (version == 6) {

            const struct ip6_hdr* ip6 =
                (const struct ip6_hdr*)net;

            if (ip6->ip6_nxt != IPPROTO_TCP)
                continue;

            ip_len = sizeof(struct ip6_hdr);

            src_ip.is_v6 = true;
            dst_ip.is_v6 = true;

            std::memcpy(&src_ip.v6,
                        &ip6->ip6_src,
                        sizeof(in6_addr));

            std::memcpy(&dst_ip.v6,
                        &ip6->ip6_dst,
                        sizeof(in6_addr));

            tcp = (const struct tcphdr*)
                (net + ip_len);
        }

        /* ===============================
         * Unknown IP Version
         * =============================== */

        else {
            continue;
        }


        /* ===============================
         * Parse TCP Header
         * =============================== */

        uint32_t tcp_len = tcp->th_off * 4;

        uint32_t pos = offset + ip_len + tcp_len;

        if (pos >= header->caplen)
            continue;

        uint32_t payload_len = header->caplen - pos;

        const u_char* payload =
            packet + pos;

        uint16_t src_port =
            ntohs(tcp->th_sport);

        uint16_t dst_port =
            ntohs(tcp->th_dport);


        /* ===============================
         * FTP Control Channel
         * =============================== */

        static std::string current_file;

        if (src_port == 21 || dst_port == 21) {

            std::string msg(
                (char*)payload,
                payload_len);

            // STOR filename
            if (msg.find("STOR") != std::string::npos) {

                size_t pos = msg.find("STOR");

                if (pos != std::string::npos) {

                    current_file =
                        msg.substr(pos + 5);

                    // Remove newline
                    current_file.erase(
                        current_file.find_last_not_of("\r\n") + 1);

                    std::cout << "[+] File: "
                            << current_file << std::endl;
                }
            }

            // PASV
            if (msg.find("227") != std::string::npos) {

                FTPParser::parsePASV(msg,
                                    data_port);
            }

            // EPSV
            else if (msg.find("229") != std::string::npos) {

                FTPParser::parseEPSV(msg,
                                    data_port);
            }

            // PORT
            else if (msg.find("PORT") != std::string::npos) {

                FTPParser::parsePORT(msg,
                                    data_port);
            }

            // EPRT
            else if (msg.find("EPRT") != std::string::npos) {

                FTPParser::parseEPRT(msg,
                                    data_port);
            }
        }


        /* ===============================
         * FTP Data Channel
         * =============================== */

        if (data_port == 0)
            continue;

        if (src_port == data_port ||
            dst_port == data_port) {

            ConnKey key{
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                current_file
            };


            Segment seg;

            seg.seq =
                ntohl(tcp->th_seq);

            seg.data.assign(
                payload,
                payload + payload_len);

            sessions[key].push_back(seg);
        }
    }

    pcap_close(handle);

    return true;
}
