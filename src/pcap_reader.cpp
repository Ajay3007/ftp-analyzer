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
                         uint16_t&) {

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


    /* ===========================
     * FTP Control Sessions
     * =========================== */
    ControlMap control_sessions;


    struct pcap_pkthdr* header;
    const u_char* packet;

    int ret;

    while ((ret = pcap_next_ex(handle,
                              &header,
                              &packet)) >= 0) {

        if (header->caplen <= offset)
            continue;

        const u_char* net = packet + offset;

        uint8_t version = net[0] >> 4;

        IPAddress src_ip{}, dst_ip{};
        uint32_t ip_len = 0;

        const struct tcphdr* tcp = nullptr;


        /* ================= IPv4 ================= */

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


        /* ================= IPv6 ================= */

        else if (version == 6) {

            const struct ip6_hdr* ip6 =
                (const struct ip6_hdr*)net;

            if (ip6->ip6_nxt != IPPROTO_TCP)
                continue;

            ip_len = sizeof(struct ip6_hdr);

            src_ip.is_v6 = true;
            dst_ip.is_v6 = true;

            memcpy(&src_ip.v6,
                   &ip6->ip6_src,
                   sizeof(in6_addr));

            memcpy(&dst_ip.v6,
                   &ip6->ip6_dst,
                   sizeof(in6_addr));

            tcp = (const struct tcphdr*)
                (net + ip_len);
        }

        else {
            continue;
        }


        /* ================= TCP ================= */

        uint32_t tcp_len = tcp->th_off * 4;

        uint32_t pos =
            offset + ip_len + tcp_len;

        if (pos >= header->caplen)
            continue;

        uint32_t payload_len =
            header->caplen - pos;

        const u_char* payload =
            packet + pos;

        uint16_t src_port =
            ntohs(tcp->th_sport);

        uint16_t dst_port =
            ntohs(tcp->th_dport);


        /* ================= Control Channel ================= */

        bool is_control =
            (src_port == 21 || dst_port == 21);

        if (is_control) {

            ControlKey ck;

            if (src_port == 21) {
                ck.client_ip = dst_ip;
                ck.client_port = dst_port;
            } else {
                ck.client_ip = src_ip;
                ck.client_port = src_port;
            }

            auto& sess = control_sessions[ck];


            std::string msg(
                (char*)payload,
                payload_len);


            /* STOR */

            if (msg.find("STOR") != std::string::npos) {

                size_t p = msg.find("STOR");

                sess.filename =
                    msg.substr(p + 5);

                sess.filename.erase(
                    sess.filename.find_last_not_of("\r\n") + 1);

                sess.state =
                    FtpSession::TRANSFERRING;

                std::cout << "[+] File: "
                          << sess.filename << std::endl;
            }


            /* PASV / EPSV */

            if (FTPParser::parsePASV(msg,
                                     sess.data_port) ||
                FTPParser::parseEPSV(msg,
                                     sess.data_port)) {

                sess.state =
                    FtpSession::PASV_SET;
            }


            /* PORT / EPRT */

            if (FTPParser::parsePORT(msg,
                                     sess.data_port) ||
                FTPParser::parseEPRT(msg,
                                     sess.data_port)) {

                sess.state =
                    FtpSession::PASV_SET;
            }
        }


        /* ================= Data Channel ================= */

        FtpSession* active = nullptr;


        for (auto& p : control_sessions) {

            auto& s = p.second;

            if (s.state ==
                    FtpSession::TRANSFERRING &&
                (src_port == s.data_port ||
                 dst_port == s.data_port)) {

                active = &s;
                break;
            }
        }

        if (!active)
            continue;


        ConnKey key{
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            active->filename
        };


        Segment seg;

        seg.seq =
            ntohl(tcp->th_seq);

        seg.data.assign(payload,
                        payload + payload_len);

        sessions[key].push_back(seg);


        /* ================= Close Session ================= */

        if (tcp->th_flags & (TH_FIN | TH_RST)) {

            if (active)
                active->state =
                    FtpSession::DONE;
        }
    }

    pcap_close(handle);

    return true;
}
