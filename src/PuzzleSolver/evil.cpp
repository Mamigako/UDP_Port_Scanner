#include "../include/puzzlesolver.h"

int Evil_port(char *ip_string, int port, uint32_t signature)
{
    /* The dark side of network programming is a pathway to many abilities some consider to be...unnatural.
       I am an evil port, I will only communicate with evil processes! (https://en.wikipedia.org/wiki/Evil_bit)
       Send us a message of 4 bytes containing the signature that you created with S.E.C.R.E.T
    */
    std::cout << "----------------------EVIL PORT-----------------------" << std::endl;
    uint32_t evil_secret_port = 0;

    // We use a raw socket so we fully control the IP header bits
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket < 0)
    {
        perror("raw socket");
        return 1;
    }

    sockaddr_in server_address{};
    int udp_socket = open_udp_connected(ip_string, port, &server_address);
    if (udp_socket < 0)
    {
        close(raw_socket);
        return 1;
    }

    int on = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt IP_HDRINCL");
        close(raw_socket);
        close(udp_socket);
        return 1;
    }

    struct sockaddr_in local_addr{};
    socklen_t la_len = sizeof(local_addr);
    if (getsockname(udp_socket, (struct sockaddr *)&local_addr, &la_len) < 0)
    {
        perror("getsockname");
        close(udp_socket);
        return 1;
    }

    std::string message;
    uint32_t sig_net = htonl(signature);
    message.assign(reinterpret_cast<const char *>(&sig_net), 4);

    std::random_device rd;

    udpmsg udpmessage;
    udpmessage.message = message;

    udpmessage.ipheader.version = 4;
    udpmessage.ipheader.daddr = server_address.sin_addr.s_addr;
    udpmessage.ipheader.saddr = local_addr.sin_addr.s_addr;

    uint16_t total_len = static_cast<uint16_t>(sizeof(iphdr) + sizeof(udphdr) + udpmessage.message.size());
    udpmessage.ipheader.tot_len = htons(total_len);
    udpmessage.ipheader.protocol = IPPROTO_UDP;
    udpmessage.ipheader.ihl = 5;
    udpmessage.ipheader.tos = 0;
    udpmessage.ipheader.ttl = 64;
    udpmessage.ipheader.id = htons(static_cast<uint16_t>(rd() & 0xffff));
    udpmessage.ipheader.frag_off = htons(0x8000); // Evil bit set
    udpmessage.ipheader.check = ip_checksum(reinterpret_cast<uint16_t *>(&udpmessage.ipheader),
                                            udpmessage.ipheader.ihl * 2);

    udpmessage.udpheader.source = local_addr.sin_port;
    udpmessage.udpheader.dest = htons(port);
    udpmessage.udpheader.len = htons(sizeof(udpmessage.udpheader) + message.size());
    udpmessage.udpheader.check = udp_checksum(&udpmessage.ipheader,
                                              &udpmessage.udpheader,
                                              udpmessage.message.c_str(),
                                              udpmessage.message.size());

    const size_t pkt_len = sizeof(udpmessage.ipheader) +
                           sizeof(udpmessage.udpheader) +
                           udpmessage.message.size();

    std::vector<uint8_t> pkt(pkt_len);
    uint8_t *p = pkt.data();

    std::memcpy(p, &udpmessage.ipheader, sizeof(udpmessage.ipheader));
    p += sizeof(udpmessage.ipheader);

    std::memcpy(p, &udpmessage.udpheader, sizeof(udpmessage.udpheader));
    p += sizeof(udpmessage.udpheader);

    std::memcpy(p, udpmessage.message.data(), udpmessage.message.size());

    // We retry 5 times since UDP is not reliable and can drop packets
    for (int i = 0; i < 5; i++)
    {
        ssize_t sent = sendto(raw_socket, pkt.data(), pkt.size(), 0,
                              (struct sockaddr *)&server_address, sizeof(server_address));

        if (sent == -1)
        {
            perror("sendto(raw)");
        }
        else
        {
            int ready = wait_readable(udp_socket, LONG_REPLY_SEC, REPLY_USEC);
            if (ready <= 0)
            {
                if (ready == 0)
                {
                    std::cerr << "Timeout waiting for Evil port reply\n";
                    continue;
                }
                else
                {
                    perror("select");
                }

                close(raw_socket);
                close(udp_socket);
                return 1;
            }

            else
            {
                char rbuf[1024];
                ssize_t n = recv(udp_socket, rbuf, sizeof(rbuf) - 1, 0);
                if (n <= 0)
                {
                    if (n == 0)
                    {
                        std::cerr << "peer closed\n";
                    }
                    else
                    {
                        perror("recv");
                    }
                    close(raw_socket);
                    close(udp_socket);
                    return 1;
                }

                rbuf[n] = '\0';
                printf("Evil port replied: %.*s\n", (int)n, rbuf);

                std::string s(rbuf, n);
                std::regex re(R"(\d{4})"); // Regex to catch the port number
                std::smatch m;

                if (std::regex_search(s, m, re))
                {
                    evil_secret_port = static_cast<uint32_t>(std::stoi(m.str(0)));
                    std::cout << "Parsed secret port: " << evil_secret_port << "\n";
                }
                else
                {
                    std::cerr << "No 4xxx port found in reply; full text was:\n"
                              << s << "\n";
                    close(raw_socket);
                    close(udp_socket);
                    return 1;
                }

                break;
            }
        }
    }

    close(raw_socket);
    close(udp_socket);
    return evil_secret_port;
}
