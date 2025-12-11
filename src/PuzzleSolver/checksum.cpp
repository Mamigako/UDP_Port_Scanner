#include "../include/puzzlesolver.h"

int Checksum_port(char *ip_string, int port, uint32_t signature, std::string &secret_phrase)
{
    /* Send me a 4-byte message containing the signature you got from S.E.C.R.E.T
       in the first 4 bytes (in network byte order).
    */
    std::cout << "-------------------CHECKSUM PORT--------------------" << std::endl;
    uint16_t target_checksum = 0;
    uint32_t target_ip_net = 0;

    struct sockaddr_in server_address{};
    int udp_socket = open_udp_connected(ip_string, port, &server_address);
    if (udp_socket < 0)
    {
        return 1;
    }

    std::string message;
    uint32_t sig_net = htonl(signature);
    message.assign(reinterpret_cast<const char *>(&sig_net), 4);

    for (int i = 0; i < 5; i++) // We retry 5 times since UDP is not reliable and can drop packets
    {
        ssize_t sent = send(udp_socket, message.data(), message.size(), 0);
        if (sent < 0)
        {
            perror("send(signature)");
        }
        else
        {
            int ready = wait_readable(udp_socket, REPLY_SEC, REPLY_USEC);
            if (ready <= 0)
            {
                if (ready == 0)
                {
                    std::cerr << "Timeout waiting for Checksum port reply\n";
                    continue;
                }
                else
                {
                    perror("select");
                }

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
                    close(udp_socket);
                    return 1;
                }

                if (n >= 6)
                {
                    // In the last 6 bytes of the recived message, we have the
                    // 2-byte checksum and 4-byte IP address
                    printf("checksum port replied: %.*s\n", (int)(n - 6), rbuf);

                    uint16_t ck_net = 0;
                    std::memcpy(&ck_net, rbuf + (n - 6), 2);
                    std::memcpy(&target_ip_net, rbuf + (n - 4), 4);

                    target_checksum = ntohs(ck_net);

                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &target_ip_net, ipstr, sizeof(ipstr));
                    fprintf(stdout, "Target UDP checksum: 0x%04x\n", target_checksum);
                    fprintf(stdout, "Required inner source IP: %s\n", ipstr);

                    break;
                }
                else
                {
                    continue;
                }
            }
        }
    }

    if (target_checksum == 0 || target_ip_net == 0)
    {
        std::cerr << "Did not obtain target checksum/IP from server.\n";
        close(udp_socket);
        return 1;
    }

    // Now we build the encapsulated IPv4 + UDP
    udpmsg inner{};
    inner.message.assign(2, '\0'); // 2-byte fixup payload

    inner.ipheader.version = 4;
    inner.ipheader.ihl = 5;
    inner.ipheader.tos = 0;
    inner.ipheader.ttl = 64;
    inner.ipheader.protocol = IPPROTO_UDP;
    inner.ipheader.saddr = target_ip_net;
    inner.ipheader.daddr = server_address.sin_addr.s_addr;
    inner.ipheader.id = htons(0x1234);
    inner.ipheader.frag_off = 0;

    // Any inner ports are fine, the target only cares about the UDP checksum and inner source IP
    inner.udpheader.source = htons(54321);
    inner.udpheader.dest = htons(12345);
    inner.udpheader.len = htons(static_cast<uint16_t>(sizeof(udphdr) + inner.message.size()));

    inner.ipheader.tot_len = htons(static_cast<uint16_t>(sizeof(iphdr) + sizeof(udphdr) + inner.message.size()));
    inner.ipheader.check = 0;
    inner.ipheader.check = ip_checksum(reinterpret_cast<uint16_t *>(&inner.ipheader),
                                       inner.ipheader.ihl * 2);

    // I need to choose a 2-byte payload W so that the final UDP checksum equals "target_checksum".
    // The UDP checksum is the one's-complement of the sum of:
    //   pseudo-header + UDP header (with check=0) + payload.
    // Everything except the payload is fixed, so I precompute that constant part and call its
    // folded 16-bit value "A". The checksum I want to end up with corresponds to a folded sum
    // of "B = ~target_checksum" (because the UDP checksum is one's-complement).
    //
    // So the goal is: fold(A + W) == B  in one's-complement arithmetic.
    // Solving for W gives: W = B − A  (still in one's-complement).
    // I implement this as "add B to the bitwise complement of A and fold the carries";
    // this is the standard way to do one's-complement subtraction. After I get W, I write it
    // into the 2-byte payload in big-endian order so the verifier sees the same 16-bit word.
    uint32_t sum = predict_checksum(&inner.ipheader, &inner.udpheader);
    sum += ntohs(inner.udpheader.len); // pseudo-header UDP length
    sum += ntohs(inner.udpheader.len); // UDP header length field

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t A = static_cast<uint16_t>(sum & 0xFFFF);
    uint16_t B = static_cast<uint16_t>((~target_checksum) & 0xFFFF);

    uint32_t t = static_cast<uint32_t>(B) + static_cast<uint32_t>((~A) & 0xFFFF);
    while (t >> 16)
    {
        t = (t & 0xFFFF) + (t >> 16);
    }
    uint16_t W = static_cast<uint16_t>(t & 0xFFFF);

    inner.message[0] = static_cast<char>(W >> 8);
    inner.message[1] = static_cast<char>(W & 0xFF);

    inner.udpheader.check = 0;
    uint16_t verify = ntohs(udp_checksum(&inner.ipheader,
                                         &inner.udpheader,
                                         inner.message.data(),
                                         inner.message.size()));

    if (verify != target_checksum)
    {
        // fallback: if the folded sum misses the target, compute the one's-complement delta and adjust W once.
        uint32_t D = static_cast<uint16_t>((~target_checksum) & 0xFFFF);
        uint32_t S = static_cast<uint16_t>((~verify) & 0xFFFF);

        uint32_t delta = D + ((~S) & 0xFFFF);
        while (delta >> 16)
        {
            delta = (delta & 0xFFFF) + (delta >> 16);
        }
        uint16_t Delta = static_cast<uint16_t>(delta & 0xFFFF);

        uint32_t newW = static_cast<uint32_t>(W) + Delta;
        while (newW >> 16)
        {
            newW = (newW & 0xFFFF) + (newW >> 16);
        }
        W = static_cast<uint16_t>(newW & 0xFFFF);

        inner.message[0] = static_cast<char>(W >> 8);
        inner.message[1] = static_cast<char>(W & 0xFF);

        verify = ntohs(udp_checksum(&inner.ipheader,
                                    &inner.udpheader,
                                    inner.message.data(),
                                    inner.message.size()));

        if (verify != target_checksum)
        {
            std::cerr << "Verification failed after correction: expected 0x"
                      << std::hex << target_checksum << " got 0x" << verify << std::dec << "\n";
            close(udp_socket);
            return 1;
        }
    }

    inner.udpheader.check = htons(target_checksum);

    std::string innerpkt;
    innerpkt.resize(sizeof(iphdr) + sizeof(udphdr) + inner.message.size());
    {
        char *p = innerpkt.data();
        std::memcpy(p, &inner.ipheader, sizeof(iphdr));
        p += sizeof(iphdr);
        std::memcpy(p, &inner.udpheader, sizeof(udphdr));
        p += sizeof(udphdr);
        std::memcpy(p, inner.message.data(), inner.message.size());
    }

    for (int i = 0; i < 5; i++)
    {
        ssize_t sent2 = send(udp_socket, innerpkt.data(), innerpkt.size(), 0);
        if (sent2 != (ssize_t)innerpkt.size())
        {
            perror("send(inner)");
            continue;
        }

        int ready = wait_readable(udp_socket, REPLY_SEC, REPLY_USEC);
        if (ready <= 0)
        {
            if (ready == 0)
            {
                std::cerr << "Checksum: timeout waiting for secret phrase\n";
                continue;
            }
            else
            {
                perror("select");
                close(udp_socket);
                return 1;
            }
        }

        else
        {
            char buf2[1024];
            ssize_t n2 = recv(udp_socket, buf2, sizeof(buf2) - 1, 0);

            if (n2 <= 0)
            {
                if (n2 == 0)
                {
                    std::cerr << "peer closed\n";
                }
                else
                {
                    perror("recv");
                }
                close(udp_socket);
                return 1;
            }

            printf("checksum secret phrase: %.*s\n", (int)n2, buf2);

            std::string s(buf2, n2);
            std::regex re("\"(.*)\"$"); // regex to extract text within quotes at end of line
            std::smatch m;

            if (std::regex_search(s, m, re))
            {
                secret_phrase += m.str(1);
                break;
            }
        }
    }

    close(udp_socket);
    return 0;
}
