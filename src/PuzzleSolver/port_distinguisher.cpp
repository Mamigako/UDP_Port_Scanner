#include "../include/puzzlesolver.h"

// Determine which of the four provided ports corresponds to which challenge port
int which_port_is_which(const char *ip_string, int port1, int port2, int port3, int port4, uint16_t *secret, uint16_t *evil, uint16_t *checksum, uint16_t *expstn)
{
    std::cout << "-------------------DISTINGUISING PORT--------------------" << std::endl;
    std::array<int, 4> ports{port1, port2, port3, port4};

    int udp_socket = open_udp();

    struct sockaddr_in server_address{};
    if (make_sockaddr(ip_string, 0, &server_address) < 0) // Port will be set in the loop
    {
        close(udp_socket);
        return 1;
    }

    std::string message = "random";
    bool got_secret = false, got_evil = false, got_checksum = false, got_expstn = false;

    for (int i = 0; i < 4; i++)
    {
        server_address.sin_port = htons(ports[i]);

        for (int j = 0; j < 5; j++) // We retry 5 times since UDP is not reliable and can drop packets
        {
            ssize_t sent = sendto(udp_socket,
                                  message.c_str(),
                                  message.length(),
                                  0,
                                  (const sockaddr *)&server_address,
                                  sizeof(server_address));

            if (sent == -1)
            {
                perror("sendto");
                continue;
            }

            // Short wait to catch the immediate reply for this probe
            int ready = wait_readable(udp_socket, REPLY_SEC, REPLY_USEC);
            if (ready == -1)
            {
                std::cout << "Error. Port: " << ntohs(server_address.sin_port) << std::endl;
                break;
            }
            else if (ready == 0)
            {
                continue;
            }
            else
            {
                char buff[2048];

                struct sockaddr_in from{};
                socklen_t from_len = sizeof(from);

                ssize_t n = recvfrom(udp_socket, buff, sizeof(buff), 0,
                                     (sockaddr *)&from, &from_len);

                if (n == -1)
                {
                    std::cerr << "recvfrom error on port " << (server_address.sin_port) << ": " << std::strerror(errno) << std::endl;
                    continue;
                }
                else
                {
                    std::string s(buff, n);
                    uint16_t reply_port = ntohs(from.sin_port);
                    uint16_t current_port = ntohs(server_address.sin_port);

                    if (!got_secret && s.find("Greetings from S.E.C.R.E.T.") != std::string::npos)
                    {
                        *secret = reply_port;
                        got_secret = true;
                    }

                    if (!got_expstn && s.find("Greetings! I am E.X.P.S.T.N") != std::string::npos)
                    {
                        *expstn = reply_port;
                        got_expstn = true;
                    }

                    if (!got_checksum && s.find("Send me a 4-byte message") != std::string::npos)
                    {
                        *checksum = reply_port;
                        got_checksum = true;
                    }

                    if (!got_evil && s.find("I am an evil port") != std::string::npos)
                    {
                        *evil = reply_port;
                        got_evil = true;
                    }

                    // Only accept a reply if it matches the port we just probed,
                    // otherwise it’s likely a straggler from a previous iteration.
                    if (current_port == reply_port)
                    {
                        break;
                    }
                    if (got_secret && got_evil && got_checksum && got_expstn)
                    {
                        break;
                    }
                }
            }
        }
    }

    std::cout << "Secret port: " << *secret
              << ", Evil port: " << *evil
              << ", Checksum port: " << *checksum
              << " EXSPTN port: " << *expstn << std::endl;

    close(udp_socket);
    return 0;
}
