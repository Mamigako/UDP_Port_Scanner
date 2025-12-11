#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <unordered_set>

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cout << "Usage: ./scanner <IPv4> <low_port> <high_port>\n"
                  << std::endl;
        return 1;
    }

    char *ip_string;
    int low_port;
    int high_port;
    int port_range;

    ip_string = argv[1];
    low_port = atoi(argv[2]);
    high_port = atoi(argv[3]);
    port_range = high_port - low_port;

    // Basic sanity checks
    if (low_port < 0 || high_port > 65535 || low_port > high_port)
    {
        std::cerr << "Invalid port range.\n";
        return 1;
    }

    int udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_string, &server_address.sin_addr) != 1)
    {
        std::cout << "Issues with IP address, exiting." << std::endl;
        close(udp_socket);
        return 1;
    }

    std::string message = "random"; // 6 bytes

    std::unordered_set<uint16_t> reported_ports;

    for (int i = 0; i <= port_range; i++)
    {
        server_address.sin_port = htons(low_port + i);

        // We retry 5 times because UDP is unreliable and can drop packets
        for (int j = 0; j < 5; j++)
        {
            ssize_t sent = sendto(udp_socket,
                                  message.c_str(),
                                  message.length(),
                                  0,
                                  reinterpret_cast<const sockaddr *>(&server_address),
                                  sizeof(server_address));

            if (sent == -1)
            {
                perror("sendto");
                continue;
            }

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(udp_socket, &readfds);

            timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 200000;

            int rc = select(udp_socket + 1, &readfds, nullptr, nullptr, &tv); // Short wait

            if (rc == -1)
            {
                std::cout << "Error. Port: " << ntohs(server_address.sin_port) << std::endl;
                break;
            }
            else if (rc == 0)
            {
                continue;
            }
            else if (FD_ISSET(udp_socket, &readfds))
            {
                char buff[2048];

                sockaddr_in from{};
                socklen_t from_len = sizeof(from);

                ssize_t n = recvfrom(udp_socket,
                                     buff,
                                     sizeof(buff),
                                     0,
                                     reinterpret_cast<sockaddr *>(&from),
                                     &from_len);

                if (n == -1)
                {
                    std::cerr << "recvfrom error on port "
                              << (low_port + i) << ": " << std::strerror(errno) << std::endl;
                    continue;
                }
                else
                {
                    uint16_t reply_port = ntohs(from.sin_port);
                    uint16_t current_port = static_cast<uint16_t>(low_port + i);

                    // Print once per responding port, even if multiple retries/packets arrive
                    auto [_, is_new] = reported_ports.insert(reply_port);
                    if (is_new)
                    {
                        std::cout << "Open port found: " << reply_port << std::endl;
                        printf("%.*s\n", static_cast<int>(n), buff);
                        std::cout << std::endl;
                    }

                    // Only advance when the reply matches the port we just probed
                    // just to avoid “cross-talk” from delayed replies to previous probes
                    if (current_port == reply_port)
                    {
                        break;
                    }
                }
            }
        }
    }

    std::cout << "Finished scanning" << std::endl;
    close(udp_socket);
    return 0;
}
