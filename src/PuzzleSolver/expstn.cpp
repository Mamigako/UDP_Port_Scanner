#include "../include/puzzlesolver.h"

int E_X_P_S_T_N_port(char *ip_string, int port, uint32_t *signature, std::string &secret_phrase, uint32_t secret_port, uint32_t evil_secret_port)
{
    /*Greetings! I am E.X.P.S.T.N, which stands for "Enhanced X-link Port Storage Transaction Node".

    What can I do for you?
    - If you provide me with a list of secret ports (comma-separated), I can guide you on the exact sequence of "knocks" to ensure you score full marks.

    How to use E.X.P.S.T.N?
    1. Each "knock" must be paired with both a secret phrase and your unique S.E.C.R.E.T signature.
    2. The correct format to send a knock: First, 4 bytes containing your S.E.C.R.E.T signature, followed by the secret phrase.

    Tip: To discover the secret ports and their associated phrases, start by solving challenges on the ports detected using your port scanner. Happy hunting!*/

    // Validation checks
    std::cout << "-------------------E.X.P.S.T.N PORT--------------------" << std::endl;
    if (signature == nullptr)
    {
        std::cerr << "signature pointer null\n";
        return 1;
    }
    if (secret_phrase.empty())
    {
        std::cerr << "secret_phrase is empty\n";
        return 1;
    }

    std::vector<uint16_t> ports_sequence;

    struct sockaddr_in server_address{};
    int udp_socket = open_udp_connected(ip_string, port, &server_address);
    if (udp_socket < 0)
    {
        return 1;
    }

    // Sending the two secret ports first
    std::string message = std::to_string(secret_port) + "," + std::to_string(evil_secret_port);

    bool got_ports = false;
    for (int attempt = 0; attempt < 5 && !got_ports; ++attempt)
    {
        ssize_t sent = send(udp_socket, message.data(), message.size(), 0);
        if (sent < 0)
        {
            perror("send(signature)");
            continue;
        }

        int ready = wait_readable(udp_socket, REPLY_SEC, REPLY_USEC);
        if (ready < 0)
        {
            perror("select");
            close(udp_socket);
            return 1;
        }
        if (ready == 0)
        {
            std::cerr << "Timeout waiting for EXPSTN port reply (attempt " << attempt << ")\n";
            continue;
        }

        else
        {
            char rbuf[1024];
            ssize_t n = recv(udp_socket, rbuf, sizeof(rbuf), 0);
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

            printf("EXPSTN port replied: %.*s\n", (int)n, rbuf);

            std::string s(rbuf, n);
            std::regex re(R"(4\d{3})"); // regex to find 4-digit port numbers starting with '4'
            std::smatch m;
            std::string tmp = s;

            while (std::regex_search(tmp, m, re) && ports_sequence.size() < 6)
            {
                try
                {
                    uint32_t portnum = static_cast<uint32_t>(std::stoul(m.str(0)));
                    ports_sequence.push_back(static_cast<uint16_t>(portnum));
                    std::cout << "Parsed knock port: " << portnum << "\n";
                }
                catch (const std::exception &e)
                {
                    std::cerr << "stoul failed: " << e.what() << "\n";
                }
                tmp = m.suffix().str();
            }

            if (!ports_sequence.empty())
            {
                got_ports = true;
            }
            else
            {
                std::cerr << "No ports found in EXPSTN reply; full text:\n"
                          << s << "\n";
            }
        }
    }

    if (!got_ports)
    {
        std::cerr << "Failed to obtain ports sequence from EXPSTN\n";
        close(udp_socket);
        return 1;
    }

    // Knock payload = signature (4 raw bytes, network order) + secret phrase
    uint32_t sig_val = *signature;
    uint32_t sig_net = htonl(sig_val);
    std::string knock;
    knock.reserve(4 + secret_phrase.size());
    knock.append(reinterpret_cast<const char *>(&sig_net), 4);
    knock += secret_phrase;

    // Use a separate socket for the actual knocks to keep request/response flows isolated
    int knock_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (knock_socket < 0)
    {
        perror("knock socket");
        close(udp_socket);
        return 1;
    }

    struct sockaddr_in knock_address{};
    knock_address.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_string, &knock_address.sin_addr) != 1)
    {
        std::cout << "Issues with IP address, exiting." << std::endl;
        close(knock_socket);
        close(udp_socket);
        return 1;
    }

    for (auto port : ports_sequence)
    {
        knock_address.sin_port = htons(port);

        ssize_t sent = sendto(knock_socket, knock.data(), knock.size(), 0, (struct sockaddr *)&knock_address, sizeof(knock_address));
        if (sent < 0)
        {
            perror("sendto(knock)");
            continue;
        }

        int ready = wait_readable(knock_socket, LONG_REPLY_SEC, REPLY_USEC);
        if (ready < 0)
        {
            perror("select");
            close(knock_socket);
            close(udp_socket);
            return 1;
        }
        if (ready == 0)
        {
            std::cerr << "Timeout waiting for knock port " << port << " reply\n";
            continue;
        }

        else
        {
            char kbuf[1024];
            socklen_t addrlen = sizeof(knock_address);
            ssize_t k = recvfrom(knock_socket, kbuf, sizeof(kbuf) - 1, 0, (struct sockaddr *)&knock_address, &addrlen);
            if (k <= 0)
            {
                if (k == 0)
                {
                    std::cerr << "peer closed\n";
                }
                else
                {
                    perror("recvfrom");
                }
                continue;
            }
            kbuf[k] = '\0';
            printf("Knock port %u replied: %.*s\n", static_cast<unsigned>(port), (int)k, kbuf);
        }
    }

    close(knock_socket);
    close(udp_socket);
    return 0;
}
