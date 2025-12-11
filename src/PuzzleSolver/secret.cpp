#include "../include/puzzlesolver.h"

int S_E_C_R_E_T_port(char *ip_string, int port, char &group_ID, uint32_t *signature)
{
    /* Greetings from S.E.C.R.E.T. (Secure Encryption Certification Relay with Enhanced Trust)! Here's how to access the secret port I'm safeguarding:
        1. Generate a 32 bit secret number (and remember it for later)
        2. Send me a message where the first byte is the letter 'S' followed by 4 bytes containing your secret number (in network byte order),
           and the rest of the message is a comma-separated list of the RU usernames of all your group members.
        3. I will reply with a 5-byte message, where the first byte is your group ID and the remaining 4 bytes are a 32 bit challenge number (in network byte order)
        4. Combine this challenge using the XOR operation with the secret number you generated in step 1 to obtain a 4 byte signature.
        5. Reply with a 5-byte message: the first byte is your group number, followed by the 4-byte signature (in network byte order).
        6. If your signature is correct, I will respond with a secret port number. Good luck!
        7. Remember to keep your group ID and signature for later, you will need them for other ports. (But do not hard-code them!)
    */
    std::cout << "-------------------S.E.C.E.R.T PORT--------------------" << std::endl;
    std::cout << "Assigning secret number\n";
    std::random_device rd;
    std::mt19937 gen(rd());

    uint32_t secret_number = gen();
    uint32_t secret_number_net = htonl(secret_number);

    uint32_t sig;
    uint32_t sig_net;
    char ID;
    int secret_port_number;

    struct sockaddr_in server_address{};
    int udp_socket = open_udp_connected(ip_string, port, &server_address);
    if (udp_socket < 0)
    {
        return 1;
    }

    std::string message;
    message.push_back('S');
    message.append(reinterpret_cast<const char *>(&secret_number_net), 4);
    message += "maximiliang23,daniele23,fridriks23";

    std::cout << "Message constructed." << std::endl;

    // We retry 5 times since UDP is not reliable and can drop packets
    for (int i = 0; i < 5; i++)
    {
        ssize_t sent = send(udp_socket,
                            message.c_str(),
                            message.length(),
                            0);

        if (sent == -1)
        {
            perror("sendto");
            continue;
        }

        int ready = wait_readable(udp_socket, REPLY_SEC, REPLY_USEC);
        if (ready == -1)
        {
            std::cout << "Error. Port: " << ntohs(server_address.sin_port) << std::endl;
            break;
        }
        else if (ready == 0)
        {
            std::cout << "port Timeout.1\n"
                      << std::endl;
            continue;
        }
        else
        {
            // The server promises exactly 5 bytes
            char buff1[5];

            ssize_t n = recv(udp_socket, buff1, sizeof(buff1), 0);

            if ((n == -1) || (n != 5))
            {
                std::cerr << "recv error on port " << (ntohs(server_address.sin_port)) << ": " << std::strerror(errno) << std::endl;
                continue;
            }
            else
            {
                ID = buff1[0];
                group_ID = ID;

                uint32_t challenge_number_net = 0;
                std::memcpy(&challenge_number_net, buff1 + 1, 4);

                uint32_t challenge_number = ntohl(challenge_number_net);

                sig = challenge_number ^ secret_number;

                *signature = sig;

                sig_net = htonl(sig);
                break;
            }
        }
    }

    // Building the 5-byte reply
    std::string reply;
    reply.reserve(5);
    reply.push_back(static_cast<char>(ID));
    reply.append(reinterpret_cast<const char *>(&sig_net), 4);
    printf("S.E.C.E.R.T port reply: %s\n", reply.data());

    for (int i = 0; i < 5; i++)
    {
        ssize_t sent = send(udp_socket, reply.c_str(), reply.length(), 0);

        if (sent == -1)
        {
            perror("send");
            continue;
        }

        int ready = wait_readable(udp_socket, REPLY_SEC, REPLY_USEC);
        if (ready == -1)
        {
            std::cout << "Error. Port: " << ntohs(server_address.sin_port) << std::endl;
            break;
        }
        else if (ready == 0)
        {
            std::cout << "port Timeout.\n"
                      << std::endl;
            continue;
        }
        else
        {
            char buff[128];

            ssize_t n = recv(udp_socket, buff, sizeof(buff), 0);

            if (n == -1)
            {
                std::cerr << "recv error on port " << (ntohs(server_address.sin_port)) << ": " << std::strerror(errno) << std::endl;
                continue;
            }
            else
            {
                printf("%.*s\n", (int)n, buff);

                char tmp[5];
                std::memcpy(tmp, buff + (n - 5), 4);
                tmp[4] = '\0';

                secret_port_number = std::strtol(tmp, nullptr, 10);
                break;
            }
        }
    }

    close(udp_socket);
    return secret_port_number;
}
