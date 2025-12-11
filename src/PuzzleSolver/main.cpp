#include "../include/puzzlesolver.h"

int main(int argc, char *argv[])
{
    /*
      sudo ./puzzlesolver <IP address> <port 1> <port 2> <port 3> <port 4>
    */

    if (argc != 6)
    {
        std::cout << "Usage: ./puzzlesolver <IP address> <port 1> <port 2> <port 3> <port 4>\n"
                  << std::endl;
        return 1;
    }

    std::cout << "Reading ip_string\n";
    char *ip_string = argv[1];

    std::cout << "Reading ports\n";
    int port1 = atoi(argv[2]);
    int port2 = atoi(argv[3]);
    int port3 = atoi(argv[4]);
    int port4 = atoi(argv[5]);

    uint16_t SECRET_port = 0;
    uint16_t evil_port = 0;
    uint16_t checksum_port = 0;
    uint16_t EXPSTN_port = 0;

    char group_ID;
    uint32_t signature;
    uint32_t secret_port;
    uint32_t evil_secret_port;
    std::string secret_phrase;

    // First, we need to distinguish the ports
    which_port_is_which(ip_string, port1, port2, port3, port4, &SECRET_port, &evil_port, &checksum_port, &EXPSTN_port);

    std::cout << std::endl << std::endl;
    secret_port = S_E_C_R_E_T_port(ip_string, SECRET_port, group_ID, &signature);

    std::cout << std::endl << std::endl;
    evil_secret_port = Evil_port(ip_string, evil_port, signature);

    std::cout << std::endl << std::endl;
    Checksum_port(ip_string, checksum_port, signature, secret_phrase);

    std::cout << std::endl << std::endl;
    E_X_P_S_T_N_port(ip_string, EXPSTN_port, &signature, secret_phrase, secret_port, evil_secret_port);

    return 0;
}
