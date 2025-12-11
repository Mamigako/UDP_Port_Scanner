#pragma once

#include <regex>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <unordered_set>
#include <algorithm>
#include <random>
#include <iostream>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// UDP message structure
struct udpmsg
{
    iphdr ipheader;
    udphdr udpheader;
    std::string message;
};

// Timeouts constants
inline constexpr int REPLY_SEC = 1;
inline constexpr int REPLY_USEC = 200000;
inline constexpr int LONG_REPLY_SEC = 2;

// Checksums
uint16_t ip_checksum(uint16_t *buf, int nwords);
uint32_t predict_checksum(const iphdr *ip, const udphdr *udp);
uint16_t udp_checksum(const iphdr *ip, const udphdr *udp, const char *payload, size_t payload_len);

extern int which_port_is_which(const char *ip_string, int port1, int port2, int port3, int port4,
                               uint16_t *secret, uint16_t *evil, uint16_t *checksum, uint16_t *expstn);

// Helper functions
extern int make_sockaddr(const char *ip, int port, sockaddr_in *out);
extern int open_udp();
extern int open_udp_connected(const char *ip, int port, sockaddr_in *out);
extern int wait_readable(int fd, int sec, int usec);

// Ports
extern int S_E_C_R_E_T_port(char *ip_string, int port, char &group_ID, uint32_t *signature);

extern int Evil_port(char *ip_string, int port, uint32_t signature);

extern int Checksum_port(char *ip_string, int port, uint32_t signature, std::string &secret_phrase);

extern int E_X_P_S_T_N_port(char *ip_string, int port, uint32_t *signature,
                            std::string &secret_phrase, uint32_t secret_port, uint32_t evil_secret_port);
