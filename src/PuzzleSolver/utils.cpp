#include "../include/puzzlesolver.h"

uint16_t ip_checksum(uint16_t *buf, int nwords)
{
    uint32_t sum = 0;

    for (; nwords > 0; --nwords)
    {
        sum += *buf++;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

// Calculate the part of the UDP checksum that doesn't change with the payload, and I use it in Checksum_port
uint32_t predict_checksum(const struct iphdr *ip, const struct udphdr *udp)
{
    uint32_t sum = 0;

    uint32_t saddr = ntohl(ip->saddr);
    uint32_t daddr = ntohl(ip->daddr);

    sum += (saddr >> 16) & 0xFFFF;
    sum += (saddr) & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += (daddr) & 0xFFFF;

    sum += IPPROTO_UDP;
    sum += ntohs(udp->source);
    sum += ntohs(udp->dest);

    return sum;
}

// Calculate the full UDP checksum
uint16_t udp_checksum(const struct iphdr *ip, const struct udphdr *udp, const char *payload, size_t payload_len)
{
    uint32_t sum = 0;

    uint32_t saddr = ntohl(ip->saddr);
    uint32_t daddr = ntohl(ip->daddr);

    sum += (saddr >> 16) & 0xFFFF;
    sum += (saddr) & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += (daddr) & 0xFFFF;

    sum += IPPROTO_UDP;
    sum += ntohs(udp->len);

    sum += ntohs(udp->source);
    sum += ntohs(udp->dest);
    sum += ntohs(udp->len);

    const uint8_t *p = reinterpret_cast<const uint8_t *>(payload);
    size_t n = payload_len;

    while (n > 1)
    {
        sum += (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]);
        p += 2;
        n -= 2;
    }

    if (n == 1)
    {
        sum += static_cast<uint16_t>(p[0]) << 8;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    uint16_t result = static_cast<uint16_t>(~sum);

    if (result == 0x0000)
    {
        result = 0xFFFF;
    }

    return htons(result);
}

int make_sockaddr(const char *ip, int port, sockaddr_in *out)
{
    if (out == nullptr)
        return -1;
    std::memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &out->sin_addr) != 1)
    {
        std::cerr << "inet_pton failed for IP: " << ip << "\n";
        return -1;
    }

    return 0;
}

int open_udp()
{
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
    {
        perror("Failed to create socket (AF_INET, SOCK_DGRAM)");
        exit(-1); // If it fail to create a socket then we cannot proceed
    }

    return fd;
}

int open_udp_connected(const char *ip, int port, sockaddr_in *out)
{
    int fd = open_udp();
    sockaddr_in addr{};

    if (make_sockaddr(ip, port, &addr) < 0)
    {
        close(fd);
        return -1;
    }
    if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        perror("connect");
        close(fd);
        return -1;
    }
    if (out)
        *out = addr;

    return fd;
}

int wait_readable(int fd, int sec, int usec)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    timeval tv{};
    tv.tv_sec = sec;
    tv.tv_usec = usec;

    int rc = select(fd + 1, &rfds, nullptr, nullptr, &tv);
    if (rc < 0)
        return -1;
    if (rc == 0)
        return 0;
    return FD_ISSET(fd, &rfds) ? 1 : 0;
}
