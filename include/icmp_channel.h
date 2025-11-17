#ifndef SECRET_ICMP_CHANNEL_H
#define SECRET_ICMP_CHANNEL_H

#include "sender.h"

#include <memory>
#include <netinet/in.h>
#include <string>
#include <vector>

class Icmpv4Channel : public OutboundChannel
{
public:
    ~Icmpv4Channel() override;

    static std::unique_ptr<Icmpv4Channel> create(
        const std::string &destination, bool verbose, std::string &errorMessage);

    bool sendPacket(
        const protocol::PacketHeader &header, const std::vector<uint8_t> &payload, std::string &errorMessage) override;

private:
    Icmpv4Channel(
        int socketFd, const struct sockaddr_in &destination, bool verbose, uint16_t identifier);

    int socketFd_ = -1;
    struct sockaddr_in destination_;
    bool verbose_ = false;
    uint16_t identifier_ = 0;
};

class Icmpv6Channel : public OutboundChannel
{
public:
    ~Icmpv6Channel() override;

    static std::unique_ptr<Icmpv6Channel> create(
        const std::string &destination, bool verbose, std::string &errorMessage);

    bool sendPacket(
        const protocol::PacketHeader &header, const std::vector<uint8_t> &payload, std::string &errorMessage) override;

private:
    Icmpv6Channel(
        int socketFd, const struct sockaddr_in6 &destination, bool verbose, uint16_t identifier);

    int socketFd_ = -1;
    struct sockaddr_in6 destination_;
    bool verbose_ = false;
    uint16_t identifier_ = 0;
};

#endif // SECRET_ICMP_CHANNEL_H
