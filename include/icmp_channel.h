// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

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

    /**
     * @brief build a channel that targets the provided destination
     * 
     * @param destination ipv4 address or hostname to resolve
     * @param verbose enable verbose logging when true
     * @param errorMessage receives a description when creation fails
     */
    static std::unique_ptr<Icmpv4Channel> create(
        const std::string &destination, bool verbose, std::string &errorMessage);

    /**
     * @brief serialize and send one protocol packet over icmpv4
     * 
     * @param header protocol header to serialize
     * @param payload payload bytes to append
     * @param errorMessage receives a description when send fails
     */
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

    /**
     * @brief build a channel that targets the provided v6 destination
     * 
     * @param destination ipv6 address or hostname to resolve
     * @param verbose enable verbose logging when true
     * @param errorMessage receives a description when creation fails
     */
    static std::unique_ptr<Icmpv6Channel> create(
        const std::string &destination, bool verbose, std::string &errorMessage);

    /**
     * @brief serialize and send one protocol packet over icmpv6
     * 
     * @param header protocol header to serialize
     * @param payload payload bytes to append
     * @param errorMessage receives a description when send fails
     */
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
