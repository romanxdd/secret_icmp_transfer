// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

// i included references in the code for
// documentation used for development

#include "icmp_channel.h"

#include "protocol.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <iostream>
#include <limits>
#include <memory>
#include <vector>

namespace
{

    /// compute classic icmp checksum over the provided buffer
    uint16_t computeChecksum(const void *data, std::size_t length)
    {
        const uint8_t *bytes = static_cast<const uint8_t *>(data);
        uint32_t sum = 0;

        std::size_t remaining = length;
        while (remaining > 1)
        {
            sum += static_cast<uint16_t>(bytes[0] << 8 | bytes[1]);
            bytes += 2;
            remaining -= 2;
        }

        if (remaining == 1)
        {
            sum += static_cast<uint16_t>(bytes[0] << 8);
        }

        while (sum >> 16)
        {
            sum = (sum & 0xFFFFu) + (sum >> 16);
        }

        return static_cast<uint16_t>(~sum & 0xFFFFu);
    }

} // namespace


// https://datatracker.ietf.org/doc/html/rfc792
Icmpv4Channel::Icmpv4Channel(int socketFd, const sockaddr_in &destination, bool verbose, uint16_t identifier)
    : socketFd_(socketFd), destination_(destination), verbose_(verbose), identifier_(identifier) 
    {
    }

/// close the raw socket on destruction
// [ref] https://linux.die.net/man/2/close
Icmpv4Channel::~Icmpv4Channel()
{
    if (socketFd_ >= 0)
    {
        ::close(socketFd_);
        socketFd_ = -1;
    }
}

/// resolve the destination and create a raw icmpv4 socket
// [ref]:
//  https://linux.die.net/man/3/getaddrinfo
//  https://linux.die.net/man/2/socket
std::unique_ptr<Icmpv4Channel> Icmpv4Channel::create(
    const std::string &destination, bool verbose, std::string &errorMessage)
{
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    struct addrinfo *result = nullptr;
    const int rc = ::getaddrinfo(destination.c_str(), nullptr, &hints, &result);
    if (rc != 0)
    {
        errorMessage = std::string("getaddrinfo failed: ") + ::gai_strerror(rc);
        return nullptr;
    }

    int socketFd = -1;
    sockaddr_in destAddr{};

    for (struct addrinfo *ai = result; ai != nullptr; ai = ai->ai_next)
    {
        if (ai->ai_family != AF_INET || ai->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in)))
        {
            continue;
        }
        // allocating raw icmp socket
        socketFd = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (socketFd < 0)
        {
            errorMessage = std::string("socket creation failed: ") + ::strerror(errno);
            continue;
        }
        // remember the resolved endpoint and drop any port info
        destAddr = *reinterpret_cast<sockaddr_in *>(ai->ai_addr);
        destAddr.sin_port = 0;
        break;
    }

    ::freeaddrinfo(result);

    if (socketFd < 0)
    {
        if (errorMessage.empty())
        {
            errorMessage = "unable to resolve destination";
        }
        return nullptr;
    }

    // tag packets with a per-process identifier
    const uint16_t identifier = static_cast<uint16_t>(::getpid() & 0xFFFF);
    return std::unique_ptr<Icmpv4Channel>(new Icmpv4Channel(socketFd, destAddr, verbose, identifier));
}

/// craft and send an icmpv4 echo packet with the protocol payload
// [ref] https://linux.die.net/man/2/sendto
bool Icmpv4Channel::sendPacket(
    const protocol::PacketHeader &header,
    const std::vector<uint8_t>   &payload,
    std::string                  &errorMessage)
{
    if (socketFd_ < 0)
    {
        errorMessage = "ICMP channel is not initialized";
        return false;
    }

    if (payload.size() > std::numeric_limits<uint16_t>::max())
    {
        errorMessage = "payload too large for ICMP";
        return false;
    }

    const auto headerBytes = protocol::serializeHeader(header);

    if (header.payloadLength != payload.size())
    {
        errorMessage = "payload length mismatch";
        return false;
    }

    const std::size_t icmpSize = sizeof(struct icmphdr);
    const std::size_t totalSize = icmpSize + headerBytes.size() + payload.size();
    std::vector<uint8_t> buffer(totalSize);

    struct icmphdr *icmpHeader = reinterpret_cast<struct icmphdr *>(buffer.data());
    std::memset(icmpHeader, 0, sizeof(*icmpHeader));
    // making echo request header with own id/seq
    icmpHeader->type = ICMP_ECHO;
    icmpHeader->code = 0;
    icmpHeader->un.echo.id = htons(identifier_);
    icmpHeader->un.echo.sequence = htons(static_cast<uint16_t>(header.sequenceNumber & 0xFFFFu));

    // stash the protocol header and payload after the icmp header
    std::memcpy(buffer.data() + icmpSize, headerBytes.data(), headerBytes.size());
    if (!payload.empty())
    {
        std::memcpy(buffer.data() + icmpSize + headerBytes.size(), payload.data(), payload.size());
    }

    // compute checksum over the entire icmp frame
    const uint16_t checksum = computeChecksum(buffer.data(), buffer.size());
    icmpHeader->checksum = htons(checksum);

    // transmit the packet to the resolved destination
    const ssize_t bytesSent = ::sendto(socketFd_, buffer.data(), buffer.size(), 0,
                                       reinterpret_cast<struct sockaddr *>(&destination_),
                                       sizeof(destination_));

    if (bytesSent < 0 || static_cast<std::size_t>(bytesSent) != buffer.size())
    {
        errorMessage = std::string("sendto failed: ") + ::strerror(errno);
        return false;
    }

    // verbose output
    if (verbose_)
    {
        std::cout << "Sent ICMP packet type=" << static_cast<int>(header.type)
                  << " seq=" << header.sequenceNumber
                  << " bytes=" << buffer.size() << std::endl;
    }

    return true;
}


// https://datatracker.ietf.org/doc/html/rfc4443
Icmpv6Channel::Icmpv6Channel(int socketFd, const sockaddr_in6 &destination, bool verbose, uint16_t identifier)
    : socketFd_(socketFd), destination_(destination), verbose_(verbose), identifier_(identifier) 
    {
    }

/// close the ipv6 socket on destruction
Icmpv6Channel::~Icmpv6Channel()
{
    if (socketFd_ >= 0)
    {
        ::close(socketFd_);
        socketFd_ = -1;
    }
}

/// resolve the destination and create a raw icmpv6 socket
// [ref]:
//  https://linux.die.net/man/3/getaddrinfo
//  https://linux.die.net/man/2/socket
std::unique_ptr<Icmpv6Channel> Icmpv6Channel::create(
    const std::string &destination, bool verbose, std::string &errorMessage)
{
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMPV6;

    struct addrinfo *result = nullptr;
    const int rc = ::getaddrinfo(destination.c_str(), nullptr, &hints, &result);
    if (rc != 0)
    {
        errorMessage = std::string("getaddrinfo failed: ") + ::gai_strerror(rc);
        return nullptr;
    }

    int socketFd = -1;
    sockaddr_in6 destAddr{};

    for (struct addrinfo *ai = result; ai != nullptr; ai = ai->ai_next)
    {
        if (ai->ai_family != AF_INET6 || ai->ai_addrlen < static_cast<socklen_t>(sizeof(sockaddr_in6)))
        {
            continue;
        }
        // allocating raw icmp socket
        socketFd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (socketFd < 0)
        {
            errorMessage = std::string("socket creation failed: ") + ::strerror(errno);
            continue;
        }

        // remember the resolved endpoint and drop any port info
        destAddr = *reinterpret_cast<sockaddr_in6 *>(ai->ai_addr);
        destAddr.sin6_port = 0;
        break;
    }

    ::freeaddrinfo(result);

    if (socketFd < 0)
    {
        if (errorMessage.empty())
        {
            errorMessage = "unable to resolve destination";
        }
        return nullptr;
    }

    // tag packets with a per-process identifier
    const uint16_t identifier = static_cast<uint16_t>(::getpid() & 0xFFFF);
    return std::unique_ptr<Icmpv6Channel>(new Icmpv6Channel(socketFd, destAddr, verbose, identifier));
}

/// craft and send an icmpv6 echo packet with the protocol payload
// [ref] https://linux.die.net/man/2/sendto
bool Icmpv6Channel::sendPacket(
    const protocol::PacketHeader &header,
    const std::vector<uint8_t>   &payload,
    std::string                  &errorMessage)
{
    if (socketFd_ < 0)
    {
        errorMessage = "ICMPv6 channel is not initialized";
        return false;
    }

    if (payload.size() > std::numeric_limits<uint16_t>::max())
    {
        errorMessage = "payload too large for ICMPv6";
        return false;
    }

    const auto headerBytes = protocol::serializeHeader(header);

    if (header.payloadLength != payload.size())
    {
        errorMessage = "payload length mismatch";
        return false;
    }

    const std::size_t icmpSize = sizeof(struct icmp6_hdr);
    const std::size_t totalSize = icmpSize + headerBytes.size() + payload.size();
    std::vector<uint8_t> buffer(totalSize);

    struct icmp6_hdr *icmpHeader = reinterpret_cast<struct icmp6_hdr *>(buffer.data());
    std::memset(icmpHeader, 0, sizeof(*icmpHeader));
    // making echo request header with own id/seq
    icmpHeader->icmp6_type = ICMP6_ECHO_REQUEST;
    icmpHeader->icmp6_code = 0;
    icmpHeader->icmp6_id = htons(identifier_);
    icmpHeader->icmp6_seq = htons(static_cast<uint16_t>(header.sequenceNumber & 0xFFFFu));

    // stash the protocol header and payload after the icmp header
    std::memcpy(buffer.data() + icmpSize, headerBytes.data(), headerBytes.size());
    if (!payload.empty())
    {
        std::memcpy(buffer.data() + icmpSize + headerBytes.size(), payload.data(), payload.size());
    }

    // transmit the packet to the resolved destination
    const ssize_t bytesSent = ::sendto(socketFd_, buffer.data(), buffer.size(), 0,
                                       reinterpret_cast<struct sockaddr *>(&destination_),
                                       sizeof(destination_));

    if (bytesSent < 0 || static_cast<std::size_t>(bytesSent) != buffer.size())
    {
        errorMessage = std::string("sendto failed: ") + ::strerror(errno);
        return false;
    }

    // verbose output
    if (verbose_)
    {
        std::cout << "Sent ICMPv6 packet type=" << static_cast<int>(header.type)
                  << " seq=" << header.sequenceNumber
                  << " bytes=" << buffer.size() << std::endl;
    }

    return true;
}
