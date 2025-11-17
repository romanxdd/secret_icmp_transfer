// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

#include "app_config.h"
#include "icmp_channel.h"
#include "receiver.h"
#include "sender.h"

#include <cstring>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <string>

namespace
{

enum class DestinationFamily
{
    IPv4,
    IPv6
};

/// figuring out if the destination resolves to ipv4 or ipv6
// [ref] https://linux.die.net/man/3/getaddrinfo
bool resolveDestinationFamily(const AppConfig &config, DestinationFamily &family, std::string &errorMessage)
{
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    switch (config.ipVersionPreference)
    {
    case AppConfig::IpVersionPreference::IPv4:
        hints.ai_family = AF_INET;
        break;
    case AppConfig::IpVersionPreference::IPv6:
        hints.ai_family = AF_INET6;
        break;
    case AppConfig::IpVersionPreference::Auto:
    default:
        hints.ai_family = AF_UNSPEC;
        break;
    }
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = 0;

    struct addrinfo *result = nullptr;
    const int rc = ::getaddrinfo(config.destination.c_str(), nullptr, &hints, &result);
    if (rc != 0)
    {
        errorMessage = std::string("getaddrinfo failed: ") + ::gai_strerror(rc);
        return false;
    }

    for (struct addrinfo *ai = result; ai != nullptr; ai = ai->ai_next)
    {
        if (ai->ai_family == AF_INET)
        {
            family = DestinationFamily::IPv4;
            ::freeaddrinfo(result);
            return true;
        }
        if (ai->ai_family == AF_INET6)
        {
            family = DestinationFamily::IPv6;
            ::freeaddrinfo(result);
            return true;
        }
    }

    ::freeaddrinfo(result);
    errorMessage = "destination does not resolve to IPv4 or IPv6";
    return false;
}

/// build an icmp channel matching the resolved destination family
std::unique_ptr<OutboundChannel> createOutboundChannel(const AppConfig &config, std::string &errorMessage)
{
    DestinationFamily family;
    if (!resolveDestinationFamily(config, family, errorMessage))
    {
        return nullptr;
    }

    if (family == DestinationFamily::IPv4)
    {
        return Icmpv4Channel::create(config.destination, config.verbose, errorMessage);
    }
    return Icmpv6Channel::create(config.destination, config.verbose, errorMessage);
}

/// print a summary of the parsed configuration
void emitConfigurationSummary(const AppConfig &config)
{
    if (config.listenMode)
    {
        std::cout << "Mode: listen" << (config.verbose ? " (verbose)" : "") << '\n';
        if (!config.interfaceName.empty())
        {
            std::cout << "  Interface: " << config.interfaceName << '\n';
        }
    }
    else
    {
        std::cout << "Mode: send to " << config.destination
                  << "\n  Source file: " << config.sourcePath
                  << "\n  Chunk size: " << config.chunkSize << " bytes"
                  << (config.verbose ? "\n  Verbose logging enabled" : "")
                  << '\n';
    }
    std::cout << "  Login key: " << config.login << '\n';
}

} // namespace

int main(int argc, char **argv)
{
    AppConfig config;
    std::string errorMessage;
    // parse flags and bail with usage if invalid
    if (!parseCommandLine(argc, argv, config, errorMessage))
    {
        if (!errorMessage.empty())
        {
            std::cerr << "Error: " << errorMessage << std::endl;
        }
        printUsage(argv[0], std::cerr);
        return 1;
    }

    if (config.showHelp)
    {
        printUsage(argv[0], std::cout);
        return 0;
    }

    // echo the parsed config for user
    emitConfigurationSummary(config);

    if (config.listenMode)
    {
        // receiver path: capture packets and write output
        ReceiverStats receiverStats;
        std::string receiverError;
        if (!runReceiver(config, receiverStats, receiverError))
        {
            std::cerr << "Receiver error: " << receiverError << std::endl;
            return 1;
        }
        std::cout << "Saved file: " << receiverStats.outputFile << std::endl;
        if (config.verbose)
        {
            std::cout << "Captured packets: " << receiverStats.packetsCaptured
                      << ", decrypted bytes: " << receiverStats.bytesDecrypted << std::endl;
        }
    }
    else
    {
        // sender path: build channel then stream file blocks
        std::string channelError;
        auto channel = createOutboundChannel(config, channelError);
        if (!channel)
        {
            std::cerr << "Channel error: " << channelError << std::endl;
            return 1;
        }

        SenderStats stats;
        std::string senderError;
        if (!runSender(config, stats, senderError, *channel))
        {
            std::cerr << "Sender error: " << senderError << std::endl;
            return 1;
        }
        std::cout << "Transfer complete" << std::endl;
        if (config.verbose)
        {
            std::cout << "Packets sent: " << stats.packetsSent
                      << ", bytes sent (approx): " << stats.bytesSent << std::endl;
        }
    }

    return 0;
}