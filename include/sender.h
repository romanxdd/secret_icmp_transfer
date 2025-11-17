// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

#ifndef SECRET_SENDER_H
#define SECRET_SENDER_H

#include "app_config.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace protocol
{
    struct PacketHeader;
}

class OutboundChannel
{
public:
    virtual ~OutboundChannel() = default;
    
    /**
     * @brief send a packet header with ciphertext payload over transport
     * 
     * @param header protocol header describing packet metadata
     * @param payload ciphertext bytes to transmit
     * @param errorMessage receives explanation when transport fails
     * @return true when packet successfully emitted
     */
    virtual bool sendPacket(
        const protocol::PacketHeader &header,
        const std::vector<uint8_t> &payload,
        std::string &errorMessage) = 0;
};

struct SenderStats
{
    std::size_t packetsSent = 0;
    std::size_t bytesSent = 0;
};

/**
 * @brief encrypt source file into icmp packets and transmit through channel
 * 
 * @param config runtime settings including source path, chunk size and login
 * @param stats structure populated with bytes and packets sent
 * @param errorMessage receives explanation when sender encounters failure
 * @param channel transport abstraction used for raw packet writes
 * @return true when file fully transmitted without errors
 */
bool runSender(
    const AppConfig &config, SenderStats &stats, std::string &errorMessage, OutboundChannel &channel);

#endif // SECRET_SENDER_H
