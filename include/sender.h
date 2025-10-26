#ifndef SECRET_SENDER_H
#define SECRET_SENDER_H

#include "app_config.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace protocol {
struct PacketHeader;
}

class OutboundChannel {
  public:
    virtual ~OutboundChannel() = default;
    virtual bool sendPacket(const protocol::PacketHeader &header,
                            const std::vector<uint8_t> &payload,
                            std::string &errorMessage) = 0;
};

struct SenderStats {
    std::size_t packetsSent = 0;
    std::size_t bytesSent = 0;
};

bool runSender(const AppConfig &config, SenderStats &stats, std::string &errorMessage,
               OutboundChannel &channel);

#endif // SECRET_SENDER_H
