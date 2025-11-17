#ifndef SECRET_RECEIVER_H
#define SECRET_RECEIVER_H

#include "app_config.h"
#include "crypto.h"
#include "protocol.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace receiver
{
    struct ReassemblyState
    {
        bool hasStart = false;
        bool hasEnd = false;
        uint32_t transferId = 0;
        uint32_t totalPackets = 0;
        uint32_t receivedPackets = 0;
        uint64_t fileSize = 0;
        uint64_t receivedBytes = 0;
        crypto::Iv iv{};
        std::string fileName;
        std::vector<std::vector<uint8_t>> chunks;
        std::vector<bool> receivedFlags;
    };

    class PacketReassembler
    {
    public:
        bool handleStart(
            const protocol::PacketHeader &header,
            const protocol::StartPacketPayload &payload,
            std::string &errorMessage);

        bool handleData(
            const protocol::PacketHeader &header,
            const uint8_t *payload, std::size_t length,
            std::string &errorMessage);

        bool handleEnd(const protocol::PacketHeader &header, std::string &errorMessage);

        bool isComplete() const;

        std::vector<uint8_t> assembleCiphertext() const;

        const ReassemblyState &state() const { return state_; }

    private:
        ReassemblyState state_;
    };

} // namespace receiver

struct ReceiverStats
{
    std::size_t packetsCaptured = 0;
    std::size_t startPackets = 0;
    std::size_t dataPackets = 0;
    std::size_t endPackets = 0;
    std::size_t bytesDecrypted = 0;
    std::string outputFile;
    uint32_t kernelPackets = 0;
    uint32_t kernelDropped = 0;
    uint32_t interfaceDropped = 0;
};

bool runReceiver(const AppConfig &config, ReceiverStats &stats, std::string &errorMessage);

#endif // SECRET_RECEIVER_H
