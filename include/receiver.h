// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

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
        /**
         * @brief record start packet metadata and prepare chunk storage
         * 
         * @param header parsed packet header describing transfer totals
         * @param payload start payload containing size iv and filename
         * @param errorMessage receives explanation when state update fails
         * @return true when packet accepted or already processed
         */
        bool handleStart(
            const protocol::PacketHeader &header,
            const protocol::StartPacketPayload &payload,
            std::string &errorMessage);

        /**
         * @brief store ciphertext chunk data and update tracking counters
         * 
         * @param header packet header identifying chunk index and transfer
         * @param payload pointer to ciphertext bytes
         * @param length number of payload bytes available
         * @param errorMessage receives explanation when validation fails
         * @return true when chunk accepted or duplicate skipped
         */
        bool handleData(
            const protocol::PacketHeader &header,
            const uint8_t *payload, std::size_t length,
            std::string &errorMessage);

        /**
         * @brief mark transfer finished when matching end packet arrives
         * 
         * @param header packet header representing end sentinel
         * @param errorMessage receives explanation when sequence mismatches
         * @return true when end accepted or already observed
         */
        bool handleEnd(const protocol::PacketHeader &header, std::string &errorMessage);

        /**
         * @brief report whether transfer has start, end and all chunks
         * 
         * @return true when capture assembled full ciphertext
         */
        bool isComplete() const;

        /**
         * @brief concatenate stored chunks into sequential ciphertext buffer
         * 
         * @return ciphertext bytes in transfer order
         */
        std::vector<uint8_t> assembleCiphertext() const;

        /**
         * @brief expose current reassembly bookkeeping for callers
         * 
         * @return const reference to mutable state snapshot
         */
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

/**
 * @brief capture icmp traffic, reassemble file, decrypt ciphertext and write output
 * 
 * @param config runtime options describing capture interface and behavior
 * @param stats structure populated with packet counters and output path
 * @param errorMessage receives explanation when receiver exits early
 * @return true when transfer succeeded and file written
 */
bool runReceiver(const AppConfig &config, ReceiverStats &stats, std::string &errorMessage);

#endif // SECRET_RECEIVER_H
