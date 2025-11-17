// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

#ifndef SECRET_PROTOCOL_H
#define SECRET_PROTOCOL_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace protocol
{

    /// protocol magic value identifying header
    constexpr uint32_t MAGIC = 0x53434354u; // "SCCT" in ASCII (secret covert channel transfer)
    /// protocol version used for a check
    constexpr uint8_t VERSION = 0x01u;
    /// sequence value for transfer start packet
    constexpr uint32_t START_SEQUENCE = 0xFFFFFFFFu;
    constexpr std::size_t HEADER_SIZE = 20u;
    constexpr std::size_t IV_LENGTH = 16u;
    constexpr std::size_t MAX_FILENAME_LENGTH = 255u;
    constexpr std::size_t MAX_CHUNK_SIZE = 1400u;
    constexpr std::size_t DEFAULT_CHUNK_SIZE = 1024u;

    /// packet role assigned to serialized payloads
    enum class PacketType : uint8_t
    {
        Start = 0x01,
        Data = 0x02,
        End = 0x03,
        Ack = 0x04 // i'm leaving this here for a possible feature implementation when i'm bored in the future
    };

    /// header carrying transport metadata
    struct PacketHeader
    {
        uint32_t magic = MAGIC;
        uint8_t version = VERSION;
        PacketType type = PacketType::Data;
        uint32_t transferId = 0;
        uint32_t sequenceNumber = 0;
        uint32_t totalPackets = 0;
        uint16_t payloadLength = 0;

        /// verifies header magic matches expectation
        bool hasValidMagic() const;
        /// verifies header version equals supported schema
        bool hasExpectedVersion() const;
    };

    /// serialize packet header into network byte order buffer
    std::array<uint8_t, HEADER_SIZE> serializeHeader(const PacketHeader &header);
    /// parse network byte order buffer back into packet header
    bool deserializeHeader(const uint8_t *buffer, std::size_t length, PacketHeader &header);

    /// metadata fields transmitted in start packets
    struct StartPacketPayload
    {
        uint8_t flags = 0;
        uint64_t fileSize = 0;
        std::array<uint8_t, IV_LENGTH> iv{};
        std::array<uint8_t, IV_LENGTH> metadataIv{};
        uint8_t fileNameLength = 0;
        std::vector<uint8_t> encryptedFileName;
        std::string fileName;
    };

    /**
     * @brief encode start packet payload into linear buffer
     * 
     * @param payload start packet metadata to serialize
     * @param out buffer receiving encoded bytes
     * @param error optional string populated with reason when false
     * @return true when payload fits protocol layout
     */
    bool encodeStartPayload(
        const StartPacketPayload &payload, std::vector<uint8_t> &out, std::string *error = nullptr);
    
    /** 
     * @brief decode start packet payload from received bytes
     * 
     * @param data pointer to encoded payload bytes
     * @param length number of bytes available in buffer
     * @param out structure populated with decoded fields
     * @param error optional string populated when validation fails
     * @return true when payload parses successfully
     */
    bool decodeStartPayload(
        const uint8_t *data, std::size_t length, StartPacketPayload &out, std::string *error = nullptr);

} // namespace protocol

#endif // SECRET_PROTOCOL_H
