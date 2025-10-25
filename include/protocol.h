#ifndef SECRET_PROTOCOL_H
#define SECRET_PROTOCOL_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace protocol {

constexpr uint32_t MAGIC = 0x53434341u;      // "SCCA" in ASCII
constexpr uint8_t VERSION = 0x01u;
constexpr uint32_t START_SEQUENCE = 0xFFFFFFFFu;
constexpr std::size_t HEADER_SIZE = 20u;
constexpr std::size_t IV_LENGTH = 16u;
constexpr std::size_t MAX_FILENAME_LENGTH = 255u;
constexpr std::size_t DEFAULT_CHUNK_SIZE = 1024u;

enum class PacketType : uint8_t {
    Start = 0x01,
    Data = 0x02,
    End = 0x03,
    Ack = 0x04
};

struct PacketHeader {
    uint32_t magic = MAGIC;
    uint8_t version = VERSION;
    PacketType type = PacketType::Data;
    uint32_t transferId = 0;
    uint32_t sequenceNumber = 0;
    uint32_t totalPackets = 0;
    uint16_t payloadLength = 0;

    bool hasValidMagic() const;
    bool hasExpectedVersion() const;
};

std::array<uint8_t, HEADER_SIZE> serializeHeader(const PacketHeader &header);
bool deserializeHeader(const uint8_t *buffer, std::size_t length, PacketHeader &header);

struct StartPacketPayload {
    uint8_t flags = 0;
    uint64_t fileSize = 0;
    std::array<uint8_t, IV_LENGTH> iv{};
    std::string fileName;
};

bool encodeStartPayload(const StartPacketPayload &payload, std::vector<uint8_t> &out, std::string *error = nullptr);
bool decodeStartPayload(const uint8_t *data, std::size_t length, StartPacketPayload &out, std::string *error = nullptr);

} // namespace protocol

#endif // SECRET_PROTOCOL_H
