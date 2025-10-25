#include "protocol.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>

namespace {

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
constexpr bool kHostIsLittleEndian = true;
#else
constexpr bool kHostIsLittleEndian = false;
#endif

uint64_t hostToNetwork64(uint64_t value) {
    if constexpr (kHostIsLittleEndian) {
#if defined(__has_builtin)
#  if __has_builtin(__builtin_bswap64)
        return static_cast<uint64_t>(__builtin_bswap64(value));
#  else
        return ((value & 0x00000000000000FFull) << 56) |
               ((value & 0x000000000000FF00ull) << 40) |
               ((value & 0x0000000000FF0000ull) << 24) |
               ((value & 0x00000000FF000000ull) << 8)  |
               ((value & 0x000000FF00000000ull) >> 8)  |
               ((value & 0x0000FF0000000000ull) >> 24) |
               ((value & 0x00FF000000000000ull) >> 40) |
               ((value & 0xFF00000000000000ull) >> 56);
#  endif
#else
        return ((value & 0x00000000000000FFull) << 56) |
               ((value & 0x000000000000FF00ull) << 40) |
               ((value & 0x0000000000FF0000ull) << 24) |
               ((value & 0x00000000FF000000ull) << 8)  |
               ((value & 0x000000FF00000000ull) >> 8)  |
               ((value & 0x0000FF0000000000ull) >> 24) |
               ((value & 0x00FF000000000000ull) >> 40) |
               ((value & 0xFF00000000000000ull) >> 56);
#endif
    }
    return value;
}

uint64_t networkToHost64(uint64_t value) {
    return hostToNetwork64(value);
}

} // namespace

namespace protocol {

bool PacketHeader::hasValidMagic() const {
    return magic == MAGIC;
}

bool PacketHeader::hasExpectedVersion() const {
    return version == VERSION;
}

std::array<uint8_t, HEADER_SIZE> serializeHeader(const PacketHeader &header) {
    std::array<uint8_t, HEADER_SIZE> buffer{};

    const uint32_t magicNetwork = htonl(header.magic);
    const uint32_t transferIdNetwork = htonl(header.transferId);
    const uint32_t sequenceNetwork = htonl(header.sequenceNumber);
    const uint32_t totalPacketsNetwork = htonl(header.totalPackets);
    const uint16_t payloadLengthNetwork = htons(header.payloadLength);

    std::uint8_t *out = buffer.data();
    std::memcpy(out, &magicNetwork, sizeof(magicNetwork));
    out += sizeof(magicNetwork);

    *out++ = header.version;
    *out++ = static_cast<uint8_t>(header.type);

    std::memcpy(out, &transferIdNetwork, sizeof(transferIdNetwork));
    out += sizeof(transferIdNetwork);

    std::memcpy(out, &sequenceNetwork, sizeof(sequenceNetwork));
    out += sizeof(sequenceNetwork);

    std::memcpy(out, &totalPacketsNetwork, sizeof(totalPacketsNetwork));
    out += sizeof(totalPacketsNetwork);

    std::memcpy(out, &payloadLengthNetwork, sizeof(payloadLengthNetwork));

    return buffer;
}

bool deserializeHeader(const uint8_t *buffer, std::size_t length, PacketHeader &header) {
    if (buffer == nullptr || length < HEADER_SIZE) {
        return false;
    }

    const std::uint8_t *in = buffer;

    uint32_t magicNetwork = 0;
    std::memcpy(&magicNetwork, in, sizeof(magicNetwork));
    in += sizeof(magicNetwork);

    header.magic = ntohl(magicNetwork);
    header.version = *in++;
    header.type = static_cast<PacketType>(*in++);

    uint32_t transferIdNetwork = 0;
    std::memcpy(&transferIdNetwork, in, sizeof(transferIdNetwork));
    in += sizeof(transferIdNetwork);
    header.transferId = ntohl(transferIdNetwork);

    uint32_t sequenceNetwork = 0;
    std::memcpy(&sequenceNetwork, in, sizeof(sequenceNetwork));
    in += sizeof(sequenceNetwork);
    header.sequenceNumber = ntohl(sequenceNetwork);

    uint32_t totalPacketsNetwork = 0;
    std::memcpy(&totalPacketsNetwork, in, sizeof(totalPacketsNetwork));
    in += sizeof(totalPacketsNetwork);
    header.totalPackets = ntohl(totalPacketsNetwork);

    uint16_t payloadLengthNetwork = 0;
    std::memcpy(&payloadLengthNetwork, in, sizeof(payloadLengthNetwork));
    header.payloadLength = ntohs(payloadLengthNetwork);

    return header.hasValidMagic();
}

bool encodeStartPayload(const StartPacketPayload &payload, std::vector<uint8_t> &out, std::string *error) {
    const std::size_t nameLen = payload.fileName.size();
    if (nameLen > MAX_FILENAME_LENGTH) {
        if (error) {
            *error = "filename too long for protocol header";
        }
        return false;
    }

    out.clear();
    out.reserve(2u + sizeof(uint64_t) + IV_LENGTH + nameLen);

    out.push_back(static_cast<uint8_t>(nameLen));
    out.push_back(payload.flags);

    const uint64_t fileSizeNetwork = hostToNetwork64(payload.fileSize);
    const auto *fileSizeBytes = reinterpret_cast<const uint8_t *>(&fileSizeNetwork);
    out.insert(out.end(), fileSizeBytes, fileSizeBytes + sizeof(fileSizeNetwork));

    out.insert(out.end(), payload.iv.begin(), payload.iv.end());
    out.insert(out.end(), payload.fileName.begin(), payload.fileName.end());

    return true;
}

bool decodeStartPayload(const uint8_t *data, std::size_t length, StartPacketPayload &out, std::string *error) {
    if (data == nullptr || length < 2u + sizeof(uint64_t) + IV_LENGTH) {
        if (error) {
            *error = "start payload too short";
        }
        return false;
    }

    const std::size_t nameLen = data[0];
    if (length < 2u + sizeof(uint64_t) + IV_LENGTH + nameLen) {
        if (error) {
            *error = "start payload truncated";
        }
        return false;
    }

    out.flags = data[1];

    uint64_t fileSizeNetwork = 0;
    std::memcpy(&fileSizeNetwork, data + 2, sizeof(fileSizeNetwork));
    out.fileSize = networkToHost64(fileSizeNetwork);

    std::copy_n(data + 2 + sizeof(fileSizeNetwork), IV_LENGTH, out.iv.begin());

    const auto nameBegin = data + 2 + sizeof(fileSizeNetwork) + IV_LENGTH;
    out.fileName.assign(reinterpret_cast<const char *>(nameBegin), nameLen);

    return true;
}

} // namespace protocol
