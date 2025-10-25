#include "protocol.h"

#include <iostream>
#include <vector>

int main() {
    using namespace protocol;

    PacketHeader header{};
    header.type = PacketType::Start;
    header.transferId = 0xAABBCCDDu;
    header.sequenceNumber = START_SEQUENCE;
    header.totalPackets = 7u;
    header.payloadLength = 64u;

    const auto encodedHeader = serializeHeader(header);

    PacketHeader parsedHeader{};
    if (!deserializeHeader(encodedHeader.data(), encodedHeader.size(), parsedHeader)) {
        std::cerr << "deserializeHeader failed" << std::endl;
        return 1;
    }

    if (parsedHeader.magic != MAGIC || parsedHeader.version != VERSION ||
        parsedHeader.type != PacketType::Start || parsedHeader.transferId != header.transferId ||
        parsedHeader.sequenceNumber != header.sequenceNumber ||
        parsedHeader.totalPackets != header.totalPackets ||
        parsedHeader.payloadLength != header.payloadLength) {
        std::cerr << "header round-trip mismatch" << std::endl;
        return 1;
    }

    StartPacketPayload start{};
    start.flags = 0x01u;
    start.fileSize = 987654321ull;
    for (std::size_t i = 0; i < start.iv.size(); ++i) {
        start.iv[i] = static_cast<uint8_t>(i);
    }
    start.fileName = "demo.bin";

    std::vector<uint8_t> startBytes;
    if (!encodeStartPayload(start, startBytes)) {
        std::cerr << "encodeStartPayload failed" << std::endl;
        return 1;
    }

    StartPacketPayload decoded{};
    if (!decodeStartPayload(startBytes.data(), startBytes.size(), decoded)) {
        std::cerr << "decodeStartPayload failed" << std::endl;
        return 1;
    }

    if (decoded.flags != start.flags || decoded.fileSize != start.fileSize ||
        decoded.fileName != start.fileName || decoded.iv != start.iv) {
        std::cerr << "start payload round-trip mismatch" << std::endl;
        return 1;
    }

    std::cout << "protocol smoke tests passed" << std::endl;
    return 0;
}
