#include "receiver.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main() {
    receiver::PacketReassembler reassembler;
    protocol::PacketHeader startHeader;
    startHeader.type = protocol::PacketType::Start;
    startHeader.transferId = 0x11223344u;
    startHeader.sequenceNumber = protocol::START_SEQUENCE;
    startHeader.totalPackets = 3u;

    protocol::StartPacketPayload startPayload;
    startPayload.fileSize = 18u;
    for (std::size_t i = 0; i < startPayload.iv.size(); ++i) {
        startPayload.iv[i] = static_cast<uint8_t>(i);
    }
    startPayload.fileName = "reassembler.txt";

    std::string error;
    if (!reassembler.handleStart(startHeader, startPayload, error)) {
        std::cerr << "handleStart failed: " << error << std::endl;
        return 1;
    }

    const std::vector<uint8_t> chunk0 = {'H', 'e', 'l'};
    const std::vector<uint8_t> chunk1 = {'l', 'o', ',', ' '};
    const std::vector<uint8_t> chunk2 = {'w', 'o', 'r', 'l', 'd', '!', '\n', '!', '!'};

    protocol::PacketHeader dataHeader = startHeader;
    dataHeader.type = protocol::PacketType::Data;

    dataHeader.sequenceNumber = 2;
    if (!reassembler.handleData(dataHeader, chunk2.data(), chunk2.size(), error)) {
        std::cerr << "handleData seq2 failed: " << error << std::endl;
        return 1;
    }

    dataHeader.sequenceNumber = 0;
    if (!reassembler.handleData(dataHeader, chunk0.data(), chunk0.size(), error)) {
        std::cerr << "handleData seq0 failed: " << error << std::endl;
        return 1;
    }

    dataHeader.sequenceNumber = 1;
    if (!reassembler.handleData(dataHeader, chunk1.data(), chunk1.size(), error)) {
        std::cerr << "handleData seq1 failed: " << error << std::endl;
        return 1;
    }

    if (!reassembler.handleData(dataHeader, chunk1.data(), chunk1.size(), error)) {
        std::cerr << "duplicate data rejected" << std::endl;
        return 1;
    }

    protocol::PacketHeader endHeader = startHeader;
    endHeader.type = protocol::PacketType::End;
    endHeader.sequenceNumber = startHeader.totalPackets;
    if (!reassembler.handleEnd(endHeader, error)) {
        std::cerr << "handleEnd failed: " << error << std::endl;
        return 1;
    }

    if (!reassembler.isComplete()) {
        std::cerr << "reassembler not complete" << std::endl;
        return 1;
    }

    const std::vector<uint8_t> assembled = reassembler.assembleCiphertext();
    if (assembled.size() != chunk0.size() + chunk1.size() + chunk2.size()) {
        std::cerr << "assembled size mismatch" << std::endl;
        return 1;
    }

    if (reassembler.state().fileName != "reassembler.txt") {
        std::cerr << "filename mismatch" << std::endl;
        return 1;
    }

    std::cout << "receiver reassembly test passed" << std::endl;
    return 0;
}
