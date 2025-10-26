#include "sender.h"

#include "protocol.h"

#include <cstdio>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

struct CapturedPacket {
    protocol::PacketHeader header;
    std::vector<uint8_t> payload;
};

class CapturingChannel : public OutboundChannel {
  public:
    bool sendPacket(const protocol::PacketHeader &header,
                    const std::vector<uint8_t> &payload,
                    std::string &errorMessage) override {
        (void)errorMessage;
        CapturedPacket packet{header, payload};
        packets.emplace_back(std::move(packet));
        return true;
    }

    std::vector<CapturedPacket> packets;
};

bool isStartPacket(const protocol::PacketHeader &header) {
    return header.type == protocol::PacketType::Start && header.sequenceNumber == protocol::START_SEQUENCE;
}

bool isEndPacket(const protocol::PacketHeader &header) {
    return header.type == protocol::PacketType::End;
}

bool isDataPacket(const protocol::PacketHeader &header) {
    return header.type == protocol::PacketType::Data;
}

int runSenderFlowTest() {
    // Create a temporary file with known contents.
    const std::string tempPath = "sender_test_input.bin";
    const std::string contents = "This is a sender flow test payload.";
    {
        FILE *fp = std::fopen(tempPath.c_str(), "wb");
        if (!fp) {
            std::cerr << "unable to create temp file" << std::endl;
            return 1;
        }
        std::fwrite(contents.data(), 1, contents.size(), fp);
        std::fclose(fp);
    }

    AppConfig config;
    config.listenMode = false;
    config.sourcePath = tempPath;
    config.destination = "198.51.100.7";
    config.chunkSize = 16;
    config.login = "alice";

    CapturingChannel channel;
    SenderStats stats;
    std::string error;

    const bool ok = runSender(config, stats, error, channel);

    std::remove(tempPath.c_str());

    if (!ok) {
        std::cerr << "runSender failed: " << error << std::endl;
        return 1;
    }

    if (channel.packets.size() < 3) {
        std::cerr << "expected at least start/data/end packets" << std::endl;
        return 1;
    }

    if (!isStartPacket(channel.packets.front().header)) {
        std::cerr << "first packet is not START" << std::endl;
        return 1;
    }

    if (!isEndPacket(channel.packets.back().header)) {
        std::cerr << "last packet is not END" << std::endl;
        return 1;
    }

    const std::size_t dataCount = channel.packets.size() - 2;
    for (std::size_t i = 1; i + 1 < channel.packets.size(); ++i) {
        if (!isDataPacket(channel.packets[i].header)) {
            std::cerr << "intermediate packet not DATA" << std::endl;
            return 1;
        }
    }

    const auto &startHeader = channel.packets.front().header;
    if (startHeader.totalPackets != dataCount) {
        std::cerr << "start header totalPackets mismatch" << std::endl;
        return 1;
    }

    const auto &endHeader = channel.packets.back().header;
    if (endHeader.sequenceNumber != startHeader.totalPackets) {
        std::cerr << "end packet sequence mismatch" << std::endl;
        return 1;
    }

    if (stats.packetsSent != channel.packets.size()) {
        std::cerr << "stats packetsSent mismatch" << std::endl;
        return 1;
    }

    std::cout << "sender flow test passed" << std::endl;
    return 0;
}

} // namespace

int main() {
    return runSenderFlowTest();
}
