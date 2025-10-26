#include "sender.h"

#include "crypto.h"
#include "protocol.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace {

class FileHandle {
  public:
    explicit FileHandle(const std::string &path) : fd_(::open(path.c_str(), O_RDONLY)) {}
    ~FileHandle() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    FileHandle(const FileHandle &) = delete;
    FileHandle &operator=(const FileHandle &) = delete;

    bool valid() const { return fd_ >= 0; }
    int get() const { return fd_; }

  private:
    int fd_ = -1;
};

uint32_t generateTransferId() {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> dist;
    return dist(rng);
}

bool readFileStat(const std::string &path, off_t &size, std::string &errorMessage) {
    struct stat st = {};
    if (::stat(path.c_str(), &st) != 0) {
        errorMessage = std::string("stat failed for ") + path + ": " + ::strerror(errno);
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        errorMessage = "source path is not a regular file";
        return false;
    }
    size = st.st_size;
    return true;
}

std::string basenameFromPath(const std::string &path) {
    const auto pos = path.find_last_of("/\\");
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

bool sendStartPacket(OutboundChannel &channel, const std::string &fileName, const crypto::Iv &iv,
                     uint32_t transferId, uint32_t totalPackets, uint64_t fileSize,
                     std::size_t &payloadLengthOut, std::string &errorMessage) {
    protocol::PacketHeader header;
    header.type = protocol::PacketType::Start;
    header.transferId = transferId;
    header.sequenceNumber = protocol::START_SEQUENCE;
    header.totalPackets = totalPackets;

    protocol::StartPacketPayload payload;
    payload.fileSize = fileSize;
    payload.iv = iv;
    payload.fileName = fileName;

    std::vector<uint8_t> encodedPayload;
    if (!protocol::encodeStartPayload(payload, encodedPayload, &errorMessage)) {
        return false;
    }

    header.payloadLength = static_cast<uint16_t>(encodedPayload.size());
    payloadLengthOut = encodedPayload.size();
    if (!channel.sendPacket(header, encodedPayload, errorMessage)) {
        return false;
    }

    return true;
}

bool sendDataPacket(OutboundChannel &channel, const std::vector<uint8_t> &chunk,
                    uint32_t seq, uint32_t transferId, uint32_t totalPackets,
                    std::string &errorMessage) {
    protocol::PacketHeader header;
    header.type = protocol::PacketType::Data;
    header.transferId = transferId;
    header.sequenceNumber = seq;
    header.totalPackets = totalPackets;
    header.payloadLength = static_cast<uint16_t>(chunk.size());

    return channel.sendPacket(header, chunk, errorMessage);
}

bool sendEndPacket(OutboundChannel &channel, uint32_t transferId, uint32_t totalPackets,
                   std::string &errorMessage) {
    protocol::PacketHeader header;
    header.type = protocol::PacketType::End;
    header.transferId = transferId;
    header.sequenceNumber = totalPackets;
    header.totalPackets = totalPackets;
    header.payloadLength = 0;

    std::vector<uint8_t> empty;
    return channel.sendPacket(header, empty, errorMessage);
}

} // namespace

bool runSender(const AppConfig &config, SenderStats &stats, std::string &errorMessage,
               OutboundChannel &channel) {
    stats = SenderStats{};

    if (config.listenMode) {
        errorMessage = "sender invoked while in listen mode";
        return false;
    }

    off_t fileSize = 0;
    if (!readFileStat(config.sourcePath, fileSize, errorMessage)) {
        return false;
    }

    FileHandle file(config.sourcePath);
    if (!file.valid()) {
        errorMessage = std::string("open failed for ") + config.sourcePath + ": " + ::strerror(errno);
        return false;
    }

    crypto::Key key{};
    if (!crypto::deriveKeyFromLogin(config.login, key)) {
        errorMessage = "failed to derive AES key";
        return false;
    }

    crypto::Iv iv{};
    if (!crypto::generateRandomIv(iv, &errorMessage)) {
        return false;
    }

    crypto::Aes256CbcEncryptor encryptor;
    if (!encryptor.init(key, iv, &errorMessage)) {
        return false;
    }

    const std::size_t chunkSize = config.chunkSize;
    const std::string fileNameOnly = basenameFromPath(config.sourcePath);
    std::vector<uint8_t> readBuffer(chunkSize);
    std::vector<uint8_t> cipherBuffer;
    std::vector<uint8_t> chunkPayload;

    uint32_t transferId = generateTransferId();
    uint32_t totalPackets = 0;

    std::vector<std::vector<uint8_t>> encryptedChunks;
    encryptedChunks.reserve(static_cast<std::size_t>((fileSize / chunkSize) + 2));

    for (;;) {
        ssize_t bytesRead = ::read(file.get(), readBuffer.data(), readBuffer.size());
        if (bytesRead < 0) {
            if (errno == EINTR) {
                continue;
            }
            errorMessage = std::string("read failed: ") + ::strerror(errno);
            return false;
        }
        if (bytesRead == 0) {
            break;
        }

        if (!encryptor.update(readBuffer.data(), static_cast<std::size_t>(bytesRead), cipherBuffer, &errorMessage)) {
            return false;
        }

        while (cipherBuffer.size() >= chunkSize) {
            chunkPayload.assign(cipherBuffer.begin(), cipherBuffer.begin() + chunkSize);
            cipherBuffer.erase(cipherBuffer.begin(), cipherBuffer.begin() + chunkSize);
            encryptedChunks.emplace_back(chunkPayload);
        }
    }

    if (!encryptor.finalize(cipherBuffer, &errorMessage)) {
        return false;
    }

    while (!cipherBuffer.empty()) {
        const std::size_t emitSize = std::min(chunkSize, cipherBuffer.size());
        chunkPayload.assign(cipherBuffer.begin(), cipherBuffer.begin() + emitSize);
        cipherBuffer.erase(cipherBuffer.begin(), cipherBuffer.begin() + emitSize);
        encryptedChunks.emplace_back(chunkPayload);
    }

    totalPackets = static_cast<uint32_t>(encryptedChunks.size());

    std::size_t startPayloadLen = 0;
    if (!sendStartPacket(channel, fileNameOnly, iv, transferId, totalPackets, static_cast<uint64_t>(fileSize),
                         startPayloadLen, errorMessage)) {
        return false;
    }
    ++stats.packetsSent;
    stats.bytesSent += protocol::HEADER_SIZE + startPayloadLen;

    uint32_t seq = 0;
    for (const auto &chunk : encryptedChunks) {
        if (!sendDataPacket(channel, chunk, seq, transferId, totalPackets, errorMessage)) {
            return false;
        }
        ++stats.packetsSent;
        stats.bytesSent += protocol::HEADER_SIZE + chunk.size();
        ++seq;
    }

    if (!sendEndPacket(channel, transferId, totalPackets, errorMessage)) {
        return false;
    }
    ++stats.packetsSent;
    stats.bytesSent += protocol::HEADER_SIZE;

    return true;
}
