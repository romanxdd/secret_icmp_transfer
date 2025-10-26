#include "receiver.h"

#include "crypto.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <memory>

namespace {

bool ensureLoginProvided(const AppConfig &config, std::string &errorMessage) {
    if (config.login.empty()) {
        errorMessage = "receiver requires login for key derivation";
        return false;
    }
    return true;
}

bool writeFile(const std::string &path, const std::vector<uint8_t> &data, std::string &errorMessage) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        errorMessage = std::string("unable to open output file: ") + path;
        return false;
    }
    output.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!output) {
        errorMessage = "failed while writing output file";
        return false;
    }
    return true;
}

const u_char *skipEthernet(const pcap_pkthdr *header, const u_char *packet, std::size_t &length) {
    if (header->caplen < sizeof(struct ether_header)) {
        return nullptr;
    }
    const struct ether_header *eth = reinterpret_cast<const struct ether_header *>(packet);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return nullptr;
    }
    length = header->caplen - sizeof(struct ether_header);
    return packet + sizeof(struct ether_header);
}

bool extractIcmpPayload(const pcap_pkthdr *header, const u_char *packet,
                        const uint8_t *&payload, std::size_t &payloadLen, std::string &errorMessage) {
    std::size_t remaining = 0;
    const u_char *ipBytes = skipEthernet(header, packet, remaining);
    if (!ipBytes || remaining < sizeof(struct ip)) {
        return false;
    }

    const struct ip *ipHeader = reinterpret_cast<const struct ip *>(ipBytes);
    if (ipHeader->ip_p != IPPROTO_ICMP) {
        return false;
    }

    const std::size_t ipHeaderLen = static_cast<std::size_t>(ipHeader->ip_hl) * 4u;
    if (ipHeaderLen < sizeof(struct ip) || ipHeaderLen > remaining) {
        errorMessage = "invalid IPv4 header length";
        return false;
    }

    const std::size_t icmpAvailable = remaining - ipHeaderLen;
    if (icmpAvailable < sizeof(struct icmphdr)) {
        return false;
    }

    const struct icmphdr *icmpHeader = reinterpret_cast<const struct icmphdr *>(ipBytes + ipHeaderLen);
    if (icmpHeader->type != ICMP_ECHO) {
        return false;
    }

    const std::size_t icmpDataAvailable = icmpAvailable - sizeof(struct icmphdr);
    if (icmpDataAvailable < protocol::HEADER_SIZE) {
        return false;
    }

    payload = reinterpret_cast<const uint8_t *>(ipBytes + ipHeaderLen + sizeof(struct icmphdr));
    payloadLen = icmpDataAvailable;
    return true;
}

bool decryptToFile(const receiver::PacketReassembler &reassembler, const AppConfig &config,
                   ReceiverStats &stats, std::string &errorMessage) {
    crypto::Key key;
    if (!crypto::deriveKeyFromLogin(config.login, key)) {
        errorMessage = "key derivation failed";
        return false;
    }

    crypto::Aes256CbcDecryptor decryptor;
    if (!decryptor.init(key, reassembler.state().iv, &errorMessage)) {
        return false;
    }

    const std::vector<uint8_t> ciphertext = reassembler.assembleCiphertext();
    std::vector<uint8_t> plaintext;
    if (!ciphertext.empty()) {
        if (!decryptor.update(ciphertext.data(), ciphertext.size(), plaintext, &errorMessage)) {
            return false;
        }
    }

    if (!decryptor.finalize(plaintext, &errorMessage)) {
        return false;
    }

    if (plaintext.size() != reassembler.state().fileSize) {
        errorMessage = "plaintext size mismatch";
        return false;
    }

    if (!writeFile(reassembler.state().fileName, plaintext, errorMessage)) {
        return false;
    }

    stats.bytesDecrypted = plaintext.size();
    stats.outputFile = reassembler.state().fileName;
    return true;
}

} // namespace

namespace receiver {

bool PacketReassembler::handleStart(const protocol::PacketHeader &header,
                                    const protocol::StartPacketPayload &payload,
                                    std::string &errorMessage) {
    if (state_.hasStart) {
        if (header.transferId != state_.transferId) {
            return false;
        }
        return true;
    }

    if (header.totalPackets == 0) {
        errorMessage = "start packet reports zero total packets";
        return false;
    }

    state_.hasStart = true;
    state_.transferId = header.transferId;
    state_.totalPackets = header.totalPackets;
    state_.receivedPackets = 0;
    state_.fileSize = payload.fileSize;
    state_.iv = payload.iv;
    state_.fileName = payload.fileName;
    state_.chunks.assign(state_.totalPackets, std::vector<uint8_t>());
    state_.receivedFlags.assign(state_.totalPackets, false);
    return true;
}

bool PacketReassembler::handleData(const protocol::PacketHeader &header,
                                   const uint8_t *payload, std::size_t length,
                                   std::string &errorMessage) {
    if (!state_.hasStart) {
        return false;
    }
    if (state_.hasEnd) {
        return false;
    }
    if (header.transferId != state_.transferId) {
        return false;
    }
    if (header.sequenceNumber >= state_.totalPackets) {
        errorMessage = "data packet sequence out of range";
        return false;
    }
    if (state_.receivedFlags[header.sequenceNumber]) {
        return true;
    }

    state_.chunks[header.sequenceNumber].assign(payload, payload + length);
    state_.receivedFlags[header.sequenceNumber] = true;
    state_.receivedPackets += 1;
    return true;
}

bool PacketReassembler::handleEnd(const protocol::PacketHeader &header, std::string &errorMessage) {
    if (!state_.hasStart) {
        return false;
    }
    if (header.transferId != state_.transferId) {
        return false;
    }
    if (state_.hasEnd) {
        return true;
    }
    if (header.sequenceNumber != state_.totalPackets) {
        errorMessage = "end packet sequence does not match total";
        return false;
    }
    state_.hasEnd = true;
    return true;
}

bool PacketReassembler::isComplete() const {
    return state_.hasStart && state_.hasEnd && state_.receivedPackets == state_.totalPackets;
}

std::vector<uint8_t> PacketReassembler::assembleCiphertext() const {
    std::vector<uint8_t> result;
    result.reserve(state_.totalPackets * protocol::DEFAULT_CHUNK_SIZE);
    for (const auto &chunk : state_.chunks) {
        result.insert(result.end(), chunk.begin(), chunk.end());
    }
    return result;
}

} // namespace receiver

bool runReceiver(const AppConfig &config, ReceiverStats &stats, std::string &errorMessage) {
    stats = ReceiverStats{};

    if (!ensureLoginProvided(config, errorMessage)) {
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *devices = nullptr;
    if (::pcap_findalldevs(&devices, errbuf) == -1) {
        errorMessage = std::string("pcap_findalldevs failed: ") + errbuf;
        return false;
    }

    std::string deviceName;
    if (!config.interfaceName.empty()) {
        for (const pcap_if_t *cur = devices; cur != nullptr; cur = cur->next) {
            if (cur->name && config.interfaceName == cur->name) {
                deviceName = cur->name;
                break;
            }
        }
        if (deviceName.empty()) {
            ::pcap_freealldevs(devices);
            errorMessage = "specified interface not found";
            return false;
        }
    } else {
        const pcap_if_t *chosen = devices;
        for (const pcap_if_t *cur = devices; cur != nullptr; cur = cur->next) {
            if (cur->name == nullptr) {
                continue;
            }
            chosen = cur;
            if ((cur->flags & PCAP_IF_LOOPBACK) == 0) {
                break;
            }
        }
        if (!chosen || !chosen->name) {
            ::pcap_freealldevs(devices);
            errorMessage = "no capture devices available";
            return false;
        }
        deviceName = chosen->name;
    }
    ::pcap_freealldevs(devices);

    pcap_t *handle = ::pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        errorMessage = std::string("pcap_open_live failed: ") + errbuf;
        return false;
    }

    struct bpf_program program;
    if (::pcap_compile(handle, &program, "icmp and icmp[8:4] = 0x53434341", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        errorMessage = std::string("pcap_compile failed: ") + ::pcap_geterr(handle);
        ::pcap_close(handle);
        return false;
    }

    if (::pcap_setfilter(handle, &program) == -1) {
        errorMessage = std::string("pcap_setfilter failed: ") + ::pcap_geterr(handle);
        ::pcap_freecode(&program);
        ::pcap_close(handle);
        return false;
    }
    ::pcap_freecode(&program);

    receiver::PacketReassembler reassembler;

    while (!reassembler.isComplete()) {
        struct pcap_pkthdr *header = nullptr;
        const u_char *packet = nullptr;
        const int rc = ::pcap_next_ex(handle, &header, &packet);
        if (rc == 0) {
            continue;
        }
        if (rc == -1) {
            errorMessage = std::string("pcap_next_ex failed: ") + ::pcap_geterr(handle);
            ::pcap_close(handle);
            return false;
        }
        if (rc == -2) {
            break;
        }

        stats.packetsCaptured += 1;

        const uint8_t *payload = nullptr;
        std::size_t payloadLen = 0;
        if (!extractIcmpPayload(header, packet, payload, payloadLen, errorMessage)) {
            continue;
        }

        protocol::PacketHeader headerParsed;
        if (!protocol::deserializeHeader(payload, payloadLen, headerParsed)) {
            continue;
        }

        const uint8_t *protocolPayload = payload + protocol::HEADER_SIZE;
        const std::size_t protocolPayloadLen = payloadLen - protocol::HEADER_SIZE;

        switch (headerParsed.type) {
            case protocol::PacketType::Start: {
                protocol::StartPacketPayload startPayload;
                if (!protocol::decodeStartPayload(protocolPayload, protocolPayloadLen, startPayload, &errorMessage)) {
                    ::pcap_close(handle);
                    return false;
                }
                if (!reassembler.handleStart(headerParsed, startPayload, errorMessage)) {
                    if (!errorMessage.empty()) {
                        ::pcap_close(handle);
                        return false;
                    }
                    continue;
                }
                stats.startPackets += 1;
                break;
            }
            case protocol::PacketType::Data: {
                if (!reassembler.handleData(headerParsed, protocolPayload, protocolPayloadLen, errorMessage)) {
                    if (!errorMessage.empty()) {
                        ::pcap_close(handle);
                        return false;
                    }
                    continue;
                }
                stats.dataPackets += 1;
                break;
            }
            case protocol::PacketType::End: {
                if (!reassembler.handleEnd(headerParsed, errorMessage)) {
                    if (!errorMessage.empty()) {
                        ::pcap_close(handle);
                        return false;
                    }
                    continue;
                }
                stats.endPackets += 1;
                break;
            }
            default:
                break;
        }
    }

    ::pcap_close(handle);

    if (!reassembler.isComplete()) {
        errorMessage = "capture ended before transfer complete";
        return false;
    }

    if (!decryptToFile(reassembler, config, stats, errorMessage)) {
        return false;
    }
    return true;
}
