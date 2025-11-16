#include "receiver.h"

#include "crypto.h"
#include "protocol.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <pcap/pcap.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>

namespace {

bool ensureLoginProvided(const AppConfig &config, std::string &errorMessage) {
    if (config.login.empty()) {
        errorMessage = "receiver requires login for key derivation";
        return false;
    }
    return true;
}

bool decryptFileName(protocol::StartPacketPayload &payload, const crypto::Key &key,
                     std::string &errorMessage) {
    if (payload.encryptedFileName.empty()) {
        errorMessage = "start packet missing encrypted filename";
        return false;
    }

    crypto::Aes256CbcDecryptor decryptor;
    if (!decryptor.init(key, payload.metadataIv, &errorMessage)) {
        return false;
    }

    std::vector<uint8_t> plaintext;
    if (!decryptor.update(payload.encryptedFileName.data(), payload.encryptedFileName.size(), plaintext, &errorMessage)) {
        return false;
    }

    if (!decryptor.finalize(plaintext, &errorMessage)) {
        return false;
    }

    if (plaintext.size() != payload.fileNameLength) {
        errorMessage = "filename length mismatch";
        return false;
    }
    if (plaintext.size() > protocol::MAX_FILENAME_LENGTH) {
        errorMessage = "filename exceeds protocol limits";
        return false;
    }

    payload.fileName.assign(reinterpret_cast<const char *>(plaintext.data()), plaintext.size());
    return true;
}

bool chooseCaptureDevice(const std::string &requestedName,
                         std::string &deviceName,
                         std::string &errorMessage) {
    if (requestedName == "any") {
        deviceName = "any";
        return true;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *devices = nullptr;
    if (::pcap_findalldevs(&devices, errbuf) == -1) {
        errorMessage = std::string("pcap_findalldevs failed: ") + errbuf;
        return false;
    }

    auto cleanup = [&]() {
        if (devices) {
            ::pcap_freealldevs(devices);
        }
    };

    if (!requestedName.empty()) {
        for (const pcap_if_t *cur = devices; cur != nullptr; cur = cur->next) {
            if (cur->name && requestedName == cur->name) {
                deviceName = cur->name;
                cleanup();
                return true;
            }
        }
        cleanup();
        errorMessage = "specified interface not found";
        return false;
    }

    const pcap_if_t *chosen = nullptr;
    for (const pcap_if_t *cur = devices; cur != nullptr; cur = cur->next) {
        if (cur->name == nullptr) {
            continue;
        }
        if (!chosen) {
            chosen = cur;
        }
        if ((cur->flags & PCAP_IF_LOOPBACK) == 0) {
            chosen = cur;
            break;
        }
    }

    if (!chosen || !chosen->name) {
        cleanup();
        errorMessage = "no capture devices available";
        return false;
    }

    deviceName = chosen->name;
    cleanup();
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

constexpr int CAPTURE_TIMEOUT_MS = 1000;
constexpr int CAPTURE_BUFFER_BYTES = 8 * 1024 * 1024;
pcap_t *openCaptureHandle(const std::string &deviceName,
                          bool &usingEnhancedBuffer,
                          std::string &errorMessage) {
    usingEnhancedBuffer = false;
    errorMessage.clear();
    std::string createError;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (pcap_t *created = ::pcap_create(deviceName.c_str(), errbuf)) {
        const bool configured = (::pcap_set_snaplen(created, 65535) == 0 &&
                                 ::pcap_set_promisc(created, 1) == 0 &&
                                 ::pcap_set_timeout(created, CAPTURE_TIMEOUT_MS) == 0 &&
                                 ::pcap_set_buffer_size(created, CAPTURE_BUFFER_BYTES) == 0);
        if (configured) {
            const int activateResult = ::pcap_activate(created);
            if (activateResult >= 0) {
                usingEnhancedBuffer = true;
                return created;
            }
            if (const char *err = ::pcap_geterr(created); err && *err) {
                createError = err;
            } else {
                createError = "pcap_activate failed";
            }
        } else {
            if (const char *err = ::pcap_geterr(created); err && *err) {
                createError = err;
            } else {
                createError = "pcap configuration failed";
            }
        }
        ::pcap_close(created);
    } else if (errbuf[0] != '\0') {
        createError = errbuf;
    }

    char fallbackErr[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = ::pcap_open_live(deviceName.c_str(), 65535, 1, CAPTURE_TIMEOUT_MS, fallbackErr);
    if (!handle) {
        std::string combined;
        if (!createError.empty()) {
            combined = createError + "; ";
        }
        combined += std::string("pcap_open_live failed: ") + fallbackErr;
        errorMessage = combined;
        return nullptr;
    }

    errorMessage.clear();
    return handle;
}

struct LinuxCookedCaptureHeader {
    uint16_t packetType;
    uint16_t addressType;
    uint16_t addressLength;
    uint8_t address[8];
    uint16_t protocol;
};

struct LinuxCookedCaptureHeaderV2 {
    uint16_t protocol;
    uint16_t reserved;
    uint32_t interfaceIndex;
    uint16_t addressType;
    uint8_t packetType;
    uint8_t addressLength;
    uint8_t address[8];
};

bool extractNetworkPayload(int datalink, const pcap_pkthdr *header, const u_char *packet,
                           const u_char *&networkBytes, std::size_t &length, uint16_t &etherType,
                           std::string &errorMessage) {
    switch (datalink) {
        case DLT_EN10MB: {
            if (header->caplen < sizeof(struct ether_header)) {
                return false;
            }
            const struct ether_header *eth = reinterpret_cast<const struct ether_header *>(packet);
            etherType = ntohs(eth->ether_type);
            networkBytes = packet + sizeof(struct ether_header);
            length = header->caplen - sizeof(struct ether_header);
            return true;
        }
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL: {
            if (header->caplen < sizeof(LinuxCookedCaptureHeader)) {
                return false;
            }
            const auto *sll = reinterpret_cast<const LinuxCookedCaptureHeader *>(packet);
            etherType = ntohs(sll->protocol);
            networkBytes = packet + sizeof(LinuxCookedCaptureHeader);
            length = header->caplen - sizeof(LinuxCookedCaptureHeader);
            return true;
        }
#endif
#ifdef DLT_LINUX_SLL2
        case DLT_LINUX_SLL2: {
            if (header->caplen < sizeof(LinuxCookedCaptureHeaderV2)) {
                return false;
            }
            const auto *sll2 = reinterpret_cast<const LinuxCookedCaptureHeaderV2 *>(packet);
            etherType = ntohs(sll2->protocol);
            networkBytes = packet + sizeof(LinuxCookedCaptureHeaderV2);
            length = header->caplen - sizeof(LinuxCookedCaptureHeaderV2);
            return true;
        }
#endif
        default:
            errorMessage = "unsupported datalink type: " + std::to_string(datalink);
            return false;
    }
}

bool extractIcmpv4Payload(const u_char *networkBytes, std::size_t remaining,
                          const uint8_t *&payload, std::size_t &payloadLen, std::string &errorMessage) {
    if (remaining < sizeof(struct ip)) {
        return false;
    }

    const struct ip *ipHeader = reinterpret_cast<const struct ip *>(networkBytes);
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

    const struct icmphdr *icmpHeader = reinterpret_cast<const struct icmphdr *>(networkBytes + ipHeaderLen);
    if (icmpHeader->type != ICMP_ECHO) {
        return false;
    }

    const std::size_t icmpDataAvailable = icmpAvailable - sizeof(struct icmphdr);
    if (icmpDataAvailable < protocol::HEADER_SIZE) {
        return false;
    }

    payload = reinterpret_cast<const uint8_t *>(networkBytes + ipHeaderLen + sizeof(struct icmphdr));
    payloadLen = icmpDataAvailable;
    return true;
}

bool extractIcmpv6Payload(const u_char *networkBytes, std::size_t remaining,
                          const uint8_t *&payload, std::size_t &payloadLen, std::string &errorMessage) {
    if (remaining < sizeof(struct ip6_hdr)) {
        return false;
    }

    const struct ip6_hdr *ipHeader = reinterpret_cast<const struct ip6_hdr *>(networkBytes);
    if (ipHeader->ip6_nxt != IPPROTO_ICMPV6) {
        return false;
    }

    std::size_t payloadAvailable = remaining - sizeof(struct ip6_hdr);
    const uint16_t ipv6PayloadLength = ntohs(ipHeader->ip6_plen);
    if (ipv6PayloadLength > payloadAvailable) {
        errorMessage = "captured frame smaller than IPv6 payload";
        return false;
    }
    payloadAvailable = std::min<std::size_t>(payloadAvailable, ipv6PayloadLength);

    if (payloadAvailable < sizeof(struct icmp6_hdr)) {
        return false;
    }

    const struct icmp6_hdr *icmpHeader = reinterpret_cast<const struct icmp6_hdr *>(networkBytes + sizeof(struct ip6_hdr));
    if (icmpHeader->icmp6_type != ICMP6_ECHO_REQUEST) {
        return false;
    }

    const std::size_t icmpDataAvailable = payloadAvailable - sizeof(struct icmp6_hdr);
    if (icmpDataAvailable < protocol::HEADER_SIZE) {
        return false;
    }

    payload = reinterpret_cast<const uint8_t *>(icmpHeader) + sizeof(struct icmp6_hdr);
    payloadLen = icmpDataAvailable;
    return true;
}

bool decryptToFile(const receiver::PacketReassembler &reassembler, const crypto::Key &key,
                   ReceiverStats &stats, std::string &errorMessage) {
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
    state_.receivedBytes = 0;
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
    state_.receivedBytes += static_cast<uint64_t>(length);
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

    crypto::Key key;
    if (!crypto::deriveKeyFromLogin(config.login, key)) {
        errorMessage = "key derivation failed";
        return false;
    }

    std::string deviceName;
    const bool preferAny = config.interfaceName.empty();
    if (preferAny) {
        deviceName = "any";
    } else {
        if (!chooseCaptureDevice(config.interfaceName, deviceName, errorMessage)) {
            return false;
        }
    }

    auto tryOpenHandle = [&](const std::string &name, std::string &openError) -> pcap_t * {
        bool usedEnhancedBuffer = false;
        pcap_t *handle = openCaptureHandle(name, usedEnhancedBuffer, openError);
        if (handle && config.verbose && usedEnhancedBuffer) {
            std::cout << "Capture buffer set to "
                      << (CAPTURE_BUFFER_BYTES / (1024 * 1024))
                      << " MB on interface " << name << std::endl;
        }
        return handle;
    };

    std::string openError;
    pcap_t *handle = tryOpenHandle(deviceName, openError);

    if (!handle && preferAny) {
        std::string chooseError;
        if (!chooseCaptureDevice("", deviceName, chooseError)) {
            errorMessage = chooseError.empty() ? "pcap_open_live failed" : chooseError;
            return false;
        }
        openError.clear();
        handle = tryOpenHandle(deviceName, openError);
    }

    if (!handle) {
        errorMessage = openError.empty() ? "pcap_open_live failed" : openError;
        return false;
    }

    const auto buildFilterExpression = [](AppConfig::IpVersionPreference pref) {
        switch (pref) {
            case AppConfig::IpVersionPreference::IPv4:
                return std::string("icmp and icmp[8:4] = 0x53434354");
            case AppConfig::IpVersionPreference::IPv6:
                return std::string("icmp6 and ip6[48:4] = 0x53434354");
            case AppConfig::IpVersionPreference::Auto:
            default:
                return std::string("(icmp and icmp[8:4] = 0x53434354) or (icmp6 and ip6[48:4] = 0x53434354)");
        }
    };

    const std::string filterExpr = buildFilterExpression(config.ipVersionPreference);

    struct bpf_program program;
    if (::pcap_compile(handle, &program, filterExpr.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
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
    const int datalinkType = ::pcap_datalink(handle);

    double lastProgressPercent = -10.0;
    const auto emitProgress = [&](bool force) {
        if (!config.verbose) {
            return;
        }
        const auto &state = reassembler.state();
        if (!state.hasStart || state.totalPackets == 0) {
            return;
        }
        double denominator = 0.0;
        double numerator = 0.0;
        if (state.fileSize > 0) {
            denominator = static_cast<double>(state.fileSize);
            numerator = static_cast<double>(std::min<uint64_t>(state.receivedBytes, state.fileSize));
        } else {
            denominator = static_cast<double>(state.totalPackets);
            numerator = static_cast<double>(state.receivedPackets);
        }

        if (denominator <= 0.0) {
            return;
        }

        double percent = (numerator * 100.0) / denominator;
        percent = std::clamp(percent, 0.0, 100.0);

        if (!force && percent < lastProgressPercent + 1.0 && state.receivedPackets != state.totalPackets) {
            return;
        }

        std::ostringstream oss;
        oss.setf(std::ios::fixed);
        oss << std::setprecision(1) << percent;
        std::cout << "Progress: " << state.receivedPackets << "/" << state.totalPackets
                  << " packets, " << state.receivedBytes << "/" << state.fileSize
                  << " bytes (" << oss.str() << "%)" << std::endl;
        lastProgressPercent = percent;
    };

    const auto announceStart = [&]() {
        if (!config.verbose) {
            return;
        }
        const auto &state = reassembler.state();
        if (!state.hasStart) {
            return;
        }
        std::cout << "Receiving \"" << state.fileName << "\" ("
                  << state.fileSize << " bytes across " << state.totalPackets
                  << " packets)" << std::endl;
    };

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
        bool havePayload = false;
    std::string packetError;

        const bool allowIpv4 = config.ipVersionPreference != AppConfig::IpVersionPreference::IPv6;
        const bool allowIpv6 = config.ipVersionPreference != AppConfig::IpVersionPreference::IPv4;

        const u_char *networkBytes = nullptr;
        std::size_t networkLength = 0;
        uint16_t etherType = 0;
        if (!extractNetworkPayload(datalinkType, header, packet, networkBytes, networkLength, etherType, packetError)) {
            if (!packetError.empty()) {
                errorMessage = packetError;
                ::pcap_close(handle);
                return false;
            }
            continue;
        }

        if (allowIpv4 && etherType == ETHERTYPE_IP) {
            if (extractIcmpv4Payload(networkBytes, networkLength, payload, payloadLen, packetError)) {
                havePayload = true;
            } else if (!packetError.empty()) {
                errorMessage = packetError;
                ::pcap_close(handle);
                return false;
            }
        }

        if (!havePayload && allowIpv6 && etherType == ETHERTYPE_IPV6) {
            if (extractIcmpv6Payload(networkBytes, networkLength, payload, payloadLen, packetError)) {
                havePayload = true;
            } else if (!packetError.empty()) {
                errorMessage = packetError;
                ::pcap_close(handle);
                return false;
            }
        }

        if (!havePayload) {
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
                if (!decryptFileName(startPayload, key, errorMessage)) {
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
                announceStart();
                emitProgress(true);
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
                emitProgress(false);
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
                emitProgress(true);
                break;
            }
            default:
                break;
        }
    }

    ::pcap_close(handle);

    emitProgress(true);

    if (!reassembler.isComplete()) {
        errorMessage = "capture ended before transfer complete";
        return false;
    }

    if (!decryptToFile(reassembler, key, stats, errorMessage)) {
        return false;
    }
    return true;
}
