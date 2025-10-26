#include "app_config.h"
#include "sender.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <pwd.h>
#include <string>
#include <sys/types.h>
#include <unistd.h>

namespace {

bool discoverLogin(std::string &login, std::string &errorMessage) {
    if (const char *env = std::getenv("LOGNAME")) {
        if (*env != '\0') {
            login.assign(env);
            return true;
        }
    }
    if (const char *env = std::getenv("USER")) {
        if (*env != '\0') {
            login.assign(env);
            return true;
        }
    }

    errno = 0;
    struct passwd *pw = ::getpwuid(::getuid());
    if (pw && pw->pw_name) {
        login.assign(pw->pw_name);
        return true;
    }

    errorMessage = errno ? std::string("getpwuid failed: ") + ::strerror(errno)
                         : "could not determine login";
    return false;
}

void emitConfigurationSummary(const AppConfig &config) {
    if (config.listenMode) {
        std::cout << "Mode: listen" << (config.verbose ? " (verbose)" : "") << '\n';
    } else {
        std::cout << "Mode: send to " << config.destination
                  << "\n  Source file: " << config.sourcePath
                  << "\n  Chunk size: " << config.chunkSize << " bytes"
                  << (config.verbose ? "\n  Verbose logging enabled" : "")
                  << '\n';
    }
    std::cout << "  Login key: " << config.login << '\n';
}

} // namespace

int main(int argc, char **argv) {
    AppConfig config;
    std::string errorMessage;
    if (!parseCommandLine(argc, argv, config, errorMessage)) {
        if (!errorMessage.empty()) {
            std::cerr << "Error: " << errorMessage << std::endl;
        }
        printUsage(argv[0], std::cerr);
        return 1;
    }

    if (config.showHelp) {
        printUsage(argv[0], std::cout);
        return 0;
    }

    if (config.login.empty()) {
        if (!discoverLogin(config.login, errorMessage)) {
            std::cerr << "Error: " << errorMessage << std::endl;
            return 1;
        }
    }

    emitConfigurationSummary(config);

        if (config.listenMode) {
                std::cerr << "Receiver mode not yet implemented" << std::endl;
                return 1;
        }

        class ConsoleChannel : public OutboundChannel {
      public:
        bool sendPacket(const protocol::PacketHeader &header,
                        const std::vector<uint8_t> &payload,
                        std::string &errorMessage) override {
            (void)errorMessage;
            if (verbose_) {
                std::cout << "Sending packet type=" << static_cast<int>(header.type)
                          << " seq=" << header.sequenceNumber
                          << " len=" << header.payloadLength << std::endl;
            }
            (void)payload;
            return true;
        }

        explicit ConsoleChannel(bool verbose) : verbose_(verbose) {}

      private:
        bool verbose_ = false;
    };

    ConsoleChannel channel(config.verbose);
    SenderStats stats;
    std::string senderError;
    if (!runSender(config, stats, senderError, channel)) {
        std::cerr << "Sender error: " << senderError << std::endl;
        return 1;
    }
    if (config.verbose) {
        std::cout << "Packets sent: " << stats.packetsSent
                  << ", bytes sent (approx): " << stats.bytesSent << std::endl;
    }

    return 0;
}
