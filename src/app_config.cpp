#include "app_config.h"

#include <cerrno>
#include <cinttypes>
#include <climits>
#include <cstdlib>
#include <getopt.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace {

bool parseChunkSize(const char *argument, std::size_t &out, std::string &errorMessage) {
    try {
        std::size_t value = std::stoul(argument);
        if (value == 0 || value > UINT16_MAX) {
            errorMessage = "chunk size must be between 1 and 65535 bytes";
            return false;
        }
        out = value;
        return true;
    } catch (const std::exception &) {
        errorMessage = "invalid numeric value for chunk size";
        return false;
    }
}

} // namespace

bool parseCommandLine(int argc, char **argv, AppConfig &config, std::string &errorMessage) {
    config = AppConfig{};
    ::optind = 1;
    int option = 0;
    while ((option = ::getopt(argc, argv, "r:s:lc:vk:h")) != -1) {
        switch (option) {
            case 'r':
                config.sourcePath = ::optarg ? ::optarg : "";
                break;
            case 's':
                config.destination = ::optarg ? ::optarg : "";
                break;
            case 'l':
                config.listenMode = true;
                break;
            case 'c':
                if (!parseChunkSize(::optarg, config.chunkSize, errorMessage)) {
                    return false;
                }
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'k':
                config.login = ::optarg ? ::optarg : "";
                break;
            case 'h':
                config.showHelp = true;
                break;
            case '?':
            default:
                errorMessage = "unknown command-line option";
                return false;
        }
    }

    if (::optind < argc) {
        errorMessage = "unexpected positional argument";
        return false;
    }

    if (config.listenMode) {
        if (!config.sourcePath.empty()) {
            errorMessage = "listen mode does not use -r";
            return false;
        }
        if (!config.destination.empty()) {
            errorMessage = "listen mode does not use -s";
            return false;
        }
    } else {
        if (config.sourcePath.empty()) {
            errorMessage = "sender mode requires -r <file>";
            return false;
        }
        if (config.destination.empty()) {
            errorMessage = "sender mode requires -s <ip|hostname>";
            return false;
        }
    }

    return true;
}

void printUsage(const char *programName, std::ostream &os) {
    os << "Usage: " << (programName ? programName : "secret")
       << " -r <file> -s <ip|hostname> [options]\n"
       << "       " << (programName ? programName : "secret") << " -l [options]\n\n"
       << "Options:\n"
       << "  -r <file>         Path to file to send (sender mode)\n"
       << "  -s <dest>         Destination IP or hostname (sender mode)\n"
       << "  -l                Listen mode (receiver)\n"
       << "  -c <bytes>        Override encrypted chunk size (default "
       << protocol::DEFAULT_CHUNK_SIZE << ")\n"
       << "  -k <login>        Override login used for key derivation\n"
       << "  -v                Verbose logging\n"
       << "  -h                Show this help message\n";
}
