#include "app_config.h"

#include <iostream>
#include <string>

namespace {

int runSenderTest() {
    char arg0[] = "secret";
    char arg1[] = "-r";
    char arg2[] = "input.bin";
    char arg3[] = "-s";
    char arg4[] = "192.0.2.10";
    char *argv[] = {arg0, arg1, arg2, arg3, arg4, nullptr};
    int argc = 5;

    AppConfig config;
    std::string error;
    if (!parseCommandLine(argc, argv, config, error)) {
        std::cerr << "sender parse failed: " << error << std::endl;
        return 1;
    }

    if (config.listenMode || config.sourcePath != "input.bin" ||
        config.destination != "192.0.2.10" || config.chunkSize != protocol::DEFAULT_CHUNK_SIZE) {
        std::cerr << "sender configuration mismatch" << std::endl;
        return 1;
    }
    return 0;
}

int runMissingDestTest() {
    char arg0[] = "secret";
    char arg1[] = "-r";
    char arg2[] = "input.bin";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int argc = 3;

    AppConfig config;
    std::string error;
    if (parseCommandLine(argc, argv, config, error)) {
        std::cerr << "expected failure when destination omitted" << std::endl;
        return 1;
    }
    if (error.find("-s") == std::string::npos) {
        std::cerr << "unexpected error message: " << error << std::endl;
        return 1;
    }
    return 0;
}

int runListenTest() {
    char arg0[] = "secret";
    char arg1[] = "-l";
    char arg2[] = "-v";
    char *argv[] = {arg0, arg1, arg2, nullptr};
    int argc = 3;

    AppConfig config;
    std::string error;
    if (!parseCommandLine(argc, argv, config, error)) {
        std::cerr << "listen parse failed: " << error << std::endl;
        return 1;
    }
    if (!config.listenMode || !config.verbose) {
        std::cerr << "listen configuration mismatch" << std::endl;
        return 1;
    }
    if (!config.interfaceName.empty()) {
        std::cerr << "interface should default empty" << std::endl;
        return 1;
    }
    return 0;
}

int runInterfaceTest() {
    char arg0[] = "secret";
    char arg1[] = "-l";
    char arg2[] = "-i";
    char arg3[] = "lo";
    char *argv[] = {arg0, arg1, arg2, arg3, nullptr};
    int argc = 4;

    AppConfig config;
    std::string error;
    if (!parseCommandLine(argc, argv, config, error)) {
        std::cerr << "interface parse failed: " << error << std::endl;
        return 1;
    }
    if (!config.listenMode || config.interfaceName != "lo") {
        std::cerr << "interface configuration mismatch" << std::endl;
        return 1;
    }
    return 0;
}

} // namespace

int main() {
    if (runSenderTest() != 0) {
        return 1;
    }
    if (runMissingDestTest() != 0) {
        return 1;
    }
    if (runListenTest() != 0) {
        return 1;
    }
    if (runInterfaceTest() != 0) {
        return 1;
    }
    std::cout << "app_config tests passed" << std::endl;
    return 0;
}
