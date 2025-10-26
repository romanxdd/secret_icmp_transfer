#ifndef SECRET_APP_CONFIG_H
#define SECRET_APP_CONFIG_H

#include "protocol.h"

#include <cstddef>
#include <ostream>
#include <string>

struct AppConfig {
    bool listenMode = false;
    bool verbose = false;
    bool showHelp = false;
    std::string sourcePath;
    std::string destination;
    std::size_t chunkSize = protocol::DEFAULT_CHUNK_SIZE;
    std::string login;
    std::string interfaceName;
};

bool parseCommandLine(int argc, char **argv, AppConfig &config, std::string &errorMessage);
void printUsage(const char *programName, std::ostream &os);

#endif // SECRET_APP_CONFIG_H
