// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

#ifndef SECRET_APP_CONFIG_H
#define SECRET_APP_CONFIG_H

#include "protocol.h"

#include <cstddef>
#include <ostream>
#include <string>

/**
 * @brief aggregates all command-line options shared between sender and receiver
 */
struct AppConfig
{
    bool listenMode = false;
    bool verbose = false;
    bool showHelp = false;
    std::string sourcePath;
    std::string destination;
    std::size_t chunkSize = protocol::DEFAULT_CHUNK_SIZE;
    std::string login = "xkrajc26";
    std::string interfaceName;
    enum class IpVersionPreference
    {
        Auto,
        IPv4,
        IPv6
    } ipVersionPreference = IpVersionPreference::Auto;
};

/**
 * @brief parse CLI arguments into an @ref AppConfig struct
 * 
 * @param argc argument count from main()
 * @param argv argument vector from main()
 * @param config output configuration populated on success
 * @param errorMessage receives human readable error text when parsing fails
 * @return true when parsing succeeded and @p config is valid, false otherwise
 */
bool parseCommandLine(int argc, char **argv, AppConfig &config, std::string &errorMessage);

/**
 * @brief print usage/help information describing sender and receiver flags
 *
 * @param programName executable name displayed in the usage header
 * @param os output stream that receives the formatted help content
 */
void printUsage(const char *programName, std::ostream &os);

#endif // SECRET_APP_CONFIG_H
