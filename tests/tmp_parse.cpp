#include "app_config.h"

#include <iostream>
#include <string>

int main() {
    {
        char arg0[] = "secret";
        char arg1[] = "-r";
        char arg2[] = "input.bin";
        char arg3[] = "-s";
        char arg4[] = "192.0.2.10";
        char *argv[] = {arg0, arg1, arg2, arg3, arg4, nullptr};
        int argc = 5;
        AppConfig config;
        std::string error;
        bool ok = parseCommandLine(argc, argv, config, error);
        std::cout << "test1 ok? " << ok << " error: " << error << "\n";
    }

    {
        char arg0[] = "secret";
        char arg1[] = "-r";
        char arg2[] = "input.bin";
        char *argv[] = {arg0, arg1, arg2, nullptr};
        int argc = 3;
        AppConfig config;
        std::string error;
        bool ok = parseCommandLine(argc, argv, config, error);
        std::cout << "test2 ok? " << ok << " error: " << error << "\n";
    }

    {
        char arg0[] = "secret";
        char arg1[] = "-l";
        char arg2[] = "-v";
        char *argv[] = {arg0, arg1, arg2, nullptr};
        int argc = 3;
        AppConfig config;
        std::string error;
        bool ok = parseCommandLine(argc, argv, config, error);
        std::cout << "test3 ok? " << ok << " error: " << error << "\n";
    }

    {
        char arg0[] = "secret";
        char arg1[] = "-r";
        char arg2[] = "input.bin";
        char arg3[] = "-s";
        char arg4[] = "198.51.100.20";
        char arg5[] = "-k";
        char arg6[] = "xabcde42";
        char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, nullptr};
        int argc = 7;
        AppConfig config;
        std::string error;
        bool ok = parseCommandLine(argc, argv, config, error);
        std::cout << "test4 ok? " << ok << " error: " << error << " login=" << config.login << "\n";
    }

    {
        char arg0[] = "secret";
        char arg1[] = "-r";
        char arg2[] = "input.bin";
        char arg3[] = "-s";
        char arg4[] = "203.0.113.15";
        char arg5[] = "-k";
        char arg6[] = "invalid";
        char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, nullptr};
        int argc = 7;
        AppConfig config;
        std::string error;
        bool ok = parseCommandLine(argc, argv, config, error);
        std::cout << "test5 ok? " << ok << " error: " << error << "\n";
    }
    return 0;
}
