## Assignment: File Transfer through a Covert Channel

### Task

Create a client/server application that allows transferring a file through a covert channel, where the data is transmitted inside **ICMP/ICMPv6 Echo-Request/Reply** messages.
The file must be **encrypted with AES** before transmission so that it is not transferred in plain text. Use your **login** as the encryption key.

### Program behavior

* The program processes input arguments, reads the specified file, encrypts it, and sends it in ICMP messages to the given IP address.
* On the receiving side, when the program is started in **listen mode** (`-l`), it should capture incoming ICMP messages, decrypt them, and save the file to disk in the same directory where the program was launched.

### Command-line usage

```
secret -r <file> -s <ip|hostname> [-l]
```

* `-r <file>`: specifies the file for transfer (a path can be included, e.g., `secret -r ../test.file`)
* `-s <ip|hostname>`: the IP address or hostname of the destination
* `-l`: runs the program in server/listen mode, where it waits for ICMP messages and reconstructs the file

### Requirements

1. Only **ICMP/ICMPv6 Echo-request/reply** messages may be used.
2. A **transfer protocol** must be defined to ensure correct behavior (e.g., sending the file name, checking that the whole file was received, etc.). The design of this protocol is up to you and must be described in the documentation.
3. The program must handle files **larger than the maximum packet size** on a standard network (1500B), i.e., split the file into multiple packets.
4. You may assume that **no packet loss** occurs during transfer. If you implement reliable transfer (e.g., acknowledgments, retransmissions), describe it in the documentation.
5. The following libraries are allowed:

   * Header files for sockets and networking (`netinet/*`, `sys/*`, `arpa/*`, etc.)
   * Libraries for threads (`pthread`), packets (`pcap`), signals, and time
   * The standard C library (ISO/ANSI or POSIX variants), C++ and STL
   * OpenSSL for AES encryption
   * No other libraries are permitted.

### Repository status

- Initial scaffolding in place with `src/`, `include/`, and `tests/` directories.
- Build driven by a top-level `Makefile` producing the `secret` binary.
- `src/main.cpp` currently contains a placeholder entry point pending argument parsing and protocol integration.
- Protocol header serialization/deserialization helpers live in `include/protocol.h` and `src/protocol.cpp`, with a smoke test stub in `tests/protocol_tests.cpp`.
- AES utilities implemented in `include/crypto.h` and `src/crypto.cpp`, with coverage via `tests/crypto_tests.cpp` to verify key derivation and round-trip encryption.
- Command-line parsing and configuration lives in `include/app_config.h` / `src/app_config.cpp`, exercised by `tests/app_config_tests.cpp`; `src/main.cpp` now resolves login defaults and prints a configuration summary.
- Sender workflow added via `include/sender.h` / `src/sender.cpp` with a mockable `OutboundChannel`; end-to-end chunking is verified by `tests/sender_tests.cpp`.
- Raw IPv4 transmission implemented in `include/icmp_channel.h` / `src/icmp_channel.cpp`; `secret` now emits genuine ICMP Echo-Requests and therefore requires root privileges (or `CAP_NET_RAW`) at runtime.