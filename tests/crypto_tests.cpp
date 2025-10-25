#include "crypto.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool checkKeyVector(const crypto::Key &key) {
    const std::array<uint8_t, crypto::AES256_KEY_SIZE> expected = {
        0x2b, 0xd8, 0x06, 0xc9, 0x7f, 0x0e, 0x00, 0xaf,
        0x1a, 0x1f, 0xc3, 0x32, 0x8f, 0xa7, 0x63, 0xa9,
        0x26, 0x97, 0x23, 0xc8, 0xdb, 0x8f, 0xac, 0x4f,
        0x93, 0xaf, 0x71, 0xdb, 0x18, 0x6d, 0x6e, 0x90
    };
    return std::equal(key.begin(), key.end(), expected.begin());
}

} // namespace

int main() {
    crypto::Key key{};
    if (!crypto::deriveKeyFromLogin("alice", key)) {
        std::cerr << "deriveKeyFromLogin failed" << std::endl;
        return 1;
    }
    if (!checkKeyVector(key)) {
        std::cerr << "unexpected SHA-256 digest for login" << std::endl;
        return 1;
    }

    crypto::Iv iv{};
    for (std::size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<uint8_t>(i);
    }

    const std::string plaintext = "All mimsy were the borogoves";
    std::vector<uint8_t> plainBytes(plaintext.begin(), plaintext.end());

    crypto::Aes256CbcEncryptor encryptor;
    std::string error;
    if (!encryptor.init(key, iv, &error)) {
        std::cerr << "encryptor init failed: " << error << std::endl;
        return 1;
    }

    std::vector<uint8_t> ciphertext;
    if (!encryptor.update(plainBytes.data(), plainBytes.size(), ciphertext, &error)) {
        std::cerr << "encrypt update failed: " << error << std::endl;
        return 1;
    }
    if (!encryptor.finalize(ciphertext, &error)) {
        std::cerr << "encrypt final failed: " << error << std::endl;
        return 1;
    }

    crypto::Aes256CbcDecryptor decryptor;
    if (!decryptor.init(key, iv, &error)) {
        std::cerr << "decryptor init failed: " << error << std::endl;
        return 1;
    }

    std::vector<uint8_t> recovered;
    if (!decryptor.update(ciphertext.data(), ciphertext.size(), recovered, &error)) {
        std::cerr << "decrypt update failed: " << error << std::endl;
        return 1;
    }
    if (!decryptor.finalize(recovered, &error)) {
        std::cerr << "decrypt final failed: " << error << std::endl;
        return 1;
    }

    if (recovered.size() != plainBytes.size() ||
        !std::equal(recovered.begin(), recovered.end(), plainBytes.begin())) {
        std::cerr << "plaintext mismatch after decrypt" << std::endl;
        return 1;
    }

    std::cout << "crypto smoke tests passed" << std::endl;
    return 0;
}
