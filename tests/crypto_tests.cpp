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
        0x62, 0x42, 0x84, 0x62, 0x56, 0xf1, 0x28, 0xf6,
        0xd8, 0x4c, 0xa3, 0x29, 0x66, 0x72, 0xdd, 0x28,
        0x27, 0xf9, 0x05, 0x17, 0x37, 0xe8, 0xd4, 0x20,
        0x80, 0xf0, 0x5f, 0x65, 0xad, 0xd0, 0x9a, 0x2f
    };
    return std::equal(key.begin(), key.end(), expected.begin());
}

} // namespace

int main() {
    crypto::Key key{};
    if (!crypto::deriveKeyFromLogin("xlogin00", key)) {
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
