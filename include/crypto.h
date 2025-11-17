// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

#ifndef SECRET_CRYPTO_H
#define SECRET_CRYPTO_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto
{

  constexpr std::size_t AES256_KEY_SIZE = 32u;
  constexpr std::size_t AES_BLOCK_SIZE = 16u;

  using Key = std::array<uint8_t, AES256_KEY_SIZE>;
  using Iv = std::array<uint8_t, AES_BLOCK_SIZE>;

  bool deriveKeyFromLogin(const std::string &login, Key &key);
  bool generateRandomIv(Iv &iv, std::string *error = nullptr);

  class Aes256CbcEncryptor
  {
  public:
    Aes256CbcEncryptor();
    ~Aes256CbcEncryptor();

    Aes256CbcEncryptor(const Aes256CbcEncryptor &) = delete;
    Aes256CbcEncryptor &operator=(const Aes256CbcEncryptor &) = delete;

    bool init(const Key &key, const Iv &iv, std::string *error = nullptr);
    bool update(const uint8_t *data, std::size_t length, std::vector<uint8_t> &out, std::string *error = nullptr);
    bool finalize(std::vector<uint8_t> &out, std::string *error = nullptr);

  private:
    void reset();

    void *ctx_ = nullptr;
    bool ready_ = false;
  };

  class Aes256CbcDecryptor
  {
  public:
    Aes256CbcDecryptor();
    ~Aes256CbcDecryptor();

    Aes256CbcDecryptor(const Aes256CbcDecryptor &) = delete;
    Aes256CbcDecryptor &operator=(const Aes256CbcDecryptor &) = delete;

    bool init(const Key &key, const Iv &iv, std::string *error = nullptr);
    bool update(const uint8_t *data, std::size_t length, std::vector<uint8_t> &out, std::string *error = nullptr);
    bool finalize(std::vector<uint8_t> &out, std::string *error = nullptr);

  private:
    void reset();

    void *ctx_ = nullptr;
    bool ready_ = false;
  };

} // namespace crypto

#endif // SECRET_CRYPTO_H
