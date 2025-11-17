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

    /**
     * @brief derive a deterministic aes key from the provided login string
     *
     * @param login login to use as key
     * @param key output buffer that receives the derived key bytes
     * @return true when the derivation succeeded
     */
    bool deriveKeyFromLogin(const std::string &login, Key &key);
    /**
     * @brief fill an iv with random bytes
     *
     * @param iv output buffer that receives random data
     * @param error optional pointer for error message
     * @return true on success, false if the rng failed
     */
    bool generateRandomIv(Iv &iv, std::string *error = nullptr);

    class Aes256CbcEncryptor
    {
    public:
        Aes256CbcEncryptor();
        ~Aes256CbcEncryptor();

        Aes256CbcEncryptor(const Aes256CbcEncryptor &) = delete;
        Aes256CbcEncryptor &operator=(const Aes256CbcEncryptor &) = delete;

        /**
         * @brief configure the encryptor for a specific key and iv pair
         *
         * @param key symmetric key to use for encryption
         * @param iv initialization vector for the cipher chain
         * @param error optional failure description target
         * @return true when the context is ready to encrypt
         */
        bool init(const Key &key, const Iv &iv, std::string *error = nullptr);
        /**
         * @brief process plaintext bytes and append ciphertext to @p out
         *
         * @param data pointer to plaintext bytes
         * @param length number of plaintext bytes available
         * @param out buffer that accumulates produced ciphertext
         * @param error optional pointer for errors
         * @return true when encryption succeeded for this chunk
         */
        bool update(const uint8_t *data, std::size_t length, std::vector<uint8_t> &out, std::string *error = nullptr);
        /**
         * @brief flush padding and finalize the encryption stream
         *
         * @param out buffer that receives the final ciphertext bytes
         * @param error optional pointer for errors
         * @return true when the context finalized successfully
         */
        bool finalize(std::vector<uint8_t> &out, std::string *error = nullptr);

    private:
        /**
         * @brief clear internal openssl state so the object can be reused
         */
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

        /**
         * @brief configure the decryptor for a specific key and iv pair
         *
         * @param key symmetric key to use for decryption
         * @param iv initialization vector for the cipher chain
         * @param error optional failure description target
         * @return true when the context is ready to decrypt
         */
        bool init(const Key &key, const Iv &iv, std::string *error = nullptr);
        /**
         * @brief consume ciphertext bytes and append plaintext into @p out
         *
         * @param data pointer to ciphertext bytes
         * @param length number of ciphertext bytes available
         * @param out buffer that accumulates produced plaintext
         * @param error optional pointer for errors
         * @return true when decryption succeeded for this chunk
         */
        bool update(const uint8_t *data, std::size_t length, std::vector<uint8_t> &out, std::string *error = nullptr);
        /**
         * @brief flush padding and finalize the decryption stream
         *
         * @param out buffer that receives the final plaintext bytes
         * @param error optional pointer for errors
         * @return true when the context finalized successfully
         */
        bool finalize(std::vector<uint8_t> &out, std::string *error = nullptr);

    private:
        /**
         * @brief clear internal openssl state so the object can be reused
         */
        void reset();

        void *ctx_ = nullptr;
        bool ready_ = false;
    };

} // namespace crypto

#endif // SECRET_CRYPTO_H
