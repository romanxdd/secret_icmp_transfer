// #############################
// ##  Author: Roman Krajčík  ##
// ##  Login:  xkrajc26       ##
// #############################

#include "crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <vector>

namespace
{

/// reinterpreting helper so i can store ctx as void*
EVP_CIPHER_CTX *asCtx(void *ptr)
{
    return static_cast<EVP_CIPHER_CTX *>(ptr);
}

/// pull the latest openssl error message into a string
std::string popOpenSslError()
{
    unsigned long code = ERR_get_error();
    if (code == 0)
    {
        return "unknown OpenSSL error";
    }
    char buf[256] = {0};
    ERR_error_string_n(code, buf, sizeof(buf));
    return std::string(buf);
}

/// allocate an evp ctx if its missing
bool ensureCtxAllocated(void *&ctx, std::string *error)
{
    if (ctx != nullptr)
    {
        return true;
    }
    EVP_CIPHER_CTX *allocated = EVP_CIPHER_CTX_new();
    if (!allocated)
    {
        if (error)
        {
            *error = "unable to allocate EVP_CIPHER_CTX";
        }
        return false;
    }
    ctx = allocated;
    return true;
}

/// append a produced block of bytes to the destination buffer
bool appendBlock(std::vector<uint8_t> &out, const uint8_t *buffer, int length, std::string *error)
{
    if (length < 0)
    {
        if (error)
        {
            *error = "negative length from OpenSSL";
        }
        return false;
    }
    if (length == 0)
    {
        return true;
    }
    const std::size_t offset = out.size();
    out.resize(offset + static_cast<std::size_t>(length));
    std::memcpy(out.data() + offset, buffer, static_cast<std::size_t>(length));
    return true;
}

} // namespace

namespace crypto
{

/// derive aes key bytes from the provided login using sha-256
bool deriveKeyFromLogin(const std::string &login, Key &key)
{
    const unsigned char *input = reinterpret_cast<const unsigned char *>(login.c_str());
    unsigned char digest[AES256_KEY_SIZE] = {0};
    SHA256(input, login.size(), digest);
    std::memcpy(key.data(), digest, AES256_KEY_SIZE);
    return true;
}

/// fill the provided iv with random bytes
bool generateRandomIv(Iv &iv, std::string *error)
{
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1)
    {
        if (error)
        {
            *error = popOpenSslError();
        }
        return false;
    }
    return true;
}


Aes256CbcEncryptor::Aes256CbcEncryptor() = default;
Aes256CbcEncryptor::~Aes256CbcEncryptor()
{
    reset();
}

/// drop any existing context and reset ready
void Aes256CbcEncryptor::reset()
{
    if (ctx_ != nullptr)
    {
        EVP_CIPHER_CTX_free(asCtx(ctx_));
        ctx_ = nullptr;
    }
    ready_ = false;
}

/// initialize the encryptor with a key and iv
bool Aes256CbcEncryptor::init(const Key &key, const Iv &iv, std::string *error)
{
    reset();
    if (!ensureCtxAllocated(ctx_, error))
    {
        return false;
    }

    EVP_CIPHER_CTX *ctx = asCtx(ctx_);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
    {
        if (error)
        {
            *error = popOpenSslError();
        }
        reset();
        return false;
    }

    ready_ = true;
    return true;
}

/// encrypt the next chunk of plaintext into the output buffer
bool Aes256CbcEncryptor::update(const uint8_t *data, std::size_t length, std::vector<uint8_t> &out, std::string *error)
{
    if (!ready_)
    {
        if (error)
        {
            *error = "encryptor not initialized";
        }
        return false;
    }

    if (length == 0)
    {
        return true;
    }

    std::vector<uint8_t> buffer(length + AES_BLOCK_SIZE);
    int produced = 0;
    if (EVP_EncryptUpdate(asCtx(ctx_), buffer.data(), &produced, data, static_cast<int>(length)) != 1)
    {
        if (error)
        {
            *error = popOpenSslError();
        }
        return false;
    }

    return appendBlock(out, buffer.data(), produced, error);
}

/// finish the encryption stream and flush padding
bool Aes256CbcEncryptor::finalize(std::vector<uint8_t> &out, std::string *error)
{
    if (!ready_)
    {
        if (error)
        {
            *error = "encryptor not initialized";
        }
        return false;
    }

    std::vector<uint8_t> buffer(AES_BLOCK_SIZE);
    int produced = 0;
    if (EVP_EncryptFinal_ex(asCtx(ctx_), buffer.data(), &produced) != 1)
    {
        if (error)
        {
            *error = popOpenSslError();
        }
        reset();
        return false;
    }

    ready_ = false;
    const bool ok = appendBlock(out, buffer.data(), produced, error);
    reset();
    return ok;
}


Aes256CbcDecryptor::Aes256CbcDecryptor() = default;
Aes256CbcDecryptor::~Aes256CbcDecryptor()
{
    reset();
}

/// drop any existing context and reset ready
void Aes256CbcDecryptor::reset()
{
    if (ctx_ != nullptr)
    {
        EVP_CIPHER_CTX_free(asCtx(ctx_));
        ctx_ = nullptr;
    }
    ready_ = false;
}

/// initialize the decryptor with a key and iv
bool Aes256CbcDecryptor::init(const Key &key, const Iv &iv, std::string *error)
{
    reset();
    if (!ensureCtxAllocated(ctx_, error))
    {
        return false;
    }

    EVP_CIPHER_CTX *ctx = asCtx(ctx_);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
    {
        if (error)
        {
            *error = popOpenSslError();
        }
        reset();
        return false;
    }

    ready_ = true;
    return true;
}

/// decrypt another ciphertext block sequence into plaintext
bool Aes256CbcDecryptor::update(const uint8_t *data, std::size_t length, std::vector<uint8_t> &out, std::string *error)
{
    if (!ready_)
    {
        if (error)
        {
            *error = "decryptor not initialized";
        }
        return false;
    }

    if (length == 0)
    {
        return true;
    }

    std::vector<uint8_t> buffer(length + AES_BLOCK_SIZE);
    int produced = 0;
    if (EVP_DecryptUpdate(asCtx(ctx_), buffer.data(), &produced, data, static_cast<int>(length)) != 1)
    {
        if (error)
        {
            *error = popOpenSslError();
        }
        return false;
    }

    return appendBlock(out, buffer.data(), produced, error);
}

/// finalize the stream and strip padding bytes
bool Aes256CbcDecryptor::finalize(std::vector<uint8_t> &out, std::string *error)
{
    if (!ready_)
    {
        if (error)
        {
            *error = "decryptor not initialized";
        }
        return false;
    }

    std::vector<uint8_t> buffer(AES_BLOCK_SIZE);
    int produced = 0;
    if (EVP_DecryptFinal_ex(asCtx(ctx_), buffer.data(), &produced) != 1)
    {
        if (error)
        {
            *error = popOpenSslError();
        }
        reset();
        return false;
    }

    ready_ = false;
    const bool ok = appendBlock(out, buffer.data(), produced, error);
    reset();
    return ok;
}

} // namespace crypto
