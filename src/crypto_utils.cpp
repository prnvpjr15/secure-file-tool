#include "crypto_utils.h"
#include "audit_log.h"
#include <algorithm>
#include <cctype>
#include <cstring>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>

// constants used internally
static const int KEY_ITERATIONS = 10000;
static const int SALT_LEN = 16; // 128-bit salt

namespace CryptoUtils {

static bool DeriveKeyAndIV(const std::string& password,
                           const CryptoPP::byte* salt,
                           size_t saltLen,
                           CryptoPP::SecByteBlock& key,
                           CryptoPP::SecByteBlock& iv)
{
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;

    const size_t keyLen = CryptoPP::AES::DEFAULT_KEYLENGTH;
    const size_t ivLen  = CryptoPP::AES::BLOCKSIZE;

    CryptoPP::SecByteBlock derived(keyLen + ivLen);

    pbkdf.DeriveKey(
        derived, derived.size(),
        0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()),
        password.size(),
        salt, saltLen,
        KEY_ITERATIONS
    );

    std::memcpy(key, derived, keyLen);
    std::memcpy(iv, derived + keyLen, ivLen);
    return true;
}

bool AesEncrypt(const std::string& password,
                const std::string& inputData,
                std::string& outputData)
{
    try {
        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

        CryptoPP::byte salt[SALT_LEN];

        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(salt, SALT_LEN);

        DeriveKeyAndIV(password, salt, SALT_LEN, key, iv);

        std::string cipher;

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc(key, key.size(), iv);

        CryptoPP::StringSource(
            inputData, true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(cipher)
            )
        );

        std::string saltString(reinterpret_cast<const char*>(salt), SALT_LEN);
        outputData = saltString + cipher;

        return true;
    }
    catch (...) {
        return false;
    }
}

bool AesDecrypt(const std::string& password,
                const std::string& inputData,
                std::string& outputData)
{
    try {
        if (inputData.size() < SALT_LEN)
            return false;

        CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);

        CryptoPP::byte salt[SALT_LEN];
        std::memcpy(salt, inputData.data(), SALT_LEN);

        DeriveKeyAndIV(password, salt, SALT_LEN, key, iv);

        std::string recovered;

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec(key, key.size(), iv);

        CryptoPP::StringSource(
            reinterpret_cast<const CryptoPP::byte*>(inputData.data() + SALT_LEN),
            inputData.size() - SALT_LEN,
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(recovered)
            )
        );

        outputData = recovered;
        return true;
    }
    catch (...) {
        return false;
    }
}

std::string Sha256(const std::string& inputData)
{
    CryptoPP::SHA256 hash;
    std::string digest;

    CryptoPP::StringSource(
        inputData, true,
        new CryptoPP::HashFilter(
            hash,
            new CryptoPP::StringSink(digest)
        )
    );

    return ToHex(digest);
}

std::string HmacSha256(const std::string& inputData,
                       const std::string& key)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(
        reinterpret_cast<const CryptoPP::byte*>(key.data()),
        key.size()
    );

    std::string digest;

    CryptoPP::StringSource(
        inputData, true,
        new CryptoPP::HashFilter(
            hmac,
            new CryptoPP::StringSink(digest)
        )
    );

    return ToHex(digest);
}

std::string ToHex(const std::string& data)
{
    std::string encoded;

    CryptoPP::HexEncoder encoder(
        new CryptoPP::StringSink(encoded)
    );

    encoder.Put(
        reinterpret_cast<const CryptoPP::byte*>(data.data()),
        data.size()
    );

    encoder.MessageEnd();

    return encoded;
}

std::string CleanString(std::string s)
{
    s.erase(std::remove_if(s.begin(), s.end(), ::isspace), s.end());
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// === Logging Variants ===

bool AesEncryptWithLog(const std::string& password, 
                       const std::string& inputData, 
                       std::string& outputData,
                       const std::string& fileName) {
    bool success = AesEncrypt(password, inputData, outputData);
    std::string fileHash = Sha256(inputData);
    std::string details = success ? "" : "Encryption failed";
    AuditLog::LogOperation(fileName, AuditLog::OperationType::AES_ENCRYPT, fileHash, success, details);
    return success;
}

bool AesDecryptWithLog(const std::string& password, 
                       const std::string& inputData, 
                       std::string& outputData,
                       const std::string& fileName) {
    bool success = AesDecrypt(password, inputData, outputData);
    std::string fileHash = Sha256(inputData);
    std::string details = success ? "" : "Decryption failed";
    AuditLog::LogOperation(fileName, AuditLog::OperationType::AES_DECRYPT, fileHash, success, details);
    return success;
}

std::string Sha256WithLog(const std::string& inputData, const std::string& fileName) {
    std::string hash = Sha256(inputData);
    AuditLog::LogOperation(fileName, AuditLog::OperationType::SHA256_HASH, hash, true, "");
    return hash;
}

std::string HmacSha256WithLog(const std::string& inputData, const std::string& key, const std::string& fileName) {
    std::string hmac = HmacSha256(inputData, key);
    std::string fileHash = Sha256(inputData);
    AuditLog::LogOperation(fileName, AuditLog::OperationType::HMAC_SIGN, fileHash, true, 
                          "HMAC: " + hmac);
    return hmac;
}

} // namespace CryptoUtils
