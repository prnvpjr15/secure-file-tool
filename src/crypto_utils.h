#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>

namespace CryptoUtils {
    // AES helpers (without logging)
    bool AesEncrypt(const std::string& password, const std::string& inputData, std::string& outputData);
    bool AesDecrypt(const std::string& password, const std::string& inputData, std::string& outputData);

    // AES helpers with logging
    bool AesEncryptWithLog(const std::string& password, 
                           const std::string& inputData, 
                           std::string& outputData,
                           const std::string& fileName);
    bool AesDecryptWithLog(const std::string& password, 
                           const std::string& inputData, 
                           std::string& outputData,
                           const std::string& fileName);

    // Hashing and HMAC (without logging)
    std::string Sha256(const std::string& inputData);
    std::string HmacSha256(const std::string& inputData, const std::string& key);

    // Hashing and HMAC with logging
    std::string Sha256WithLog(const std::string& inputData, const std::string& fileName);
    std::string HmacSha256WithLog(const std::string& inputData, const std::string& key, const std::string& fileName);

    // Misc utilities
    std::string ToHex(const std::string& data);
    std::string CleanString(std::string s);
}

#endif // CRYPTO_UTILS_H
