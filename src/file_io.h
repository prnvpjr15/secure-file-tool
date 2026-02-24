#ifndef FILE_IO_H
#define FILE_IO_H

#include <string>

namespace FileIO {
    extern std::string hmacKey;

    // Load configuration values (currently only HMAC key)
    void LoadConfig();

    // Basic file operations used by the UI
    bool ReadFile(const std::string& path, std::string& outData);
    bool WriteFile(const std::string& path, const std::string& data);
}

#endif // FILE_IO_H
