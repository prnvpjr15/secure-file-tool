#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

#include <string>

namespace AuditLog {
    // Operation types
    enum class OperationType {
        AES_ENCRYPT,
        AES_DECRYPT,
        SHA256_HASH,
        HMAC_SIGN
    };

    // Log an operation with timestamp and file hash
    // fileName: the name/path of the file processed
    // opType: type of operation performed
    // fileHash: SHA-256 hash of the file contents
    // success: whether the operation succeeded
    // details: optional additional details (error message, etc.)
    void LogOperation(const std::string& fileName, 
                      OperationType opType,
                      const std::string& fileHash,
                      bool success,
                      const std::string& details = "");

    // Get the audit log file path
    std::string GetLogFilePath();

    // Clear the audit log (for testing)
    void ClearLog();
}

#endif // AUDIT_LOG_H
