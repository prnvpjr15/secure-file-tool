#include "audit_log.h"
#include "crypto_utils.h"
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>

using namespace std;

namespace AuditLog {
    static const string LOG_FILENAME = "audit_log.jsonl";

    string GetLogFilePath() {
        return LOG_FILENAME;
    }

    string GetTimestamp() {
        auto now = chrono::system_clock::now();
        auto time = chrono::system_clock::to_time_t(now);
        auto ms = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) % 1000;
        
        stringstream ss;
        ss << put_time(localtime(&time), "%Y-%m-%dT%H:%M:%S");
        ss << "." << setfill('0') << setw(3) << ms.count() << "Z";
        return ss.str();
    }

    string OperationTypeToString(OperationType op) {
        switch (op) {
            case OperationType::AES_ENCRYPT: return "AES_ENCRYPT";
            case OperationType::AES_DECRYPT: return "AES_DECRYPT";
            case OperationType::SHA256_HASH: return "SHA256_HASH";
            case OperationType::HMAC_SIGN: return "HMAC_SIGN";
            default: return "UNKNOWN";
        }
    }

    // Simple JSON escape for strings
    string EscapeJson(const string& s) {
        stringstream ss;
        for (char c : s) {
            switch (c) {
                case '"': ss << "\\\""; break;
                case '\\': ss << "\\\\"; break;
                case '\b': ss << "\\b"; break;
                case '\f': ss << "\\f"; break;
                case '\n': ss << "\\n"; break;
                case '\r': ss << "\\r"; break;
                case '\t': ss << "\\t"; break;
                default:
                    if (c >= 0 && c < 32) {
                        ss << "\\u" << hex << setfill('0') << setw(4) << (int)c;
                    } else {
                        ss << c;
                    }
            }
        }
        return ss.str();
    }

    void LogOperation(const string& fileName,
                      OperationType opType,
                      const string& fileHash,
                      bool success,
                      const string& details) {
        try {
            ofstream log(LOG_FILENAME, ios::app);
            if (!log.is_open()) {
                // Silently fail if we can't open log file
                return;
            }

            // Write a JSON Lines entry (one JSON object per line)
            log << "{"
                << "\"timestamp\":\"" << GetTimestamp() << "\","
                << "\"operation\":\"" << OperationTypeToString(opType) << "\","
                << "\"file\":\"" << EscapeJson(fileName) << "\","
                << "\"file_hash\":\"" << EscapeJson(fileHash) << "\","
                << "\"success\":" << (success ? "true" : "false") << ","
                << "\"details\":\"" << EscapeJson(details) << "\""
                << "}\n";

            log.close();
        } catch (...) {
            // Fail silently — we don't want logging failures to crash the app
        }
    }

    void ClearLog() {
        try {
            filesystem::remove(LOG_FILENAME);
        } catch (...) {
            // Silently fail if we can't remove the log
        }
    }
}
