#include "file_io.h"
#include <fstream>
#include <cstdlib>

using namespace std;

namespace FileIO {
    std::string hmacKey = "default_hmac";

    void LoadConfig() {
        // First, try to load from environment variable (secure)
        const char* envKey = getenv("SECUREFILE_HMAC_KEY");
        if (envKey && strlen(envKey) > 0) {
            hmacKey = envKey;
            return;
        }
        
        // Fall back to config.txt (less secure, for development only)
        ifstream in("config.txt");
        string line;
        if (in.is_open()) {
            while (getline(in, line)) {
                if (line.find("HMAC_KEY=") == 0) {
                    hmacKey = line.substr(9);
                }
            }
        }
    }

    bool ReadFile(const string& path, string& outData) {
        ifstream in(path, ios::binary);
        if (!in) return false;
        outData.assign((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        return true;
    }

    bool WriteFile(const string& path, const string& data) {
        ofstream out(path, ios::binary);
        if (!out) return false;
        out << data;
        return true;
    }
}
