SecureFile Tool 🔒

A robust, cross-platform Desktop GUI application for file encryption and integrity verification. Built using wxWidgets for the interface and Crypto++ for industry-standard cryptographic operations.

Features ✨

AES-256 Encryption: Securely encrypts any file type.

Random Salts: Generates a unique 16-byte random salt for every encryption to prevent Rainbow Table attacks.

PBKDF2: Derives the key and IV from your password using 10,000 iterations of SHA-256.

SHA-256 Hashing: Generate unique file fingerprints.

Hash Comparator: Paste an expected hash to instantly verify if a downloaded file is authentic (Green = Match, Red = Mismatch).

HMAC Signing: Verify file authenticity using a shared secret key.

Drag & Drop: Simply drag files onto the window to load them.

Cross-Platform: Runs on Windows, Linux, and macOS.

Installation 🛠️

Prerequisites

C++ Compiler (MSVC, GCC, or Clang)

CMake (v3.10+)

wxWidgets (v3.x)

Crypto++ (v8.x)

1. Windows (using vcpkg)

The easiest way to build on Windows is using the vcpkg package manager.

# Install dependencies
.\vcpkg\vcpkg install wxwidgets:x64-windows
.\vcpkg\vcpkg install cryptopp:x64-windows

# Build
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build .


2. Linux (Ubuntu/Debian)

# Install dependencies
sudo apt-get install build-essential cmake libwxgtk3.0-gtk3-dev libcrypto++-dev

# Build
mkdir build && cd build
cmake ..
make


Usage 🚀

Launch the App: Run SecureFileTool (or SecureFileTool.exe).

Load a File: Drag and drop a file or click "Open File".

Choose Operation:

AES: Enter a password. If the file is plain, it encrypts. If it's .enc, it decrypts.

SHA-256: View the hash. Paste an expected hash in the comparison box to verify.

HMAC: Calculates signature based on the HMAC key (see Security section below).

### Configuring the HMAC Key

**Recommended (Secure):** Set the `SECUREFILE_HMAC_KEY` environment variable before launching the app:

```bash
# Linux/macOS
export SECUREFILE_HMAC_KEY="your-secret-key-here"
./SecureFileTool

# Windows (PowerShell)
$env:SECUREFILE_HMAC_KEY = "your-secret-key-here"
.\SecureFileTool.exe

# Windows (Command Prompt)
set SECUREFILE_HMAC_KEY=your-secret-key-here
SecureFileTool.exe
```

**Fallback (Development Only):** If no environment variable is set, the app reads `config.txt` (see Security note below).

### Audit Logging

Every encryption, decryption, hashing, and signature operation is logged to `audit_log.jsonl` in the application directory. Each log entry contains:

- **timestamp**: ISO 8601 timestamp of the operation
- **operation**: Type of operation (AES_ENCRYPT, AES_DECRYPT, SHA256_HASH, HMAC_SIGN)
- **file**: Name/path of the processed file
- **file_hash**: SHA-256 hash of the input file
- **success**: Boolean indicating if the operation succeeded
- **details**: Additional context (error messages or HMAC result)

**Log Format (JSON Lines):**
```json
{"timestamp":"2025-02-25T14:30:45.123Z","operation":"AES_ENCRYPT","file":"document.pdf","file_hash":"a1b2c3d4...","success":true,"details":""}
{"timestamp":"2025-02-25T14:35:12.456Z","operation":"SHA256_HASH","file":"README.md","file_hash":"e5f6g7h8...","success":true,"details":""}
```

This audit trail provides accountability and traceability for security-sensitive operations in production environments.


SecureFileTool/
├── src/
│   ├── main.cpp              # GUI and event handling
│   ├── crypto_utils.h/.cpp   # AES, SHA-256, HMAC operations
│   ├── file_io.h/.cpp        # File I/O and config loading
│   ├── audit_log.h/.cpp      # Audit logging (JSON Lines format)
├── config.txt                # Configuration file (HMAC Key) — DEVELOPMENT ONLY
├── audit_log.jsonl           # Audit trail (generated at runtime)
├── CMakeLists.txt            # CMake Build System
└── README.md                 # Documentation
├── CMakeLists.txt         # CMake Build System
└── README.md              # Documentation

## Security Notes ⚠️

### HMAC Key Storage (Known Limitation)

**⚠️ Current Implementation:** The `config.txt` file stores the HMAC key in **plaintext**. This is a **security weakness** and is intended for **development/testing purposes only**.

**Why it's a problem:**
- Any attacker with file access can read the key.
- HMAC signatures become meaningless if the key is compromised.
- Sensitive secrets should never be stored unencrypted on disk.

**Production Recommendations:**

1. **Environment Variables (Current Fallback):** Set `SECUREFILE_HMAC_KEY` before launching (preferred).
2. **OS Keychain:** On macOS, use Keychain; on Windows, use DPAPI or Windows Credential Manager; on Linux, use a secret manager like `pass`.
3. **Configuration Management:** Use Vault, AWS Secrets Manager, or similar for enterprise deployments.
4. **Remove config.txt:** In production, remove or ignore the `config.txt` file and rely exclusively on environment variables or secure vaults.

### AES Encryption Notes

- Each encryption uses a **random 128-bit salt** to prevent rainbow table attacks.
- Keys are derived using **PBKDF2 with 10,000 iterations** of SHA-256.
- The **salt is prepended** to the ciphertext; no separate storage needed.

### Best Practices

- **Passwords:** Use strong, unique passwords for AES encryption.
- **File Integrity:** Always compare SHA-256 hashes over a trusted channel (never via the same untrusted link as the file).
- **HMAC Secrets:** Treat HMAC keys like passwords—never commit them to version control.
- **Docker/CI:** Use secrets management tools (GitHub Secrets, GitLab CI Variables, etc.) rather than embedding keys in code or config files.


License

This project is licensed under the MIT License - see the LICENSE file for details.