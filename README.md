# SecureFileTool 🔒

A cross-platform desktop application for file encryption and integrity verification, built with **wxWidgets** and **Crypto++**.

---

## Features

| Feature | Description |
|---|---|
| **AES-256 Encryption** | Encrypts any file type with industry-standard symmetric encryption |
| **Random Salts** | Unique 16-byte salt per encryption — prevents rainbow table attacks |
| **PBKDF2 Key Derivation** | 10,000 iterations of SHA-256 to derive keys and IVs from passwords |
| **SHA-256 Hashing** | Generate and compare file fingerprints for integrity verification |
| **Hash Comparator** | Paste an expected hash — green means match, red means mismatch |
| **HMAC Signing** | Verify file authenticity using a shared secret key |
| **Drag & Drop** | Drop any file onto the window to load it instantly |
| **Cross-Platform** | Runs on Windows, Linux, and macOS |

---

## Installation

### Prerequisites

- C++ compiler: MSVC, GCC, or Clang
- CMake v3.10+
- wxWidgets v3.x
- Crypto++ v8.x

### Windows (vcpkg)

```powershell
# Install dependencies
.\vcpkg\vcpkg install wxwidgets:x64-windows
.\vcpkg\vcpkg install cryptopp:x64-windows

# Build
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build .
```

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get install build-essential cmake libwxgtk3.0-gtk3-dev libcrypto++-dev

# Build
mkdir build && cd build
cmake ..
make
```

---

## Usage

1. **Launch** — run `SecureFileTool` (or `SecureFileTool.exe` on Windows)
2. **Load a file** — drag and drop, or click **Open File**
3. **Choose an operation:**
   - **AES** — enter a password to encrypt (plain files) or decrypt (`.enc` files)
   - **SHA-256** — view the file hash; paste an expected hash to verify
   - **HMAC** — calculate a signature using your HMAC key

---

## Configuration

### HMAC Key

**Recommended:** Set the `SECUREFILE_HMAC_KEY` environment variable before launching.

```bash
# Linux / macOS
export SECUREFILE_HMAC_KEY="your-secret-key"
./SecureFileTool

# Windows — PowerShell
$env:SECUREFILE_HMAC_KEY = "your-secret-key"
.\SecureFileTool.exe

# Windows — Command Prompt
set SECUREFILE_HMAC_KEY=your-secret-key
SecureFileTool.exe
```

**Fallback (development only):** If no environment variable is set, the app reads `config.txt`. See the [Security Notes](#security-notes) section before using this in any non-development context.

---

## Audit Logging

Every operation is logged to `audit_log.jsonl` in the application directory.

**Fields logged per entry:**

| Field | Description |
|---|---|
| `timestamp` | ISO 8601 timestamp |
| `operation` | `AES_ENCRYPT`, `AES_DECRYPT`, `SHA256_HASH`, or `HMAC_SIGN` |
| `file` | Path/name of the processed file |
| `file_hash` | SHA-256 hash of the input file |
| `success` | Boolean — whether the operation succeeded |
| `details` | Error message or HMAC result |

**Example entries:**

```json
{"timestamp":"2025-02-25T14:30:45.123Z","operation":"AES_ENCRYPT","file":"document.pdf","file_hash":"a1b2c3d4...","success":true,"details":""}
{"timestamp":"2025-02-25T14:35:12.456Z","operation":"SHA256_HASH","file":"README.md","file_hash":"e5f6g7h8...","success":true,"details":""}
```

---

## Project Structure

```
SecureFileTool/
├── src/
│   ├── main.cpp              # GUI and event handling
│   ├── crypto_utils.h/.cpp   # AES, SHA-256, HMAC operations
│   ├── file_io.h/.cpp        # File I/O and config loading
│   └── audit_log.h/.cpp      # Audit logging (JSON Lines format)
├── config.txt                # HMAC key config — development only
├── audit_log.jsonl           # Audit trail (generated at runtime)
├── CMakeLists.txt            # CMake build system
└── README.md
```

---

## Security Notes ⚠️

### HMAC Key Storage

The `config.txt` fallback stores the HMAC key in **plaintext**. This is a known limitation intended for development only.

- Any attacker with file access can read the key
- A compromised key renders HMAC signatures meaningless
- Secrets should never be stored unencrypted on disk

**Production alternatives:**

- **Environment variable** — set `SECUREFILE_HMAC_KEY` at launch (preferred)
- **OS keychain** — macOS Keychain, Windows DPAPI / Credential Manager, Linux `pass`
- **Secrets management** — HashiCorp Vault, AWS Secrets Manager, or similar
- **Remove `config.txt`** — in production, delete it and rely on environment variables or vaults

### AES Encryption

- Each encryption uses a **random 128-bit salt** prepended to the ciphertext
- Keys are derived with **PBKDF2 — 10,000 iterations of SHA-256**
- No separate salt storage required

### Best Practices

- Use strong, unique passwords for AES encryption
- Always compare SHA-256 hashes over a **trusted, separate channel** — not the same link as the file
- Never commit HMAC keys to version control
- In CI/CD, use proper secrets management (GitHub Secrets, GitLab CI Variables, etc.)

---

## License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.
