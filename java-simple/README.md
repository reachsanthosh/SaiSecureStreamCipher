# PassAuth Stream Cipher - Simple Version

A complete implementation of the PassAuth Stream Cipher in a single Java file for easy distribution and understanding.

## Features

- **Single File Implementation**: Everything in one Java file (`PassAuthSimple.java`)
- **Hand-implemented Cryptography**: Custom SaiSecureStreamCipher algorithm
- **HMAC Key Derivation**: Secure H(IV, password) key derivation
- **GUI Interface**: Easy-to-use Swing GUI
- **File & Text Encryption**: Support for both modes
- **No External Dependencies**: Uses only Java standard library

## Quick Start

### Windows

```batch
# Just double-click run.bat or:
run.bat
```

### Linux/macOS

```bash
# Compile and run
javac PassAuthSimple.java
java PassAuthSimple
```

## Requirements

- Java 8 or higher (no Maven required)
- About 500KB of disk space

## What's Different from Full Version?

| Feature             | Full Version        | Simple Version    |
| ------------------- | ------------------- | ----------------- |
| Files               | 4 separate classes  | 1 single file     |
| Build System        | Maven required      | Simple javac      |
| Size                | ~50KB source        | ~25KB source      |
| Password Validation | Advanced validation | Basic validation  |
| Modularity          | Highly modular      | Monolithic        |
| Maintenance         | Enterprise-ready    | Educational focus |

## Architecture

All functionality is contained in `PassAuthSimple.java`:

- **GUI Components**: Swing interface with tabs
- **Cryptographic Engine**: SaiSecureStreamCipher implementation
- **Key Derivation**: HMAC-SHA256 based key derivation
- **File Operations**: Direct file encryption/decryption
- **Utility Functions**: Base64 encoding, error handling

## Security Features

- 256-bit keys derived from passwords using HMAC-SHA256
- Unique 16-byte IV and 12-byte nonce for each encryption
- Stream cipher based on ChaCha20-like algorithm
- Cryptographically secure random number generation

## Usage

1. **Text Encryption**:

   - Enter text in the input area
   - Enter a password
   - Click "Encrypt Text" or "Decrypt Text"

2. **File Encryption**:
   - Go to "File Encryption" tab
   - Enter a password
   - Click "Encrypt File" or "Decrypt File"
   - Select files using the file chooser

## Compatibility

- **Cross-platform**: Works on Windows, macOS, Linux
- **Format Compatible**: Files encrypted with this version can be decrypted by the full version and vice versa
- **Python Compatible**: Uses the same algorithm as the Python version

## Educational Benefits

This single-file version is perfect for:

- Understanding the complete cryptographic flow
- Learning stream cipher implementation
- Studying GUI development patterns
- Quick deployment and testing

## Important Notes

- **Educational Purpose**: This is for learning cryptography concepts
- **Password Security**: Use strong passwords (12+ characters)
- **Backup Files**: Keep backups of important data
- **Test First**: Always test with non-critical data

## File Size Comparison

- `PassAuthSimple.java`: ~25KB (everything included)
- Full version: ~50KB across 4 files + pom.xml
- Python version: ~15KB across multiple files

## Quick Test

```java
// Test encryption/decryption in code
PassAuthSimple app = new PassAuthSimple();
String encrypted = app.encryptString("Hello World", "password123");
String decrypted = app.decryptString(encrypted, "password123");
System.out.println("Test passed: " + "Hello World".equals(decrypted));
```

Perfect for educational purposes, demonstrations, and quick deployments!
