# PassAuth Stream Cipher - Java Edition

A Java implementation of the PassAuth Stream Cipher with hand-implemented cryptography and GUI.

## Features

- **Hand-implemented SaiSecureStreamCipher**: Custom stream cipher implementation
- **H(IV, password) Key Derivation**: Secure key derivation using HMAC or SHA256
- **Java Swing GUI**: User-friendly interface for encryption/decryption
- **File & Text Encryption**: Support for both file and text encryption
- **No External Dependencies**: Uses only Java standard library
- **Cross-platform**: Works on Windows, macOS, and Linux

## Requirements

- Java 11 or higher
- Maven (for building)

## Building

```bash
# Clone or navigate to the java-version directory
cd java-version

# Compile and package
mvn clean package

# The executable JAR will be created as:
# target/passauth-stream-cipher-1.0.0.jar
```

## Running

### GUI Application

```bash
java -jar target/passauth-stream-cipher-1.0.0.jar
```

### Command Line Testing

```bash
# Test individual components
java -cp target/classes com.passauth.SaiSecureStreamCipher
java -cp target/classes com.passauth.KeyDerivation
java -cp target/classes com.passauth.CryptoEngine
```

## Usage

### Text Encryption

1. Open the application
2. Go to "Text Encryption" tab
3. Enter your text and password
4. Click "Encrypt Text" or "Decrypt Text"

### File Encryption

1. Go to "File Encryption" tab
2. Enter a password
3. Click "Encrypt File" to select and encrypt a file
4. Click "Decrypt File" to decrypt an encrypted file

## Architecture

### Core Classes

- **SaiSecureStreamCipher**: Main cipher implementation
- **KeyDerivation**: Key derivation utilities (HMAC/SHA256)
- **CryptoEngine**: High-level encryption/decryption engine
- **PassAuthGUI**: Java Swing user interface

### Security Features

- 256-bit keys derived from passwords
- Unique IV (16 bytes) and nonce (12 bytes) for each encryption
- HMAC-based key derivation (default) or SHA256-based
- Cryptographically secure random generation

## Development

### Project Structure

```
java-version/
├── src/main/java/com/passauth/
│   ├── SaiSecureStreamCipher.java
│   ├── KeyDerivation.java
│   ├── CryptoEngine.java
│   └── PassAuthGUI.java
├── pom.xml
└── README.md
```

### Testing

Each class includes a main method for testing:

```bash
mvn compile
java -cp target/classes com.passauth.SaiSecureStreamCipher
java -cp target/classes com.passauth.KeyDerivation
java -cp target/classes com.passauth.CryptoEngine
```

## Educational Purpose

This implementation is designed for educational purposes to demonstrate:

- Stream cipher implementation
- Key derivation techniques
- Java cryptography concepts
- GUI development with Swing
- Security best practices

## Security Notes

- **Educational Implementation**: This is for learning purposes
- **Password Strength**: Use strong passwords (12+ characters)
- **Backup Important Data**: Keep backups of encrypted files
- **Test First**: Test with non-critical data before production use

## Comparison with Python Version

This Java version provides the same functionality as the Python implementation:

- ✅ Same SaiSecureStreamCipher algorithm
- ✅ Same H(IV, password) key derivation
- ✅ Same encryption/decryption logic
- ✅ Cross-compatible encrypted files
- ✅ Similar GUI functionality

## License

Educational use only. Hand-implemented cryptography for learning purposes.
