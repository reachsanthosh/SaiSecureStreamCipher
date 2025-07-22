# PassAuthStreamCipher

A secure, educational password-based encryption tool implementing SaiSecureStreamCipher with H(IV, password) key derivation.

## 🔒 Overview

PassAuthStreamCipher is a user-friendly application that enables secure encryption and decryption of files and text using password-based authentication combined with the SaiSecureStreamCipher. The tool emphasizes both security and education, featuring hand-implemented algorithms for complete transparency and learning.

## 🛡️ Security Features

- **SaiSecureStreamCipher**: Hand-implemented stream cipher for educational transparency
- **H(IV, password) Key Derivation**: Hand-implemented using HMAC-SHA256
- **Random Nonce Generation**: 12-byte nonce for each encryption
- **Password Strength Validation**: Real-time feedback on password quality
- **No Key Reuse**: Fresh cryptographic material for each operation
- **Fully Hand-Implemented**: No external cryptographic libraries

## 🚀 Features

### Text Encryption

- Encrypt/decrypt text messages directly in the GUI
- Base64 encoding for easy sharing
- Real-time password strength validation

### File Encryption

- Encrypt/decrypt files of any type
- Progress indication for large files
- Automatic output file naming suggestions

### Security Information

- Comprehensive security documentation
- Best practices for password management
- Educational content about encryption algorithms

## 📁 Project Structure

```
PassAuthStreamCipher/
├── src/
│   ├── __init__.py
│   ├── sai_secure_stream_cipher.py    # Hand-implemented SaiSecureStreamCipher
│   ├── key_derivation.py             # H(IV, password) implementation
│   ├── crypto_engine.py              # Main encryption engine
│   └── gui.py                        # Tkinter GUI application
├── main.py                           # Application entry point
├── requirements.txt                  # Python dependencies
└── README.md                         # This file
```

## 🔧 Installation & Setup

### Prerequisites

- Python 3.7 or higher
- Tkinter (usually included with Python)

### Installation

1. Clone or download this repository
2. Navigate to the project directory
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application

```bash
python main.py
```

## 🎯 Usage

### Text Encryption

1. Open the "Text Encryption" tab
2. Enter a strong password
3. Type or paste your text in the input area
4. Click "Encrypt Text" to encrypt or "Decrypt Text" to decrypt
5. Copy the result from the output area

### File Encryption

1. Open the "File Encryption" tab
2. Enter a strong password
3. Browse and select your input file
4. Specify the output file location
5. Click "Encrypt File" or "Decrypt File"

## 🔐 Technical Details

### Encryption Process

1. **Password Input**: User provides password
2. **Nonce Generation**: 12 random bytes generated
3. **Key Derivation**: HMAC(nonce, password) derives 32-byte key
4. **Encryption**: SaiSecureStreamCipher encrypts the data
5. **Packaging**: Nonce + Ciphertext

### File Format

```
[Nonce(12 bytes)] + [Ciphertext]
```

### Security Parameters

- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Hash Function**: SHA-256
- **Key Derivation**: HMAC(nonce, password)

## ⚠️ Security Warnings

- **Password Recovery**: There is NO password recovery mechanism
- **Backup Important Files**: Always keep backups of encrypted files
- **Test Decryption**: Verify you can decrypt files immediately after encryption
- **Strong Passwords**: Use unique, complex passwords for each encrypted file
- **Secure Communication**: Never share passwords over insecure channels

## 📚 Educational Purpose

This implementation is designed for educational purposes to demonstrate:

- Secure key derivation practices (H(IV, password))
- Password-based encryption systems
- Cryptographic best practices
- Ethical use of encryption technology

## 🔬 Algorithm Verification

The SaiSecureStreamCipher implementation can be verified with test vectors. Run the test functions:

```bash
python -m src.sai_secure_stream_cipher
python -m src.crypto_engine
```

## 🎯 Password Best Practices

- Minimum 12 characters (longer is better)
- Mix of uppercase and lowercase letters
- Include numbers and special characters
- Avoid dictionary words and patterns
- Use unique passwords for different purposes
- Consider using a password manager

## 🚫 Ethical Use Guidelines

- Only encrypt data you own or have permission to encrypt
- Respect privacy laws and regulations in your jurisdiction
- Use encryption for legitimate, legal purposes
- Understand the legal implications of encryption in your location
- Promote responsible digital citizenship

## 🐛 Testing

Run individual module tests:

```bash
python -m src.sai_secure_stream_cipher    # Test SaiSecureStreamCipher implementation
python -m src.key_derivation              # Test H(IV, password) and password validation
python -m src.crypto_engine               # Test complete encryption engine
```

## 📄 License

This project is provided for educational purposes. Please ensure compliance with local laws and regulations regarding encryption software.

## 🤝 Contributing

This is an educational project demonstrating cryptographic implementations. Contributions should maintain the educational nature and security best practices.

## 📞 Support

For questions about cryptographic concepts or implementation details, refer to:

- RFC 7539 (Cryptographic specification - basis for SaiSecureStreamCipher)
- HMAC specification (RFC 2104)
- NIST cryptographic standards

---

**Remember**: Strong encryption is only as secure as your password and key management practices. Always prioritize security and follow best practices when handling sensitive data.
