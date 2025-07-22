package com.passauth;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Main cryptographic engine that combines SaiSecureStreamCipher with key
 * derivation
 * Ported from Python implementation
 */
public class CryptoEngine {
    private boolean useHmac;

    public CryptoEngine(boolean useHmac) {
        this.useHmac = useHmac;
    }

    public CryptoEngine() {
        this(true); // Default to HMAC
    }

    /**
     * Encrypt data with password
     */
    public byte[] encryptData(String password, byte[] plaintext) {
        try {
            // Generate IV and nonce
            byte[] iv = KeyDerivation.generateIv();
            byte[] nonce = KeyDerivation.generateNonce();

            // Derive key from password and IV
            byte[] key;
            if (useHmac) {
                key = KeyDerivation.deriveKeyHmac(password, iv);
            } else {
                key = KeyDerivation.deriveKeySha256(password, iv);
            }

            // Create cipher and encrypt
            SaiSecureStreamCipher cipher = new SaiSecureStreamCipher(key, nonce);
            byte[] encrypted = cipher.encrypt(plaintext);

            // Combine IV + nonce + encrypted data
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.write(iv);
            output.write(nonce);
            output.write(encrypted);

            return output.toByteArray();

        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypt data with password
     */
    public byte[] decryptData(String password, byte[] ciphertext) {
        try {
            if (ciphertext.length < 28) { // 16 (IV) + 12 (nonce) = 28 minimum
                throw new IllegalArgumentException("Invalid ciphertext length");
            }

            // Extract IV, nonce, and encrypted data
            byte[] iv = new byte[16];
            byte[] nonce = new byte[12];
            System.arraycopy(ciphertext, 0, iv, 0, 16);
            System.arraycopy(ciphertext, 16, nonce, 0, 12);

            byte[] encrypted = new byte[ciphertext.length - 28];
            System.arraycopy(ciphertext, 28, encrypted, 0, encrypted.length);

            // Derive key from password and IV
            byte[] key;
            if (useHmac) {
                key = KeyDerivation.deriveKeyHmac(password, iv);
            } else {
                key = KeyDerivation.deriveKeySha256(password, iv);
            }

            // Decrypt
            SaiSecureStreamCipher cipher = new SaiSecureStreamCipher(key, nonce);
            return cipher.decrypt(encrypted);

        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    /**
     * Encrypt text and return base64 encoded result
     */
    public String encryptText(String text, String password) {
        try {
            byte[] plaintext = text.getBytes("UTF-8");
            byte[] encrypted = encryptData(password, plaintext);
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Text encryption failed", e);
        }
    }

    /**
     * Decrypt base64 encoded text
     */
    public String decryptText(String encryptedText, String password) {
        try {
            byte[] encrypted = Base64.getDecoder().decode(encryptedText);
            byte[] decrypted = decryptData(password, encrypted);
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("Text decryption failed", e);
        }
    }

    /**
     * Encrypt file
     */
    public void encryptFile(String inputFile, String outputFile, String password) {
        try {
            // Read input file
            byte[] plaintext = Files.readAllBytes(Paths.get(inputFile));

            // Encrypt
            byte[] encrypted = encryptData(password, plaintext);

            // Write output file
            Files.write(Paths.get(outputFile), encrypted);

        } catch (Exception e) {
            throw new RuntimeException("File encryption failed", e);
        }
    }

    /**
     * Decrypt file
     */
    public void decryptFile(String inputFile, String outputFile, String password) {
        try {
            // Read encrypted file
            byte[] encrypted = Files.readAllBytes(Paths.get(inputFile));

            // Decrypt
            byte[] decrypted = decryptData(password, encrypted);

            // Write output file
            Files.write(Paths.get(outputFile), decrypted);

        } catch (Exception e) {
            throw new RuntimeException("File decryption failed", e);
        }
    }

    // Test method
    public static void main(String[] args) {
        try {
            System.out.println("Testing CryptoEngine...");

            CryptoEngine engine = new CryptoEngine(true); // Use HMAC
            String password = "test123";
            String testText = "Hello World! This is a test message for encryption.";

            System.out.println("Original text: " + testText);
            System.out.println("Password: " + password);

            // Test text encryption
            String encrypted = engine.encryptText(testText, password);
            System.out
                    .println("Encrypted (base64): " + encrypted.substring(0, Math.min(50, encrypted.length())) + "...");

            String decrypted = engine.decryptText(encrypted, password);
            System.out.println("Decrypted text: " + decrypted);

            boolean textTestPassed = testText.equals(decrypted);
            System.out.println("Text test: " + (textTestPassed ? "✅ PASSED" : "❌ FAILED"));

            // Test file encryption
            String testFile = "test.txt";
            String encryptedFile = "test.txt.encrypted";
            String decryptedFile = "test_decrypted.txt";

            // Create test file
            Files.write(Paths.get(testFile), testText.getBytes("UTF-8"));

            // Encrypt file
            engine.encryptFile(testFile, encryptedFile, password);
            System.out.println("File encrypted to: " + encryptedFile);

            // Decrypt file
            engine.decryptFile(encryptedFile, decryptedFile, password);
            System.out.println("File decrypted to: " + decryptedFile);

            // Verify file content
            String fileContent = new String(Files.readAllBytes(Paths.get(decryptedFile)), "UTF-8");
            boolean fileTestPassed = testText.equals(fileContent);
            System.out.println("File test: " + (fileTestPassed ? "✅ PASSED" : "❌ FAILED"));

            // Clean up
            Files.deleteIfExists(Paths.get(testFile));
            Files.deleteIfExists(Paths.get(encryptedFile));
            Files.deleteIfExists(Paths.get(decryptedFile));

            if (textTestPassed && fileTestPassed) {
                System.out.println("\n✅ ALL TESTS PASSED!");
            } else {
                System.out.println("\n❌ SOME TESTS FAILED!");
            }

        } catch (Exception e) {
            System.err.println("❌ CryptoEngine tests failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
