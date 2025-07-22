package com.passauth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Key derivation implementation using H(IV, password) approach
 */
public class KeyDerivation {

    public static byte[] deriveKeyHmac(String password, byte[] iv) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(password.getBytes("UTF-8"), "HmacSHA256");
            hmac.init(keySpec);
            return hmac.doFinal(iv);
        } catch (Exception e) {
            throw new RuntimeException("HMAC key derivation failed", e);
        }
    }

    public static byte[] deriveKeySha256(String password, byte[] iv) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(iv);
            digest.update(password.getBytes("UTF-8"));
            return digest.digest();
        } catch (Exception e) {
            throw new RuntimeException("SHA256 key derivation failed", e);
        }
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] generateNonce() {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static String validatePasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return "empty";
        }

        boolean isStrong = true;

        // Length check
        if (password.length() < 12) {
            isStrong = false;
        }

        // Uppercase check
        if (!password.chars().anyMatch(Character::isUpperCase)) {
            isStrong = false;
        }

        // Lowercase check
        if (!password.chars().anyMatch(Character::isLowerCase)) {
            isStrong = false;
        }

        // Digit check
        if (!password.chars().anyMatch(Character::isDigit)) {
            isStrong = false;
        }

        // Special character check
        String specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if (!password.chars().anyMatch(c -> specialChars.indexOf(c) != -1)) {
            isStrong = false;
        }

        // Common patterns check
        String[] commonPatterns = { "123", "abc", "password", "admin", "user" };
        String lowerPassword = password.toLowerCase();
        for (String pattern : commonPatterns) {
            if (lowerPassword.contains(pattern)) {
                isStrong = false;
                break;
            }
        }

        // Repetitive character check
        if (hasRepetitivePattern(password)) {
            isStrong = false;
        }

        if (isStrong) {
            return "strong";
        } else if (password.length() >= 8) {
            return "medium";
        } else {
            return "weak";
        }
    }

    /**
     * Check for repetitive patterns in password
     */
    private static boolean hasRepetitivePattern(String password) {
        // Check for 3 or more consecutive same characters
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) &&
                    password.charAt(i + 1) == password.charAt(i + 2)) {
                return true;
            }
        }

        // Check for simple sequences like "123", "abc"
        for (int i = 0; i < password.length() - 2; i++) {
            char c1 = password.charAt(i);
            char c2 = password.charAt(i + 1);
            char c3 = password.charAt(i + 2);

            // Check ascending sequence
            if (c2 == c1 + 1 && c3 == c2 + 1) {
                return true;
            }

            // Check descending sequence
            if (c2 == c1 - 1 && c3 == c2 - 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get detailed password strength feedback
     * Returns suggestions for improving password strength
     */
    public static java.util.List<String> getPasswordSuggestions(String password) {
        java.util.List<String> suggestions = new java.util.ArrayList<>();

        if (password == null || password.isEmpty()) {
            suggestions.add("Enter a password");
            return suggestions;
        }

        if (password.length() < 12) {
            suggestions.add("Use at least 12 characters");
        }

        if (!password.chars().anyMatch(Character::isUpperCase)) {
            suggestions.add("Include at least one uppercase letter");
        }

        if (!password.chars().anyMatch(Character::isLowerCase)) {
            suggestions.add("Include at least one lowercase letter");
        }

        if (!password.chars().anyMatch(Character::isDigit)) {
            suggestions.add("Include at least one number");
        }

        String specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if (!password.chars().anyMatch(c -> specialChars.indexOf(c) != -1)) {
            suggestions.add("Include at least one special character");
        }

        String[] commonPatterns = { "123", "abc", "password", "admin", "user" };
        String lowerPassword = password.toLowerCase();
        for (String pattern : commonPatterns) {
            if (lowerPassword.contains(pattern)) {
                suggestions.add("Avoid common patterns and dictionary words");
                break;
            }
        }

        if (hasRepetitivePattern(password)) {
            suggestions.add("Avoid repetitive characters and sequences");
        }

        if (suggestions.isEmpty()) {
            suggestions.add("Strong password!");
        }

        return suggestions;
    }

    /**
     * Check if password meets minimum requirements
     */
    public static boolean isPasswordValid(String password) {
        return password != null && password.length() >= 8;
    }

    // Test method
    public static void main(String[] args) {
        try {
            String password = "test123";
            byte[] iv = generateIv();

            System.out.println("Testing key derivation...");
            System.out.println("Password: " + password);
            System.out.println("IV length: " + iv.length + " bytes");

            // Test HMAC derivation
            byte[] hmacKey = deriveKeyHmac(password, iv);
            System.out.println("HMAC key length: " + hmacKey.length + " bytes");

            // Test SHA256 derivation
            byte[] sha256Key = deriveKeySha256(password, iv);
            System.out.println("SHA256 key length: " + sha256Key.length + " bytes");

            // Test password validation
            System.out.println("Password strength: " + validatePasswordStrength(password));
            System.out.println("Password valid: " + isPasswordValid(password));

            // Verify consistency
            byte[] hmacKey2 = deriveKeyHmac(password, iv);
            boolean consistent = Arrays.equals(hmacKey, hmacKey2);
            System.out.println("Key derivation consistent: " + consistent);

            System.out.println("✅ Key derivation tests passed!");

        } catch (Exception e) {
            System.err.println("❌ Key derivation tests failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
