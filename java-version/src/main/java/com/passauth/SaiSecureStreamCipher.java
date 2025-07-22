package com.passauth;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * SaiSecureStreamCipher - Hand-implemented stream cipher for Java
 * Ported from Python implementation for educational purposes
 */
public class SaiSecureStreamCipher {
    private byte[] key;
    private byte[] nonce;
    private int counter;

    public SaiSecureStreamCipher(byte[] key, byte[] nonce, int counter) {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be exactly 32 bytes");
        }
        if (nonce.length != 12) {
            throw new IllegalArgumentException("Nonce must be exactly 12 bytes");
        }

        this.key = key.clone();
        this.nonce = nonce.clone();
        this.counter = counter;
    }

    public SaiSecureStreamCipher(byte[] key, byte[] nonce) {
        this(key, nonce, 0);
    }

    /**
     * Encrypt data using the stream cipher
     */
    public byte[] encrypt(byte[] plaintext) {
        return processData(plaintext);
    }

    /**
     * Decrypt data using the stream cipher
     */
    public byte[] decrypt(byte[] ciphertext) {
        return processData(ciphertext);
    }

    private byte[] processData(byte[] data) {
        byte[] result = new byte[data.length];
        int blockCount = 0;
        int position = 0;

        while (position < data.length) {
            // Generate keystream block
            byte[] keystreamBlock = generateBlock(counter + blockCount);

            // XOR with data
            int bytesToProcess = Math.min(64, data.length - position);
            for (int i = 0; i < bytesToProcess; i++) {
                result[position + i] = (byte) (data[position + i] ^ keystreamBlock[i]);
            }

            position += bytesToProcess;
            blockCount++;
        }

        return result;
    }

    private byte[] generateBlock(int counter) {
        // Initialize state array
        int[] state = new int[16];

        // Constants: "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key (8 words)
        ByteBuffer keyBuffer = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 8; i++) {
            state[4 + i] = keyBuffer.getInt(i * 4);
        }

        // Counter
        state[12] = counter;

        // Nonce (3 words)
        ByteBuffer nonceBuffer = ByteBuffer.wrap(nonce).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 3; i++) {
            state[13 + i] = nonceBuffer.getInt(i * 4);
        }

        // Save initial state
        int[] initialState = state.clone();

        // Perform 20 rounds (10 double rounds)
        for (int round = 0; round < 10; round++) {
            // Column rounds
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);

            // Diagonal rounds
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }

        // Add initial state back
        for (int i = 0; i < 16; i++) {
            state[i] = (int) ((Integer.toUnsignedLong(state[i]) + Integer.toUnsignedLong(initialState[i]))
                    & 0xFFFFFFFFL);
        }

        // Convert to bytes
        ByteBuffer result = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < 16; i++) {
            result.putInt(state[i]);
        }

        return result.array();
    }

    private void quarterRound(int[] state, int a, int b, int c, int d) {
        state[a] = (int) ((Integer.toUnsignedLong(state[a]) + Integer.toUnsignedLong(state[b])) & 0xFFFFFFFFL);
        state[d] = rotateLeft(state[d] ^ state[a], 16);
        state[c] = (int) ((Integer.toUnsignedLong(state[c]) + Integer.toUnsignedLong(state[d])) & 0xFFFFFFFFL);
        state[b] = rotateLeft(state[b] ^ state[c], 12);
        state[a] = (int) ((Integer.toUnsignedLong(state[a]) + Integer.toUnsignedLong(state[b])) & 0xFFFFFFFFL);
        state[d] = rotateLeft(state[d] ^ state[a], 8);
        state[c] = (int) ((Integer.toUnsignedLong(state[c]) + Integer.toUnsignedLong(state[d])) & 0xFFFFFFFFL);
        state[b] = rotateLeft(state[b] ^ state[c], 7);
    }

    private int rotateLeft(int value, int bits) {
        return Integer.rotateLeft(value, bits);
    }

    // Test method
    public static void main(String[] args) {
        try {
            // Test the cipher
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];

            // Fill with test data
            for (int i = 0; i < 32; i++)
                key[i] = (byte) i;
            for (int i = 0; i < 12; i++)
                nonce[i] = (byte) i;

            SaiSecureStreamCipher cipher = new SaiSecureStreamCipher(key, nonce);

            String testData = "Hello World! This is a test message.";
            byte[] plaintext = testData.getBytes();

            System.out.println("Original: " + testData);

            byte[] encrypted = cipher.encrypt(plaintext);
            System.out.println("Encrypted length: " + encrypted.length + " bytes");

            byte[] decrypted = cipher.decrypt(encrypted);
            String result = new String(decrypted);

            System.out.println("Decrypted: " + result);
            System.out.println("Test " + (testData.equals(result) ? "PASSED" : "FAILED"));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
