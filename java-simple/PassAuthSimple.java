import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * PassAuth Stream Cipher - Simplified Single-File Version
 * 
 * A complete implementation of the PassAuth Stream Cipher with GUI
 * in a single Java file for easy distribution and understanding.
 */
public class PassAuthSimple extends JFrame {

    // GUI Components
    private JTextArea textInput;
    private JTextArea textOutput;
    private JPasswordField passwordField;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    private static final boolean DEBUG = false;

    // Cryptographic constants
    private static final int IV_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int KEY_SIZE = 32;

    public PassAuthSimple() {
        initializeGUI();
    }

    private void initializeGUI() {
        setTitle("PassAuth Stream Cipher - Simple Version");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 700);
        setLocationRelativeTo(null);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Text Encryption", createTextPanel());
        tabbedPane.addTab("File Encryption", createFilePanel());
        tabbedPane.addTab("Information", createInfoPanel());

        JPanel statusPanel = createStatusPanel();

        setLayout(new BorderLayout());
        add(tabbedPane, BorderLayout.CENTER);
        add(statusPanel, BorderLayout.SOUTH);
    }

    private JPanel createTextPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder("Input Text"));
        textInput = new JTextArea(8, 50);
        textInput.setLineWrap(true);
        textInput.setWrapStyleWord(true);
        JScrollPane inputScroll = new JScrollPane(textInput);
        inputPanel.add(inputScroll, BorderLayout.CENTER);

        // Password panel
        JPanel passwordPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        passwordPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField(20);
        passwordPanel.add(passwordField);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        JButton encryptBtn = new JButton("Encrypt Text");
        JButton decryptBtn = new JButton("Decrypt Text");
        JButton clearBtn = new JButton("Clear All");

        encryptBtn.addActionListener(e -> encryptText());
        decryptBtn.addActionListener(e -> decryptText());
        clearBtn.addActionListener(e -> clearTextFields());

        buttonPanel.add(encryptBtn);
        buttonPanel.add(decryptBtn);
        buttonPanel.add(clearBtn);

        // Output panel
        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createTitledBorder("Output"));
        textOutput = new JTextArea(8, 50);
        textOutput.setLineWrap(true);
        textOutput.setWrapStyleWord(true);
        textOutput.setEditable(false);
        JScrollPane outputScroll = new JScrollPane(textOutput);
        outputPanel.add(outputScroll, BorderLayout.CENTER);

        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(passwordPanel, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.CENTER);
        panel.add(outputPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createFilePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();

        // Instructions
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        JPanel fileSelectPanel = new JPanel(new BorderLayout());
        fileSelectPanel.setBorder(BorderFactory.createTitledBorder("File Operations"));
        JTextArea fileInstructions = new JTextArea(
                "Select a file to encrypt or decrypt.\n" +
                        "Encrypted files will have .encrypted extension.\n" +
                        "Make sure to remember your password!");
        fileInstructions.setEditable(false);
        fileInstructions.setBackground(panel.getBackground());
        fileSelectPanel.add(fileInstructions, BorderLayout.CENTER);
        panel.add(fileSelectPanel, gbc);

        // Password field
        gbc.gridy++;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        panel.add(new JLabel("Password:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JPasswordField filePasswordField = new JPasswordField(20);
        panel.add(filePasswordField, gbc);

        // Buttons
        gbc.gridy++;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;

        JPanel fileButtonPanel = new JPanel(new FlowLayout());
        JButton encryptFileBtn = new JButton("Encrypt File");
        JButton decryptFileBtn = new JButton("Decrypt File");

        encryptFileBtn.addActionListener(e -> encryptFile(filePasswordField));
        decryptFileBtn.addActionListener(e -> decryptFile(filePasswordField));

        fileButtonPanel.add(encryptFileBtn);
        fileButtonPanel.add(decryptFileBtn);
        panel.add(fileButtonPanel, gbc);

        return panel;
    }

    private JPanel createInfoPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        JTextArea infoText = new JTextArea();
        infoText.setEditable(false);
        infoText.setLineWrap(true);
        infoText.setWrapStyleWord(true);

        String info = "PassAuth Stream Cipher - Simple Version\n\n" +
                "FEATURES:\n" +
                "• Hand-implemented SaiSecureStreamCipher\n" +
                "• H(IV, password) key derivation using HMAC\n" +
                "• Secure file and text encryption\n" +
                "• Single file implementation for easy distribution\n\n" +
                "SECURITY FEATURES:\n" +
                "• 256-bit keys derived from passwords\n" +
                "• Unique IV and nonce for each encryption\n" +
                "• Cryptographically secure random generation\n" +
                "• HMAC-based key derivation\n\n" +
                "USAGE TIPS:\n" +
                "• Use strong passwords (12+ characters)\n" +
                "• Mix letters, numbers, and symbols\n" +
                "• Keep backups of encrypted files\n" +
                "• Test with non-critical data first\n\n" +
                "IMPORTANT:\n" +
                "• Educational implementation for learning\n" +
                "• Remember passwords - cannot be recovered\n" +
                "• Compatible with full Java version\n\n" +
                "Implementation: Single-file Java application\n" +
                "All cryptographic functions included in one file";

        infoText.setText(info);
        JScrollPane scrollPane = new JScrollPane(infoText);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createStatusPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));

        statusLabel = new JLabel("Ready");
        progressBar = new JProgressBar();
        progressBar.setVisible(false);

        panel.add(statusLabel, BorderLayout.WEST);
        panel.add(progressBar, BorderLayout.EAST);

        return panel;
    }

    // ========== ENCRYPTION/DECRYPTION METHODS ==========

    private void encryptText() {
        String text = textInput.getText().trim();
        String password = new String(passwordField.getPassword());

        if (text.isEmpty()) {
            showError("Please enter text to encrypt");
            return;
        }

        if (password.isEmpty()) {
            showError("Please enter a password");
            return;
        }

        try {
            setStatus("Encrypting text...", true);
            String encrypted = encryptString(text, password);
            textOutput.setText(encrypted);
            setStatus("Text encrypted successfully", false);
        } catch (Exception e) {
            showError("Encryption failed: " + e.getMessage());
            setStatus("Encryption failed", false);
        }
    }

    private void decryptText() {
        String text = textInput.getText().trim();
        String password = new String(passwordField.getPassword());

        if (text.isEmpty()) {
            showError("Please enter encrypted text to decrypt");
            return;
        }

        if (password.isEmpty()) {
            showError("Please enter the password");
            return;
        }

        try {
            setStatus("Decrypting text...", true);
            String decrypted = decryptString(text, password);
            textOutput.setText(decrypted);
            setStatus("Text decrypted successfully", false);
        } catch (Exception e) {
            showError("Decryption failed: " + e.getMessage());
            setStatus("Decryption failed", false);
        }
    }

    private void clearTextFields() {
        textInput.setText("");
        textOutput.setText("");
        passwordField.setText("");
        setStatus("Fields cleared", false);
    }

    private void encryptFile(JPasswordField filePasswordField) {
        String password = new String(filePasswordField.getPassword());

        if (password.isEmpty()) {
            showError("Please enter a password for file encryption");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select file to encrypt");

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File inputFile = fileChooser.getSelectedFile();
            File outputFile = new File(inputFile.getAbsolutePath() + ".encrypted");

            try {
                setStatus("Encrypting file: " + inputFile.getName(), true);
                encryptFileData(inputFile.getAbsolutePath(), outputFile.getAbsolutePath(), password);
                setStatus("File encrypted: " + outputFile.getName(), false);
                showInfo("File encrypted successfully:\n" + outputFile.getAbsolutePath());
            } catch (Exception e) {
                showError("File encryption failed: " + e.getMessage());
                setStatus("File encryption failed", false);
            }
        }
    }

    private void decryptFile(JPasswordField filePasswordField) {
        String password = new String(filePasswordField.getPassword());

        if (password.isEmpty()) {
            showError("Please enter the password for file decryption");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select encrypted file to decrypt");
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Encrypted files (*.encrypted)", "encrypted");
        fileChooser.setFileFilter(filter);

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File inputFile = fileChooser.getSelectedFile();

            String outputPath = inputFile.getAbsolutePath();
            if (outputPath.endsWith(".encrypted")) {
                outputPath = outputPath.substring(0, outputPath.length() - 10);
            } else {
                outputPath += ".decrypted";
            }
            File outputFile = new File(outputPath);

            try {
                setStatus("Decrypting file: " + inputFile.getName(), true);
                decryptFileData(inputFile.getAbsolutePath(), outputFile.getAbsolutePath(), password);
                setStatus("File decrypted: " + outputFile.getName(), false);
                showInfo("File decrypted successfully:\n" + outputFile.getAbsolutePath());
            } catch (Exception e) {
                showError("File decryption failed: " + e.getMessage());
                setStatus("File decryption failed", false);
            }
        }
    }

    // ========== CORE CRYPTOGRAPHIC FUNCTIONS ==========

    /**
     * Encrypt a string and return Base64 encoded result
     */
    public String encryptString(String plaintext, String password) throws Exception {
        byte[] data = plaintext.getBytes("UTF-8");
        byte[] encrypted = encrypt(data, password);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt a Base64 encoded string
     */
    public String decryptString(String base64Encrypted, String password) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(base64Encrypted);
        byte[] decrypted = decrypt(encrypted, password);
        return new String(decrypted, "UTF-8");
    }

    /**
     * Encrypt file data
     */
    public void encryptFileData(String inputPath, String outputPath, String password) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(inputPath));
        byte[] encrypted = encrypt(data, password);
        Files.write(Paths.get(outputPath), encrypted);
    }

    /**
     * Decrypt file data
     */
    public void decryptFileData(String inputPath, String outputPath, String password) throws Exception {
        byte[] encrypted = Files.readAllBytes(Paths.get(inputPath));
        byte[] decrypted = decrypt(encrypted, password);
        Files.write(Paths.get(outputPath), decrypted);
    }

    /**
     * Main encryption function
     */
    public byte[] encrypt(byte[] data, String password) throws Exception {
        // Generate random IV and nonce
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(iv);
        random.nextBytes(nonce);

        // Derive key using HMAC
        byte[] key = deriveKey(password, iv);

        // Initialize cipher
        SaiSecureStreamCipher cipher = new SaiSecureStreamCipher();
        cipher.init(key, nonce);

        // Encrypt data
        byte[] encrypted = cipher.encrypt(data);

        // Combine IV + nonce + encrypted data
        byte[] result = new byte[IV_SIZE + NONCE_SIZE + encrypted.length];
        System.arraycopy(iv, 0, result, 0, IV_SIZE);
        System.arraycopy(nonce, 0, result, IV_SIZE, NONCE_SIZE);
        System.arraycopy(encrypted, 0, result, IV_SIZE + NONCE_SIZE, encrypted.length);

        return result;
    }

    /**
     * Main decryption function
     */
    public byte[] decrypt(byte[] encryptedData, String password) throws Exception {
        if (encryptedData.length < IV_SIZE + NONCE_SIZE) {
            throw new IllegalArgumentException("Invalid encrypted data format");
        }

        // Extract IV, nonce, and encrypted data
        byte[] iv = new byte[IV_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];
        byte[] encrypted = new byte[encryptedData.length - IV_SIZE - NONCE_SIZE];

        System.arraycopy(encryptedData, 0, iv, 0, IV_SIZE);
        System.arraycopy(encryptedData, IV_SIZE, nonce, 0, NONCE_SIZE);
        System.arraycopy(encryptedData, IV_SIZE + NONCE_SIZE, encrypted, 0, encrypted.length);

        // Derive key using HMAC
        byte[] key = deriveKey(password, iv);

        // Initialize cipher
        SaiSecureStreamCipher cipher = new SaiSecureStreamCipher();
        cipher.init(key, nonce);

        // Decrypt data
        return cipher.decrypt(encrypted);
    }

    /**
     * Key derivation using HMAC-SHA256
     */
    private byte[] deriveKey(String password, byte[] iv) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(password.getBytes("UTF-8"), "HmacSHA256");
        mac.init(keySpec);
        mac.update(iv);
        return mac.doFinal();
    }

    // ========== SAISECURESTREAMCIPHER IMPLEMENTATION ==========

    /**
     * Hand-implemented stream cipher
     */
    private static class SaiSecureStreamCipher {
        private int[] state;
        private int counter;

        public void init(byte[] key, byte[] nonce) throws Exception {
            if (key.length != KEY_SIZE) {
                throw new IllegalArgumentException("Key must be 32 bytes");
            }
            if (nonce.length != NONCE_SIZE) {
                throw new IllegalArgumentException("Nonce must be 12 bytes");
            }

            // Initialize state array (similar to ChaCha20 but simplified)
            state = new int[16];

            // Constants
            state[0] = 0x61707865; // "expa"
            state[1] = 0x6e642d32; // "nd 3"
            state[2] = 0x322d6279; // "2-by"
            state[3] = 0x7465206b; // "te k"

            // Key (8 words)
            for (int i = 0; i < 8; i++) {
                state[4 + i] = bytesToInt(key, i * 4);
            }

            // Counter
            state[12] = 0;

            // Nonce (3 words)
            for (int i = 0; i < 3; i++) {
                state[13 + i] = bytesToInt(nonce, i * 4);
            }

            counter = 0;
        }

        public byte[] encrypt(byte[] data) {
            return processData(data);
        }

        public byte[] decrypt(byte[] data) {
            return processData(data);
        }

        private byte[] processData(byte[] data) {
            byte[] result = new byte[data.length];
            int offset = 0;

            while (offset < data.length) {
                byte[] keystream = generateKeystream();
                int blockSize = Math.min(64, data.length - offset);

                for (int i = 0; i < blockSize; i++) {
                    result[offset + i] = (byte) (data[offset + i] ^ keystream[i]);
                }

                offset += blockSize;
                counter++;
                state[12] = counter;
            }

            return result;
        }

        private byte[] generateKeystream() {
            int[] workingState = state.clone();

            // 20 rounds of operations (simplified ChaCha20-like)
            for (int round = 0; round < 20; round += 2) {
                quarterRound(workingState, 0, 4, 8, 12);
                quarterRound(workingState, 1, 5, 9, 13);
                quarterRound(workingState, 2, 6, 10, 14);
                quarterRound(workingState, 3, 7, 11, 15);
                quarterRound(workingState, 0, 5, 10, 15);
                quarterRound(workingState, 1, 6, 11, 12);
                quarterRound(workingState, 2, 7, 8, 13);
                quarterRound(workingState, 3, 4, 9, 14);
            }

            // Add original state
            for (int i = 0; i < 16; i++) {
                workingState[i] += state[i];
            }

            // Convert to bytes
            byte[] keystream = new byte[64];
            for (int i = 0; i < 16; i++) {
                intToBytes(workingState[i], keystream, i * 4);
            }

            return keystream;
        }

        private void quarterRound(int[] state, int a, int b, int c, int d) {
            state[a] += state[b];
            state[d] ^= state[a];
            state[d] = rotateLeft(state[d], 16);
            state[c] += state[d];
            state[b] ^= state[c];
            state[b] = rotateLeft(state[b], 12);
            state[a] += state[b];
            state[d] ^= state[a];
            state[d] = rotateLeft(state[d], 8);
            state[c] += state[d];
            state[b] ^= state[c];
            state[b] = rotateLeft(state[b], 7);
        }

        private int rotateLeft(int value, int bits) {
            return (value << bits) | (value >>> (32 - bits));
        }

        private int bytesToInt(byte[] bytes, int offset) {
            return (bytes[offset] & 0xFF) |
                    ((bytes[offset + 1] & 0xFF) << 8) |
                    ((bytes[offset + 2] & 0xFF) << 16) |
                    ((bytes[offset + 3] & 0xFF) << 24);
        }

        private void intToBytes(int value, byte[] bytes, int offset) {
            bytes[offset] = (byte) (value & 0xFF);
            bytes[offset + 1] = (byte) ((value >> 8) & 0xFF);
            bytes[offset + 2] = (byte) ((value >> 16) & 0xFF);
            bytes[offset + 3] = (byte) ((value >> 24) & 0xFF);
        }
    }

    // ========== UI UTILITY METHODS ==========

    private void setStatus(String message, boolean showProgress) {
        statusLabel.setText(message);
        progressBar.setVisible(showProgress);
        if (showProgress) {
            progressBar.setIndeterminate(true);
        } else {
            progressBar.setIndeterminate(false);
        }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    private void showInfo(String message) {
        JOptionPane.showMessageDialog(this, message, "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    // ========== MAIN METHOD ==========

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            System.out.println("Starting PassAuth Stream Cipher - Simple Version");
            System.out.println("Hand-implemented SaiSecureStreamCipher with H(IV, password)");
            System.out.println("Single-file implementation for easy distribution");
            System.out.println("============================================================");

            PassAuthSimple gui = new PassAuthSimple();
            gui.setVisible(true);
        });
    }
}
