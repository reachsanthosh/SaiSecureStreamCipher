package com.passauth;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

/**
 * Java Swing GUI for PassAuth Stream Cipher
 */
public class PassAuthGUI extends JFrame {
    private CryptoEngine cryptoEngine;
    private JTextArea textInput;
    private JTextArea textOutput;
    private JPasswordField passwordField;
    private JLabel statusLabel;
    private JProgressBar progressBar;

    public PassAuthGUI() {
        cryptoEngine = new CryptoEngine(true);
        initializeGUI();
    }

    private void initializeGUI() {
        setTitle("PassAuth Stream Cipher");
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

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder("Input Text"));

        textInput = new JTextArea(8, 50);
        textInput.setLineWrap(true);
        textInput.setWrapStyleWord(true);
        JScrollPane inputScroll = new JScrollPane(textInput);
        inputPanel.add(inputScroll, BorderLayout.CENTER);

        JPanel passwordPanel = new JPanel(new BorderLayout());

        JPanel passwordInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        passwordInputPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField(20);
        passwordInputPanel.add(passwordField);

        JPanel strengthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        strengthPanel.add(new JLabel("Strength: "));

        JLabel strengthLabel = new JLabel("Enter password");
        strengthLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
        strengthLabel.setPreferredSize(new Dimension(600, 20));
        strengthPanel.add(strengthLabel);

        passwordPanel.add(passwordInputPanel, BorderLayout.NORTH);
        passwordPanel.add(strengthPanel, BorderLayout.SOUTH);

        passwordField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updatePasswordStrength(strengthLabel);
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updatePasswordStrength(strengthLabel);
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updatePasswordStrength(strengthLabel);
            }
        });

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

        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.setBorder(BorderFactory.createTitledBorder("Output"));

        textOutput = new JTextArea(8, 50);
        textOutput.setLineWrap(true);
        textOutput.setWrapStyleWord(true);
        textOutput.setEditable(false);
        JScrollPane outputScroll = new JScrollPane(textOutput);
        outputPanel.add(outputScroll, BorderLayout.CENTER);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(inputPanel, BorderLayout.CENTER);
        topPanel.add(passwordPanel, BorderLayout.SOUTH);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(buttonPanel, BorderLayout.CENTER);
        panel.add(outputPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createFilePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();

        // File selection
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

        // Password for files with strength indicator
        gbc.gridy++;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        panel.add(new JLabel("Password:"), gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JPasswordField filePasswordField = new JPasswordField(20);

        // File password strength label
        JLabel fileStrengthLabel = new JLabel("Enter password");
        fileStrengthLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));

        // Add password change listener for file password
        filePasswordField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                updateFilePasswordStrength(filePasswordField, fileStrengthLabel);
            }

            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                updateFilePasswordStrength(filePasswordField, fileStrengthLabel);
            }

            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                updateFilePasswordStrength(filePasswordField, fileStrengthLabel);
            }
        });

        panel.add(filePasswordField, gbc);

        gbc.gridy++;
        gbc.gridx = 0;
        panel.add(new JLabel("Strength:"), gbc);
        gbc.gridx = 1;
        panel.add(fileStrengthLabel, gbc);

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

        String info = "PassAuth Stream Cipher\n\n" +
                "FEATURES:\n" +
                "• Hand-implemented SaiSecureStreamCipher\n" +
                "• H(IV, password) key derivation using HMAC\n" +
                "• Secure file and text encryption\n\n" +
                "SECURITY NOTES:\n" +
                "• Uses 256-bit keys derived from passwords\n" +
                "• Each encryption uses unique IV and nonce\n" +
                "• Cryptographically secure random generation\n\n" +
                "PASSWORD RECOMMENDATIONS:\n" +
                "• Use at least 12 characters\n" +
                "• Mix letters, numbers, and symbols\n" +
                "• Don't reuse passwords from other accounts\n" +
                "• Keep backups of important encrypted files\n\n" +
                "IMPORTANT WARNINGS:\n" +
                "• Keep backups of important encrypted files\n" +
                "• Remember your passwords - they cannot be recovered\n" +
                "• Test with non-critical data first\n\n" +
                "Implementation: Java Swing GUI with hand-coded cryptography\n";

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
            String encrypted = cryptoEngine.encryptText(text, password);
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
            String decrypted = cryptoEngine.decryptText(text, password);
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
                cryptoEngine.encryptFile(inputFile.getAbsolutePath(), outputFile.getAbsolutePath(), password);
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

            // Determine output filename
            String outputPath = inputFile.getAbsolutePath();
            if (outputPath.endsWith(".encrypted")) {
                outputPath = outputPath.substring(0, outputPath.length() - 10); // Remove .encrypted
            } else {
                outputPath += ".decrypted";
            }
            File outputFile = new File(outputPath);

            try {
                setStatus("Decrypting file: " + inputFile.getName(), true);
                cryptoEngine.decryptFile(inputFile.getAbsolutePath(), outputFile.getAbsolutePath(), password);
                setStatus("File decrypted: " + outputFile.getName(), false);
                showInfo("File decrypted successfully:\n" + outputFile.getAbsolutePath());
            } catch (Exception e) {
                showError("File decryption failed: " + e.getMessage());
                setStatus("File decryption failed", false);
            }
        }
    }

    private void updatePasswordStrength(JLabel strengthLabel) {
        String password = new String(passwordField.getPassword());

        if (password.isEmpty()) {
            strengthLabel.setText("Enter password");
            strengthLabel.setForeground(Color.GRAY);
            return;
        }

        String strength = KeyDerivation.validatePasswordStrength(password);
        java.util.List<String> suggestions = KeyDerivation.getPasswordSuggestions(password);

        switch (strength) {
            case "weak":
                strengthLabel.setText("WEAK: " + String.join("; ", suggestions));
                strengthLabel.setForeground(Color.RED);
                break;
            case "medium":
                strengthLabel.setText("MEDIUM: " + String.join("; ", suggestions));
                strengthLabel.setForeground(Color.ORANGE);
                break;
            case "strong":
                strengthLabel.setText("STRONG: " + String.join("; ", suggestions));
                strengthLabel.setForeground(Color.GREEN);
                break;
            case "empty":
                strengthLabel.setText("Enter password");
                strengthLabel.setForeground(Color.GRAY);
                break;
            default:
                strengthLabel.setText("Unknown strength");
                strengthLabel.setForeground(Color.GRAY);
        }

        strengthLabel.revalidate();
        strengthLabel.repaint();
    }

    private void updateFilePasswordStrength(JPasswordField passwordField, JLabel strengthLabel) {
        String password = new String(passwordField.getPassword());

        if (password.isEmpty()) {
            strengthLabel.setText("Enter password");
            strengthLabel.setForeground(Color.GRAY);
            return;
        }

        String strength = KeyDerivation.validatePasswordStrength(password);
        java.util.List<String> suggestions = KeyDerivation.getPasswordSuggestions(password);

        switch (strength) {
            case "weak":
                strengthLabel.setText("WEAK: " + String.join("; ", suggestions));
                strengthLabel.setForeground(Color.RED);
                break;
            case "medium":
                strengthLabel.setText("MEDIUM: " + String.join("; ", suggestions));
                strengthLabel.setForeground(Color.ORANGE);
                break;
            case "strong":
                strengthLabel.setText("STRONG: " + String.join("; ", suggestions));
                strengthLabel.setForeground(Color.GREEN);
                break;
            default:
                strengthLabel.setText("Enter password");
                strengthLabel.setForeground(Color.GRAY);
        }
    }

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

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            System.out.println("Starting PassAuth Stream Cipher");
            System.out.println("Hand-implemented SaiSecureStreamCipher with H(IV, password)");
            System.out.println("============================================================");

            PassAuthGUI gui = new PassAuthGUI();
            gui.setVisible(true);
        });
    }
}
