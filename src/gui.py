# GUI for the encryption app
# tkinter interface for file/text encryption

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os

try:
    from .crypto_engine import PassAuthStreamCipher, SecureTextProcessor
    from .key_derivation import validate_password_strength
except ImportError:
    # Fallback for when running from main.py
    from crypto_engine import PassAuthStreamCipher, SecureTextProcessor
    from key_derivation import validate_password_strength


class PassAuthStreamCipherGUI:
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password File Encryptor")  # simpler title
        self.root.geometry("800x700")
        self.root.resizable(True, True)
        
        # setup the crypto stuff
        self.cipher_engine = PassAuthStreamCipher(use_hmac=True)
        self.text_processor = SecureTextProcessor(self.cipher_engine)
        
        # make the GUI
        self.setup_styles()
        self.create_widgets()
        
    def setup_styles(self):
        """Configure GUI styles and themes."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure custom styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Info.TLabel', font=('Arial', 10), foreground='blue')
        style.configure('Warning.TLabel', font=('Arial', 10), foreground='red')
        style.configure('Success.TLabel', font=('Arial', 10), foreground='green')
    
    def create_widgets(self):
        """Create and layout all GUI widgets."""
        # Main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Text encryption tab
        text_frame = ttk.Frame(notebook)
        notebook.add(text_frame, text='Text Encryption')
        self.create_text_tab(text_frame)
        
        # File encryption tab
        file_frame = ttk.Frame(notebook)
        notebook.add(file_frame, text='File Encryption')
        self.create_file_tab(file_frame)
        
        # Security info tab
        info_frame = ttk.Frame(notebook)
        notebook.add(info_frame, text='Security Information')
        self.create_info_tab(info_frame)
    
    def create_text_tab(self, parent):
        """Create the text encryption/decryption tab."""
        # Title
        title_label = ttk.Label(parent, text="Text Encryption with H(IV, password)", style='Title.TLabel')
        title_label.pack(pady=(10, 20))
        
        # Password frame
        pwd_frame = ttk.LabelFrame(parent, text="Password", padding=10)
        pwd_frame.pack(fill='x', padx=10, pady=5)
        
        self.text_password_var = tk.StringVar()
        self.text_password_var.trace('w', self.on_password_change)
        
        ttk.Label(pwd_frame, text="Enter password:").pack(anchor='w')
        self.text_password_entry = ttk.Entry(pwd_frame, textvariable=self.text_password_var, 
                                           show='*', width=50)
        self.text_password_entry.pack(fill='x', pady=5)
        
        # Password strength indicator
        self.text_pwd_strength_label = ttk.Label(pwd_frame, text="", style='Info.TLabel')
        self.text_pwd_strength_label.pack(anchor='w')
        
        # Input text frame
        input_frame = ttk.LabelFrame(parent, text="Input Text", padding=10)
        input_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.text_input = scrolledtext.ScrolledText(input_frame, height=8, wrap=tk.WORD)
        self.text_input.pack(fill='both', expand=True)
        
        # Buttons frame
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(btn_frame, text="Encrypt Text", command=self.encrypt_text).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Decrypt Text", command=self.decrypt_text).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_text).pack(side='left', padx=5)
        
        # Output text frame
        output_frame = ttk.LabelFrame(parent, text="Output", padding=10)
        output_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.text_output = scrolledtext.ScrolledText(output_frame, height=8, wrap=tk.WORD)
        self.text_output.pack(fill='both', expand=True)
    
    def create_file_tab(self, parent):
        """Create the file encryption/decryption tab."""
        # Title
        title_label = ttk.Label(parent, text="File Encryption with H(IV, password)", style='Title.TLabel')
        title_label.pack(pady=(10, 20))
        
        # Password frame
        pwd_frame = ttk.LabelFrame(parent, text="Password", padding=10)
        pwd_frame.pack(fill='x', padx=10, pady=5)
        
        self.file_password_var = tk.StringVar()
        self.file_password_var.trace('w', self.on_file_password_change)
        
        ttk.Label(pwd_frame, text="Enter password:").pack(anchor='w')
        self.file_password_entry = ttk.Entry(pwd_frame, textvariable=self.file_password_var, 
                                           show='*', width=50)
        self.file_password_entry.pack(fill='x', pady=5)
        
        # Password strength indicator
        self.file_pwd_strength_label = ttk.Label(pwd_frame, text="", style='Info.TLabel')
        self.file_pwd_strength_label.pack(anchor='w')
        
        # File selection frame
        file_frame = ttk.LabelFrame(parent, text="File Selection", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)
        
        # Input file
        ttk.Label(file_frame, text="Input file:").pack(anchor='w')
        input_file_frame = ttk.Frame(file_frame)
        input_file_frame.pack(fill='x', pady=5)
        
        self.input_file_var = tk.StringVar()
        self.input_file_entry = ttk.Entry(input_file_frame, textvariable=self.input_file_var)
        self.input_file_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(input_file_frame, text="Browse", 
                  command=self.browse_input_file).pack(side='right', padx=(5, 0))
        
        # Output file
        ttk.Label(file_frame, text="Output file:").pack(anchor='w', pady=(10, 0))
        output_file_frame = ttk.Frame(file_frame)
        output_file_frame.pack(fill='x', pady=5)
        
        self.output_file_var = tk.StringVar()
        self.output_file_entry = ttk.Entry(output_file_frame, textvariable=self.output_file_var)
        self.output_file_entry.pack(side='left', fill='x', expand=True)
        ttk.Button(output_file_frame, text="Browse", 
                  command=self.browse_output_file).pack(side='right', padx=(5, 0))
        
        # Operation buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill='x', padx=10, pady=20)
        
        self.encrypt_file_btn = ttk.Button(btn_frame, text="Encrypt File", 
                                          command=self.encrypt_file)
        self.encrypt_file_btn.pack(side='left', padx=5)
        
        self.decrypt_file_btn = ttk.Button(btn_frame, text="Decrypt File", 
                                          command=self.decrypt_file)
        self.decrypt_file_btn.pack(side='left', padx=5)
        
        # Progress bar
        self.progress_var = tk.StringVar()
        self.progress_label = ttk.Label(parent, textvariable=self.progress_var, style='Info.TLabel')
        self.progress_label.pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(parent, mode='indeterminate')
        self.progress_bar.pack(fill='x', padx=10, pady=5)
    
    def create_info_tab(self, parent):
        """Create the security information tab."""
        # Title
        title_label = ttk.Label(parent, text="H(IV, password) Security Information", style='Title.TLabel')
        title_label.pack(pady=(10, 20))
        
        # Create scrollable text widget for information
        info_text = scrolledtext.ScrolledText(parent, height=25, wrap=tk.WORD, state='disabled')
        info_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Security information content
        info_content = """
PASSAUTHSTREAMCIPHER SECURITY INFORMATION

ENCRYPTION ALGORITHM
- Stream Cipher: SaiSecureStreamCipher - Hand-implemented for transparency
- Key Derivation: H(IV, password) - Fully hand-implemented approach
- Key Methods: HMAC-SHA256 or Simple SHA256 (configurable)
- Key Size: 256-bit (32 bytes)
- Nonce Size: 96-bit (12 bytes) - randomly generated for each encryption

SECURITY FEATURES
- Password-based encryption with H(IV, password) key derivation
- Random nonce generation to ensure unique encryption for identical data
- No key reuse - each encryption uses fresh nonce (IV)
- Secure memory handling for sensitive data
- Choice of HMAC or simple hash for key derivation

PASSWORD BEST PRACTICES
- Use at least 12 characters (longer is better)
- Include uppercase and lowercase letters
- Include numbers and special characters
- Avoid dictionary words and common patterns
- Don't reuse passwords from other accounts
- Consider using a password manager

IMPORTANT WARNINGS
- NEVER lose your password - there is no recovery mechanism
- Keep backups of important encrypted files
- Test decryption immediately after encryption
- Use strong, unique passwords for each encrypted file
- Don't share passwords over insecure channels

TECHNICAL DETAILS
- File Format: [Method(1)] + [Nonce(12)] + [Ciphertext]
- Method Flag: 0x01 for HMAC, 0x00 for simple hash
- Nonce: 12 random bytes for SaiSecureStreamCipher initialization
- Key Derivation: key = HMAC(nonce, password) or key = SHA256(nonce || password)

EDUCATIONAL PURPOSE
This implementation demonstrates the H(IV, password) key derivation approach
that you suggested. It's fully hand-implemented for educational transparency.
The SaiSecureStreamCipher provides the encryption layer.

ETHICAL USE
- Only encrypt your own data or data you have permission to encrypt
- Respect privacy and legal requirements in your jurisdiction
- Use encryption responsibly and for legitimate purposes
- Understand the legal implications of encryption in your location

ALGORITHM VERIFICATION
You can verify the SaiSecureStreamCipher implementation against RFC 7539.
The H(IV, password) key derivation uses standard SHA256 and HMAC functions.

TIPS FOR SECURE USAGE
1. Always test decryption with a small file first
2. Keep multiple backups of important encrypted data
3. Use different passwords for different purposes
4. Regularly update your passwords
5. Be aware of shoulder surfing when entering passwords

KEY DERIVATION METHODS
- HMAC Method: key = HMAC-SHA256(nonce, password) [Default - More Secure]
- Simple Method: key = SHA256(nonce || password) [Alternative - Still Secure]

The current implementation uses the HMAC method by default for enhanced security.
        """
        
        # Insert content and make it read-only
        info_text.config(state='normal')
        info_text.insert('1.0', info_content)
        info_text.config(state='disabled')
    
    def on_password_change(self, *args):
        """Handle password changes in text tab."""
        password = self.text_password_var.get()
        if password:
            is_strong, suggestions = validate_password_strength(password)
            if is_strong:
                self.text_pwd_strength_label.config(text="Strong password", style='Success.TLabel')
            else:
                self.text_pwd_strength_label.config(text=f"Weak: {'; '.join(suggestions)}", 
                                                   style='Warning.TLabel')
        else:
            self.text_pwd_strength_label.config(text="")
    
    def on_file_password_change(self, *args):
        """Handle password changes in file tab."""
        password = self.file_password_var.get()
        if password:
            is_strong, suggestions = validate_password_strength(password)
            if is_strong:
                self.file_pwd_strength_label.config(text="Strong password", style='Success.TLabel')
            else:
                self.file_pwd_strength_label.config(text=f"Weak: {'; '.join(suggestions)}", 
                                                   style='Warning.TLabel')
        else:
            self.file_pwd_strength_label.config(text="")
    
    def encrypt_text(self):
        """Encrypt text from input field."""
        password = self.text_password_var.get()
        text = self.text_input.get('1.0', 'end-1c')
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if not text.strip():
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
        
        try:
            encrypted = self.text_processor.encrypt_text(text, password)
            self.text_output.delete('1.0', tk.END)
            self.text_output.insert('1.0', encrypted)
            messagebox.showinfo("Success", "Text encrypted using H(IV, password)!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        """Decrypt text from input field."""
        password = self.text_password_var.get()
        encrypted_text = self.text_input.get('1.0', 'end-1c')
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if not encrypted_text.strip():
            messagebox.showerror("Error", "Please enter encrypted text to decrypt")
            return
        
        try:
            decrypted = self.text_processor.decrypt_text(encrypted_text, password)
            self.text_output.delete('1.0', tk.END)
            self.text_output.insert('1.0', decrypted)
            messagebox.showinfo("Success", "Text decrypted using H(IV, password)!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def clear_text(self):
        """Clear text input and output fields."""
        self.text_input.delete('1.0', tk.END)
        self.text_output.delete('1.0', tk.END)
    
    def browse_input_file(self):
        """Browse for input file."""
        filename = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.input_file_var.set(filename)
            # Auto-suggest output filename
            if not self.output_file_var.get():
                base, ext = os.path.splitext(filename)
                suggested = f"{base}_encrypted{ext}"
                self.output_file_var.set(suggested)
    
    def browse_output_file(self):
        """Browse for output file."""
        filename = filedialog.asksaveasfilename(
            title="Save encrypted/decrypted file as",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.output_file_var.set(filename)
    
    def encrypt_file(self):
        """Encrypt selected file."""
        password = self.file_password_var.get()
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file")
            return
        
        if not output_file:
            messagebox.showerror("Error", "Please specify an output file")
            return
        
        # Run encryption in background thread
        self.run_file_operation(self.cipher_engine.encrypt_file, input_file, output_file, password, "Encrypting")
    
    def decrypt_file(self):
        """Decrypt selected file."""
        password = self.file_password_var.get()
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file")
            return
        
        if not output_file:
            messagebox.showerror("Error", "Please specify an output file")
            return
        
        # Run decryption in background thread
        self.run_file_operation(self.cipher_engine.decrypt_file, input_file, output_file, password, "Decrypting")
    
    def run_file_operation(self, operation, input_file, output_file, password, operation_name):
        """Run file operation in background thread with progress indication."""
        def worker():
            try:
                self.root.after(0, self.start_progress, operation_name)
                operation(input_file, output_file, password)
                self.root.after(0, self.operation_success, operation_name)
            except Exception as e:
                self.root.after(0, self.operation_error, str(e))
        
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
    
    def start_progress(self, operation_name):
        """Start progress indication."""
        self.progress_var.set(f"{operation_name} file using H(IV, password)...")
        self.progress_bar.start()
        self.encrypt_file_btn.config(state='disabled')
        self.decrypt_file_btn.config(state='disabled')
    
    def operation_success(self, operation_name):
        """Handle successful operation."""
        self.progress_bar.stop()
        self.progress_var.set("")
        self.encrypt_file_btn.config(state='normal')
        self.decrypt_file_btn.config(state='normal')
        messagebox.showinfo("Success", f"{operation_name} completed successfully with H(IV, password)!")
    
    def operation_error(self, error_msg):
        """Handle operation error."""
        self.progress_bar.stop()
        self.progress_var.set("")
        self.encrypt_file_btn.config(state='normal')
        self.decrypt_file_btn.config(state='normal')
        messagebox.showerror("Error", f"Operation failed: {error_msg}")
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main function to run the GUI application."""
    app = PassAuthStreamCipherGUI()
    app.run()


if __name__ == "__main__":
    main()
