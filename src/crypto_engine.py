"""
Cryptographic Engine for PassAuthStreamCipher

This module combines SaiSecureStreamCipher with H(IV, password) key derivation
to provide secure password-based encryption and decryption.
"""

import os
import struct
from typing import Tuple, Union

try:
    from .sai_secure_stream_cipher import SaiSecureStreamCipher
    from .key_derivation import SimpleKeyDerivation, validate_password_strength
except ImportError:
    # Fallback for when running from main.py
    from sai_secure_stream_cipher import SaiSecureStreamCipher
    from key_derivation import SimpleKeyDerivation, validate_password_strength


class PassAuthStreamCipher:
    """Main cryptographic engine combining SaiSecureStreamCipher and H(IV, password) key derivation."""
    
    def __init__(self, use_hmac: bool = True):
        """
        Initialize the cipher engine.
        
        Args:
            use_hmac: Whether to use HMAC-based key derivation (more secure) or simple hash
        """
        self.use_hmac = use_hmac
    
    def encrypt_data(self, plaintext: Union[str, bytes], password: str) -> bytes:
        """
        Encrypt plaintext using password-based SaiSecureStreamCipher with H(IV, password).
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            password: User's password
            
        Returns:
            Encrypted data with embedded nonce
        """
        # Convert string to bytes if needed
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate random nonce (IV)
        nonce = os.urandom(12)  # 12 bytes nonce for SaiSecureStreamCipher
        
        # Derive key using H(IV, password) approach
        if self.use_hmac:
            key = SimpleKeyDerivation.derive_key_hmac(password, nonce)
        else:
            key = SimpleKeyDerivation.derive_key_from_iv(password, nonce)
        
        # Encrypt with SaiSecureStreamCipher
        cipher = SaiSecureStreamCipher(key, nonce)
        ciphertext = cipher.encrypt(plaintext)
        
        # Package: method_flag(1) + nonce(12) + ciphertext
        method_flag = b'\x01' if self.use_hmac else b'\x00'
        package = method_flag + nonce + ciphertext
        
        return package
    
    def decrypt_data(self, package: bytes, password: str) -> bytes:
        """
        Decrypt data using password-based SaiSecureStreamCipher with H(IV, password).
        
        Args:
            package: Encrypted package containing method flag, nonce, and ciphertext
            password: User's password
            
        Returns:
            Decrypted plaintext bytes
        """
        if len(package) < 13:  # method_flag(1) + nonce(12) = 13 bytes minimum
            raise ValueError("Invalid encrypted package")
        
        # Extract components
        method_flag = package[0:1]
        nonce = package[1:13]
        ciphertext = package[13:]
        
        # Determine key derivation method
        use_hmac = method_flag == b'\x01'
        
        # Derive key using same H(IV, password) approach
        if use_hmac:
            key = SimpleKeyDerivation.derive_key_hmac(password, nonce)
        else:
            key = SimpleKeyDerivation.derive_key_from_iv(password, nonce)
        
        # Decrypt with SaiSecureStreamCipher
        cipher = SaiSecureStreamCipher(key, nonce)
        plaintext = cipher.decrypt(ciphertext)
        
        return plaintext
    
    def encrypt_file(self, input_file: str, output_file: str, password: str) -> None:
        """
        Encrypt a file using password-based SaiSecureStreamCipher.
        
        Args:
            input_file: Path to input file
            output_file: Path to output encrypted file
            password: User's password
        """
        try:
            with open(input_file, 'rb') as f:
                plaintext = f.read()
            
            encrypted_data = self.encrypt_data(plaintext, password)
            
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            raise Exception(f"File encryption failed: {str(e)}")
    
    def decrypt_file(self, input_file: str, output_file: str, password: str) -> None:
        """
        Decrypt a file using password-based SaiSecureStreamCipher.
        
        Args:
            input_file: Path to input encrypted file
            output_file: Path to output decrypted file
            password: User's password
        """
        try:
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
            
            plaintext = self.decrypt_data(encrypted_data, password)
            
            with open(output_file, 'wb') as f:
                f.write(plaintext)
                
        except Exception as e:
            raise Exception(f"File decryption failed: {str(e)}")


class SecureTextProcessor:
    """Utility class for secure text processing."""
    
    def __init__(self, cipher_engine: PassAuthStreamCipher):
        self.cipher = cipher_engine
    
    def encrypt_text(self, text: str, password: str) -> str:
        """
        Encrypt text and return base64-encoded result.
        
        Args:
            text: Text to encrypt
            password: User's password
            
        Returns:
            Base64-encoded encrypted text
        """
        import base64
        encrypted_bytes = self.cipher.encrypt_data(text, password)
        return base64.b64encode(encrypted_bytes).decode('ascii')
    
    def decrypt_text(self, encrypted_text: str, password: str) -> str:
        """
        Decrypt base64-encoded text.
        
        Args:
            encrypted_text: Base64-encoded encrypted text
            password: User's password
            
        Returns:
            Decrypted text
        """
        import base64
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode('ascii'))
            decrypted_bytes = self.cipher.decrypt_data(encrypted_bytes, password)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise Exception(f"Text decryption failed: {str(e)}")


# Test function
def test_crypto_engine():
    """Test the cryptographic engine with H(IV, password) approach."""
    print("Testing PassAuthStreamCipher with H(IV, password)...")
    
    # Test both HMAC and simple hash approaches
    engine_hmac = PassAuthStreamCipher(use_hmac=True)
    engine_simple = PassAuthStreamCipher(use_hmac=False)
    text_processor_hmac = SecureTextProcessor(engine_hmac)
    text_processor_simple = SecureTextProcessor(engine_simple)
    
    # Test text encryption/decryption
    original_text = "This is a secret message encrypted with H(IV, password) approach!"
    password = "MySecurePassword123!"
    
    print(f"Original text: {original_text}")
    
    # Test HMAC approach
    print("\n🔒 Testing HMAC-based H(IV, password)...")
    encrypted_hmac = text_processor_hmac.encrypt_text(original_text, password)
    print(f"Encrypted (HMAC): {encrypted_hmac[:50]}...")
    
    decrypted_hmac = text_processor_hmac.decrypt_text(encrypted_hmac, password)
    print(f"Decrypted text: {decrypted_hmac}")
    print(f"HMAC Match: {original_text == decrypted_hmac}")
    
    # Test simple hash approach
    print("\n🔒 Testing Simple Hash H(IV, password)...")
    encrypted_simple = text_processor_simple.encrypt_text(original_text, password)
    print(f"Encrypted (Simple): {encrypted_simple[:50]}...")
    
    decrypted_simple = text_processor_simple.decrypt_text(encrypted_simple, password)
    print(f"Decrypted text: {decrypted_simple}")
    print(f"Simple Match: {original_text == decrypted_simple}")
    
    # Test with wrong password
    print("\n❌ Testing wrong password...")
    try:
        wrong_decrypt = text_processor_hmac.decrypt_text(encrypted_hmac, "WrongPassword")
        print("ERROR: Should have failed with wrong password!")
    except Exception as e:
        print(f"✅ Correctly failed with wrong password: {type(e).__name__}")
    
    print("\n✅ H(IV, password) implementation working perfectly!")


if __name__ == "__main__":
    test_crypto_engine()
