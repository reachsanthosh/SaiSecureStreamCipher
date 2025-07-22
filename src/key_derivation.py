"""
Password-Based Key Derivation Functions

This module implements H(IV, password) key derivation for deriving cryptographic keys from passwords.
Uses hand-implemented approaches with SHA-256 and HMAC for educational transparency.
"""

import hashlib
import hmac
import os


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password strength and provide feedback.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_strong: bool, suggestions: list[str])
    """
    suggestions = []
    is_strong = True
    
    if len(password) < 12:
        suggestions.append("Use at least 12 characters")
        is_strong = False
    
    if not any(c.isupper() for c in password):
        suggestions.append("Include at least one uppercase letter")
        is_strong = False
    
    if not any(c.islower() for c in password):
        suggestions.append("Include at least one lowercase letter")
        is_strong = False
    
    if not any(c.isdigit() for c in password):
        suggestions.append("Include at least one number")
        is_strong = False
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        suggestions.append("Include at least one special character")
        is_strong = False
    
    # Check for common patterns
    common_patterns = ['123', 'abc', 'password', 'admin', 'user']
    if any(pattern in password.lower() for pattern in common_patterns):
        suggestions.append("Avoid common patterns and dictionary words")
        is_strong = False
    
    if not suggestions:
        suggestions.append("Strong password!")
    
    return is_strong, suggestions


class SimpleKeyDerivation:
    """Hand-implemented key derivation using H(IV, password) approach."""
    
    @staticmethod
    def derive_key_from_iv(password: str, iv: bytes) -> bytes:
        """
        Derive a key using H(IV, password) approach - fully hand-implemented.
        
        This implements your original suggestion: key = H(IV, password)
        
        Args:
            password: User's password string
            iv: Initialization Vector (nonce) - 12 bytes
            
        Returns:
            32-byte key derived from IV and password
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Combine IV and password: IV || password
        combined = iv + password
        
        # Hash the combination using SHA-256
        key = hashlib.sha256(combined).digest()
        
        return key  # 32 bytes for SaiSecureStreamCipher
    
    @staticmethod
    def derive_key_hmac(password: str, iv: bytes) -> bytes:
        """
        Enhanced version using HMAC for better security.
        
        Args:
            password: User's password string
            iv: Initialization Vector (nonce) - 12 bytes
            
        Returns:
            32-byte key derived using HMAC(IV, password)
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Use HMAC with IV as key and password as message
        # This is more secure than simple concatenation
        key = hmac.new(iv, password, hashlib.sha256).digest()
        
        return key  # 32 bytes


# Test function
def test_simple_key_derivation():
    """Test the hand-implemented H(IV, password) approach."""
    print("🔑 Testing Hand-Implemented Key Derivation H(IV, password)")
    print("=" * 60)
    
    password = "MySecurePassword123!"
    iv = os.urandom(12)  # 12 bytes IV (nonce)
    
    print(f"Password: {password}")
    print(f"IV (nonce): {iv.hex()}")
    
    # Test simple hash approach
    key1 = SimpleKeyDerivation.derive_key_from_iv(password, iv)
    print(f"Key (SHA256): {key1.hex()}")
    
    # Test HMAC approach
    key2 = SimpleKeyDerivation.derive_key_hmac(password, iv)
    print(f"Key (HMAC): {key2.hex()}")
    
    # Test that same inputs produce same key
    key1_again = SimpleKeyDerivation.derive_key_from_iv(password, iv)
    key2_again = SimpleKeyDerivation.derive_key_hmac(password, iv)
    
    print(f"SHA256 reproducible: {key1 == key1_again}")
    print(f"HMAC reproducible: {key2 == key2_again}")
    
    # Test that different IV produces different key
    different_iv = os.urandom(12)
    key3 = SimpleKeyDerivation.derive_key_from_iv(password, different_iv)
    print(f"Different IV gives different key: {key1 != key3}")
    
    # Test password validation
    is_strong, suggestions = validate_password_strength(password)
    print(f"Password strong: {is_strong}")
    print(f"Suggestions: {suggestions}")


if __name__ == "__main__":
    test_simple_key_derivation()
    test_simple_key_derivation()
