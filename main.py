#!/usr/bin/env python3
"""
PassAuthStreamCipher - Secure Password-Based File and Text Encryption

Main entry point for the PassAuthStreamCipher application.
This tool provides secure encryption and decryption using:
- SaiSecureStreamCipher (hand-implemented stream cipher)
- H(IV, password) key derivation
- Password-based authentication
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

try:
    from src.gui import main
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure all files are in the correct directories")
    sys.exit(1)

if __name__ == "__main__":
    print("Starting PassAuthStreamCipher...")
    print("Secure encryption with SaiSecureStreamCipher and H(IV, password)")
    print("=" * 60)
    main()
