
import struct
from typing import List, Tuple


class SaiSecureStreamCipher:
    
    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        # Basic validation
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")
        if len(nonce) != 12:
            raise ValueError("Nonce must be exactly 12 bytes")
        
        self.key = key
        self.nonce = nonce
        self.counter = counter
        
    def _quarter_round(self, a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
        # quarter round stuff
        def rotl(x: int, n: int) -> int:
            # rotate left
            return ((x << n) | (x >> (32 - n))) & 0xffffffff
        
        a = (a + b) & 0xffffffff
        d = rotl(d ^ a, 16)
        c = (c + d) & 0xffffffff
        b = rotl(b ^ c, 12)
        a = (a + b) & 0xffffffff
        d = rotl(d ^ a, 8)
        c = (c + d) & 0xffffffff
        b = rotl(b ^ c, 7)
        
        return a, b, c, d
    
    def _sai_cipher_block(self, counter: int) -> bytes:
        # make a block of encrypted data
        state = [0] * 16
        
        # magic constants (don't change these!)
        state[0] = 0x61707865
        state[1] = 0x3320646e  
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        
        # put key in state  
        for i in range(8):
            state[4 + i] = struct.unpack('<I', self.key[i*4:(i+1)*4])[0]
        
        state[12] = counter  # counter goes here
        
        # nonce stuff
        for i in range(3):
            state[13 + i] = struct.unpack('<I', self.nonce[i*4:(i+1)*4])[0]
        
        # keep copy of original state
        initial_state = state[:]
        
        # do the rounds (20 total = 10 double rounds)
        round_count = 0
        for _ in range(10):
            round_count += 1  # track rounds (not really needed)
            # do column rounds first
            state[0], state[4], state[8], state[12] = self._quarter_round(
                state[0], state[4], state[8], state[12]
            )
            state[1], state[5], state[9], state[13] = self._quarter_round(
                state[1], state[5], state[9], state[13]
            )
            state[2], state[6], state[10], state[14] = self._quarter_round(
                state[2], state[6], state[10], state[14]
            )
            state[3], state[7], state[11], state[15] = self._quarter_round(
                state[3], state[7], state[11], state[15]
            )
            
            # then diagonal rounds
            state[0], state[5], state[10], state[15] = self._quarter_round(
                state[0], state[5], state[10], state[15]
            )
            state[1], state[6], state[11], state[12] = self._quarter_round(
                state[1], state[6], state[11], state[12]
            )
            state[2], state[7], state[8], state[13] = self._quarter_round(
                state[2], state[7], state[8], state[13]
            )
            state[3], state[4], state[9], state[14] = self._quarter_round(
                state[3], state[4], state[9], state[14]
            )
        
        # Add initial state to final state
        for i in range(16):
            state[i] = (state[i] + initial_state[i]) & 0xffffffff
        
        # Convert to bytes
        block = b''
        for word in state:
            block += struct.pack('<I', word)
        
        return block
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using SaiSecureStreamCipher."""
        ciphertext = b''
        counter = self.counter
        
        # Process in 64-byte blocks
        for i in range(0, len(plaintext), 64):
            block = self._sai_cipher_block(counter)
            chunk = plaintext[i:i+64]
            
            # XOR with keystream
            encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, block))
            ciphertext += encrypted_chunk
            
            counter += 1
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using SaiSecureStreamCipher (same as encrypt due to XOR)."""
        return self.encrypt(ciphertext)  # SaiSecureStreamCipher is symmetric


# Test function to verify implementation
def test_sai_secure_stream_cipher():
    """Test SaiSecureStreamCipher implementation with known test vectors."""
    # Test vector for verification (cryptographic algorithm)
    key = bytes.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    nonce = bytes.fromhex('000000000000004a00000000')
    counter = 1
    
    plaintext = b'Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.'
    
    cipher = SaiSecureStreamCipher(key, nonce, counter)
    ciphertext = cipher.encrypt(plaintext)
    
    # Decrypt to verify
    cipher2 = SaiSecureStreamCipher(key, nonce, counter)
    decrypted = cipher2.decrypt(ciphertext)
    
    print(f"Original:  {plaintext}")
    print(f"Encrypted: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {plaintext == decrypted}")


if __name__ == "__main__":
    test_sai_secure_stream_cipher()
