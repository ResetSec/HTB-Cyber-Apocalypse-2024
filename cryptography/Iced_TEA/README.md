solved by greysneakthief

**challenge**:

```python
import os
from secret import FLAG
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum

class Mode(Enum):
    ECB = 0x01
    CBC = 0x02

class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))

    def encrypt(self, msg):
        msg = pad(msg, self.BLOCK_SIZE//8)
        blocks = [msg[i:i+self.BLOCK_SIZE//8] for i in range(0, len(msg), self.BLOCK_SIZE//8)]
        
        ct = b''
        if self.mode == Mode.ECB:
            for pt in blocks:
                ct += self.encrypt_block(pt)
        elif self.mode == Mode.CBC:
            X = self.IV
            for pt in blocks:
                enc_block = self.encrypt_block(self._xor(X, pt))
                ct += enc_block
                X = enc_block
        return ct

    def encrypt_block(self, msg):
        m0 = b2l(msg[:4])
        m1 = b2l(msg[4:])
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1

        s = 0
        for i in range(32):
            s += self.DELTA
            m0 += ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            m1 += ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1) # m = m0 || m1

        return l2b(m)



if __name__ == '__main__':
    KEY = os.urandom(16)
    cipher = Cipher(KEY)
    ct = cipher.encrypt(FLAG)
    with open('output.txt', 'w') as f:
        f.write(f'Key : {KEY.hex()}\nCiphertext : {ct.hex()}')
```

**output**:
[output.txt](./output.txt)


First step was to determine what algorithm we're looking at, and since **TEA** is a **symmetric algorithm** it simplifies decoding a bit. 
Being Canadian I instantly realized the hint was referring to the **blocking function** - igloo building is in my blood (perhaps not as 'mystical' as the description hint), so did some referencing to block ciphers and **TEA matched**...just like the name of the challenge.

Since it's a White-Box situation, we have the code and know implementation for cryptographic primitives. We even have how it produces an initialization vector, a static delta, how it does *Feistel* rounds, what sorts of blocking it does, and the key.

Having all of these elements means that it is just a matter of reversing the process symmetrically for each portion. Some of these features appear to be intentionally insecurely or haphazardly implemented here? Idk, I am a mere script kiddie but a static key schedule seems really insecure.

Here's the solve script:

```python
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long as b2l, long_to_bytes as l2b
from enum import Enum
import os
class Mode(Enum):
    ECB = 0x01
    CBC = 0x02
class Cipher:
    def __init__(self, key, iv=None):
        self.BLOCK_SIZE = 64
        self.KEY = [b2l(key[i:i+self.BLOCK_SIZE//16]) for i in range(0, len(key), self.BLOCK_SIZE//16)]
        self.DELTA = 0x9e3779b9
        self.IV = iv
        if self.IV:
            self.mode = Mode.CBC
        else:
            self.mode = Mode.ECB
    
    def _xor(self, a, b):
        return b''.join(bytes([_a ^ _b]) for _a, _b in zip(a, b))
    def decrypt(self, ct):
        blocks = [ct[i:i+self.BLOCK_SIZE//8] for i in range(0, len(ct), self.BLOCK_SIZE//8)]
        
        msg = b''
        if self.mode == Mode.ECB:
            for ct_block in blocks:
                msg += self.decrypt_block(ct_block)
        elif self.mode == Mode.CBC:
            X = self.IV
            for ct_block in blocks:
                dec_block = self.decrypt_block(ct_block)
                msg += self._xor(X, dec_block)
                X = ct_block
        return unpad(msg, self.BLOCK_SIZE//8)
    def decrypt_block(self, ct_block):
        c = b2l(ct_block)
        m0 = c >> (self.BLOCK_SIZE//2)
        m1 = c & ((1 << (self.BLOCK_SIZE//2)) - 1)
        K = self.KEY
        msk = (1 << (self.BLOCK_SIZE//2)) - 1
        s = self.DELTA * 32
        for i in range(32):
            m1 -= ((m0 << 4) + K[2]) ^ (m0 + s) ^ ((m0 >> 5) + K[3])
            m1 &= msk
            m0 -= ((m1 << 4) + K[0]) ^ (m1 + s) ^ ((m1 >> 5) + K[1])
            m0 &= msk
            s -= self.DELTA
        
        m = ((m0 << (self.BLOCK_SIZE//2)) + m1) & ((1 << self.BLOCK_SIZE) - 1)
        return l2b(m)
# Read the key from input
KEY = bytes.fromhex("850c1413787c389e0b34437a6828a1b2")
# Read the ciphertext from the file
with open('output.txt', 'r') as f:
    lines = f.readlines()
    ct_hex = lines[1].split(': ')[1].strip()
    ciphertext = bytes.fromhex(ct_hex)
# Decrypt the ciphertext
cipher = Cipher(KEY)
plaintext = cipher.decrypt(ciphertext)
# Print the decrypted plaintext
print("Decrypted plaintext:", plaintext.decode())
 ```