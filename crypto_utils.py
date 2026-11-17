from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
HMAC_SIZE = 32


# -----------------PKCS#7 Padding

def pkcs7_pad(data: bytes):
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([pad_len] * pad_len)
    return data + padding

def pkcs7_unpad(data: bytes):
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded length")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding value")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")

    return data[:-pad_len]


# -----------------AES-128

def aes_encrypt(key: bytes, iv: bytes, plaintext: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


# -----------------HMAC

def hmac_compute(key: bytes, data: bytes):
    h = HMAC.new(key, data, digestmod=SHA256)
    return h.digest()

def hmac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    h = HMAC.new(key, data, digestmod=SHA256)
    try:
        h.verify(tag)
        return True
    except ValueError:
        return False

# -----------------Random number generator

def generate_num():
    return get_random_bytes(16)


# -----------------Encrypt-then-MAC

def encrypt_then_mac(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes:
    iv = generate_num()
    ciphertext = aes_encrypt(enc_key, iv, pkcs7_pad(plaintext))
    tag = hmac_compute(mac_key, iv + ciphertext)
    return iv + ciphertext + tag

def verify_then_decrypt(enc_key: bytes, mac_key: bytes, message: bytes) -> bytes:
    if len(message) < 2 * BLOCK_SIZE + HMAC_SIZE:
        raise ValueError("Message too short")

    iv = message[:BLOCK_SIZE]
    ciphertext = message[BLOCK_SIZE:-HMAC_SIZE]
    tag = message[-HMAC_SIZE:]

    if not hmac_verify(mac_key, iv + ciphertext, tag):
        raise ValueError("Authentication failed")

    return pkcs7_unpad(aes_decrypt(enc_key, iv, ciphertext))
