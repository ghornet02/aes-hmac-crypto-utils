# AES-HMAC Crypto Utils

A small Python module for authenticated encryption, using AES-128-CBC with HMAC-SHA256 in an encrypt-then-MAC scheme. PKCS#7 padding is written by hand rather than taken from a library, and the module is built on [PyCryptodome](https://www.pycryptodome.org/).

## What's included

| Function | Purpose |
|---|---|
| `pkcs7_pad(data)` / `pkcs7_unpad(data)` | PKCS#7 padding to 16-byte blocks. Unpadding checks the length, the pad value and every pad byte |
| `aes_encrypt(key, iv, data)` / `aes_decrypt(key, iv, data)` | AES-128 in CBC mode, on input that's already padded |
| `hmac_compute(key, data)` / `hmac_verify(key, data, tag)` | HMAC-SHA256. Verification is constant-time |
| `generate_num()` | 16 cryptographically secure random bytes, used for IVs and keys |
| `encrypt_then_mac(enc_key, mac_key, plaintext)` | Pads, encrypts with a fresh random IV, and tags `IV + ciphertext` |
| `verify_then_decrypt(enc_key, mac_key, message)` | Checks the tag before decrypting, then unpads |

A message from `encrypt_then_mac` is laid out like this:

```
| IV (16 bytes) | ciphertext (multiple of 16 bytes) | HMAC-SHA256 tag (32 bytes) |
```

## Usage

```python
from crypto_utils import encrypt_then_mac, verify_then_decrypt, generate_num

enc_key = generate_num()   # 16-byte AES key
mac_key = generate_num()   # separate key for the MAC

message = encrypt_then_mac(enc_key, mac_key, b"meet at noon")
plaintext = verify_then_decrypt(enc_key, mac_key, message)   # b"meet at noon"
```

If the message has been changed in any way, `verify_then_decrypt` raises `ValueError("Authentication failed")` and doesn't decrypt anything.

## Design notes

- **Encrypt-then-MAC.** The tag covers the IV and the ciphertext, and it's checked before any decryption or unpadding. So an attacker can't use padding errors to learn anything about the plaintext (a padding-oracle attack).
- **Separate keys.** Encryption and authentication use independent keys.
- **Fresh IV per message.** Each message gets a new random IV, so encrypting the same plaintext twice gives different ciphertexts.

## Tests

```sh
pip install -r requirements.txt
pytest
```

The tests check AES and HMAC against published test vectors (NIST SP 800-38A F.2.1 and RFC 4231 test case 2). They also cover padding edge cases, malformed padding, round trips of different lengths, and tampering with the IV, the ciphertext and the tag.
