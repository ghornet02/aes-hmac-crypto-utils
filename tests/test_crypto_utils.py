import pytest

from crypto_utils import (
    BLOCK_SIZE,
    HMAC_SIZE,
    aes_decrypt,
    aes_encrypt,
    encrypt_then_mac,
    generate_num,
    hmac_compute,
    hmac_verify,
    pkcs7_pad,
    pkcs7_unpad,
    verify_then_decrypt,
)

ENC_KEY = bytes(range(16))
MAC_KEY = bytes(range(16, 48))


# PKCS#7

@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 100])
def test_pad_round_trip(length):
    data = bytes([7]) * length
    padded = pkcs7_pad(data)
    assert len(padded) % BLOCK_SIZE == 0
    assert len(padded) > len(data)
    assert pkcs7_unpad(padded) == data


def test_full_block_gets_extra_block():
    assert pkcs7_pad(b"A" * 16) == b"A" * 16 + bytes([16]) * 16


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"A" * 15,
        b"A" * 15 + b"\x00",
        b"A" * 15 + b"\x11",
        b"A" * 14 + b"\x01\x02",
    ],
)
def test_unpad_rejects_bad_padding(bad):
    with pytest.raises(ValueError):
        pkcs7_unpad(bad)


# AES-128-CBC (NIST SP 800-38A, F.2.1)

def test_aes_cbc_known_answer():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")

    assert aes_encrypt(key, iv, plaintext) == expected
    assert aes_decrypt(key, iv, expected) == plaintext


# HMAC-SHA256 (RFC 4231, test case 2)

def test_hmac_known_answer():
    tag = hmac_compute(b"Jefe", b"what do ya want for nothing?")
    assert tag.hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_hmac_verify():
    tag = hmac_compute(MAC_KEY, b"message")
    assert hmac_verify(MAC_KEY, b"message", tag)
    assert not hmac_verify(MAC_KEY, b"messagf", tag)
    assert not hmac_verify(b"other key", b"message", tag)


def test_random_bytes():
    a, b = generate_num(), generate_num()
    assert len(a) == 16
    assert a != b


# Encrypt-then-MAC

@pytest.mark.parametrize("plaintext", [b"", b"hi", b"exactly 16 bytes", b"x" * 1000])
def test_round_trip(plaintext):
    message = encrypt_then_mac(ENC_KEY, MAC_KEY, plaintext)
    assert verify_then_decrypt(ENC_KEY, MAC_KEY, message) == plaintext


def test_message_layout():
    message = encrypt_then_mac(ENC_KEY, MAC_KEY, b"hello")
    assert len(message) == BLOCK_SIZE + BLOCK_SIZE + HMAC_SIZE


def test_fresh_iv_each_time():
    a = encrypt_then_mac(ENC_KEY, MAC_KEY, b"same text")
    b = encrypt_then_mac(ENC_KEY, MAC_KEY, b"same text")
    assert a != b


@pytest.mark.parametrize("index", [0, BLOCK_SIZE, -1])
def test_any_flipped_bit_is_rejected(index):
    message = bytearray(encrypt_then_mac(ENC_KEY, MAC_KEY, b"transfer 100 to bob"))
    message[index] ^= 0x01
    with pytest.raises(ValueError, match="Authentication failed"):
        verify_then_decrypt(ENC_KEY, MAC_KEY, bytes(message))


def test_wrong_mac_key_is_rejected():
    message = encrypt_then_mac(ENC_KEY, MAC_KEY, b"secret")
    with pytest.raises(ValueError, match="Authentication failed"):
        verify_then_decrypt(ENC_KEY, b"\x00" * 32, message)


def test_short_message_is_rejected():
    with pytest.raises(ValueError, match="too short"):
        verify_then_decrypt(ENC_KEY, MAC_KEY, b"\x00" * 40)
