"""PBKDF2 - Password-Based Key Derication Function utilities."""
import binascii
import hmac
import struct
import sys
from hashlib import sha256

from six import text_type


def binary_type(string):
    """Return binary_type of string."""
    if sys.version_info[0] == 2:
        return string

    return string.encode('utf-8')


def xorbytes(string_a, string_b):
    """XOR all bytes in a string"""
    if sys.version_info[0] == 2:
        return ''.join([chr(ord(x) ^ ord(y))
                        for (x, y) in zip(string_a, string_b)])

    return bytes([x ^ y for (x, y) in zip(string_a, string_b)])


def prf(hsh, data):
    """Internal hash update for pbkdf2/hmac-sha256"""
    hshm = hsh.copy()
    hshm.update(data)
    return hshm.digest()


def pbkdf2(password, salt, rounds, length):
    """PBKDF2-SHA256 password derivation."""
    key = b''
    hash_object = hmac.new(password, None, sha256)

    if isinstance(salt, text_type):
        salt = binary_type(salt)

    for block in range(0, int((length + 31) / 32)):
        index = hash_value = prf(
            hash_object,
            salt + struct.pack('>I', block + 1)
        )

        for _ in range(1, rounds):
            hash_value = prf(hash_object, hash_value)
            index = xorbytes(index, hash_value)

        key = key + index

    return binascii.hexlify(key[0:length])
