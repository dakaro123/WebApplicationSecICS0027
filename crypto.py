import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_vault_key(master_password, salt):
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )


def encrypt_entry(key, username, password, notes):
    data = {
        "username": username,
        "password": password,
        "notes": notes
    }

    plaintext = json.dumps(data).encode("utf-8")

    nonce = os.urandom(12)

    aes = AESGCM(key)
    encrypted_data = aes.encrypt(nonce, plaintext, None)

    return encrypted_data, nonce


def decrypt_entry(key, encrypted_data, nonce):
    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        encrypted_data,
        None
    )

    return json.loads(plaintext.decode("utf-8"))