import os
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Securely derive AES key from environment variable
MASTER_KEY = os.getenv("MASTER_KEY", "default_master_key")
AES_KEY = hashlib.sha256(MASTER_KEY.encode()).digest()

# HMAC key
HMAC_MASTER = os.getenv("HMAC_MASTER", "default_hmac_key")
HMAC_KEY = hashlib.sha256(HMAC_MASTER.encode()).digest()


def encrypt_text(plain_text):
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode()
    }


def decrypt_text(ciphertext, nonce, tag):
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=base64.b64decode(nonce))

    plaintext = cipher.decrypt_and_verify(
        base64.b64decode(ciphertext),
        base64.b64decode(tag)
    )

    return plaintext.decode()


def generate_token(word):
    return hmac.new(HMAC_KEY, word.encode(), hashlib.sha256).hexdigest()


def generate_ngrams(text, n=3):
    text = text.lower()
    return [text[i:i+n] for i in range(len(text)-n+1)]