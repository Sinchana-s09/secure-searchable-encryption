from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hmac
import hashlib

AES_KEY = b"12345678901234567890123456789012"   

HMAC_KEY = b"supperr_key"

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

    plain_text = cipher.decrypt_and_verify(
        base64.b64decode(ciphertext),
        base64.b64decode(tag)
    )

    return plain_text.decode()

def generate_token(word):
    return hmac.new(HMAC_KEY, word.encode(), hashlib.sha256).hexdigest()