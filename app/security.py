"""Passwort-Hashing und Verschlüsselung gespeicherter Zugangsdaten."""
import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken

SECRET_KEY = os.environ.get("SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY fehlt oder ist kürzer als 32 Zeichen (siehe .env.example).")


def _derive(purpose: str) -> bytes:
    return hashlib.sha256(f"{purpose}:{SECRET_KEY}".encode()).digest()


SESSION_SECRET = base64.urlsafe_b64encode(_derive("session")).decode()
_fernet = Fernet(base64.urlsafe_b64encode(_derive("enc")))


def encrypt(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode() if text else ""


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet.decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Entschlüsselung fehlgeschlagen. Wurde SECRET_KEY geändert?") from exc


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, digest_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except ValueError:
        return False
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(digest, expected)
