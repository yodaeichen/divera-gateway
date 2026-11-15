"""Push-Meldungen an Handy und Rechner (Web Push nach RFC 8030, 8291 und 8292), ohne zusätzliche Bibliothek.

Der Inhalt wird für jedes Gerät einzeln verschlüsselt; der Push-Dienst des Browsers (Google, Apple, Mozilla, Microsoft)
reicht ihn nur durch und kann ihn nicht lesen.
"""
import base64
import hashlib
import json
import os
import struct
import time
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select

from . import db as m
from . import mailer
from . import security as sec

# Nur an die Push-Dienste der Browser senden: die Adresse kommt vom Gerät des Benutzers und darf kein beliebiges Ziel sein.
ALLOWED_HOSTS = ("fcm.googleapis.com", ".push.apple.com", ".push.services.mozilla.com", ".notify.windows.com")
MAX_DEVICES = 10     # je Benutzer
TTL = 12 * 3600      # so lange hebt der Push-Dienst eine Meldung für ein ausgeschaltetes Gerät auf
GONE = (403, 404, 410)   # Gerät hat sich abgemeldet oder der Schlüssel passt nicht mehr: Eintrag entfernen
PROJECT_URL = "https://github.com/yodaeichen/divera-gateway"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    text = (text or "").strip().replace("+", "-").replace("/", "_")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def allowed_endpoint(endpoint: str) -> bool:
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return (parts.scheme == "https" and len(endpoint) <= 1000 and parts.port in (None, 443)
            and any(host == h or (h.startswith(".") and host.endswith(h)) for h in ALLOWED_HOSTS))


def valid_keys(p256dh: str, auth: str) -> bool:
    try:
        point, secret = unb64(p256dh), unb64(auth)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except Exception:
        return False
    return len(point) == 65 and len(secret) == 16


def endpoint_hash(endpoint: str) -> str:
    return hashlib.sha256(endpoint.encode()).hexdigest()


def _raw_public(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def server_key(db) -> ec.EllipticCurvePrivateKey:
    """Schlüsselpaar des Gateways, mit dem es sich bei den Push-Diensten ausweist. Entsteht beim ersten Gebrauch."""
    row = db.get(m.Setting, "push_private_key")
    if row and row.value:
        return ec.derive_private_key(int(sec.decrypt(row.value), 16), ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    row = row or m.Setting(key="push_private_key")
    row.value = sec.encrypt(format(key.private_numbers().private_value, "x"))
    db.add(row)
    db.commit()
    return key


def public_key(db) -> str:
    """Öffentlicher Schlüssel für den Browser (applicationServerKey)."""
    return b64(_raw_public(server_key(db)))


def contact(db) -> str:
    """Ansprechpartner für die Push-Dienste: die Absenderadresse des Gateways, sonst die Projektseite."""
    settings = mailer.load(db)
    return f"mailto:{settings['mail_from']}" if mailer.valid_address(settings["mail_from"]) else PROJECT_URL


def encrypt(plaintext: bytes, p256dh: bytes, auth: bytes) -> bytes:
    """Verschlüsselt eine Meldung für genau ein Gerät (aes128gcm nach RFC 8291, ein Datensatz)."""
    receiver = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
    sender = ec.generate_private_key(ec.SECP256R1())
    sender_public = _raw_public(sender)
    shared = sender.exchange(ec.ECDH(), receiver)
    ikm = HKDF(hashes.SHA256(), 32, auth, b"WebPush: info\x00" + p256dh + sender_public).derive(shared)
    salt = os.urandom(16)
    key = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    sealed = AESGCM(key).encrypt(nonce, plaintext + b"\x02", None)   # 0x02 kennzeichnet den letzten Datensatz
    return salt + struct.pack("!IB", 4096, len(sender_public)) + sender_public + sealed


def authorization(key: ec.EllipticCurvePrivateKey, endpoint: str, subject: str) -> str:
    """Ausweis gegenüber dem Push-Dienst (VAPID, RFC 8292): ein kurzlebiges, mit dem Gateway-Schlüssel signiertes Token."""
    parts = urlsplit(endpoint)
    claims = {"aud": f"{parts.scheme}://{parts.netloc}", "exp": int(time.time()) + 12 * 3600, "sub": subject}
    signing_input = (b64(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode()) + "."
                     + b64(json.dumps(claims, separators=(",", ":")).encode()))
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    token = signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"vapid t={token}, k={b64(_raw_public(key))}"


def post(endpoint: str, headers: dict, body: bytes) -> int:
    """Übergibt die verschlüsselte Meldung an den Push-Dienst und liefert dessen Statuscode. In Tests ersetzt."""
    return httpx.post(endpoint, headers=headers, content=body, timeout=10).status_code


def send(key: ec.EllipticCurvePrivateKey, subject: str, device: m.PushDevice, payload: dict) -> int:
    """Schickt eine Meldung an ein Gerät. Liefert den Statuscode des Push-Dienstes (201 = angenommen)."""
    endpoint = sec.decrypt(device.endpoint_enc)
    if not allowed_endpoint(endpoint):
        return 404
    body = encrypt(json.dumps(payload, ensure_ascii=False).encode(), unb64(device.p256dh), unb64(device.auth))
    headers = {"Authorization": authorization(key, endpoint, subject), "Content-Encoding": "aes128gcm",
               "Content-Type": "application/octet-stream", "TTL": str(TTL), "Urgency": "high"}
    return post(endpoint, headers, body)


def devices_of(db, user_id: int) -> list[m.PushDevice]:
    return list(db.scalars(select(m.PushDevice).where(m.PushDevice.user_id == user_id).order_by(m.PushDevice.id)))


def label_for(user_agent: str) -> str:
    """Kurze Bezeichnung des Geräts für die Liste unter „Mein Konto“, aus der Kennung des Browsers."""
    ua = user_agent or ""
    system = next((name for mark, name in (("iPhone", "iPhone"), ("iPad", "iPad"), ("Android", "Android"), ("Windows", "Windows"),
                                           ("Mac OS", "Mac"), ("Linux", "Linux")) if mark in ua), "Gerät")
    browser = next((name for mark, name in (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("SamsungBrowser/", "Samsung Internet"),
                                            ("Chrome/", "Chrome"), ("CriOS/", "Chrome"), ("Safari/", "Safari")) if mark in ua), "")
    return f"{system}, {browser}" if browser else system


def register(db, user: m.User, endpoint: str, p256dh: str, auth: str, user_agent: str) -> m.PushDevice:
    """Trägt ein Gerät ein. Meldet sich dasselbe Gerät erneut an (auch unter anderem Benutzer), wird der Eintrag übernommen."""
    if not allowed_endpoint(endpoint):
        raise ValueError("Dieser Push-Dienst wird nicht unterstützt.")
    if not valid_keys(p256dh, auth):
        raise ValueError("Die Schlüssel des Geräts sind ungültig.")
    digest = endpoint_hash(endpoint)
    device = db.scalar(select(m.PushDevice).where(m.PushDevice.endpoint_hash == digest))
    if device is None:
        if len(devices_of(db, user.id)) >= MAX_DEVICES:
            raise ValueError(f"Mehr als {MAX_DEVICES} Geräte je Benutzer sind nicht möglich. Bitte erst ein altes entfernen.")
        device = m.PushDevice(endpoint_hash=digest)
    device.user_id, device.endpoint_enc = user.id, sec.encrypt(endpoint)
    device.p256dh, device.auth, device.label = p256dh.strip(), auth.strip(), label_for(user_agent)[:120]
    db.add(device)
    db.commit()
    return device


def deliver(db, user_ids, payload_for) -> tuple[int, list[str]]:
    """Schickt jedem genannten Benutzer seine Meldung auf alle seine Geräte.

    payload_for(user_id) liefert den Inhalt. Abgemeldete Geräte werden entfernt. Gibt die Zahl der angenommenen
    Meldungen und die Liste der Probleme zurück.
    """
    devices = list(db.scalars(select(m.PushDevice).where(m.PushDevice.user_id.in_(list(user_ids)))))
    if not devices:
        return 0, []
    key, subject = server_key(db), contact(db)
    sent, problems = 0, []
    for device in devices:
        try:
            status = send(key, subject, device, payload_for(device.user_id))
        except Exception as exc:
            problems.append(f"{device.label}: {type(exc).__name__}: {exc}")
            continue
        if status in GONE:
            db.delete(device)
        elif 200 <= status < 300:
            device.last_ok = m.utcnow()
            sent += 1
        else:
            problems.append(f"{device.label}: HTTP {status}")
    db.commit()
    return sent, problems
