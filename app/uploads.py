"""Zwischenablage für Dateien, die beim Senden von Hand angehängt werden.

Zwischen Formular und Bestätigungsseite kann der Browser keine Datei weiterreichen. Deshalb liegt sie so lange im
Datenverzeichnis, gebunden an den Benutzer, und wird nach dem Senden oder spätestens nach einem Tag gelöscht.
"""
import datetime as dt
import json
import os
import re
import secrets
import shutil
import time

from . import db as m

DIR = os.path.join(m.DATA_DIR, "uploads")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
KEEP_HOURS = 24


def clean_name(name: str) -> str:
    """Nur der Dateiname, ohne Pfad und ohne Zeichen, die Probleme machen."""
    name = os.path.basename(str(name or "").replace("\\", "/")).strip()
    name = re.sub(r"[\x00-\x1f<>:\"/\\|?*]", "_", name)
    return (name or "Anhang")[:200]


def _folder(token: str) -> str | None:
    return os.path.join(DIR, token) if _TOKEN.match(token or "") else None


def save(files: list[dict], user_id: int) -> str:
    """Legt die Dateien ab und gibt das Kennzeichen zurück, mit dem sie wieder geholt werden."""
    token = secrets.token_urlsafe(18)
    folder = os.path.join(DIR, token)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    meta = []
    for number, item in enumerate(files):
        with open(os.open(os.path.join(folder, str(number)), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as out:
            out.write(item["data"])
        meta.append({"name": clean_name(item["name"]), "type": item.get("type") or "application/octet-stream", "size": len(item["data"])})
    with open(os.path.join(folder, "meta.json"), "w", encoding="utf-8") as out:
        json.dump({"user": user_id, "files": meta}, out)
    return token


def load(token: str, user_id: int) -> list[dict]:
    """Die abgelegten Dateien; leer, wenn das Kennzeichen unbekannt ist oder einem anderen Benutzer gehört."""
    folder = _folder(token)
    if not folder or not os.path.isfile(os.path.join(folder, "meta.json")):
        return []
    with open(os.path.join(folder, "meta.json"), encoding="utf-8") as src:
        meta = json.load(src)
    if meta.get("user") != user_id:
        return []
    found = []
    for number, item in enumerate(meta.get("files", [])):
        with open(os.path.join(folder, str(number)), "rb") as src:
            found.append(dict(item, data=src.read(), inline=False))
    return found


def remove(token: str):
    folder = _folder(token)
    if folder and os.path.isdir(folder):
        shutil.rmtree(folder, ignore_errors=True)


def prune():
    """Löscht liegengebliebene Dateien, etwa wenn jemand die Bestätigung nie abgeschickt hat."""
    if not os.path.isdir(DIR):
        return
    limit = time.time() - KEEP_HOURS * 3600
    for name in os.listdir(DIR):
        path = os.path.join(DIR, name)
        if os.path.isdir(path) and os.path.getmtime(path) < limit:
            shutil.rmtree(path, ignore_errors=True)
