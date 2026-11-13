"""Sicherung der Datenbank: alle Einstellungen, Löschgruppen, Quellen, Regeln, Benutzer und Protokolle in einer ZIP-Datei."""
import datetime as dt
import io
import os
import re
import sqlite3
import tempfile
import zipfile

from . import db as m
from .version import VERSION

DIR = os.path.join(m.DATA_DIR, "backups")
KEEP = int(os.environ.get("BACKUP_KEEP", "14"))        # so viele Sicherungen bleiben auf dem Server liegen
AUTO_HOURS = int(os.environ.get("BACKUP_HOURS", "24"))  # Abstand der automatischen Sicherung, 0 = aus
NAME = re.compile(r"^divera-gateway-\d{8}-\d{6}(-auto)?\.zip$")

INFO = """DIVERA Gateway – Sicherung
Erstellt: {stamp} (UTC), Version {version}

Inhalt
  gateway.db   Datenbank mit allen Einstellungen, Löschgruppen, Quellen, Regeln, Benutzern und Protokollen
{key_line}
Wichtig
  Accesskeys und Passwörter der Postfächer liegen verschlüsselt in der Datenbank. Lesbar sind sie nur mit dem
  SECRET_KEY aus /etc/divera-gateway.env. {key_hint}

Wiederherstellen (auf dem Proxmox-Host, <CTID> ist die Nummer des Containers)
  1. Diese ZIP-Datei in den Container legen, z. B. nach /root/sicherung.zip
  2. pct exec <CTID> -- systemctl stop divera-gateway
  3. pct exec <CTID> -- python3 -m zipfile -e /root/sicherung.zip /root/sicherung
  4. pct exec <CTID> -- bash -c 'rm -f /var/lib/divera-gateway/gateway.db-wal /var/lib/divera-gateway/gateway.db-shm'
  5. pct exec <CTID> -- install -o divera-gw -g divera-gw -m 600 /root/sicherung/gateway.db /var/lib/divera-gateway/gateway.db
  6. Auf einem neuen Container zusätzlich den SECRET_KEY in /etc/divera-gateway.env auf den alten Wert setzen
  7. pct exec <CTID> -- systemctl start divera-gateway
"""


def _snapshot() -> bytes:
    """Ein in sich stimmiger Abzug der laufenden Datenbank (SQLite-Sicherungsfunktion, auch im WAL-Betrieb sicher)."""
    handle, path = tempfile.mkstemp(suffix=".db", dir=m.DATA_DIR)
    os.close(handle)
    try:
        source = sqlite3.connect(os.path.join(m.DATA_DIR, "gateway.db"), timeout=30)
        target = sqlite3.connect(path)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        with open(path, "rb") as file:
            return file.read()
    finally:
        os.remove(path)


def build(with_key: bool = False) -> tuple[str, bytes]:
    """Erzeugt die ZIP-Datei im Speicher. Gibt Dateinamen und Inhalt zurück."""
    now = dt.datetime.now(dt.timezone.utc)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("gateway.db", _snapshot())
        if with_key:
            archive.writestr("secret.env", f"SECRET_KEY={os.environ.get('SECRET_KEY', '')}\n")
        archive.writestr("LIESMICH.txt", INFO.format(
            stamp=now.strftime("%d.%m.%Y %H:%M"), version=VERSION,
            key_line="  secret.env   der SECRET_KEY dieses Gateways\n" if with_key else "",
            key_hint=("Er liegt dieser Sicherung als secret.env bei: Wer die Datei hat, kann alle Zugangsdaten lesen. Sicher aufbewahren."
                      if with_key else "Er ist NICHT in dieser Sicherung. Bewahre ihn getrennt auf, sonst sind die Zugangsdaten nach "
                                       "einem Verlust des Containers neu einzutragen.")))
    return f"divera-gateway-{now.strftime('%Y%m%d-%H%M%S')}.zip", buffer.getvalue()


def listing() -> list[dict]:
    if not os.path.isdir(DIR):
        return []
    items = []
    for name in sorted((n for n in os.listdir(DIR) if NAME.match(n)), reverse=True):
        stat = os.stat(os.path.join(DIR, name))
        items.append({"name": name, "size": stat.st_size, "auto": name.endswith("-auto.zip"),
                      "ts": dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc).replace(tzinfo=None)})
    return items


def store(auto: bool = False) -> str:
    """Legt eine Sicherung im Datenverzeichnis ab (ohne SECRET_KEY) und räumt alte weg. Gibt den Dateinamen zurück."""
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    name, data = build()
    if auto:
        name = name.replace(".zip", "-auto.zip")
    path = os.path.join(DIR, name)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as file:
        file.write(data)
    for old in listing()[KEEP:]:
        os.remove(os.path.join(DIR, old["name"]))
    return name


def path_of(name: str) -> str | None:
    """Pfad einer vorhandenen Sicherung; None bei unbekanntem oder unzulässigem Namen."""
    path = os.path.join(DIR, name)
    return path if NAME.match(name or "") and os.path.isfile(path) else None


def auto_due() -> bool:
    if AUTO_HOURS <= 0:
        return False
    items = listing()
    return not items or (m.utcnow() - items[0]["ts"]).total_seconds() >= AUTO_HOURS * 3600
