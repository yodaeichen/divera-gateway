"""Systemprotokoll: Fehler und Ereignisse des Gateways selbst (Anmeldungen, Verbindungsprobleme, Änderungen)."""
import logging

from . import db as m

log = logging.getLogger("gateway.syslog")
LEVELS = [("fehler", "Fehler"), ("warnung", "Warnung"), ("info", "Hinweis")]
CATEGORIES = ["Anmeldung", "Quelle", "DIVERA", "E-Mail-Versand", "Benutzer", "Löschgruppe", "Einstellungen", "Berechtigung", "Sicherung", "Benachrichtigung", "System"]


def event(level: str, category: str, message: str, detail: str = "", tenant: m.Tenant | None = None, actor: str = "") -> m.SystemEvent:
    return m.SystemEvent(level=level, category=category, message=message[:300], detail=str(detail)[:2000], actor=actor[:80],
                         tenant_id=tenant.id if tenant is not None else None, tenant_name=tenant.name if tenant is not None else "")


def note(db, level: str, category: str, message: str, detail: str = "", tenant: m.Tenant | None = None, actor: str = ""):
    """Hängt einen Eintrag an eine laufende Datenbanksitzung; gespeichert wird er mit deren nächstem commit."""
    db.add(event(level, category, message, detail, tenant, actor))


def record(level: str, category: str, message: str, detail: str = "", tenant: m.Tenant | None = None, actor: str = ""):
    """Schreibt einen Eintrag sofort über eine eigene Verbindung. Schlägt nie fehl, damit das Protokollieren nichts zerstört."""
    try:
        with m.LogSession() as db:
            db.add(event(level, category, message, detail, tenant, actor))
            db.commit()
    except Exception:
        log.exception("Systemprotokoll konnte nicht geschrieben werden: %s", message)
