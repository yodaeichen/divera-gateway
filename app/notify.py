"""Benachrichtigungen per E-Mail: jeder Benutzer wählt unter „Mein Konto“, worüber er informiert werden will."""
import json
import logging

from sqlalchemy import func, select

from . import access, mailer, syslog
from . import db as m
from . import security as sec

log = logging.getLogger("gateway.notify")
INTERVAL = 60        # Sekunden zwischen zwei Durchläufen; was in dieser Zeit anfällt, kommt in einer Nachricht
MAX_LINES = 25       # so viele Ereignisse stehen höchstens in einer Nachricht
# Schlüssel, Bezeichnung, Erklärung, nur für Administratoren?
OPTIONS = [
    ("transfer", "Übergabe an DIVERA fehlgeschlagen",
     "DIVERA hat eine Meldung abgelehnt oder war nicht erreichbar. Betrifft automatische Regeln und von Hand Gesendetes.", False),
    ("source", "Störung beim Abruf eines Postfachs",
     "Ein Postfach lässt sich nicht mehr abrufen, zum Beispiel wegen abgelaufener Zugangsdaten. Du erfährst auch, wenn es wieder läuft.", False),
    ("system", "Fehler des Gateways selbst",
     "Alle übrigen Fehler aus dem Systemprotokoll: fehlgeschlagene Sicherung, Fehler im Hintergrunddienst, abgelehnte Schlüssel.", True),
]
SILENT = ("E-Mail-Versand", "Benachrichtigung")   # darüber wird nie per Mail berichtet, sonst meldet ein Mailfehler sich selbst


def chosen(user) -> list[str]:
    """Die gewählten Benachrichtigungen eines Benutzers, bereinigt um Unbekanntes und um das, was er nicht (mehr) darf."""
    try:
        picked = json.loads(user.notify or "[]")
    except ValueError:
        picked = []
    admin = access.perms_of(user)["users"] == 2
    return [key for key, _, _, admin_only in OPTIONS if key in picked and (admin or not admin_only)]


def available(user) -> list[tuple]:
    admin = access.perms_of(user)["users"] == 2
    return [option for option in OPTIONS if admin or not option[3]]


def _mark(db, key: str, value: int | None = None) -> int:
    """Liest oder setzt den Stand, bis zu welchem Eintrag schon benachrichtigt wurde."""
    row = db.get(m.Setting, key)
    if value is None:
        try:
            return int(sec.decrypt(row.value)) if row else -1
        except (ValueError, TypeError):
            return -1
    row = row or m.Setting(key=key)
    row.value = sec.encrypt(str(value))
    db.add(row)
    return value


def _stamp(ts) -> str:
    from .main import TZ   # spät laden: main bindet dieses Modul ein
    import datetime as dt
    return ts.replace(tzinfo=dt.timezone.utc).astimezone(TZ).strftime("%d.%m.%Y %H:%M")


def collect(db) -> dict[int, list[str]]:
    """Sammelt neue Ereignisse seit dem letzten Durchlauf und verteilt sie auf die Benutzer, die sie sehen wollen und dürfen."""
    top_log = db.scalar(select(func.max(m.Log.id))) or 0
    top_event = db.scalar(select(func.max(m.SystemEvent.id))) or 0
    seen_log, seen_event = _mark(db, "notify_log_id"), _mark(db, "notify_event_id")
    _mark(db, "notify_log_id", top_log)
    _mark(db, "notify_event_id", top_event)
    if seen_log < 0 or seen_event < 0:   # erster Lauf: nichts Altes nachmelden
        db.commit()
        return {}
    failed = db.scalars(select(m.Log).where(m.Log.id > seen_log, m.Log.id <= top_log, m.Log.status == "fehler").order_by(m.Log.id)).all()
    events = db.scalars(select(m.SystemEvent).where(m.SystemEvent.id > seen_event, m.SystemEvent.id <= top_event,
                                                    m.SystemEvent.category.notin_(SILENT)).order_by(m.SystemEvent.id)).all()
    events = [e for e in events if e.level == "fehler" or (e.category == "Quelle" and "funktioniert wieder" in e.message)]
    db.commit()
    result: dict[int, list[str]] = {}
    if not failed and not events:
        return result
    for user in db.scalars(select(m.User)):
        wants = chosen(user)
        if not wants or not mailer.valid_address(user.email):
            continue
        lines = []
        if "transfer" in wants:
            lines += [f"{_stamp(l.ts)}  Übergabe an DIVERA fehlgeschlagen ({l.tenant_name})\n    Betreff: {l.subject[:120]}\n    {l.detail[:300]}"
                      for l in failed if l.tenant_id is None or access.allowed(user, l.tenant_id)]
        for e in events:
            where = f" ({e.tenant_name})" if e.tenant_name else ""
            text = f"{_stamp(e.ts)}  {e.message}{where}" + (f"\n    {e.detail[:300]}" if e.detail else "")
            if e.category == "Quelle":
                if "source" in wants and (e.tenant_id is None or access.allowed(user, e.tenant_id)):
                    lines.append(text)
            elif "system" in wants:
                lines.append(text)
        if lines:
            result[user.id] = lines
    return result


def message(lines: list[str], base_url: str) -> tuple[str, str]:
    count = len(lines)
    subject = f"DIVERA Gateway: {count} {'Meldung' if count == 1 else 'Meldungen'}"
    more = f"\n… und {count - MAX_LINES} weitere, siehe Protokoll.\n" if count > MAX_LINES else ""
    body = ("Hallo,\n\ndas DIVERA Gateway meldet:\n\n" + "\n\n".join(lines[:MAX_LINES]) + "\n" + more
            + (f"\nProtokoll: {base_url}logs\n" if base_url else "")
            + "\nDu bekommst diese Nachricht, weil du sie unter „Mein Konto“ im Gateway eingeschaltet hast. Dort lässt sie sich auch abschalten.\n")
    return subject, body


def run() -> int:
    """Ein Durchlauf: neue Ereignisse einsammeln und je Benutzer eine Nachricht verschicken. Gibt die Zahl der Nachrichten zurück."""
    sent = 0
    with m.SessionLocal() as db:
        pending = collect(db)
        if not pending:
            return 0
        settings = mailer.load(db)
        if not mailer.configured(settings):
            return 0
        base = (settings.get("base_url") or "").rstrip("/")
        base = base + "/" if base else ""
        targets = {u.id: (u.username, u.email) for u in db.scalars(select(m.User).where(m.User.id.in_(pending)))}
    problems = []
    for uid, lines in pending.items():
        name, address = targets[uid]
        try:
            mailer.deliver(settings, address, *message(lines, base))
            sent += 1
        except Exception as exc:
            problems.append(f"{name}: {exc}")
    if problems:
        syslog.record("warnung", "Benachrichtigung", "Benachrichtigung per E-Mail konnte nicht verschickt werden", " | ".join(problems)[:1500])
    return sent
