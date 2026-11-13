"""Hintergrunddienst: fragt die Postfächer ab und räumt alte Daten auf."""
import asyncio
import datetime as dt
import json
import logging
import os
import time

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from . import db as m
from . import backup, notify, rules, sources, syslog

log = logging.getLogger("gateway.worker")
LOG_DAYS = int(os.environ.get("LOG_DAYS", "30"))
DEFAULT_SEND_DELAY = 10   # Sekunden Pause zwischen zwei automatischen Übergaben an DIVERA
MAX_SEND_DELAY = 300


def send_delay(config: dict) -> int:
    """Pause der Quelle in Sekunden; ohne Angabe gilt die Vorgabe, 0 schaltet sie ab."""
    try:
        value = config.get("send_delay")
        return max(0, min(MAX_SEND_DELAY, int(value))) if value not in (None, "") else DEFAULT_SEND_DELAY
    except (ValueError, TypeError, RuntimeError):
        return DEFAULT_SEND_DELAY


def already_processed(db, source_id: int, key: str) -> bool:
    """Merkt die Nachricht vor der Verarbeitung vor: lieber kein Alarm als ein doppelter."""
    try:
        db.add(m.Processed(source_id=source_id, key=key[:400]))
        db.commit()
        return False
    except IntegrityError:
        db.rollback()
        return True


def handle_message(db, source: m.Source, msg: dict) -> int:
    # Jede Nachricht wird genau einmal übergeben, unabhängig vom Alter. Nur wenn bei der Quelle ausdrücklich ein
    # Höchstalter eingestellt ist, bleiben ältere Nachrichten liegen (Schutz vor alten Alarmen nach einem Ausfall).
    try:
        limit = int(source.config.get("max_age") or 0)
    except (ValueError, RuntimeError):
        limit = 0
    age = dt.datetime.now(dt.timezone.utc) - msg["ts"] if msg.get("ts") else dt.timedelta(0)
    if limit > 0 and age > dt.timedelta(minutes=limit):
        db.add(m.Log(tenant_id=source.tenant_id, tenant_name=source.tenant.name, source_name=source.name,
                     sender=msg["from"][:200], subject=msg["subject"][:300], status="veraltet",
                     detail=f"Nachricht ist älter als das bei der Quelle eingestellte Höchstalter von {limit} Minuten und wurde nicht übergeben."))
        db.commit()
        return 0
    return rules.process_message(db, source, msg)


def run_source(source_id: int) -> dict:
    """Fragt eine Quelle einmal ab. Gibt zurück, wie viele neue Nachrichten verarbeitet wurden und ob es einen Fehler gab."""
    outcome = {"new": 0, "error": ""}
    with m.SessionLocal() as db:
        source = db.get(m.Source, source_id)
        if not source or not source.active or not source.tenant.active:
            return outcome
        messages, before = [], source.last_error or ""
        try:
            messages, state = sources.POLLERS[source.type](source.config, json.loads(source.state or "{}"))
            source.state = json.dumps(state)
            source.last_error = ""
            if before:  # nur der Wechsel wird protokolliert, nicht jede einzelne Abfrage
                syslog.note(db, "info", "Quelle", f"Verbindung zu „{source.name}“ funktioniert wieder", tenant=source.tenant)
        except Exception as exc:  # Verbindungsfehler dürfen den Dienst nicht beenden
            source.last_error = f"{type(exc).__name__}: {exc}"[:500]
            outcome["error"] = source.last_error
            if source.last_error != before:
                syslog.note(db, "fehler", "Quelle", f"Abruf von „{source.name}“ fehlgeschlagen", source.last_error, tenant=source.tenant)
        source.last_poll = m.utcnow()
        db.commit()
        pause, handed_over = send_delay(source.config), False
        for msg in messages:
            if already_processed(db, source.id, msg["id"]):
                continue
            outcome["new"] += 1
            if handed_over and pause:   # mehrere Nachrichten aus einem Abruf gehen nacheinander an DIVERA, nicht im selben Augenblick
                time.sleep(pause)
                handed_over = False
            try:
                handed_over = handle_message(db, source, msg) > 0
            except Exception as exc:
                db.rollback()
                log.exception("Verarbeitung fehlgeschlagen (Quelle %s)", source.id)
                syslog.record("fehler", "System", f"Nachricht aus „{source.name}“ konnte nicht verarbeitet werden",
                              f"{type(exc).__name__}: {exc} | Betreff: {msg.get('subject', '')[:120]}", tenant=source.tenant)
    return outcome


def prune():
    with m.SessionLocal() as db:
        db.execute(delete(m.Log).where(m.Log.ts < m.utcnow() - dt.timedelta(days=LOG_DAYS)))
        db.execute(delete(m.Processed).where(m.Processed.ts < m.utcnow() - dt.timedelta(days=7)))
        db.execute(delete(m.SystemEvent).where(m.SystemEvent.ts < m.utcnow() - dt.timedelta(days=LOG_DAYS)))
        db.execute(delete(m.ImportBatch).where(m.ImportBatch.created < m.utcnow() - dt.timedelta(days=1)))
        db.commit()


async def loop():
    running: set[int] = set()
    last_prune = last_notify = 0.0
    while True:
        try:
            now = m.utcnow()
            with m.SessionLocal() as db:
                due = [s.id for s in db.scalars(select(m.Source).where(m.Source.active, m.Source.type.in_(("m365", "imap"))))
                       if s.tenant.active and (not s.last_poll or (now - s.last_poll).total_seconds() >= s.poll_interval)]
            for sid in due:
                if sid in running:
                    continue
                running.add(sid)
                task = asyncio.create_task(asyncio.to_thread(run_source, sid))
                task.add_done_callback(lambda _t, sid=sid: running.discard(sid))
            if time.time() - last_notify > notify.INTERVAL:
                last_notify = time.time()
                await asyncio.to_thread(notify.run)
            if time.time() - last_prune > 3600:
                last_prune = time.time()
                await asyncio.to_thread(prune)
                if await asyncio.to_thread(backup.auto_due):   # tägliche Sicherung ohne Zutun
                    try:
                        await asyncio.to_thread(backup.store, True)
                    except Exception as exc:
                        await asyncio.to_thread(syslog.record, "fehler", "Sicherung", "Automatische Sicherung fehlgeschlagen", f"{type(exc).__name__}: {exc}")
        except Exception as exc:
            log.exception("Fehler im Hintergrunddienst")
            await asyncio.to_thread(syslog.record, "fehler", "System", "Fehler im Hintergrunddienst", f"{type(exc).__name__}: {exc}")
        await asyncio.sleep(3)
