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
from . import rules, sources

log = logging.getLogger("gateway.worker")
MAX_AGE_MIN = int(os.environ.get("MAX_AGE_MINUTES", "15"))
LOG_DAYS = int(os.environ.get("LOG_DAYS", "30"))


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
    age = dt.datetime.now(dt.timezone.utc) - msg["ts"] if msg.get("ts") else dt.timedelta(0)
    if age > dt.timedelta(minutes=MAX_AGE_MIN):
        db.add(m.Log(tenant_id=source.tenant_id, tenant_name=source.tenant.name, source_name=source.name,
                     sender=msg["from"][:200], subject=msg["subject"][:300], status="veraltet",
                     detail=f"Nachricht ist älter als {MAX_AGE_MIN} Minuten und wurde nicht übergeben."))
        db.commit()
        return 0
    return rules.process_message(db, source, msg)


def run_source(source_id: int):
    with m.SessionLocal() as db:
        source = db.get(m.Source, source_id)
        if not source or not source.active or not source.tenant.active:
            return
        messages = []
        try:
            messages, state = sources.POLLERS[source.type](source.config, json.loads(source.state or "{}"))
            source.state = json.dumps(state)
            source.last_error = ""
        except Exception as exc:  # Verbindungsfehler dürfen den Dienst nicht beenden
            source.last_error = f"{type(exc).__name__}: {exc}"[:500]
        source.last_poll = m.utcnow()
        db.commit()
        for msg in messages:
            if already_processed(db, source.id, msg["id"]):
                continue
            try:
                handle_message(db, source, msg)
            except Exception:
                db.rollback()
                log.exception("Verarbeitung fehlgeschlagen (Quelle %s)", source.id)


def prune():
    with m.SessionLocal() as db:
        db.execute(delete(m.Log).where(m.Log.ts < m.utcnow() - dt.timedelta(days=LOG_DAYS)))
        db.execute(delete(m.Processed).where(m.Processed.ts < m.utcnow() - dt.timedelta(days=7)))
        db.commit()


async def loop():
    running: set[int] = set()
    last_prune = 0.0
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
            if time.time() - last_prune > 3600:
                last_prune = time.time()
                await asyncio.to_thread(prune)
        except Exception:
            log.exception("Fehler im Hintergrunddienst")
        await asyncio.sleep(3)
