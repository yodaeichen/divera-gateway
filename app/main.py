"""Web-Oberfläche und Webhook-Eingang."""
import asyncio
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import db as m
from . import access, mailer, rules, sources, suggest, worker
from . import security as sec
from .version import VERSION

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
for _name in ("httpx", "httpx2", "httpcore"):  # sonst landen Accesskeys aus URLs im Log
    logging.getLogger(_name).setLevel(logging.WARNING)
log = logging.getLogger("gateway")

BASE = os.path.dirname(__file__)
TZ = ZoneInfo(os.environ.get("TZ", "Europe/Berlin"))
SOURCE_TYPES = {"m365": "Microsoft 365", "imap": "IMAP", "webhook": "Webhook"}
MAX_WEBHOOK_BYTES = 256 * 1024


@asynccontextmanager
async def lifespan(_app):
    m.init_db()
    with m.SessionLocal() as db:
        if not db.scalar(select(func.count(m.User.id))):
            password = os.environ.get("ADMIN_PASSWORD", "")
            if len(password) < 12:
                raise RuntimeError("ADMIN_PASSWORD fehlt oder ist kürzer als 12 Zeichen (siehe .env.example).")
            db.add(m.User(username=os.environ.get("ADMIN_USER", "admin"), password_hash=sec.hash_password(password)))
            db.commit()
            log.info("Erster Benutzer wurde angelegt.")
    log.info("DIVERA Gateway %s gestartet.", VERSION)
    task = asyncio.create_task(worker.loop())
    yield
    task.cancel()


app = FastAPI(title="DIVERA Gateway", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=sec.SESSION_SECRET, session_cookie="gw_session", same_site="lax",
                   https_only=os.environ.get("COOKIE_SECURE", "true").lower() == "true", max_age=12 * 3600)
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))
templates.env.globals["version"] = VERSION
templates.env.filters["localtime"] = lambda value: (
    value.replace(tzinfo=dt.timezone.utc).astimezone(TZ).strftime("%d.%m.%Y %H:%M:%S") if value else "nie")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    return response


class LoginRequired(Exception):
    pass


@app.exception_handler(LoginRequired)
async def _login_required(_request, _exc):
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(access.Denied)
async def _denied(request: Request, exc: access.Denied):
    if request.url.path == "/rules/preview":
        return JSONResponse({"detail": exc.message}, status_code=403)
    response = templates.TemplateResponse(request, "denied.html", {"message": exc.message, "user": None, "flash": None, "csrf": ""})
    response.status_code = 403
    return response


def get_db():
    with m.SessionLocal() as db:
        yield db


def current_user(request: Request, db: Session = Depends(get_db)) -> m.User:
    uid = request.session.get("uid")
    user = db.get(m.User, uid) if uid else None
    if not user:
        raise LoginRequired()
    now = m.utcnow()
    if user.last_seen is None or (now - user.last_seen).total_seconds() > 60:  # höchstens einmal je Minute schreiben
        user.last_seen = now
        db.commit()
    return user


def csrf_token(request: Request) -> str:
    if "csrf" not in request.session:
        request.session["csrf"] = secrets.token_urlsafe(32)
    return request.session["csrf"]


async def read_form(request: Request):
    form = await request.form()
    if not hmac.compare_digest(str(form.get("csrf", "")), request.session.get("csrf", "-")):
        raise HTTPException(403, "Ungültiges Formular-Token. Bitte Seite neu laden.")
    return form


def flash(request: Request, text: str, kind: str = "ok"):
    request.session["flash"] = [kind, text]


def allow(*needs: str):
    """Abhängigkeit für Seiten und Aktionen: angemeldet und mit den genannten Rechten, z. B. allow("rules:2", "send")."""
    def dependency(request: Request, db: Session = Depends(get_db)) -> m.User:
        user = current_user(request, db)
        access.require(user, *needs)
        return user
    return dependency


def tenant_for(db: Session, user: m.User, tenant_id) -> m.Tenant:
    """Lädt eine Löschgruppe nur, wenn der Benutzer sie sehen darf. Fremde Löschgruppen verhalten sich wie nicht vorhanden."""
    tenant = db.get(m.Tenant, int(tenant_id))
    if tenant is None or not access.allowed(user, tenant.id):
        raise HTTPException(404, "Nicht gefunden")
    return tenant


def source_for(db: Session, user: m.User, source_id) -> m.Source:
    source = need(db.get(m.Source, int(source_id)))
    tenant_for(db, user, source.tenant_id)
    return source


def rule_for(db: Session, user: m.User, rule_id) -> m.Rule:
    rule = need(db.get(m.Rule, int(rule_id)))
    tenant_for(db, user, rule.tenant_id)
    return rule


def visible_tenants(db: Session, user: m.User) -> list[m.Tenant]:
    tenants = db.scalars(select(m.Tenant).order_by(m.Tenant.name)).all()
    return [t for t in tenants if access.allowed(user, t.id)]


def page(request: Request, name: str, user: m.User | None = None, **ctx):
    ctx.update(user=user, csrf=csrf_token(request), flash=request.session.pop("flash", None), types=SOURCE_TYPES,
               perm=access.perms_of(user) if user else {}, sees_all=access.sees_all(user) if user else False)
    return templates.TemplateResponse(request, name, ctx)


def go(url: str):
    return RedirectResponse(url, status_code=303)


def need(obj):
    if obj is None:
        raise HTTPException(404, "Nicht gefunden")
    return obj


def text(form, key: str, limit: int = 300) -> str:
    return str(form.get(key, "")).strip()[:limit]


# ---------- Anmeldung ----------

_failed: dict[str, list[float]] = {}


@app.get("/login")
def login_form(request: Request):
    return page(request, "login.html")


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    form = await read_form(request)
    username = text(form, "username", 80)
    recent = [t for t in _failed.get(username.lower(), []) if time.time() - t < 300]
    if len(recent) >= 5:
        flash(request, "Zu viele Fehlversuche. Bitte fünf Minuten warten.", "err")
        return go("/login")
    user = db.scalar(select(m.User).where(m.User.username == username))
    stored = user.password_hash if user else sec.hash_password("dummy")
    if not sec.verify_password(str(form.get("password", "")), stored) or not user:
        _failed[username.lower()] = recent + [time.time()]
        flash(request, "Benutzername oder Passwort falsch.", "err")
        return go("/login")
    _failed.pop(username.lower(), None)
    user.last_login = user.last_seen = m.utcnow()
    db.commit()
    request.session.clear()
    request.session["uid"] = user.id
    return go("/")


@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    await read_form(request)
    user = db.get(m.User, request.session.get("uid") or 0)
    if user:
        user.last_seen = None  # gilt sofort als abgemeldet
        db.commit()
    request.session.clear()
    return go("/login")


# ---------- Übersicht und Löschgruppen ----------

ONLINE_MINUTES = 15
STATUS_LABELS = [("gesendet", "Erfolgreich an DIVERA gesendet"), ("fehler", "Fehlgeschlagen"), ("test", "Nur Testmodus (nicht gesendet)"),
                 ("ignoriert", "Keine Regel hat gepasst"), ("veraltet", "Zu alt, nicht übergeben")]


def admin_overview(db: Session, now: dt.datetime) -> dict:
    """Für Benutzer mit Rechteverwaltung: wer angemeldet ist und wie viele Meldungen erfolgreich oder fehlgeschlagen sind."""
    limit = now - dt.timedelta(minutes=ONLINE_MINUTES)
    people = [{"name": u.username, "role": access.role_of(u), "last_seen": u.last_seen, "last_login": u.last_login,
               "online": bool(u.last_seen and u.last_seen >= limit)}
              for u in db.scalars(select(m.User).order_by(m.User.username))]
    people.sort(key=lambda p: (not p["online"], p["name"].lower()))

    def counts(since: dt.datetime | None) -> dict:
        query = select(m.Log.status, func.count(m.Log.id)).group_by(m.Log.status)
        if since:
            query = query.where(m.Log.ts >= since)
        return dict(db.execute(query).all())

    windows = [("letzte 24 Stunden", counts(now - dt.timedelta(hours=24))), ("letzte 7 Tage", counts(now - dt.timedelta(days=7))),
               (f"gesamt (Protokoll reicht {worker.LOG_DAYS} Tage zurück)", counts(None))]
    per_tenant: dict[str, dict] = {}
    week = select(m.Log.tenant_name, m.Log.status, func.count(m.Log.id)).where(m.Log.ts >= now - dt.timedelta(days=7)) \
        .group_by(m.Log.tenant_name, m.Log.status)
    for name, status, number in db.execute(week).all():
        per_tenant.setdefault(name or "ohne Löschgruppe", {})[status] = number
    return {"people": people, "online": sum(1 for p in people if p["online"]), "windows": windows,
            "per_tenant": sorted(per_tenant.items()), "labels": STATUS_LABELS, "minutes": ONLINE_MINUTES}


@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    tenants = visible_tenants(db, user)
    logs = []
    if access.perms_of(user)["logs"]:
        logs = db.scalars(select(m.Log).where(m.Log.tenant_id.in_([t.id for t in tenants])).order_by(m.Log.id.desc()).limit(15)).all()
    now, schedule = m.utcnow(), {}
    for tenant in tenants:  # letzter und nächster Abruf je Löschgruppe, über alle aktiven Postfächer
        pollable = [s for s in tenant.sources if s.active and s.type in sources.POLLERS]
        polled = [s.last_poll for s in pollable if s.last_poll]
        info = {"last": max(polled) if polled else None, "next": None, "due": False, "interval": None}
        if tenant.active and pollable:
            upcoming = [s.last_poll + dt.timedelta(seconds=s.poll_interval) if s.last_poll else now for s in pollable]
            info.update(next=min(upcoming), due=min(upcoming) <= now, interval=min(s.poll_interval for s in pollable))
        schedule[tenant.id] = info
    admin = admin_overview(db, now) if access.perms_of(user)["users"] == 2 else None
    return page(request, "dashboard.html", user, tenants=tenants, logs=logs, schedule=schedule, admin=admin)


@app.get("/tenants/new")
def tenant_new(request: Request, user: m.User = Depends(allow("tenants:2"))):
    if not access.sees_all(user):
        raise access.Denied("Neue Löschgruppen kann nur anlegen, wer alle Löschgruppen sehen darf.")
    return page(request, "tenant_form.html", user, tenant=None)


@app.get("/tenants/{tid}")
def tenant_view(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    tenant = tenant_for(db, user, tid)
    since = {}  # ab wann ein Microsoft-365-Postfach Nachrichten berücksichtigt
    for source in tenant.sources:
        stamp = json.loads(source.state or "{}").get("since") if source.type == "m365" else None
        if stamp:
            try:
                since[source.id] = dt.datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(dt.timezone.utc).replace(tzinfo=None)
            except ValueError:
                pass
    return page(request, "tenant.html", user, tenant=tenant, base_url=str(request.base_url), directory=directory_of(tenant), since=since)


@app.get("/tenants/{tid}/edit")
def tenant_edit(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("tenants:2"))):
    return page(request, "tenant_form.html", user, tenant=tenant_for(db, user, tid))


@app.post("/tenants/save")
async def tenant_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("tenants:2"))):
    form = await read_form(request)
    if not form.get("id") and not access.sees_all(user):
        raise access.Denied("Neue Löschgruppen kann nur anlegen, wer alle Löschgruppen sehen darf.")
    tenant = tenant_for(db, user, int(form["id"])) if form.get("id") else m.Tenant()
    tenant.name = text(form, "name", 120) or "Unbenannt"
    tenant.active = "active" in form
    tenant.test_mode = "test_mode" in form
    if text(form, "accesskey"):
        tenant.accesskey_enc = sec.encrypt(text(form, "accesskey"))
    if text(form, "accesskey_user"):
        tenant.accesskey_user_enc = sec.encrypt(text(form, "accesskey_user"))
    if "accesskey_user_clear" in form:
        tenant.accesskey_user_enc = ""
    db.add(tenant)
    db.commit()
    flash(request, "Löschgruppe gespeichert.")
    return go(f"/tenants/{tenant.id}")


@app.post("/tenants/{tid}/keycheck")
async def tenant_keycheck(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("tenants:2"))):
    """Prüft beide hinterlegten Schlüssel lesend gegen DIVERA und zeigt, was sie dürfen."""
    await read_form(request)
    tenant = tenant_for(db, user, tid)
    checks = []
    for label, enc in (("Alarm-Accesskey der Einheit", tenant.accesskey_enc), ("Persönlicher Accesskey", tenant.accesskey_user_enc)):
        if not enc:
            checks.append({"label": label, "missing": True})
            continue
        key = sec.decrypt(enc)
        result = await asyncio.to_thread(rules.check_key, key)
        result.update(label=label, missing=False, length=len(key), spaces=key != key.strip())
        checks.append(result)
    return page(request, "tenant.html", user, tenant=tenant, base_url=str(request.base_url), directory=directory_of(tenant),
                since={}, checks=checks)


@app.post("/tenants/{tid}/directory")
async def tenant_directory(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("tenants:2"))):
    """Lädt Personen und Gruppen der Einheit aus DIVERA für die Empfängerauswahl in Regeln."""
    await read_form(request)
    tenant = tenant_for(db, user, tid)
    try:
        directory = await asyncio.to_thread(rules.fetch_directory, rules.key_for(tenant))
    except Exception as exc:
        flash(request, f"Empfänger konnten nicht geladen werden: {str(exc)[:300]}", "err")
        return go(f"/tenants/{tid}")
    tenant.directory, tenant.directory_ts = json.dumps(directory, ensure_ascii=False), m.utcnow()
    db.commit()
    flash(request, f"{len(directory['persons'])} Personen und {len(directory['groups'])} Gruppen aus DIVERA geladen.")
    return go(f"/tenants/{tid}")


@app.post("/tenants/{tid}/poll")
async def tenant_poll(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("send"))):
    """Fragt alle Postfächer einer Löschgruppe sofort ab, ohne auf das Intervall zu warten."""
    form = await read_form(request)
    tenant = tenant_for(db, user, tid)
    back = "/" if form.get("back") == "home" else f"/tenants/{tid}"
    pollable = [s for s in tenant.sources if s.active and s.type in sources.POLLERS]
    if not tenant.active:
        flash(request, f"{tenant.name} ist inaktiv und wird nicht abgerufen.", "err")
    elif not pollable:
        flash(request, f"{tenant.name} hat keine aktiven Postfächer. Webhooks kommen von selbst an.", "err")
    else:
        results = await asyncio.gather(*(asyncio.to_thread(worker.run_source, s.id) for s in pollable))
        new = sum(r["new"] for r in results)
        hint = "" if new else (" Automatisch verarbeitet werden nur Nachrichten, die nach dem Anlegen oder letzten Speichern der Quelle "
                               "eingegangen sind. Ältere kannst du über „Verbindung testen“ einzeln verarbeiten.")
        failed = [s.name for s, r in zip(pollable, results) if r["error"]]
        text_ = f"{tenant.name}: {len(pollable)} {'Postfach' if len(pollable) == 1 else 'Postfächer'} abgerufen, " \
                f"{new} neue {'Nachricht' if new == 1 else 'Nachrichten'}."
        if failed:
            text_ += " Fehler bei: " + ", ".join(failed) + "."
        flash(request, text_ + ("" if failed else hint), "err" if failed else "ok")
    return go(back)


@app.post("/tenants/{tid}/delete")
async def tenant_delete(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("tenants:2"))):
    await read_form(request)
    db.delete(tenant_for(db, user, tid))
    db.commit()
    flash(request, "Löschgruppe gelöscht.")
    return go("/")


# ---------- Quellen ----------

@app.get("/tenants/{tid}/sources/new")
def source_new(tid: int, request: Request, type: str = "m365", db: Session = Depends(get_db),
               user: m.User = Depends(allow("sources:2"))):
    if type not in SOURCE_TYPES:
        raise HTTPException(400, "Unbekannter Quelltyp")
    return page(request, "source_form.html", user, tenant=tenant_for(db, user, tid), source=None, stype=type, cfg={})


@app.get("/sources/{sid}/edit")
def source_edit(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("sources:2"))):
    source = source_for(db, user, sid)
    cfg = {k: v for k, v in source.config.items() if k not in ("client_secret", "password")}
    return page(request, "source_form.html", user, tenant=source.tenant, source=source, stype=source.type, cfg=cfg)


@app.post("/sources/save")
async def source_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("sources:2"))):
    form = await read_form(request)
    if form.get("id"):
        source = source_for(db, user, int(form["id"]))
    else:
        stype = text(form, "type", 20)
        if stype not in SOURCE_TYPES:
            raise HTTPException(400, "Unbekannter Quelltyp")
        source = m.Source(tenant_id=tenant_for(db, user, int(form["tenant_id"])).id, type=stype)
        if stype == "webhook":
            source.webhook_token = secrets.token_urlsafe(32)
    source.name = text(form, "name", 120) or SOURCE_TYPES[source.type]
    source.active = "active" in form
    try:
        source.poll_interval = max(10, min(3600, int(form.get("poll_interval") or 30)))
    except ValueError:
        source.poll_interval = 30
    cfg = source.config if source.config_enc else {}
    plain, secret = {"m365": (("tenant_id", "client_id", "mailbox", "folder"), "client_secret"),
                     "imap": (("host", "port", "security", "username", "folder"), "password"),
                     "webhook": ((), None)}[source.type]
    for key in plain:
        cfg[key] = text(form, "directory_id" if key == "tenant_id" else key)
    if secret and str(form.get(secret, "")):
        cfg[secret] = str(form[secret])
    source.config = cfg
    source.state, source.last_error, source.last_poll = "{}", "", None  # Startpunkt neu setzen
    db.add(source)
    db.commit()
    flash(request, "Quelle gespeichert. Es werden nur Nachrichten ab jetzt verarbeitet.")
    return go(f"/tenants/{source.tenant_id}")


@app.post("/sources/{sid}/test")
async def source_test(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("sources:1"))):
    await read_form(request)
    source = source_for(db, user, sid)
    result, error = None, ""
    if source.type == "webhook":
        result = {"last": json.loads(source.state or "{}").get("last")}
    else:
        try:
            result = await asyncio.to_thread(sources.TESTERS[source.type], source.config)
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:300]}"
    return page(request, "source_test.html", user, tenant=source.tenant, source=source, result=result, error=error,
                base_url=str(request.base_url))


def _process_one(source_id: int, msg: dict) -> int:
    """Verarbeitet eine von Hand ausgewählte Nachricht wie eine neu eingegangene (ohne Altersgrenze)."""
    with m.SessionLocal() as db:
        source = db.get(m.Source, source_id)
        worker.already_processed(db, source.id, msg["id"])  # vormerken, damit der automatische Abruf sie nicht noch einmal nimmt
        return rules.process_message(db, source, msg)


@app.post("/sources/{sid}/process")
async def source_process(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("sources:1", "send"))):
    """Übergibt eine im Verbindungstest gezeigte Nachricht jetzt an die Regeln. Im scharfen Betrieb wird wirklich gesendet."""
    form = await read_form(request)
    source = source_for(db, user, sid)
    if source.type not in sources.FETCHERS:
        raise HTTPException(400, "Für diese Quelle nicht möglich")
    if not source.tenant.active:
        flash(request, "Die Löschgruppe ist inaktiv, es wird nichts verarbeitet.", "err")
        return go(f"/tenants/{source.tenant_id}")
    try:
        msg = await asyncio.to_thread(sources.FETCHERS[source.type], source.config, text(form, "ref", 600))
        matched = await asyncio.to_thread(_process_one, source.id, msg)
    except Exception as exc:
        flash(request, f"Nachricht konnte nicht verarbeitet werden ({type(exc).__name__}: {str(exc)[:200]})", "err")
        return go(f"/tenants/{source.tenant_id}")
    if matched:
        mode = "Testmodus: nichts gesendet" if source.tenant.test_mode else "an DIVERA übergeben"
        flash(request, f"„{msg['subject'][:80]}“ verarbeitet, {matched} {'Regel hat' if matched == 1 else 'Regeln haben'} gegriffen ({mode}). Details stehen unten.")
    else:
        flash(request, f"„{msg['subject'][:80]}“ verarbeitet, aber keine Regel passt. Öffne die Regel und prüfe sie mit dieser Nachricht in der Live-Ansicht.", "err")
    return go(f"/logs?tenant={source.tenant_id}")


@app.post("/sources/{sid}/token")
async def source_token(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("sources:2"))):
    await read_form(request)
    source = source_for(db, user, sid)
    if source.type == "webhook":
        source.webhook_token = secrets.token_urlsafe(32)
        db.commit()
        flash(request, "Neue Webhook-Adresse erzeugt. Die alte ist ab sofort ungültig.")
    return go(f"/tenants/{source.tenant_id}")


@app.post("/sources/{sid}/delete")
async def source_delete(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("sources:2"))):
    await read_form(request)
    source = source_for(db, user, sid)
    tid = source.tenant_id
    db.delete(source)
    db.commit()
    flash(request, "Quelle gelöscht.")
    return go(f"/tenants/{tid}")


# ---------- Regeln ----------

def directory_of(tenant: m.Tenant) -> dict:
    data = json.loads(tenant.directory or "{}")
    return {"persons": data.get("persons") or [], "groups": data.get("groups") or []}


def rule_page(request, user, tenant, rule, **extra):
    directory = directory_of(tenant)
    chosen = {"persons": [int(i) for i in rules.id_list(rule.ucr_ids)] if rule else [],
              "groups": [int(i) for i in rules.id_list(rule.group_ids)] if rule else []}
    known = {kind: {entry["id"] for entry in directory[kind]} for kind in directory}
    stale = {kind: [i for i in chosen[kind] if i not in known[kind]] for kind in chosen}  # gewählt, aber nicht mehr in der Liste
    return page(request, "rule_form.html", user, tenant=tenant, rule=rule, directory=directory, chosen=chosen, stale=stale, **extra)


def apply_rule_form(rule: m.Rule, form, db: Session) -> str:
    """Überträgt die Formularwerte auf die Regel. Gibt eine Fehlermeldung zurück oder ''."""
    rule.name = text(form, "name", 120) or "Regel"
    rule.active, rule.priority = "active" in form, "priority" in form
    rule.push = form.get("push") != "0"
    rule.require_regex, rule.stop = "require_regex" in form, "stop" in form
    rule.kind = "alarm" if form.get("kind") == "alarm" else "news"  # Alarm nur bei ausdrücklicher Auswahl
    try:
        rule.position = int(form.get("position") or 10)
    except ValueError:
        rule.position = 10
    source_id = int(form["source_id"]) if form.get("source_id") else None
    if source_id and need(db.get(m.Source, source_id)).tenant_id != rule.tenant_id:
        raise HTTPException(400, "Quelle gehört zu einer anderen Löschgruppe")
    rule.source_id = source_id
    for key in ("match_from", "match_subject", "match_body"):
        setattr(rule, key, text(form, key, 500))
    rule.ric = text(form, "ric", 300)
    rule.ucr_ids = ",".join(rules.id_list(form.getlist("ucr")))[:1000]
    rule.group_ids = ",".join(rules.id_list(form.getlist("grp")))[:1000]
    for key in ("extract_regex", "title_tpl", "text_tpl", "address_tpl", "extra_params"):
        setattr(rule, key, str(form.get(key, "")).replace("\r\n", "\n").strip()[:4000])
    for number, line in enumerate(rule.extract_regex.splitlines(), 1):
        try:
            re.compile(line)
        except re.error as exc:
            return f"Ausdruck in Zeile {number} ungültig: {exc}."
    return ""


def read_sample(form) -> dict | None:
    if not (form.get("t_from") or form.get("t_subject") or form.get("t_body")):
        return None
    return {"from": text(form, "t_from"), "subject": text(form, "t_subject"),
            "body": str(form.get("t_body", "")).replace("\r\n", "\n")[:20000],
            "date": m.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}


def evaluate(rule: m.Rule, sample: dict) -> dict:
    """Probelauf einer Regel gegen eine Beispielnachricht, ohne etwas zu senden."""
    try:
        values = rules.match_rule(rule, sample)
    except re.error as exc:
        return {"match": False, "error": str(exc)}
    return {"match": values is not None, "payload": rules.build_payload(rule, values) if values else None,
            "values": {k: v for k, v in (values or {}).items() if k != "body"}}


def unsaved_rule(form, db: Session, user: m.User) -> m.Rule:
    """Regel nur im Speicher, damit ein Probelauf oder Fehler nichts an der Datenbank ändert."""
    rule = m.Rule()
    if form.get("id"):
        existing = rule_for(db, user, int(form["id"]))
        rule.id, rule.tenant_id = existing.id, existing.tenant_id
    else:
        rule.tenant_id = tenant_for(db, user, int(form["tenant_id"])).id
    return rule


@app.get("/tenants/{tid}/rules/new")
def rule_new(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:2"))):
    return rule_page(request, user, tenant_for(db, user, tid), None)


@app.get("/rules/{rid}/edit")
def rule_edit(rid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:1"))):
    rule = rule_for(db, user, rid)
    return rule_page(request, user, rule.tenant, rule)


@app.post("/rules/test")
async def rule_test(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:1"))):
    form = await read_form(request)
    rule = unsaved_rule(form, db, user)
    error = apply_rule_form(rule, form, db)
    sample = read_sample(form)
    tenant = tenant_for(db, user, rule.tenant_id)
    if not error and not sample:
        error = "Zum Prüfen bitte unten eine Beispielnachricht eintragen."
    result = evaluate(rule, sample) if sample and not error else None
    return rule_page(request, user, tenant, rule, sample=sample, result=result, error=error)


@app.post("/rules/preview")
async def rule_preview(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:1"))):
    """Live-Ansicht: wertet die gerade im Formular stehenden Werte aus. Speichert und sendet nichts."""
    form = await read_form(request)
    rule = unsaved_rule(form, db, user)
    error = apply_rule_form(rule, form, db)
    sample = read_sample(form)
    if not sample:
        return JSONResponse({"state": "nosample"})
    data = rules.preview(rule, sample)
    directory = directory_of(tenant_for(db, user, rule.tenant_id))
    def names(kind: str, ids: str) -> list[str]:
        lookup = {str(entry["id"]): entry["name"] for entry in directory[kind]}
        return [lookup.get(i, f"ID {i}") for i in rules.id_list(ids)]
    data.update(state="ok", form_error=error, persons=names("persons", rule.ucr_ids), groups=names("groups", rule.group_ids),
                user_key=bool(tenant_for(db, user, rule.tenant_id).accesskey_user_enc))
    return JSONResponse(data)


@app.post("/rules/send-test")
async def rule_send_test(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:1", "send"))):
    """Sendet das Ergebnis der Regel für die Beispielnachricht wirklich an DIVERA, auch im Testmodus.

    Zwei Schritte: erst eine Bestätigungsseite mit genau dem, was gesendet würde, dann das Senden.
    """
    form = await read_form(request)
    rule = unsaved_rule(form, db, user)
    error = apply_rule_form(rule, form, db)
    sample = read_sample(form)
    tenant = tenant_for(db, user, rule.tenant_id)
    if not error and not sample:
        error = "Zum Senden bitte unten eine Beispielnachricht eintragen."
    if not error and not tenant.accesskey_enc:
        error = "Für diese Löschgruppe ist kein DIVERA-Accesskey hinterlegt."
    data = rules.preview(rule, sample) if sample and not error else None
    if data and not data["match"]:
        error = "Die Regel greift bei der Beispielnachricht nicht, deshalb würde auch im Betrieb nichts gesendet."
    if error:
        return rule_page(request, user, tenant, rule, sample=sample, result=evaluate(rule, sample) if sample else None, error=error)
    directory = directory_of(tenant)
    def names(kind: str, ids: str) -> list[str]:
        lookup = {str(entry["id"]): entry["name"] for entry in directory[kind]}
        return [lookup.get(i, f"ID {i}") for i in rules.id_list(ids)]
    if form.get("confirm") != "ja":
        fields = [(k, v) for k, v in form.multi_items() if k not in ("csrf", "confirm") and isinstance(v, str)]
        return page(request, "rule_send_confirm.html", user, tenant=tenant, rule=rule, data=data, fields=fields,
                    persons=names("persons", rule.ucr_ids), groups=names("groups", rule.group_ids))
    ok, detail = await asyncio.to_thread(rules.send_divera, rules.key_for(tenant, data["payload"]), data["payload"])
    detail += rules.refusal_hint(tenant, data["payload"], detail)
    db.add(m.Log(tenant_id=tenant.id, tenant_name=tenant.name, source_name="Testsendung von Hand", rule_name=rule.name,
                 sender=sample["from"][:200], subject=sample["subject"][:300], status="gesendet" if ok else "fehler",
                 detail=f"{rules.title_of(data['payload'])} | {detail} | ausgelöst von {user.username}"[:2000]))
    db.commit()
    return rule_page(request, user, tenant, rule, sample=sample, result=evaluate(rule, sample), send_result={"ok": ok, "detail": detail})


@app.post("/rules/save")
async def rule_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:2"))):
    form = await read_form(request)
    draft = unsaved_rule(form, db, user)
    error = apply_rule_form(draft, form, db)
    sample = read_sample(form)
    if error:
        return rule_page(request, user, tenant_for(db, user, draft.tenant_id), draft, sample=sample, error=error)
    rule = rule_for(db, user, draft.id) if draft.id else m.Rule(tenant_id=draft.tenant_id)
    apply_rule_form(rule, form, db)
    db.add(rule)
    db.commit()
    if sample:  # Beispielnachricht stehen lassen, damit man weiter herantesten kann
        return rule_page(request, user, rule.tenant, rule, sample=sample, result=evaluate(rule, sample), just_saved=True)
    flash(request, "Regel gespeichert.")
    return go(f"/rules/{rule.id}/edit")


@app.post("/sources/{sid}/suggest")
async def rule_suggest(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:2", "sources:1"))):
    """Erzeugt aus einer Nachricht der Quelle einen ungespeicherten Regelvorschlag."""
    form = await read_form(request)
    source = source_for(db, user, sid)
    if source.type == "webhook":
        last = json.loads(source.state or "{}").get("last")
        if not last:
            flash(request, "Für diese Quelle ist noch nichts eingegangen.", "err")
            return go(f"/tenants/{source.tenant_id}")
        msg = {"from": last.get("from", ""), "subject": last.get("subject", ""), "body": last.get("body", ""),
               "extra": last.get("fields") or {}}
    else:
        try:
            msg = await asyncio.to_thread(sources.FETCHERS[source.type], source.config, text(form, "ref", 600))
        except Exception as exc:
            flash(request, f"Nachricht konnte nicht geladen werden ({type(exc).__name__}: {str(exc)[:200]})", "err")
            return go(f"/tenants/{source.tenant_id}")
    proposal = suggest.suggest(msg)
    rule = m.Rule(tenant_id=source.tenant_id, source_id=source.id, active=True, position=10, match_body="",
                  require_regex=False, kind="news", ric="", ucr_ids="", group_ids="", priority=False, push=True, extra_params="", stop=True,
                  **proposal["fields"])
    sample = dict(msg, body=msg["body"][:20000], date=m.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
    return rule_page(request, user, source.tenant, rule, sample=sample, result=evaluate(rule, sample), notes=proposal["notes"])


@app.post("/rules/{rid}/delete")
async def rule_delete(rid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("rules:2"))):
    await read_form(request)
    rule = rule_for(db, user, rid)
    tid = rule.tenant_id
    db.delete(rule)
    db.commit()
    flash(request, "Regel gelöscht.")
    return go(f"/tenants/{tid}")


# ---------- Protokoll und Benutzer ----------

@app.get("/logs")
def logs_view(request: Request, tenant: int | None = None, status: str = "", db: Session = Depends(get_db),
              user: m.User = Depends(allow("logs:1"))):
    tenants = visible_tenants(db, user)
    visible = [t.id for t in tenants]
    query = select(m.Log).where(m.Log.tenant_id.in_(visible)).order_by(m.Log.id.desc()).limit(300)
    if tenant:
        query = query.where(m.Log.tenant_id == tenant)
    if status:
        query = query.where(m.Log.status == status)
    return page(request, "logs.html", user, logs=db.scalars(query).all(), tenants=tenants, sel_tenant=tenant, sel_status=status)


# ---------- Benutzer und Rechte ----------

def admins_left(db: Session) -> int:
    return sum(1 for u in db.scalars(select(m.User)) if access.perms_of(u)["users"] == 2)


def public_url(request: Request, settings: dict) -> str:
    """Adresse, unter der Benutzer das Gateway erreichen: aus den Einstellungen, sonst aus dem aktuellen Aufruf."""
    return (settings.get("base_url") or str(request.base_url)).rstrip("/") + "/"


def start_invite(target: m.User) -> str:
    """Erzeugt einen Einmal-Link-Schlüssel. Gespeichert wird nur sein Hash."""
    token = secrets.token_urlsafe(32)
    target.invite_hash = hashlib.sha256(token.encode()).hexdigest()
    target.invite_expires = m.utcnow() + dt.timedelta(hours=mailer.INVITE_HOURS)
    return token


async def send_invite(request: Request, db: Session, target: m.User, inviter: m.User) -> str:
    """Schickt die Einladung. Gibt '' zurück oder eine Fehlermeldung; der Benutzer bleibt in jedem Fall angelegt."""
    settings = mailer.load(db)
    token = start_invite(target)
    db.commit()
    base = public_url(request, settings)
    subject, body = mailer.invite_text(target.username, f"{base}invite/{token}", base, inviter.username)
    try:
        await asyncio.to_thread(mailer.deliver, settings, target.email, subject, body)
    except RuntimeError as exc:
        return str(exc)
    return ""


def user_form_page(request, user, db, target, **extra):
    extra.setdefault("mail_ready", mailer.configured(mailer.load(db)))
    perms = access.perms_of(target) if target is not None and target.id else dict(access.PRESETS["viewer"])
    return page(request, "user_form.html", user, target=target, tperms=perms, areas=access.AREAS, presets=access.PRESETS,
                role_names=access.ROLE_NAMES, role_hints=access.ROLE_HINTS, send_hint=access.SEND_HINT,
                tenants=db.scalars(select(m.Tenant).order_by(m.Tenant.name)).all(),
                t_all=access.sees_all(target) if target is not None and target.id else False,
                t_ids=access.tenant_ids(target) if target is not None and target.id else set(), **extra)


@app.get("/users")
def users_view(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    names = {t.id: t.name for t in db.scalars(select(m.Tenant))}
    now = m.utcnow()
    rows = [{"user": u, "role": access.role_of(u), "all": access.sees_all(u),
             "pending": bool(u.invite_hash and u.invite_expires and u.invite_expires > now and not u.last_login),
             "tenants": [names[i] for i in sorted(access.tenant_ids(u)) if i in names]}
            for u in db.scalars(select(m.User).order_by(m.User.username))]
    return page(request, "users.html", user, rows=rows)


@app.get("/users/new")
def users_new(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    return user_form_page(request, user, db, None)


@app.get("/users/{uid}/edit")
def users_edit(uid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    return user_form_page(request, user, db, need(db.get(m.User, uid)))


@app.post("/users/save")
async def users_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    form = await read_form(request)
    password = str(form.get("password", ""))
    email = text(form, "email", 200)
    invite = "send_invite" in form
    target = need(db.get(m.User, int(form["id"]))) if form.get("id") else None
    back = f"/users/{target.id}/edit" if target else "/users/new"
    if email and not mailer.valid_address(email):
        flash(request, "Die E-Mail-Adresse ist ungültig.", "err")
        return go(back)
    if invite and not email:
        flash(request, "Für die Einladung per E-Mail fehlt die E-Mail-Adresse.", "err")
        return go(back)
    if invite and not mailer.configured(mailer.load(db)):
        flash(request, "Der E-Mail-Versand ist noch nicht eingerichtet. Bitte zuerst unter „Einstellungen“ eintragen.", "err")
        return go(back)
    if password and len(password) < 12:
        flash(request, "Das Passwort braucht mindestens 12 Zeichen." + (" Leer lassen, um es nicht zu ändern." if target else ""), "err")
        return go(back)
    created = target is None
    if created:
        username = text(form, "username", 80)
        if not username or db.scalar(select(m.User).where(m.User.username == username)):
            flash(request, "Benutzername fehlt oder ist schon vergeben.", "err")
            return go(back)
        if not password and not invite:
            flash(request, "Bitte ein Passwort vergeben oder die Einladung per E-Mail ankreuzen.", "err")
            return go(back)
        # ohne eigenes Passwort bekommt das Konto ein zufälliges, das niemand kennt; es wird über den Einladungslink ersetzt
        target = m.User(username=username, password_hash=sec.hash_password(password or secrets.token_urlsafe(32)))
    elif password:
        target.password_hash = sec.hash_password(password)
    target.email = email
    perms, everything, ids = access.from_form(form)
    target.perms, target.all_tenants, target.tenant_ids = json.dumps(perms), everything, ids
    db.add(target)
    db.flush()
    if admins_left(db) == 0:
        db.rollback()
        flash(request, "Nicht gespeichert: Es muss mindestens ein Benutzer übrig bleiben, der Benutzer und Rechte verwalten darf.", "err")
        return go(back)
    db.commit()
    if invite:
        problem = await send_invite(request, db, target, user)
        if problem:
            flash(request, f"Benutzer {target.username} gespeichert, aber die Einladung ging nicht raus: {problem} "
                           "Du kannst sie beim Benutzer erneut senden.", "err")
            return go(f"/users/{target.id}/edit")
        flash(request, f"Benutzer {target.username} gespeichert. Die Einladung wurde an {target.email} geschickt.")
    else:
        flash(request, f"Benutzer {target.username} gespeichert.")
    return go("/users")


@app.post("/users/{uid}/invite")
async def users_invite(uid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    """Schickt einem Benutzer (erneut) einen Link, mit dem er sein Passwort selbst festlegt."""
    await read_form(request)
    target = need(db.get(m.User, uid))
    if not target.email:
        flash(request, "Bei diesem Benutzer ist keine E-Mail-Adresse hinterlegt.", "err")
    else:
        problem = await send_invite(request, db, target, user)
        if problem:
            flash(request, f"Die Einladung ging nicht raus: {problem}", "err")
        else:
            flash(request, f"Link zum Festlegen des Passworts an {target.email} geschickt. Er gilt {mailer.INVITE_HOURS} Stunden.")
    return go(f"/users/{uid}/edit")


def invited_user(db: Session, token: str) -> m.User | None:
    digest = hashlib.sha256(token.encode()).hexdigest()
    found = db.scalar(select(m.User).where(m.User.invite_hash == digest))
    if not found or not found.invite_expires or found.invite_expires < m.utcnow():
        return None
    return found


@app.get("/invite/{token}")
def invite_form(token: str, request: Request, db: Session = Depends(get_db)):
    return page(request, "invite.html", None, target=invited_user(db, token), token=token, hours=mailer.INVITE_HOURS)


@app.post("/invite/{token}")
async def invite_save(token: str, request: Request, db: Session = Depends(get_db)):
    form = await read_form(request)
    target = invited_user(db, token)
    if target is None:
        return page(request, "invite.html", None, target=None, token=token, hours=mailer.INVITE_HOURS)
    password = str(form.get("password", ""))
    if len(password) < 12 or password != str(form.get("repeat", "")):
        flash(request, "Das Passwort braucht mindestens 12 Zeichen, und beide Eingaben müssen gleich sein.", "err")
        return go(f"/invite/{token}")
    target.password_hash = sec.hash_password(password)
    target.invite_hash, target.invite_expires = "", None  # Link ist damit verbraucht
    db.commit()
    flash(request, "Passwort gespeichert. Du kannst dich jetzt anmelden.")
    return go("/login")


@app.get("/settings")
def settings_view(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    settings = mailer.load(db)
    return page(request, "settings.html", user, s=settings, has_password=bool(settings["smtp_password"]),
                ready=mailer.configured(settings), detected=str(request.base_url))


@app.post("/settings")
async def settings_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    form = await read_form(request)
    values = {"smtp_host": text(form, "smtp_host", 200), "smtp_user": text(form, "smtp_user", 200),
              "smtp_security": text(form, "smtp_security", 10) if text(form, "smtp_security") in ("starttls", "ssl", "none") else "starttls",
              "smtp_port": text(form, "smtp_port", 5) if text(form, "smtp_port").isdigit() else "",
              "mail_from": text(form, "mail_from", 200), "base_url": text(form, "base_url", 200)}
    if values["mail_from"] and not mailer.valid_address(values["mail_from"]):
        flash(request, "Die Absenderadresse ist ungültig. Nichts gespeichert.", "err")
        return go("/settings")
    if values["base_url"] and not re.match(r"^https?://[^\s/]+", values["base_url"]):
        flash(request, "Die Adresse des Gateways muss mit http:// oder https:// beginnen. Nichts gespeichert.", "err")
        return go("/settings")
    if str(form.get("smtp_password", "")):
        values["smtp_password"] = str(form["smtp_password"])
    if "smtp_password_clear" in form:
        values["smtp_password"] = ""
    mailer.save(db, values)
    if "send_test" in form:
        to = text(form, "test_to", 200)
        try:
            await asyncio.to_thread(mailer.deliver, mailer.load(db), to, "Testnachricht vom DIVERA Gateway",
                                    "Der E-Mail-Versand des DIVERA Gateway funktioniert.\n")
            flash(request, f"Gespeichert. Testnachricht an {to} verschickt.")
        except RuntimeError as exc:
            flash(request, f"Gespeichert, aber die Testnachricht ging nicht raus: {exc}", "err")
    else:
        flash(request, "Einstellungen gespeichert.")
    return go("/settings")


@app.post("/users/{uid}/delete")
async def users_delete(uid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(allow("users:2"))):
    await read_form(request)
    if uid == user.id:
        flash(request, "Du kannst dich nicht selbst löschen.", "err")
    else:
        db.delete(need(db.get(m.User, uid)))
        db.commit()
        flash(request, "Benutzer gelöscht.")
    return go("/users")


@app.get("/account")
def account_view(request: Request, user: m.User = Depends(current_user)):
    return page(request, "account.html", user, role=access.role_of(user))


@app.post("/account")
async def account_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    form = await read_form(request)
    if not sec.verify_password(str(form.get("current", "")), user.password_hash):
        flash(request, "Das aktuelle Passwort stimmt nicht.", "err")
    elif len(str(form.get("password", ""))) < 12:
        flash(request, "Das neue Passwort braucht mindestens 12 Zeichen.", "err")
    else:
        user.password_hash = sec.hash_password(str(form["password"]))
        db.add(user)
        db.commit()
        flash(request, "Passwort geändert.")
    return go("/account")


# ---------- Webhook-Eingang (ohne Anmeldung, Schutz über das Token in der Adresse) ----------

def _webhook_process(source_id: int, msg: dict) -> int:
    with m.SessionLocal() as db:
        return rules.process_message(db, db.get(m.Source, source_id), msg)


@app.post("/hook/{token}")
async def webhook(token: str, request: Request, db: Session = Depends(get_db)):
    source = db.scalar(select(m.Source).where(m.Source.webhook_token == token, m.Source.type == "webhook"))
    if not source or not source.active or not source.tenant.active:
        raise HTTPException(404, "Nicht gefunden")
    raw = await request.body()
    if len(raw) > MAX_WEBHOOK_BYTES:
        raise HTTPException(413, "Zu groß")
    data: dict = {}
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        try:
            parsed = json.loads(raw)
            data = parsed if isinstance(parsed, dict) else {"body": json.dumps(parsed, ensure_ascii=False)}
        except ValueError:
            raise HTTPException(400, "Ungültiges JSON")
    elif "form" in content_type:
        data = {k: str(v) for k, v in (await request.form()).items()}
    extra = {k: v for k, v in data.items() if isinstance(v, (str, int, float, bool)) and re.fullmatch(r"\w+", str(k))}
    msg = {
        "id": secrets.token_hex(8), "extra": extra,
        "from": str(data.get("from") or (request.client.host if request.client else "")),
        "subject": str(data.get("subject") or data.get("title") or ""),
        "body": str(data.get("body") or data.get("text") or data.get("message") or (raw.decode("utf-8", "replace") if not data else "")),
        "date": m.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    # Letzten Empfang für die Kontrollansicht merken (gekürzt, ohne den vollständigen Text)
    source.state = json.dumps({"last": {
        "ts": dt.datetime.now(TZ).strftime("%d.%m.%Y %H:%M:%S"), "from": msg["from"][:200], "subject": msg["subject"][:300],
        "preview": msg["body"][:200], "body": msg["body"][:4000], "fields": {k: str(v)[:100] for k, v in list(extra.items())[:30]}}})
    db.commit()
    matched = await asyncio.to_thread(_webhook_process, source.id, msg)
    return JSONResponse({"ok": True, "matched": matched})


@app.get("/help")
def help_view(request: Request, user: m.User = Depends(current_user)):
    return page(request, "help.html", user)


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": VERSION}
