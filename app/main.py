"""Web-Oberfläche und Webhook-Eingang."""
import asyncio
import datetime as dt
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
from . import rules, sources, suggest, worker
from . import security as sec

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
    task = asyncio.create_task(worker.loop())
    yield
    task.cancel()


app = FastAPI(title="DIVERA Gateway", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=sec.SESSION_SECRET, session_cookie="gw_session", same_site="lax",
                   https_only=os.environ.get("COOKIE_SECURE", "true").lower() == "true", max_age=12 * 3600)
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE, "templates"))
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


def get_db():
    with m.SessionLocal() as db:
        yield db


def current_user(request: Request, db: Session = Depends(get_db)) -> m.User:
    uid = request.session.get("uid")
    user = db.get(m.User, uid) if uid else None
    if not user:
        raise LoginRequired()
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


def page(request: Request, name: str, user: m.User | None = None, **ctx):
    ctx.update(user=user, csrf=csrf_token(request), flash=request.session.pop("flash", None), types=SOURCE_TYPES)
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
    request.session.clear()
    request.session["uid"] = user.id
    return go("/")


@app.post("/logout")
async def logout(request: Request):
    await read_form(request)
    request.session.clear()
    return go("/login")


# ---------- Übersicht und Kunden ----------

@app.get("/")
def dashboard(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    tenants = db.scalars(select(m.Tenant).order_by(m.Tenant.name)).all()
    logs = db.scalars(select(m.Log).order_by(m.Log.id.desc()).limit(15)).all()
    return page(request, "dashboard.html", user, tenants=tenants, logs=logs)


@app.get("/tenants/new")
def tenant_new(request: Request, user: m.User = Depends(current_user)):
    return page(request, "tenant_form.html", user, tenant=None)


@app.get("/tenants/{tid}")
def tenant_view(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    tenant = need(db.get(m.Tenant, tid))
    return page(request, "tenant.html", user, tenant=tenant, base_url=str(request.base_url))


@app.get("/tenants/{tid}/edit")
def tenant_edit(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    return page(request, "tenant_form.html", user, tenant=need(db.get(m.Tenant, tid)))


@app.post("/tenants/save")
async def tenant_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    form = await read_form(request)
    tenant = need(db.get(m.Tenant, int(form["id"]))) if form.get("id") else m.Tenant()
    tenant.name = text(form, "name", 120) or "Unbenannt"
    tenant.active = "active" in form
    tenant.test_mode = "test_mode" in form
    if text(form, "accesskey"):
        tenant.accesskey_enc = sec.encrypt(text(form, "accesskey"))
    db.add(tenant)
    db.commit()
    flash(request, "Kunde gespeichert.")
    return go(f"/tenants/{tenant.id}")


@app.post("/tenants/{tid}/delete")
async def tenant_delete(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    await read_form(request)
    db.delete(need(db.get(m.Tenant, tid)))
    db.commit()
    flash(request, "Kunde gelöscht.")
    return go("/")


# ---------- Quellen ----------

@app.get("/tenants/{tid}/sources/new")
def source_new(tid: int, request: Request, type: str = "m365", db: Session = Depends(get_db),
               user: m.User = Depends(current_user)):
    if type not in SOURCE_TYPES:
        raise HTTPException(400, "Unbekannter Quelltyp")
    return page(request, "source_form.html", user, tenant=need(db.get(m.Tenant, tid)), source=None, stype=type, cfg={})


@app.get("/sources/{sid}/edit")
def source_edit(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    source = need(db.get(m.Source, sid))
    cfg = {k: v for k, v in source.config.items() if k not in ("client_secret", "password")}
    return page(request, "source_form.html", user, tenant=source.tenant, source=source, stype=source.type, cfg=cfg)


@app.post("/sources/save")
async def source_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    form = await read_form(request)
    if form.get("id"):
        source = need(db.get(m.Source, int(form["id"])))
    else:
        stype = text(form, "type", 20)
        if stype not in SOURCE_TYPES:
            raise HTTPException(400, "Unbekannter Quelltyp")
        source = m.Source(tenant_id=need(db.get(m.Tenant, int(form["tenant_id"]))).id, type=stype)
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
async def source_test(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    await read_form(request)
    source = need(db.get(m.Source, sid))
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


@app.post("/sources/{sid}/token")
async def source_token(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    await read_form(request)
    source = need(db.get(m.Source, sid))
    if source.type == "webhook":
        source.webhook_token = secrets.token_urlsafe(32)
        db.commit()
        flash(request, "Neue Webhook-Adresse erzeugt. Die alte ist ab sofort ungültig.")
    return go(f"/tenants/{source.tenant_id}")


@app.post("/sources/{sid}/delete")
async def source_delete(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    await read_form(request)
    source = need(db.get(m.Source, sid))
    tid = source.tenant_id
    db.delete(source)
    db.commit()
    flash(request, "Quelle gelöscht.")
    return go(f"/tenants/{tid}")


# ---------- Regeln ----------

def rule_page(request, user, tenant, rule, **extra):
    return page(request, "rule_form.html", user, tenant=tenant, rule=rule, **extra)


def apply_rule_form(rule: m.Rule, form, db: Session) -> str:
    """Überträgt die Formularwerte auf die Regel. Gibt eine Fehlermeldung zurück oder ''."""
    rule.name = text(form, "name", 120) or "Regel"
    rule.active, rule.priority = "active" in form, "priority" in form
    rule.require_regex, rule.stop = "require_regex" in form, "stop" in form
    rule.kind = "news" if form.get("kind") == "news" else "alarm"
    try:
        rule.position = int(form.get("position") or 10)
    except ValueError:
        rule.position = 10
    source_id = int(form["source_id"]) if form.get("source_id") else None
    if source_id and need(db.get(m.Source, source_id)).tenant_id != rule.tenant_id:
        raise HTTPException(400, "Quelle gehört zu einem anderen Kunden")
    rule.source_id = source_id
    for key in ("match_from", "match_subject", "match_body"):
        setattr(rule, key, text(form, key, 200))
    rule.ric = text(form, "ric", 300)
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


def unsaved_rule(form, db: Session) -> m.Rule:
    """Regel nur im Speicher, damit ein Probelauf oder Fehler nichts an der Datenbank ändert."""
    rule = m.Rule()
    if form.get("id"):
        existing = need(db.get(m.Rule, int(form["id"])))
        rule.id, rule.tenant_id = existing.id, existing.tenant_id
    else:
        rule.tenant_id = need(db.get(m.Tenant, int(form["tenant_id"]))).id
    return rule


@app.get("/tenants/{tid}/rules/new")
def rule_new(tid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    return rule_page(request, user, need(db.get(m.Tenant, tid)), None)


@app.get("/rules/{rid}/edit")
def rule_edit(rid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    rule = need(db.get(m.Rule, rid))
    return rule_page(request, user, rule.tenant, rule)


@app.post("/rules/test")
async def rule_test(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    form = await read_form(request)
    rule = unsaved_rule(form, db)
    error = apply_rule_form(rule, form, db)
    sample = read_sample(form)
    tenant = need(db.get(m.Tenant, rule.tenant_id))
    if not error and not sample:
        error = "Zum Prüfen bitte unten eine Beispielnachricht eintragen."
    result = evaluate(rule, sample) if sample and not error else None
    return rule_page(request, user, tenant, rule, sample=sample, result=result, error=error)


@app.post("/rules/preview")
async def rule_preview(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    """Live-Ansicht: wertet die gerade im Formular stehenden Werte aus. Speichert und sendet nichts."""
    form = await read_form(request)
    rule = unsaved_rule(form, db)
    error = apply_rule_form(rule, form, db)
    sample = read_sample(form)
    if not sample:
        return JSONResponse({"state": "nosample"})
    data = rules.preview(rule, sample)
    data.update(state="ok", form_error=error)
    return JSONResponse(data)


@app.post("/rules/save")
async def rule_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    form = await read_form(request)
    draft = unsaved_rule(form, db)
    error = apply_rule_form(draft, form, db)
    sample = read_sample(form)
    if error:
        return rule_page(request, user, need(db.get(m.Tenant, draft.tenant_id)), draft, sample=sample, error=error)
    rule = need(db.get(m.Rule, draft.id)) if draft.id else m.Rule(tenant_id=draft.tenant_id)
    apply_rule_form(rule, form, db)
    db.add(rule)
    db.commit()
    if sample:  # Beispielnachricht stehen lassen, damit man weiter herantesten kann
        return rule_page(request, user, rule.tenant, rule, sample=sample, result=evaluate(rule, sample), just_saved=True)
    flash(request, "Regel gespeichert.")
    return go(f"/rules/{rule.id}/edit")


@app.post("/sources/{sid}/suggest")
async def rule_suggest(sid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    """Erzeugt aus einer Nachricht der Quelle einen ungespeicherten Regelvorschlag."""
    form = await read_form(request)
    source = need(db.get(m.Source, sid))
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
                  require_regex=False, kind="alarm", ric="", priority=False, extra_params="", stop=True,
                  **proposal["fields"])
    sample = dict(msg, body=msg["body"][:20000], date=m.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
    return rule_page(request, user, source.tenant, rule, sample=sample, result=evaluate(rule, sample), notes=proposal["notes"])


@app.post("/rules/{rid}/delete")
async def rule_delete(rid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    await read_form(request)
    rule = need(db.get(m.Rule, rid))
    tid = rule.tenant_id
    db.delete(rule)
    db.commit()
    flash(request, "Regel gelöscht.")
    return go(f"/tenants/{tid}")


# ---------- Protokoll und Benutzer ----------

@app.get("/logs")
def logs_view(request: Request, tenant: int | None = None, status: str = "", db: Session = Depends(get_db),
              user: m.User = Depends(current_user)):
    query = select(m.Log).order_by(m.Log.id.desc()).limit(300)
    if tenant:
        query = query.where(m.Log.tenant_id == tenant)
    if status:
        query = query.where(m.Log.status == status)
    tenants = db.scalars(select(m.Tenant).order_by(m.Tenant.name)).all()
    return page(request, "logs.html", user, logs=db.scalars(query).all(), tenants=tenants, sel_tenant=tenant, sel_status=status)


@app.get("/users")
def users_view(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    return page(request, "users.html", user, users=db.scalars(select(m.User).order_by(m.User.username)).all())


@app.post("/users/save")
async def users_save(request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    form = await read_form(request)
    password = str(form.get("password", ""))
    if len(password) < 12:
        flash(request, "Das Passwort braucht mindestens 12 Zeichen.", "err")
        return go("/users")
    if form.get("id"):
        target = need(db.get(m.User, int(form["id"])))
    else:
        username = text(form, "username", 80)
        if not username or db.scalar(select(m.User).where(m.User.username == username)):
            flash(request, "Benutzername fehlt oder ist schon vergeben.", "err")
            return go("/users")
        target = m.User(username=username)
    target.password_hash = sec.hash_password(password)
    db.add(target)
    db.commit()
    flash(request, f"Benutzer {target.username} gespeichert.")
    return go("/users")


@app.post("/users/{uid}/delete")
async def users_delete(uid: int, request: Request, db: Session = Depends(get_db), user: m.User = Depends(current_user)):
    await read_form(request)
    if uid == user.id:
        flash(request, "Du kannst dich nicht selbst löschen.", "err")
    else:
        db.delete(need(db.get(m.User, uid)))
        db.commit()
        flash(request, "Benutzer gelöscht.")
    return go("/users")


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


@app.get("/healthz")
def healthz():
    return {"ok": True}
