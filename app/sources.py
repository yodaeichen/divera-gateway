"""Abruf neuer Nachrichten aus Microsoft 365 (Graph) und IMAP.

Jeder Poller bekommt (config, state) und liefert (nachrichten, neuer_state).
Beim ersten Lauf wird nur der aktuelle Stand gemerkt; alte Mails lösen nichts aus.
Nachricht: {"id", "from", "subject", "body", "date", "ts" (datetime, UTC)}
"""
import datetime as dt
import email
import html
import imaplib
import re
import time
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import quote

import httpx

GRAPH = "https://graph.microsoft.com/v1.0"
MAX_PER_POLL = 50
PAGE_SIZE = 25  # Listeneinträge je Antwort von Microsoft (ohne Text); weitere Seiten werden nachgeladen
RETRY_STATUS = {429, 502, 503, 504}
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
PREVIEW_COUNT = 5
TIMEOUT = 20


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style).*?</\1>", "", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", markup)
    text = html.unescape(re.sub(r"<[^>]+>", "", markup))
    return re.sub(r"\n{3,}", "\n\n", text).strip()


# ---------- Microsoft 365 ----------

GRAPH_TIMEOUT = httpx.Timeout(45, connect=10)
GRAPH_TRIES = 3


def _request(method: str, url: str, **kwargs) -> httpx.Response:
    """Aufruf bei Microsoft mit Geduld: Antwortet der Dienst nicht rechtzeitig oder bricht die Verbindung ab,
    wird es noch zweimal versucht, bevor der Abruf als fehlgeschlagen gilt."""
    problem = "unbekannt"
    for attempt in range(GRAPH_TRIES):
        pause = 2 + attempt * 3
        try:
            resp = httpx.request(method, url, timeout=GRAPH_TIMEOUT, **kwargs)
            if resp.status_code not in RETRY_STATUS:
                return resp
            # 429 = zu viele Anfragen, 502/503/504 = Störung bei Microsoft: kurz warten und noch einmal versuchen
            problem = f"Microsoft meldet eine vorübergehende Störung (HTTP {resp.status_code})"
            wait = resp.headers.get("Retry-After", "") if hasattr(resp, "headers") else ""
            if str(wait).isdigit():
                pause = min(int(wait), 20)
        except httpx.TimeoutException:
            problem = "Microsoft hat nicht rechtzeitig geantwortet (Zeitüberschreitung)"
        except httpx.TransportError as exc:
            problem = f"Verbindung zu Microsoft gestört ({type(exc).__name__})"
        if attempt < GRAPH_TRIES - 1:
            time.sleep(pause)
    raise RuntimeError(f"{problem}, auch nach {GRAPH_TRIES} Versuchen. Meist vorübergehend; der nächste Abruf versucht es erneut.")


_TOKENS: dict[tuple, tuple[str, float]] = {}


def _graph_token(cfg: dict) -> str:
    """Zugangs-Token von Microsoft. Es gilt etwa eine Stunde und wird so lange wiederverwendet, statt bei jedem Abruf neu geholt."""
    cache_key = (cfg.get("tenant_id"), cfg.get("client_id"), cfg.get("client_secret", ""))
    cached = _TOKENS.get(cache_key)
    if cached and cached[1] > time.time():
        return cached[0]
    token, lifetime = _new_token(cfg)
    _TOKENS[cache_key] = (token, time.time() + max(60, lifetime - 300))
    return token


def _forget_token(cfg: dict):
    _TOKENS.pop((cfg.get("tenant_id"), cfg.get("client_id"), cfg.get("client_secret", "")), None)


def _new_token(cfg: dict) -> tuple[str, int]:
    resp = _request("POST", 
        f"https://login.microsoftonline.com/{cfg['tenant_id']}/oauth2/v2.0/token",
        data={"grant_type": "client_credentials", "client_id": cfg["client_id"],
              "client_secret": cfg.get("client_secret", ""), "scope": "https://graph.microsoft.com/.default"})
    if resp.status_code != 200:
        info = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        raise RuntimeError("Anmeldung bei Microsoft fehlgeschlagen: " + str(info.get("error_description", resp.status_code))[:300])
    data = resp.json()
    return data["access_token"], int(data.get("expires_in") or 3600)


def _graph_error(cfg: dict, resp) -> RuntimeError:
    if resp.status_code == 401:
        _forget_token(cfg)  # Token abgelaufen oder widerrufen: beim nächsten Abruf neu anmelden
    try:
        reason = resp.json()["error"]["message"]
    except Exception:
        reason = getattr(resp, "text", "")
    return RuntimeError(f"Graph-Fehler {resp.status_code}: {str(reason)[:300] or 'ohne nähere Angabe von Microsoft'}")


WELL_KNOWN = {"inbox", "archive", "drafts", "sentitems", "deleteditems", "junkemail", "outbox", "msgfolderroot"}
ALIASES = {"posteingang": "inbox", "archiv": "archive", "junk-e-mail": "junkemail", "gelöschte elemente": "deleteditems"}


def _find_folder(cfg: dict, headers: dict, parent: str | None, name: str) -> str:
    """Sucht einen Ordner per Anzeigename, entweder auf oberster Ebene oder unter einem Elternordner."""
    base = f"{GRAPH}/users/{cfg['mailbox']}/mailFolders"
    url = f"{base}/{parent}/childFolders" if parent else base
    escaped = name.replace("'", "''")
    resp = _request("GET", url, params={"$filter": f"displayName eq '{escaped}'", "$select": "id"}, headers=headers)
    if resp.status_code != 200:
        raise _graph_error(cfg, resp)
    found = resp.json().get("value", [])
    if not found:
        raise RuntimeError(f"Ordner '{name}' nicht gefunden. Schreibweise wie in Outlook, Unterordner mit / trennen.")
    return found[0]["id"]


_FOLDERS: dict[tuple, tuple[str, float]] = {}


def _resolve_folder(cfg: dict, headers: dict) -> str:
    """Wie _lookup_folder, merkt sich das Ergebnis aber eine Stunde: Die Ordner-ID ändert sich nicht, und so entfallen
    bei Unterordnern ein bis zwei zusätzliche Anfragen je Abruf."""
    cache_key = (cfg.get("mailbox"), (cfg.get("folder") or "inbox").strip().lower())
    cached = _FOLDERS.get(cache_key)
    if cached and cached[1] > time.time():
        return cached[0]
    folder = _lookup_folder(cfg, headers)
    _FOLDERS[cache_key] = (folder, time.time() + 3600)
    return folder


def _lookup_folder(cfg: dict, headers: dict) -> str:
    """Erlaubt Pfade wie 'Posteingang/Alarme/Leitstelle', Standardnamen wie 'inbox' oder eine Ordner-ID."""
    parts = [p.strip() for p in (cfg.get("folder") or "inbox").replace("\\", "/").split("/") if p.strip()] or ["inbox"]
    first = ALIASES.get(parts[0].lower(), parts[0])
    if first.lower() in WELL_KNOWN:
        folder = first.lower()
    elif len(parts) == 1 and len(first) > 60 and " " not in first:
        return first  # sieht nach einer Ordner-ID aus
    else:
        folder = _find_folder(cfg, headers, None, first)
    for name in parts[1:]:
        folder = _find_folder(cfg, headers, folder, name)
    return folder


def _graph_messages(cfg: dict, params: dict, limit: int = MAX_PER_POLL) -> list[dict]:
    token = _graph_token(cfg)
    headers = {"Authorization": f"Bearer {token}", "Prefer": 'outlook.body-content-type="text"'}
    folder = _resolve_folder(cfg, headers)
    url = f"{GRAPH}/users/{cfg['mailbox']}/mailFolders/{folder}/messages"
    items: list[dict] = []
    while url and len(items) < limit:
        resp = _request("GET", url, params=params, headers=headers)
        if resp.status_code != 200:
            if resp.status_code == 404:  # Ordner umbenannt oder gelöscht: beim nächsten Abruf neu suchen
                _FOLDERS.pop((cfg.get("mailbox"), (cfg.get("folder") or "inbox").strip().lower()), None)
            raise _graph_error(cfg, resp)
        data = resp.json()
        items.extend(data.get("value", []))
        url, params = data.get("@odata.nextLink"), None
    return items[:limit]


def _graph_body(cfg: dict, item: dict) -> str:
    """Holt den Text einer einzelnen Nachricht. Die Liste wird ohne Texte abgefragt, weil das Umwandeln vieler Mails
    in einer Antwort bei Microsoft zu Zeitüberschreitungen führt. Scheitert es bei einer Nachricht, wird ihr
    Textanfang verwendet, damit eine einzelne problematische Mail nicht das ganze Postfach blockiert."""
    headers = {"Authorization": f"Bearer {_graph_token(cfg)}", "Prefer": 'outlook.body-content-type="text"'}
    try:
        resp = _request("GET", f"{GRAPH}/users/{cfg['mailbox']}/messages/{quote(item['id'], safe='')}", params={"$select": "body"}, headers=headers)
        if resp.status_code == 200:
            return ((resp.json().get("body") or {}).get("content") or "").strip()
        if resp.status_code == 401:
            _forget_token(cfg)
    except RuntimeError:
        pass
    return (item.get("bodyPreview") or "").strip()


def poll_m365(cfg: dict, state: dict) -> tuple[list[dict], dict]:
    """Holt alles ab dem gemerkten Zeitpunkt. Was bei genau diesem Zeitpunkt schon gelesen wurde, steht in state["seen"]
    und wird nicht noch einmal geliefert: So wird jede Nachricht genau einmal übergeben, egal wie alt sie ist."""
    if "since" not in state:
        _graph_token(cfg)  # Zugang prüfen, Startpunkt merken
        return [], {"since": _now().strftime("%Y-%m-%dT%H:%M:%SZ"), "seen": []}
    raw = _graph_messages(cfg, {
        "$filter": f"receivedDateTime ge {state['since']}",
        "$orderby": "receivedDateTime asc",
        "$top": str(PAGE_SIZE),
        "$select": "id,internetMessageId,subject,from,bodyPreview,receivedDateTime",
    })
    seen = set(state.get("seen") or [])
    legacy = "seen" not in state  # Stand aus einer Version vor 1.28: was genau zum gemerkten Zeitpunkt einging, gilt als gelesen
    newest, at_newest, messages = state["since"], list(state.get("seen") or []), []
    for item in raw:
        received = item.get("receivedDateTime", "")
        key = item.get("internetMessageId") or item["id"]
        if key in seen:
            continue
        if legacy and received == state["since"]:
            at_newest.append(key)
            continue
        ts = dt.datetime.fromisoformat(received.replace("Z", "+00:00")) if received else _now()
        messages.append({
            "id": key,
            "from": ((item.get("from") or {}).get("emailAddress") or {}).get("address", ""),
            "subject": item.get("subject") or "",
            "body": _graph_body(cfg, item),
            "date": received, "ts": ts,
        })
        if received and received > newest:
            newest, at_newest = received, [key]
        elif received == newest:
            at_newest.append(key)
    return messages, {"since": newest, "seen": at_newest[-200:]}


def _naive_utc(value: dt.datetime) -> dt.datetime:
    value = value.replace(tzinfo=dt.timezone.utc) if value.tzinfo is None else value.astimezone(dt.timezone.utc)
    return value.replace(tzinfo=None)


def test_m365(cfg: dict) -> dict:
    """Verbindungstest: liefert die neuesten Nachrichten des Ordners zur Kontrolle."""
    raw = _graph_messages(cfg, {"$top": str(PREVIEW_COUNT), "$orderby": "receivedDateTime desc",
                                "$select": "id,subject,from,receivedDateTime,bodyPreview"}, limit=PREVIEW_COUNT)
    items = []
    for item in raw:
        received = item.get("receivedDateTime", "")
        items.append({
            "ts": _naive_utc(dt.datetime.fromisoformat(received.replace("Z", "+00:00"))) if received else None,
            "from": ((item.get("from") or {}).get("emailAddress") or {}).get("address", ""),
            "subject": item.get("subject") or "", "preview": (item.get("bodyPreview") or "")[:200],
            "ref": item.get("id", ""),
        })
    return {"message": "Verbindung in Ordnung, Anmeldung und Ordner erreichbar.", "items": items}


# ---------- IMAP ----------

def _imap_connect(cfg: dict) -> imaplib.IMAP4:
    host, port = cfg["host"], int(cfg.get("port") or 993)
    if (cfg.get("security") or "ssl") == "ssl":
        conn = imaplib.IMAP4_SSL(host, port, timeout=TIMEOUT)
    else:
        conn = imaplib.IMAP4(host, port, timeout=TIMEOUT)
        conn.starttls()
    conn.login(cfg["username"], cfg.get("password", ""))
    status, _ = conn.select(cfg.get("folder") or "INBOX", readonly=True)
    if status != "OK":
        raise RuntimeError("IMAP-Ordner nicht gefunden.")
    return conn


def _imap_uids(conn: imaplib.IMAP4, criteria: str) -> list[int]:
    status, data = conn.uid("search", None, criteria)
    if status != "OK":
        raise RuntimeError("IMAP-Suche fehlgeschlagen.")
    return sorted(int(u) for u in (data[0] or b"").split())


def _parse_mail(raw: bytes) -> tuple[str, str, str, dt.datetime]:
    """Zerlegt eine Roh-Mail in Absender, Betreff, Text und Zeitpunkt (UTC)."""
    mail = email.message_from_bytes(raw, policy=policy.default)
    part = mail.get_body(preferencelist=("plain", "html"))
    body = part.get_content() if part else ""
    if part and part.get_content_type() == "text/html":
        body = html_to_text(body)
    try:
        ts = parsedate_to_datetime(str(mail["Date"]))
        ts = ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts.astimezone(dt.timezone.utc)
    except (TypeError, ValueError):
        ts = _now()
    return parseaddr(str(mail.get("From", "")))[1], str(mail.get("Subject", "")), str(body).strip(), ts


def poll_imap(cfg: dict, state: dict) -> tuple[list[dict], dict]:
    conn = _imap_connect(cfg)
    try:
        validity = (conn.response("UIDVALIDITY")[1] or [b"0"])[0]
        validity = validity.decode() if isinstance(validity, bytes) else str(validity)
        rewind = None
        if state.get("rewind"):
            # Zurückgesetzt: einmalig alles ab dem gewählten Zeitpunkt erneut lesen, danach normal weiter
            rewind = dt.datetime.fromisoformat(state["rewind"].replace("Z", "+00:00"))
            day = rewind - dt.timedelta(days=1)  # IMAP sucht nur tagesgenau und in Serverzeit, daher großzügig
            everything = _imap_uids(conn, "ALL")
            uids = _imap_uids(conn, f"SINCE {day.day:02d}-{_MONTHS[day.month - 1]}-{day.year}")[-MAX_PER_POLL:]
            last = everything[-1] if everything else 0
        elif state.get("uidvalidity") != validity or "last_uid" not in state:
            uids = _imap_uids(conn, "ALL")
            return [], {"uidvalidity": validity, "last_uid": uids[-1] if uids else 0}
        else:
            last = int(state["last_uid"])
            uids = [u for u in _imap_uids(conn, f"UID {last + 1}:*") if u > last][:MAX_PER_POLL]
        messages = []
        for uid in uids:
            status, data = conn.uid("fetch", str(uid), "(BODY.PEEK[])")
            last = max(last, uid)
            if status != "OK" or not data or not isinstance(data[0], tuple):
                continue
            sender, subject, body, ts = _parse_mail(data[0][1])
            if rewind is not None and ts < rewind:
                continue
            messages.append({"id": f"{validity}:{uid}", "from": sender, "subject": subject, "body": body,
                             "date": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "ts": ts})
        return messages, {"uidvalidity": validity, "last_uid": last}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def test_imap(cfg: dict) -> dict:
    """Verbindungstest: liefert Absender, Betreff und Datum der neuesten Nachrichten."""
    conn = _imap_connect(cfg)
    items = []
    try:
        for uid in reversed(_imap_uids(conn, "ALL")[-PREVIEW_COUNT:]):
            status, data = conn.uid("fetch", str(uid), "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
            if status != "OK" or not data or not isinstance(data[0], tuple):
                continue
            mail = email.message_from_bytes(data[0][1], policy=policy.default)
            try:
                ts = _naive_utc(parsedate_to_datetime(str(mail["Date"])))
            except (TypeError, ValueError):
                ts = None
            items.append({"ts": ts, "from": parseaddr(str(mail.get("From", "")))[1],
                          "subject": str(mail.get("Subject", "")), "preview": "", "ref": str(uid)})
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return {"message": "Verbindung in Ordnung, Anmeldung und Ordner erreichbar.", "items": items}


def fetch_m365(cfg: dict, ref: str) -> dict:
    """Holt eine einzelne Nachricht vollständig, als Vorlage für einen Regelvorschlag."""
    headers = {"Authorization": f"Bearer {_graph_token(cfg)}", "Prefer": 'outlook.body-content-type="text"'}
    resp = _request("GET", f"{GRAPH}/users/{cfg['mailbox']}/messages/{quote(ref, safe='')}",
                     params={"$select": "internetMessageId,subject,from,body,receivedDateTime"}, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"Graph-Fehler {resp.status_code} beim Laden der Nachricht.")
    item = resp.json()
    return {"id": item.get("internetMessageId") or ref, "date": item.get("receivedDateTime", ""),
            "from": ((item.get("from") or {}).get("emailAddress") or {}).get("address", ""),
            "subject": item.get("subject") or "", "body": ((item.get("body") or {}).get("content") or "").strip()}


def fetch_imap(cfg: dict, ref: str) -> dict:
    if not ref.isdigit():
        raise RuntimeError("Ungültige Nachrichtenkennung.")
    conn = _imap_connect(cfg)
    try:
        status, data = conn.uid("fetch", ref, "(BODY.PEEK[])")
        if status != "OK" or not data or not isinstance(data[0], tuple):
            raise RuntimeError("Nachricht nicht mehr vorhanden.")
        sender, subject, body, ts = _parse_mail(data[0][1])
        validity = (conn.response("UIDVALIDITY")[1] or [b"0"])[0]
        validity = validity.decode() if isinstance(validity, bytes) else str(validity)
        return {"id": f"{validity}:{ref}", "date": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "from": sender, "subject": subject, "body": body}
    finally:
        try:
            conn.logout()
        except Exception:
            pass


FETCHERS = {"m365": fetch_m365, "imap": fetch_imap}
POLLERS = {"m365": poll_m365, "imap": poll_imap}
TESTERS = {"m365": test_m365, "imap": test_imap}
