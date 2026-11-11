"""Termine aus einer CSV-Datei lesen und über die DIVERA-Schnittstelle v2 (POST api/v2/events) anlegen."""
import csv
import datetime as dt
import hashlib
import io
import os
import re
from zoneinfo import ZoneInfo

import httpx

DIVERA_EVENTS_URL = os.environ.get("DIVERA_EVENTS_URL", "https://app.divera247.com/api/v2/events")
TZ = ZoneInfo(os.environ.get("TZ", "Europe/Berlin"))
MAX_BYTES = 1024 * 1024
MAX_ROWS = 200
DEFAULT_HOURS = 2  # angenommene Dauer, wenn kein Ende angegeben ist

# Spaltenüberschriften, die erkannt werden (kleingeschrieben, ohne Leerzeichen am Rand)
COLUMNS = {
    "title": ("titel", "title", "termin", "bezeichnung", "betreff", "thema", "dienst", "veranstaltung"),
    "text": ("beschreibung", "text", "bemerkung", "bemerkungen", "info", "details", "hinweis", "inhalt"),
    "address": ("ort", "adresse", "treffpunkt", "address", "wo"),
    "date": ("datum", "tag", "startdatum", "date"),
    "start": ("beginn", "start", "von", "uhrzeit", "startzeit", "anfang"),
    "end": ("ende", "bis", "end", "endzeit", "schluss"),
    "enddate": ("enddatum", "bis datum", "enddate"),
    "fullday": ("ganztägig", "ganztaegig", "ganztags", "ganztag", "fullday"),
    "groups": ("gruppen", "gruppe", "group", "groups", "empfänger", "empfaenger"),
    "id": ("id", "nummer", "nr", "nr.", "foreign_id", "kennung"),
}
LABELS = {"title": "Titel", "text": "Beschreibung", "address": "Ort", "date": "Datum", "start": "Beginn", "end": "Ende",
          "enddate": "Enddatum", "fullday": "Ganztägig", "groups": "Gruppen", "id": "ID"}
_DATE_FORMATS = ("%d.%m.%Y", "%d.%m.%y", "%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y")
_TRUE = {"ja", "j", "x", "1", "true", "wahr", "yes", "y"}


def decode(raw: bytes) -> str:
    """Excel speichert CSV je nach Einstellung als UTF-8 oder Windows-1252."""
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def split_datetime(value: str) -> tuple[dt.date | None, dt.time | None, str]:
    """Zerlegt '24.12.2026 19:00', '2026-12-24T19:00', '19:30', '19 Uhr' usw. Dritter Wert: Fehlertext oder ''."""
    value = (value or "").strip()
    if not value:
        return None, None, ""
    day = clock = None
    for part in re.split(r"[ T]+", value.replace(" Uhr", "").replace("Uhr", "").strip()):
        if not part:
            continue
        found = None
        for fmt in _DATE_FORMATS:
            try:
                found = dt.datetime.strptime(part, fmt).date()
                break
            except ValueError:
                pass
        if found:
            day = found
            continue
        match = re.fullmatch(r"(\d{1,2})(?:[:.](\d{2}))?(?::(\d{2}))?", part)
        if match and int(match.group(1)) < 24 and int(match.group(2) or 0) < 60:
            clock = dt.time(int(match.group(1)), int(match.group(2) or 0))
            continue
        return None, None, f"„{value}“ ist kein erkennbares Datum oder keine Uhrzeit"
    return day, clock, ""


def parse_csv(raw: bytes, group_lookup: dict[str, int] | None = None) -> dict:
    """Liest die Datei und liefert {"rows": [...], "columns": {...}, "error": ""}.

    Jede Zeile bekommt entweder fertige Zeitstempel oder eine Liste von Fehlern; importiert wird nur, was fehlerfrei ist.
    group_lookup ordnet kleingeschriebene DIVERA-Gruppennamen ihren IDs zu.
    """
    if len(raw) > MAX_BYTES:
        return {"rows": [], "columns": {}, "error": "Die Datei ist größer als 1 MB."}
    content = decode(raw)
    first_line = content.splitlines()[0] if content.strip() else ""
    delimiter = max(";,\t", key=first_line.count)
    reader = csv.reader(io.StringIO(content), delimiter=delimiter)
    try:
        header = next(reader)
    except (StopIteration, csv.Error):
        return {"rows": [], "columns": {}, "error": "Die Datei ist leer."}
    columns: dict[str, int] = {}
    for index, name in enumerate(header):
        clean = name.strip().lower()
        for key, aliases in COLUMNS.items():
            if clean in aliases and key not in columns:
                columns[key] = index
    if "title" not in columns:
        return {"rows": [], "columns": columns, "error": "Keine Spalte für den Titel gefunden. Erwartet wird eine Überschrift wie „Titel“ oder „Termin“."}
    if "date" not in columns and "start" not in columns:
        return {"rows": [], "columns": columns, "error": "Keine Spalte für das Datum gefunden. Erwartet wird „Datum“ oder „Beginn“."}

    now = dt.datetime.now(TZ)
    rows, seen = [], set()
    for line, cells in enumerate(reader, start=2):
        if not any(cell.strip() for cell in cells):
            continue
        if len(rows) >= MAX_ROWS:
            return {"rows": rows, "columns": columns, "error": f"Die Datei hat mehr als {MAX_ROWS} Termine. Bitte in mehrere Dateien aufteilen."}

        def cell(key: str) -> str:
            index = columns.get(key)
            return cells[index].strip() if index is not None and index < len(cells) else ""

        errors, notes = [], []
        title = cell("title")
        if not title:
            errors.append("Titel fehlt")
        date_day, _, problem1 = split_datetime(cell("date"))
        start_day, start_clock, problem2 = split_datetime(cell("start"))
        end_day, end_clock, problem3 = split_datetime(cell("end"))
        enddate_day, _, problem4 = split_datetime(cell("enddate"))
        errors.extend(p for p in (problem1, problem2, problem3, problem4) if p)
        day = start_day or date_day
        fullday = cell("fullday").lower() in _TRUE or (start_clock is None and day is not None)
        start = end = None
        if day is None:
            if not errors:
                errors.append("Datum fehlt")
        elif fullday:
            last = end_day or enddate_day or day
            start = dt.datetime.combine(day, dt.time(0, 0), TZ)
            end = dt.datetime.combine(last, dt.time(23, 59), TZ)
        else:
            start = dt.datetime.combine(day, start_clock, TZ)
            if end_clock is not None:
                end = dt.datetime.combine(end_day or enddate_day or day, end_clock, TZ)
                if end <= start and not (end_day or enddate_day):
                    end += dt.timedelta(days=1)  # z. B. 22:00 bis 01:00
                    notes.append("Ende am Folgetag angenommen")
            else:
                end = start + dt.timedelta(hours=DEFAULT_HOURS)
                notes.append(f"kein Ende angegeben, {DEFAULT_HOURS} Stunden angenommen")
        if start and end and end <= start:
            errors.append("Ende liegt vor dem Beginn")
        if start and end and end < now and not errors:
            notes.append("liegt in der Vergangenheit")

        group_ids, names = [], [n.strip() for n in re.split(r"[;,|]", cell("groups")) if n.strip()]
        for name in names:
            ident = (group_lookup or {}).get(name.lower())
            if ident is None:
                errors.append(f"Gruppe „{name}“ gibt es in der geladenen DIVERA-Liste nicht")
            else:
                group_ids.append(ident)

        key = cell("id")[:80]
        if not key and title and start:
            key = "gw-" + hashlib.sha1(f"{title}|{int(start.timestamp())}|{int(end.timestamp())}".encode()).hexdigest()[:16]
        if key and key in seen:
            errors.append("kommt in der Datei doppelt vor")
        seen.add(key)
        rows.append({
            "line": line, "key": key, "title": title[:100], "text": cell("text")[:5000], "address": cell("address")[:200],
            "fullday": fullday, "ts_start": int(start.timestamp()) if start else None, "ts_end": int(end.timestamp()) if end else None,
            "when": describe(start, end, fullday) if start and end else "", "groups": names, "group_ids": group_ids,
            "errors": errors, "notes": notes,
        })
    if not rows:
        return {"rows": [], "columns": columns, "error": "Die Datei enthält keine Termine."}
    return {"rows": rows, "columns": columns, "error": ""}


def describe(start: dt.datetime, end: dt.datetime, fullday: bool) -> str:
    if fullday:
        if start.date() == end.date():
            return start.strftime("%d.%m.%Y") + ", ganztägig"
        return start.strftime("%d.%m.%Y") + " bis " + end.strftime("%d.%m.%Y") + ", ganztägig"
    if start.date() == end.date():
        return start.strftime("%d.%m.%Y %H:%M") + " bis " + end.strftime("%H:%M")
    return start.strftime("%d.%m.%Y %H:%M") + " bis " + end.strftime("%d.%m.%Y %H:%M")


def build_event(row: dict, options: dict) -> dict:
    """Baut den JSON-Inhalt für POST api/v2/events.

    options: audience ("all" | "groups" | "persons"), group_ids, ucr_ids, push (bool), reminder_hours (int, 0 = keine).
    Stehen in der Zeile eigene Gruppen, gehen sie vor.
    """
    event: dict = {
        "foreign_id": row["key"], "title": row["title"], "ts_start": row["ts_start"], "ts_end": row["ts_end"],
        "fullday": bool(row["fullday"]), "send_push": bool(options.get("push")),
        "send_sms": False, "send_call": False, "send_mail": False, "send_pager": False,
    }
    if row["text"]:
        event["text"] = row["text"]
    if row["address"]:
        event["address"] = row["address"]
    instructions = {}
    if row["group_ids"]:
        event["notification_type"], event["group"] = 3, list(row["group_ids"])
        instructions["group"] = {"mapping": "id"}
    elif options.get("audience") == "persons" and options.get("ucr_ids"):
        event["notification_type"], event["user_cluster_relation"] = 4, list(options["ucr_ids"])
        instructions["user_cluster_relation"] = {"mapping": "id"}
    elif options.get("audience") == "groups" and options.get("group_ids"):
        event["notification_type"], event["group"] = 3, list(options["group_ids"])
        instructions["group"] = {"mapping": "id"}
    else:
        event["notification_type"] = 2
    payload: dict = {"Event": event, "instructions": instructions}
    hours = int(options.get("reminder_hours") or 0)
    if hours > 0:
        payload["Reminder"] = {"ts": row["ts_start"] - hours * 3600, "send_push": True, "send_mail": False}
    return payload


def audience_of(payload: dict) -> str:
    return {2: "alle", 3: "Gruppen", 4: "Personen"}.get(payload["Event"].get("notification_type"), "?")


def send_event(accesskey: str, payload: dict) -> tuple[bool, str]:
    if not accesskey:
        return False, "Kein DIVERA-Accesskey hinterlegt."
    try:
        resp = httpx.post(DIVERA_EVENTS_URL, params={"accesskey": accesskey}, json=payload, timeout=20)
    except httpx.HTTPError as exc:
        return False, f"Netzwerkfehler: {type(exc).__name__}"
    ok = resp.status_code in (200, 201)
    try:
        if resp.json().get("success") is False:
            ok = False
    except (ValueError, AttributeError):
        pass
    return ok, f"HTTP {resp.status_code}: {resp.text[:200]}"
