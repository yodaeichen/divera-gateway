"""Regelauswertung und Übergabe an die DIVERA-API."""
import json
import logging
import os
import re
import time

import httpx
from sqlalchemy import or_, select

from . import db as m
from . import security as sec

log = logging.getLogger("gateway.rules")
DIVERA_API_URL = os.environ.get("DIVERA_API_URL", "https://app.divera247.com/api/alarm")
DIVERA_NEWS_URL = os.environ.get("DIVERA_NEWS_URL", "https://app.divera247.com/api/v2/news")
DIVERA_PULL_URL = os.environ.get("DIVERA_PULL_URL", "https://app.divera247.com/api/v2/pull/all")
# Laut DIVERA-Dokumentation vom Typ "Integer-Array": werden als Liste übertragen, nicht als Text mit Kommas.
ARRAY_KEYS = ("group_ids", "cluster_ids", "user_cluster_relation_ids", "ucr", "vehicle_ids")
RECIPIENT_KEYS = ("ric", "group_ids", "user_cluster_relation_ids", "ucr", "cluster_ids", "vehicle", "vehicle_ids", "person", "alarmcode_id")
LIMITS = {"title": 50, "text": 1000, "address": 200}
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def render(template: str, values: dict) -> str:
    """Ersetzt {name} durch den Wert; unbekannte Platzhalter werden leer."""
    return _PLACEHOLDER.sub(lambda mt: str(values.get(mt.group(1), "")), template or "").strip()


def split_terms(needle: str) -> list[str]:
    """Zerlegt ein Bedingungsfeld an Semikolons in einzelne Suchbegriffe."""
    return [term.strip() for term in (needle or "").split(";") if term.strip()]


def analyse(rule: m.Rule, msg: dict, strict: bool = False) -> dict:
    """Wertet eine Regel gegen eine Nachricht aus und hält jeden Zwischenschritt fest.

    Dieselbe Funktion entscheidet im Betrieb und füllt die Live-Ansicht, damit beide nie auseinanderlaufen.
    Mit strict=True lösen fehlerhafte Ausdrücke eine re.error aus, sonst werden sie nur vermerkt.
    """
    conditions = []
    for label, needle, haystack in (("Absender", rule.match_from, msg["from"]), ("Betreff", rule.match_subject, msg["subject"]),
                                    ("Text", rule.match_body, msg["body"])):
        terms = split_terms(needle)
        if terms:  # mehrere Begriffe mit Semikolon: einer davon genügt
            hit = next((term for term in terms if term.lower() in (haystack or "").lower()), "")
            conditions.append({"label": label, "needle": needle, "terms": terms, "hit": hit, "ok": bool(hit)})
    values = {k: str(v) for k, v in (msg.get("extra") or {}).items()}
    values.update({"from": msg["from"], "subject": msg["subject"], "body": msg["body"], "date": msg.get("date", "")})
    haystack = msg["subject"] + "\n" + msg["body"].replace("\r\n", "\n")
    expressions = []
    for line in (rule.extract_regex or "").splitlines():  # ein Ausdruck je Zeile
        if not line.strip():
            continue
        try:
            found = re.search(line.strip(), haystack, re.M | re.I)
        except re.error as exc:
            if strict:
                raise
            expressions.append({"line": line.strip(), "ok": False, "error": str(exc), "groups": {}})
            continue
        groups = {k: (v or "").strip() for k, v in found.groupdict().items()} if found else {}
        values.update(groups)
        expressions.append({"line": line.strip(), "ok": bool(found), "error": "", "groups": groups})
    match = all(c["ok"] for c in conditions) and (not rule.require_regex or all(e["ok"] for e in expressions))
    return {"match": match, "conditions": conditions, "expressions": expressions, "values": values}


def match_rule(rule: m.Rule, msg: dict) -> dict | None:
    """Gibt die Platzhalterwerte zurück, wenn die Regel passt, sonst None."""
    result = analyse(rule, msg, strict=True)
    return result["values"] if result["match"] else None


def preview(rule: m.Rule, msg: dict) -> dict:
    """Alles für die Live-Ansicht: Auswertung, fertige Felder mit Längen, leere Platzhalter und die API-Daten."""
    result = analyse(rule, msg)
    values = result.pop("values")
    fields = []
    for key, label, template in (("title", "Stichwort", rule.title_tpl), ("address", "Adresse", rule.address_tpl),
                                 ("text", "Text", rule.text_tpl)):
        full = render(template, values)
        fields.append({"key": key, "label": label, "value": full[:LIMITS[key]], "length": len(full), "limit": LIMITS[key]})
    used = _PLACEHOLDER.findall(" ".join([rule.title_tpl or "", rule.text_tpl or "", rule.address_tpl or "", rule.ric or "",
                                          rule.extra_params or ""]))
    result.update(
        fields=fields, payload=(payload := build_payload(rule, values)), kind=rule.kind,
        has_recipient="News" in payload or any(payload.get(key) for key in RECIPIENT_KEYS), plan=plan(rule), priority=bool(rule.priority),
        active=bool(rule.active), require_regex=bool(rule.require_regex),
        unknown=sorted({name for name in used if name not in values}),
        empty=sorted({name for name in used if name in values and not values[name]}),
        placeholders={k: v[:80] for k, v in values.items() if k != "body"},
    )
    return result


def id_list(value) -> list[str]:
    """Bereinigt eine Liste von DIVERA-IDs: nur Zahlen, ohne Doppelte, Reihenfolge bleibt."""
    parts = value if isinstance(value, (list, tuple)) else str(value or "").split(",")
    seen: list[str] = []
    for part in parts:
        part = str(part).strip()
        if part.isdigit() and part not in seen:
            seen.append(part)
    return seen


def _entries(node) -> list[dict]:
    """Liest {id: {...}} oder [{id: ...}] aus der DIVERA-Antwort und liefert sortierte {id, name}-Einträge."""
    if isinstance(node, dict):
        items = list(node.items())
    elif isinstance(node, list):
        items = [(entry.get("id"), entry) for entry in node if isinstance(entry, dict)]
    else:
        items = []
    result = []
    for key, entry in items:
        if not isinstance(entry, dict):
            continue
        ident = str(entry.get("id", key))
        name = (entry.get("stdformat_name") or " ".join(str(x) for x in (entry.get("firstname"), entry.get("lastname")) if x)
                or entry.get("name") or entry.get("title") or f"ID {ident}")
        if ident.isdigit():
            result.append({"id": int(ident), "name": str(name).strip()[:120]})
    return sorted(result, key=lambda e: e["name"].lower())


def parse_directory(data) -> dict:
    cluster = ((data or {}).get("data") or {}).get("cluster") if isinstance(data, dict) else None
    if not isinstance(cluster, dict):
        keys = ", ".join(list(data)[:8]) if isinstance(data, dict) else type(data).__name__
        raise RuntimeError(f"Unerwartete Antwort von DIVERA (enthält: {keys}).")
    directory = {"persons": _entries(cluster.get("consumer")), "groups": _entries(cluster.get("group"))}
    if not directory["persons"] and not directory["groups"]:
        raise RuntimeError("DIVERA hat weder Personen noch Gruppen geliefert. Darf dieser Accesskey die Stammdaten lesen?")
    return directory


def fetch_directory(accesskey: str) -> dict:
    """Lädt Personen und Gruppen der Einheit aus DIVERA, damit man sie in Regeln auswählen kann."""
    if not accesskey:
        raise RuntimeError("Kein DIVERA-Accesskey hinterlegt.")
    try:
        resp = httpx.get(DIVERA_PULL_URL, params={"accesskey": accesskey}, timeout=20)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Netzwerkfehler: {type(exc).__name__}") from None
    if resp.status_code in (401, 403):
        raise RuntimeError(f"DIVERA lehnt den Accesskey für diese Abfrage ab (HTTP {resp.status_code}).")
    if resp.status_code != 200:
        raise RuntimeError(f"DIVERA antwortet mit HTTP {resp.status_code}.")
    try:
        return parse_directory(resp.json())
    except ValueError:
        raise RuntimeError("DIVERA hat keine lesbare Antwort geliefert.") from None


def wants_push(rule: m.Rule) -> bool:
    return rule.push is None or bool(rule.push)


def plan(rule: m.Rule) -> dict:
    """Legt fest, über welche DIVERA-Schnittstelle eine Regel sendet und wen sie damit erreicht.

    v1 (api/alarm) ist der bisherige Weg mit RIC. v2 (api/v2/news) wird für Mitteilungen genommen, wenn sie ohne Push
    gehen sollen oder wenn Gruppen bzw. Personen angekreuzt sind und keine RIC eingetragen ist: nur dort lassen sich
    Push und der Empfängerkreis ausdrücklich festlegen.
    """
    persons, groups, ric = id_list(rule.ucr_ids), id_list(rule.group_ids), (rule.ric or "").strip()
    push = wants_push(rule) or rule.kind != "news"
    if rule.kind != "news" or (push and (ric or not (persons or groups))):
        return {"route": "v1", "push": push, "ntype": None, "audience": "", "notes": []}
    notes = []
    if persons:
        ntype, audience = 4, "nur die angekreuzten Personen"
        if groups:
            notes.append("Gruppen und Personen sind beide angekreuzt. Bei diesem Übertragungsweg zählen dann nur die Personen.")
    elif groups:
        ntype, audience = 3, "nur die angekreuzten Gruppen"
    else:
        ntype, audience = 2, "alle Mitglieder der Einheit"
    if ric:
        notes.append("Die RIC wird bei „ohne Push“ nicht übertragen. Kreuze stattdessen Gruppen oder Personen an.")
    if (rule.extra_params or "").strip():
        notes.append("„Weitere API-Parameter“ werden bei diesem Übertragungsweg nicht mitgeschickt.")
    return {"route": "v2", "push": push, "ntype": ntype, "audience": audience, "notes": notes}


def title_of(payload: dict) -> str:
    return str((payload.get("News") or payload).get("title", ""))


def build_news_v2(rule: m.Rule, values: dict, route: dict) -> dict:
    """Mitteilung für POST api/v2/news (JSON), Aufbau nach der DIVERA-Dokumentation."""
    news: dict = {
        "title": render(rule.title_tpl, values)[:LIMITS["title"]],
        "text": render(rule.text_tpl, values)[:LIMITS["text"]],
        "notification_type": route["ntype"],
        "send_push": route["push"],
    }
    address = render(rule.address_tpl, values)[:LIMITS["address"]]
    if address:
        news["address"] = address
    if not route["push"]:  # ausdrücklich still: auch keine SMS, Anrufe, Mails oder Pager
        news.update(send_sms=False, send_call=False, send_mail=False, send_pager=False)
    instructions = {}
    if route["ntype"] == 4:
        news["user_cluster_relation"] = [int(i) for i in id_list(rule.ucr_ids)]
        instructions["user_cluster_relation"] = {"mapping": "id"}
    elif route["ntype"] == 3:
        news["group"] = [int(i) for i in id_list(rule.group_ids)]
        instructions["group"] = {"mapping": "id"}
    return {"News": news, "instructions": instructions}


def build_payload(rule: m.Rule, values: dict) -> dict:
    route = plan(rule)
    if route["route"] == "v2":
        return build_news_v2(rule, values, route)
    payload = {
        "title": render(rule.title_tpl, values)[:LIMITS["title"]],
        "text": render(rule.text_tpl, values)[:LIMITS["text"]],
    }
    address = render(rule.address_tpl, values)[:LIMITS["address"]]
    if address:
        payload["address"] = address
    if rule.ric.strip():
        payload["ric"] = render(rule.ric, values)
    if id_list(rule.ucr_ids):
        # Zwei dokumentierte Wege zugleich: die ID-Liste und "person" (nimmt laut Doku Fremdschlüssel oder IDs, mit Komma)
        payload["user_cluster_relation_ids"] = id_list(rule.ucr_ids)
        payload["person"] = ",".join(id_list(rule.ucr_ids))
    if id_list(rule.group_ids):
        payload["group_ids"] = id_list(rule.group_ids)
    if rule.priority:
        payload["priority"] = "1"
    if rule.kind == "news":
        payload["news"] = "1"
    for line in (rule.extra_params or "").splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key and key != "accesskey":
            payload[key] = id_list(render(value, values)) if key in ARRAY_KEYS else render(value, values)
    return payload


def key_for(tenant: m.Tenant, payload: dict | None = None) -> str:
    """Der passende Accesskey: für die v2-Schnittstelle der persönliche Schlüssel, wenn einer hinterlegt ist."""
    if (payload is None or "News" in payload) and tenant.accesskey_user_enc:
        return sec.decrypt(tenant.accesskey_user_enc)
    return sec.decrypt(tenant.accesskey_enc)


V2_FORBIDDEN_HINT = (" Hinweis: Die v2-Schnittstelle hat den Accesskey abgelehnt. Sie verlangt den persönlichen Accesskey eines "
                     "DIVERA-Benutzers, der Mitteilungen schreiben darf. Trage ihn beim Kunden unter „Persönlicher Accesskey“ ein.")


def encode_payload(payload: dict) -> dict:
    """Formulardaten für DIVERA: Listen gehen als wiederholtes name[]=wert, so entsteht dort ein Array."""
    return {(f"{key}[]" if isinstance(value, list) else key): value for key, value in payload.items()}


def send_divera(accesskey: str, payload: dict) -> tuple[bool, str]:
    if not accesskey:
        return False, "Kein DIVERA-Accesskey hinterlegt."
    error = ""
    for attempt in range(3):
        try:
            if "News" in payload:  # Mitteilung über die JSON-Schnittstelle v2
                resp = httpx.post(DIVERA_NEWS_URL, params={"accesskey": accesskey}, json=payload, timeout=15)
            else:
                resp = httpx.post(DIVERA_API_URL, params={"accesskey": accesskey}, data=encode_payload(payload), timeout=15)
            body = resp.text[:300]
            ok = resp.status_code == 200
            try:
                if resp.json().get("success") is False:
                    ok = False
            except (ValueError, AttributeError):
                pass
            if ok or resp.status_code < 500:
                hint = V2_FORBIDDEN_HINT if "News" in payload and resp.status_code in (401, 403) else ""
                return ok, f"HTTP {resp.status_code}: {body}{hint}"
            error = f"HTTP {resp.status_code}: {body}"
        except httpx.HTTPError as exc:
            error = f"Netzwerkfehler: {type(exc).__name__}"
        time.sleep(1 + attempt * 2)
    return False, error


def applicable_rules(db, source: m.Source) -> list[m.Rule]:
    return list(db.scalars(
        select(m.Rule).where(m.Rule.tenant_id == source.tenant_id, m.Rule.active,
                             or_(m.Rule.source_id.is_(None), m.Rule.source_id == source.id))
        .order_by(m.Rule.position, m.Rule.id)))


def process_message(db, source: m.Source, msg: dict) -> int:
    """Wendet die Regeln des Kunden auf eine Nachricht an. Gibt die Zahl der Treffer zurück."""
    tenant = source.tenant
    common = dict(tenant_id=tenant.id, tenant_name=tenant.name, source_name=source.name,
                  sender=msg["from"][:200], subject=msg["subject"][:300])
    matched = 0
    for rule in applicable_rules(db, source):
        try:
            values = match_rule(rule, msg)
        except re.error as exc:
            db.add(m.Log(**common, rule_name=rule.name, status="fehler", detail=f"Regex ungültig: {exc}"))
            continue
        if values is None:
            continue
        matched += 1
        payload = build_payload(rule, values)
        if tenant.test_mode:
            status, detail = "test", "Testmodus, nicht gesendet: " + json.dumps(payload, ensure_ascii=False)
        else:
            ok, detail = send_divera(key_for(tenant, payload), payload)
            status = "gesendet" if ok else "fehler"
            detail = f"{title_of(payload)} | {detail}"
        db.add(m.Log(**common, rule_name=rule.name, status=status, detail=detail[:2000]))
        if rule.stop:
            break
    if not matched:
        db.add(m.Log(**common, status="ignoriert", detail="Keine Regel passt."))
    db.commit()
    return matched
