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
        fields=fields, payload=build_payload(rule, values), kind=rule.kind, priority=bool(rule.priority),
        active=bool(rule.active), require_regex=bool(rule.require_regex),
        unknown=sorted({name for name in used if name not in values}),
        empty=sorted({name for name in used if name in values and not values[name]}),
        placeholders={k: v[:80] for k, v in values.items() if k != "body"},
    )
    return result


def build_payload(rule: m.Rule, values: dict) -> dict:
    payload = {
        "title": render(rule.title_tpl, values)[:LIMITS["title"]],
        "text": render(rule.text_tpl, values)[:LIMITS["text"]],
    }
    address = render(rule.address_tpl, values)[:LIMITS["address"]]
    if address:
        payload["address"] = address
    if rule.ric.strip():
        payload["ric"] = render(rule.ric, values)
    if rule.priority:
        payload["priority"] = "1"
    if rule.kind == "news":
        payload["news"] = "1"
    for line in (rule.extra_params or "").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and key.strip() != "accesskey":
            payload[key.strip()] = render(value, values)
    return payload


def send_divera(accesskey: str, payload: dict) -> tuple[bool, str]:
    if not accesskey:
        return False, "Kein DIVERA-Accesskey hinterlegt."
    error = ""
    for attempt in range(3):
        try:
            resp = httpx.post(DIVERA_API_URL, params={"accesskey": accesskey}, data=payload, timeout=15)
            body = resp.text[:300]
            ok = resp.status_code == 200
            try:
                if resp.json().get("success") is False:
                    ok = False
            except (ValueError, AttributeError):
                pass
            if ok or resp.status_code < 500:
                return ok, f"HTTP {resp.status_code}: {body}"
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
            ok, detail = send_divera(sec.decrypt(tenant.accesskey_enc), payload)
            status = "gesendet" if ok else "fehler"
            detail = f"{payload.get('title', '')} | {detail}"
        db.add(m.Log(**common, rule_name=rule.name, status=status, detail=detail[:2000]))
        if rule.stop:
            break
    if not matched:
        db.add(m.Log(**common, status="ignoriert", detail="Keine Regel passt."))
    db.commit()
    return matched
