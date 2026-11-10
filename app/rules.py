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


def match_rule(rule: m.Rule, msg: dict) -> dict | None:
    """Gibt die Platzhalterwerte zurück, wenn die Regel passt, sonst None."""
    def contains(needle: str, haystack: str) -> bool:
        return not needle or needle.lower() in (haystack or "").lower()

    if not (contains(rule.match_from, msg["from"]) and contains(rule.match_subject, msg["subject"])
            and contains(rule.match_body, msg["body"])):
        return None
    values = {k: str(v) for k, v in (msg.get("extra") or {}).items()}
    values.update({"from": msg["from"], "subject": msg["subject"], "body": msg["body"], "date": msg.get("date", "")})
    if rule.extract_regex:
        found = re.search(rule.extract_regex, msg["subject"] + "\n" + msg["body"], re.M | re.I)
        if found:
            values.update({k: (v or "").strip() for k, v in found.groupdict().items()})
        elif rule.require_regex:
            return None
    return values


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
