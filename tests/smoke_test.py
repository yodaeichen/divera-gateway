"""Durchlauftest ohne Netzwerk: Anmeldung, Kunde, Quelle, Regel, Webhook, Protokoll.

Aufruf:  python tests/smoke_test.py
"""
import os
import re
import sys
import tempfile

os.environ.update(SECRET_KEY="x" * 40, ADMIN_PASSWORD="test-passwort-123", COOKIE_SECURE="false",
                  DATA_DIR=tempfile.mkdtemp())
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from app import db as m  # noqa: E402
from app import rules, sources, worker  # noqa: E402
from app.main import app  # noqa: E402


def csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


with TestClient(app, base_url="http://testserver") as c:
    assert c.get("/", follow_redirects=False).status_code == 303, "ohne Anmeldung muss umgeleitet werden"
    tok = csrf(c.get("/login").text)
    assert "falsch" in c.post("/login", data={"csrf": tok, "username": "admin", "password": "nein"}).text
    tok = csrf(c.get("/login").text)
    assert c.post("/login", data={"username": "admin", "password": "test-passwort-123"}).status_code == 403, "CSRF"
    r = c.post("/login", data={"csrf": tok, "username": "admin", "password": "test-passwort-123"})
    assert "Kunden" in r.text
    tok = csrf(r.text)

    r = c.post("/tenants/save", data={"csrf": tok, "name": "FF Musterstadt", "accesskey": "geheim123", "active": "on", "test_mode": "on"})
    assert "FF Musterstadt" in r.text and "geheim123" not in r.text
    assert "geheim123" not in c.get("/tenants/1/edit").text, "Accesskey darf nie angezeigt werden"

    for stype in ("m365", "imap", "webhook"):
        assert c.get(f"/tenants/1/sources/new?type={stype}").status_code == 200
    c.post("/sources/save", data={"csrf": tok, "tenant_id": "1", "type": "m365", "name": "Leitstelle", "directory_id": "dir-1",
                                  "client_id": "cid", "client_secret": "s3cret", "mailbox": "a@b.de", "folder": "inbox", "active": "on"})
    r = c.post("/sources/save", data={"csrf": tok, "tenant_id": "1", "type": "webhook", "name": "BMA", "active": "on"})
    hook = re.search(r"/hook/([\w-]+)", r.text).group(1)
    with m.SessionLocal() as db:
        src = db.get(m.Source, 1)
        assert src.config["tenant_id"] == "dir-1" and src.config["client_secret"] == "s3cret" and src.tenant_id == 1
        assert "s3cret" not in src.config_enc and "geheim123" not in db.get(m.Tenant, 1).accesskey_enc
    assert "s3cret" not in c.get("/sources/1/edit").text

    r = c.post("/rules/save", data={"csrf": tok, "tenant_id": "1", "name": "Brand", "position": "10", "source_id": "",
                                    "match_subject": "alarm", "extract_regex": r"Stichwort:\s*(?P<stichwort>.+)\nOrt:\s*(?P<ort>.+)",
                                    "require_regex": "on", "kind": "alarm", "ric": "LZ1", "title_tpl": "{stichwort}",
                                    "text_tpl": "{subject} von {from} {geraet}", "address_tpl": "{ort}", "extra_params": "group_ids=1,2\naccesskey=boese",
                                    "stop": "on", "active": "on", "priority": "on"})
    assert "Regel gespeichert" in r.text
    assert "ungültig" in c.post("/rules/save", data={"csrf": tok, "tenant_id": "1", "name": "kaputt", "extract_regex": "("}).text

    body = "Stichwort: B2 Wohnungsbrand\nOrt: Musterstraße 1, Musterstadt\n"
    r = c.post("/rules/1/test", data={"csrf": tok, "t_from": "ls@x.de", "t_subject": "ALARM", "t_body": body})
    assert "Die Regel greift." in r.text and "B2 Wohnungsbrand" in r.text
    r = c.post("/rules/1/test", data={"csrf": tok, "t_from": "ls@x.de", "t_subject": "Info", "t_body": body})
    assert "greift bei dieser Nachricht nicht" in r.text

    r = c.post(f"/hook/{hook}", json={"subject": "Alarm BMA", "body": body, "geraet": "BMZ-7"})
    assert r.json() == {"ok": True, "matched": 1}, r.text
    assert c.post(f"/hook/{hook}", json={"subject": "nix", "body": "x"}).json()["matched"] == 0
    assert c.post("/hook/falsch", json={}).status_code == 404
    logs = c.get("/logs").text
    assert "Testmodus, nicht gesendet" in logs and "BMZ-7" in logs and "ignoriert" in logs
    assert "boese" not in logs and "geheim123" not in logs

    # Regel-Logik direkt
    with m.SessionLocal() as db:
        rule = db.get(m.Rule, 1)
        p = rules.build_payload(rule, rules.match_rule(rule, {"from": "a", "subject": "Alarm", "body": body}))
        assert p == {"title": "B2 Wohnungsbrand", "text": "Alarm von a", "address": "Musterstraße 1, Musterstadt",
                     "ric": "LZ1", "priority": "1", "group_ids": "1,2"}, p
        # doppelte Nachricht wird nur einmal verarbeitet, veraltete gar nicht
        import datetime as dt
        webhook_src = db.get(m.Source, 2)
        assert worker.already_processed(db, 2, "abc") is False and worker.already_processed(db, 2, "abc") is True
        old = {"id": "o", "from": "a", "subject": "Alarm", "body": body, "ts": dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)}
        assert worker.handle_message(db, webhook_src, old) == 0
    assert "veraltet" in c.get("/logs?status=veraltet").text

    assert sources.html_to_text("<p>Hallo<br>Welt &amp; Co</p><style>x</style>") == "Hallo\nWelt & Co"
    assert rules.render("{a}-{fehlt}-{a.__class__}", {"a": "x"}) == "x--{a.__class__}"

    r = c.post("/users/save", data={"csrf": tok, "username": "zwei", "password": "kurz"})
    assert "mindestens 12" in r.text
    c.post("/users/save", data={"csrf": tok, "username": "zwei", "password": "lang-genug-12345"})
    assert "zwei" in c.get("/users").text
    c.post("/logout", data={"csrf": tok})
    assert c.get("/logs", follow_redirects=False).status_code == 303

print("Alle Prüfungen bestanden.")
