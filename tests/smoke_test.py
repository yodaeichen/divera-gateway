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
    RULE = {"csrf": tok, "id": "1", "tenant_id": "1", "name": "Brand", "match_subject": "alarm", "require_regex": "on",
            "extract_regex": "^Stichwort:\\s*(?P<stichwort>.+)$\r\n^Ort:\\s*(?P<ort>.+)$", "title_tpl": "{stichwort}",
            "text_tpl": "{subject} von {from} {geraet}", "address_tpl": "{ort}", "ric": "LZ1", "priority": "on",
            "extra_params": "group_ids=1,2\naccesskey=boese", "stop": "on", "active": "on", "t_from": "ls@x.de"}
    r = c.post("/rules/test", data=dict(RULE, t_subject="ALARM", t_body=body.replace("\n", "\r\n")))
    assert "Die Regel greift" in r.text and "B2 Wohnungsbrand" in r.text and "Musterstraße 1, Musterstadt" in r.text
    assert "greift bei der Beispielnachricht nicht" in c.post("/rules/test", data=dict(RULE, t_subject="Info", t_body=body)).text
    assert "greift bei der Beispielnachricht nicht" in c.post("/rules/test", data=dict(RULE, t_subject="Alarm", t_body="Stichwort: X")).text
    r = c.post("/rules/test", data=dict(RULE, name="NICHT SPEICHERN", extract_regex="(", t_subject="Alarm", t_body=body))
    assert "Zeile 1 ungültig" in r.text
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).name == "Brand", "Probelauf darf nichts speichern"
    # Live-Ansicht
    assert c.post("/rules/preview", data={k: v for k, v in RULE.items() if k != "t_from"}).json() == {"state": "nosample"}
    live = c.post("/rules/preview", data=dict(RULE, t_subject="ALARM", t_body=body, title_tpl="{stichwort} " + "x" * 60 + " {gibtsnicht}")).json()
    assert live["match"] and live["conditions"] == [{"label": "Betreff", "needle": "alarm", "terms": ["alarm"], "hit": "alarm", "ok": True}]
    multi = dict(RULE, match_subject="Einsatz; ALARM ;", match_from="@kreis.de;ls@x.de", t_subject="Probe-Alarm", t_body=body)
    live2 = c.post("/rules/preview", data=multi).json()
    assert live2["match"] and live2["conditions"][0]["hit"] == "ls@x.de" and live2["conditions"][1]["terms"] == ["Einsatz", "ALARM"]
    assert not c.post("/rules/preview", data=dict(multi, match_subject="Einsatz; Brand")).json()["match"]
    assert not c.post("/rules/preview", data=dict(multi, match_from="@kreis.de; @bma.de")).json()["match"]
    assert [e["ok"] for e in live["expressions"]] == [True, True] and live["expressions"][1]["groups"] == {"ort": "Musterstraße 1, Musterstadt"}
    title = live["fields"][0]
    assert title["length"] > 50 and len(title["value"]) == 50 and live["payload"]["title"] == title["value"]
    assert live["unknown"] == ["geraet", "gibtsnicht"] and "accesskey" not in live["payload"] and "body" not in live["placeholders"]
    live = c.post("/rules/preview", data=dict(RULE, t_subject="Info", t_body="Stichwort: X", extract_regex="^Stichwort: (?P<stichwort>.+)$\n(")).json()
    assert not live["match"] and live["conditions"][0]["ok"] is False and "Zeile 2" in live["form_error"]
    assert live["expressions"][0]["ok"] and live["expressions"][1]["error"]
    assert c.post("/rules/preview", data={"id": "1"}).status_code == 403
    page_html = c.get("/rules/1/edit").text
    assert 'id="rule-form"' in page_html and 'id="live"' in page_html and "rule_live.js" in page_html
    assert c.get("/static/rule_live.js").status_code == 200
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).name == "Brand", "Live-Ansicht darf nichts speichern"
    r = c.post("/rules/save", data=dict(RULE, t_subject="Alarm", t_body=body))  # mehrzeilige Ausdrücke speichern
    assert "Regel gespeichert" in r.text and "Die Regel greift" in r.text

    r = c.post(f"/hook/{hook}", json={"subject": "Alarm BMA", "body": body, "geraet": "BMZ-7"})
    assert r.json() == {"ok": True, "matched": 1}, r.text
    assert c.post(f"/hook/{hook}", json={"subject": "nix", "body": "x"}).json()["matched"] == 0
    assert c.post("/hook/falsch", json={}).status_code == 404
    assert "nix" in c.post("/sources/2/test", data={"csrf": tok}).text
    c.post(f"/hook/{hook}", data={"subject": "Formular", "geraet": "BMZ-7"})
    last = c.post("/sources/2/test", data={"csrf": tok}).text
    assert "Letzter Empfang" in last and "{geraet}" in last and "BMZ-7" in last
    import datetime as dt
    sources.TESTERS["m365"] = lambda cfg: {"message": "Verbindung in Ordnung", "items": [
        {"ts": dt.datetime(2026, 11, 10, 9, 0), "from": "ls@x.de", "subject": "Probealarm <b>", "preview": "Textanfang", "ref": "AAMk=1"}]}
    shown = c.post("/sources/1/test", data={"csrf": tok}).text
    assert "Probealarm &lt;b&gt;" in shown and "10.11.2026 10:00:00" in shown and "Textanfang" in shown
    sources.TESTERS["m365"] = lambda cfg: (_ for _ in ()).throw(RuntimeError("Ordner 'X' nicht gefunden"))
    assert "Test fehlgeschlagen" in c.post("/sources/1/test", data={"csrf": tok}).text

    # Regelvorschlag aus einer Nachricht
    assert 'name="ref" value="AAMk=1"' in shown and "Regel vorschlagen" in shown
    mail = ("Einsatznummer: 2026-004711\r\nEinsatzstichwort: B3 - Brand Gebäude\r\nStraße / Nr.: Hauptstr. 12\r\n"
            "Ort: 63679 Eichen\r\nBemerkung: Rauch aus Dachstuhl\r\nhttp://karte.example/1\r\n")
    sources.FETCHERS["m365"] = lambda cfg, ref: {"from": "leitstelle@kreis.example", "subject": "Alarmierung FF Eichen 10.11.2026 16:02", "body": mail}
    sug = c.post("/sources/1/suggest", data={"csrf": tok, "ref": "AAMk=1"}).text
    assert "Vorschlag aus der Beispielnachricht" in sug and "Die Regel greift" in sug
    assert 'value="Alarmierung FF Eichen"' in sug and 'value="leitstelle@kreis.example"' in sug
    assert 'value="{einsatzstichwort}"' in sug and 'value="{strasse_nr}, {ort}"' in sug and "{bemerkung}" in sug
    assert "B3 - Brand Gebäude" in sug and "Hauptstr. 12, 63679 Eichen" in sug and "karte.example" not in sug.split("<form")[0]
    with m.SessionLocal() as db:
        assert db.query(m.Rule).count() == 1, "Vorschlag darf nicht automatisch gespeichert werden"
    hooksug = c.post("/sources/2/suggest", data={"csrf": tok}).text
    assert "Übergebene Felder" in hooksug and "{geraet}" in hooksug
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
