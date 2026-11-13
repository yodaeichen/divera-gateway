"""Durchlauftest ohne Netzwerk: Anmeldung, Löschgruppe, Quelle, Regel, Webhook, Protokoll.

Aufruf:  python tests/smoke_test.py
"""
import datetime as dt
import json
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
    from app.version import VERSION
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION) and c.get("/healthz").json() == {"ok": True, "version": VERSION}
    assert f"## {VERSION}" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "CHANGELOG.md"), encoding="utf-8").read(), "CHANGELOG nachziehen"
    first = c.get("/login").text
    assert f"DIVERA Gateway {VERSION}" in first
    assert "powered by yodaeichen" in first and "https://github.com/sponsors/yodaeichen" in first and "<iframe" not in first
    assert "falsch" in c.post("/login", data={"csrf": tok, "username": "admin", "password": "nein"}).text
    tok = csrf(c.get("/login").text)
    assert c.post("/login", data={"username": "admin", "password": "test-passwort-123"}).status_code == 403, "CSRF"
    r = c.post("/login", data={"csrf": tok, "username": "admin", "password": "test-passwort-123"})
    assert "Löschgruppen" in r.text
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
    assert '<option value="news" selected>' in c.get("/tenants/1/rules/new").text, "Mitteilung ist die Vorgabe"

    r = c.post("/rules/save", data={"csrf": tok, "tenant_id": "1", "name": "Brand", "position": "10", "source_id": "",
                                    "match_subject": "alarm", "extract_regex": r"Stichwort:\s*(?P<stichwort>.+)\nOrt:\s*(?P<ort>.+)",
                                    "require_regex": "on", "kind": "alarm", "ric": "LZ1", "title_tpl": "{stichwort}",
                                    "text_tpl": "{subject} von {from} {geraet}", "address_tpl": "{ort}", "extra_params": "group_ids=1,2\naccesskey=boese",
                                    "stop": "on", "active": "on", "priority": "on"})
    assert "Regel gespeichert" in r.text
    assert "ungültig" in c.post("/rules/save", data={"csrf": tok, "tenant_id": "1", "name": "kaputt", "extract_regex": "("}).text

    body = "Stichwort: B2 Wohnungsbrand\nOrt: Musterstraße 1, Musterstadt\n"
    RULE = {"csrf": tok, "id": "1", "tenant_id": "1", "name": "Brand", "kind": "alarm", "match_subject": "alarm", "require_regex": "on",
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
    assert "Vorschlag aus der Beispielnachricht" in sug and "Die Regel greift" in sug and '<option value="news" selected>' in sug
    assert 'value="Alarmierung FF Eichen"' in sug and 'value="leitstelle@kreis.example"' in sug
    assert 'value="{einsatzstichwort}"' in sug and 'value="{strasse_nr}, {ort}"' in sug and "{bemerkung}" in sug
    assert "B3 - Brand Gebäude" in sug and "Hauptstr. 12, 63679 Eichen" in sug and "karte.example" not in sug.split("<form")[0]
    with m.SessionLocal() as db:
        assert db.query(m.Rule).count() == 1, "Vorschlag darf nicht automatisch gespeichert werden"
    # Einzelne Nachricht von Hand verarbeiten
    assert "Jetzt verarbeiten" in shown and "Testmodus ist an" in shown
    sources.FETCHERS["m365"] = lambda cfg, ref: {"id": "<mid-77>", "date": "", "from": "ls@x.de", "subject": "Alarm von Hand", "body": body}
    done = c.post("/sources/1/process", data={"csrf": tok, "ref": "AAMk=1"}).text
    assert "1 Regel hat gegriffen (Testmodus: nichts gesendet)" in done and "Alarm von Hand" in done
    with m.SessionLocal() as db:
        assert worker.already_processed(db, 1, "<mid-77>") is True, "von Hand verarbeitete Nachricht ist vorgemerkt"
    sources.FETCHERS["m365"] = lambda cfg, ref: {"id": "<mid-78>", "date": "", "from": "x@y.de", "subject": "Newsletter", "body": "nix"}
    assert "keine Regel passt" in c.post("/sources/1/process", data={"csrf": tok, "ref": "AAMk=2"}).text
    assert c.post("/sources/2/process", data={"csrf": tok}).status_code == 400
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
                     "ric": "LZ1", "priority": "1", "group_ids": ["1", "2"]}, p
        # doppelte Nachricht wird nur einmal verarbeitet, veraltete gar nicht
        import datetime as dt
        webhook_src = db.get(m.Source, 2)
        assert worker.already_processed(db, 2, "abc") is False and worker.already_processed(db, 2, "abc") is True
        old = {"id": "o", "from": "a", "subject": "Alarm", "body": body, "ts": dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)}
        assert worker.handle_message(db, webhook_src, old) == 0
    assert "veraltet" in c.get("/logs?status=veraltet").text

    nokind = c.post("/rules/preview", data={k: v for k, v in dict(RULE, t_subject="Alarm", t_body=body).items() if k != "kind"}).json()  # ohne Angabe der Art
    assert nokind["kind"] == "news" and nokind["payload"]["news"] == "1"
    askind = c.post("/rules/preview", data=dict(RULE, kind="alarm", t_subject="Alarm", t_body=body)).json()
    assert askind["kind"] == "alarm" and "news" not in askind["payload"]

    # Testsendung von Hand: erst bestätigen, dann wirklich senden (auch im Testmodus)
    sent = []
    real_send = rules.send_divera
    rules.send_divera = lambda key, payload: sent.append((key, payload)) or (True, 'HTTP 200: {"success":true}')
    SEND = dict(RULE, name="NICHT SPEICHERN", t_subject="Alarm", t_body=body)
    ask = c.post("/rules/send-test", data=SEND)
    assert "Wirklich an DIVERA senden?" in ask.text and "Achtung, echter Alarm" in ask.text and "B2 Wohnungsbrand" in ask.text and not sent
    assert 'name="title_tpl" value="{stichwort}"' in ask.text and 'name="confirm" value="ja"' in ask.text
    assert "Mitteilung mit Push gesendet" in c.post("/rules/send-test", data=dict(SEND, kind="news")).text
    assert "Kein Empfänger angegeben" in c.post("/rules/send-test", data=dict(SEND, ric="", extra_params="")).text and not sent
    assert "greift bei der Beispielnachricht nicht" in c.post("/rules/send-test", data=dict(SEND, t_subject="Info", confirm="ja")).text and not sent
    assert "Beispielnachricht eintragen" in c.post("/rules/send-test", data={k: v for k, v in RULE.items() if k != "t_from"} | {"confirm": "ja"}).text and not sent
    done = c.post("/rules/send-test", data=dict(SEND, confirm="ja"))
    assert "An DIVERA gesendet." in done.text and len(sent) == 1 and sent[0][0] == "geheim123"
    assert sent[0][1]["title"] == "B2 Wohnungsbrand" and sent[0][1]["ric"] == "LZ1" and "news" not in sent[0][1]
    assert "Testsendung von Hand" in c.get("/logs").text and "ausgelöst von admin" in c.get("/logs").text
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).name == "Brand", "Testsendung darf die Regel nicht speichern"
    rules.send_divera = lambda key, payload: (False, "HTTP 403: Zugriff verweigert")
    assert "Senden fehlgeschlagen" in c.post("/rules/send-test", data=dict(SEND, confirm="ja")).text
    rules.send_divera = real_send

    # Empfänger aus DIVERA: Personen und Gruppen ankreuzen
    sample_pull = {"success": True, "data": {"cluster": {
        "consumer": {"501": {"firstname": "Max", "lastname": "Muster", "stdformat_name": "Muster, Max"}, "502": {"firstname": "Erika", "lastname": "Beispiel"}, "x": "kaputt"},
        "group": [{"id": 12, "name": "Löschzug 1"}, {"id": 13, "title": "Führung"}]}}}
    parsed = rules.parse_directory(sample_pull)
    assert parsed == {"persons": [{"id": 502, "name": "Erika Beispiel"}, {"id": 501, "name": "Muster, Max"}],
                      "groups": [{"id": 13, "name": "Führung"}, {"id": 12, "name": "Löschzug 1"}]}, parsed
    for bad in ({"success": False}, {"data": {"cluster": {}}}, []):
        try:
            rules.parse_directory(bad); raise SystemExit("kein Fehler bei " + str(bad))
        except RuntimeError:
            pass
    assert rules.id_list("5, 7,x,5,;DROP") == ["5", "7"] and rules.id_list(["3", "3", "a"]) == ["3"]
    assert "Noch keine Liste vorhanden" in c.get("/rules/1/edit").text
    seen_keys = []
    rules.fetch_directory = lambda key: seen_keys.append(key) or parsed
    r = c.post("/tenants/1/directory", data={"csrf": tok})
    assert "2 Personen und 2 Gruppen aus DIVERA geladen" in r.text and seen_keys == ["geheim123"]
    edit = c.get("/rules/1/edit").text
    assert 'name="ucr" value="501"' in edit and "Muster, Max" in edit and 'name="grp" value="12"' in edit
    PICK = dict(RULE, ric="", extra_params="", ucr=["501", "999", "boese"], grp=["12"], t_subject="Alarm", t_body=body)
    live3 = c.post("/rules/preview", data=PICK).json()
    assert live3["payload"]["user_cluster_relation_ids"] == ["501", "999"] and live3["payload"]["person"] == "501,999"
    assert live3["payload"]["group_ids"] == ["12"] and "ric" not in live3["payload"]
    # Mitteilungen über v2: ohne Push und gezielt an Personen oder Gruppen
    NEWS = dict(RULE, kind="news", extra_params="", t_subject="Alarm", t_body=body)
    v1 = c.post("/rules/preview", data=NEWS).json()                                   # mit RIC und Push: alter Weg
    assert v1["plan"]["route"] == "v1" and v1["payload"]["news"] == "1" and v1["payload"]["ric"] == "LZ1"
    one = c.post("/rules/preview", data=dict(NEWS, ric="", ucr=["501"], push="0")).json()
    assert one["payload"] == {"News": {"title": "B2 Wohnungsbrand", "text": "Alarm von ls@x.de", "notification_type": 4, "send_push": False,
                                       "address": "Musterstraße 1, Musterstadt", "send_sms": False, "send_call": False, "send_mail": False,
                                       "send_pager": False, "user_cluster_relation": [501]},
                              "instructions": {"user_cluster_relation": {"mapping": "id"}}}, one["payload"]
    assert one["plan"]["audience"] == "nur die angekreuzten Personen" and one["has_recipient"] and not one["plan"]["notes"]
    grp = c.post("/rules/preview", data=dict(NEWS, ric="", grp=["12", "13"], push="0")).json()   # Gruppen ohne Push: v2
    assert grp["payload"]["News"]["notification_type"] == 3 and grp["payload"]["News"]["group"] == [12, 13]
    assert grp["payload"]["News"]["send_push"] is False
    pv1 = c.post("/rules/preview", data=dict(NEWS, ric="", ucr=["501"], grp=["12"])).json()        # mit Push: immer alter Weg
    assert pv1["plan"]["route"] == "v1" and pv1["payload"]["person"] == "501" and pv1["payload"]["user_cluster_relation_ids"] == ["501"]
    assert pv1["payload"]["group_ids"] == ["12"] and pv1["payload"]["news"] == "1" and pv1["has_recipient"]
    alle = c.post("/rules/preview", data=dict(NEWS, push="0", extra_params="group_ids=1")).json()  # ohne Push, nur RIC
    assert alle["payload"]["News"]["notification_type"] == 2 and "group" not in alle["payload"]["News"] and len(alle["plan"]["notes"]) == 2
    both = c.post("/rules/preview", data=dict(NEWS, ric="", ucr=["501"], grp=["12"], push="0")).json()
    assert both["payload"]["News"]["notification_type"] == 4 and "group" not in both["payload"]["News"] and both["plan"]["notes"]
    assert c.post("/rules/preview", data=dict(NEWS, kind="alarm", push="0", ucr=["501"])).json()["plan"]["route"] == "v1", "Alarm bleibt beim alten Weg"
    import httpx as _hx
    v2wire = {}
    class _R2:
        status_code, text = 200, '{"success":true}'
        def json(self): return {"success": True}
    def _post2(url, params=None, data=None, json=None, timeout=None):
        v2wire.update(url=url, json=json, data=data, params=params); return _R2()
    keep_post, rules.httpx.post = rules.httpx.post, _post2
    assert rules.send_divera("k", one["payload"])[0] and v2wire["url"].endswith("/api/v2/news") and v2wire["data"] is None
    assert v2wire["json"]["News"]["user_cluster_relation"] == [501] and v2wire["params"] == {"accesskey": "k"}
    rules.httpx.post = keep_post
    # v2 braucht den persönlichen Accesskey
    assert one["user_key"] is False
    class _R403:
        status_code, text = 403, '{"name":"Forbidden","message":"Nicht autorisiert"}'
        def json(self): return {"name": "Forbidden"}
    rules.httpx.post = lambda *a, **k: _R403()
    ok403, det403 = rules.send_divera("k", one["payload"])
    assert not ok403 and det403.startswith("HTTP 403")
    with m.SessionLocal() as db:
        t1 = db.get(m.Tenant, 1)
        assert "weil kein persönlicher Accesskey hinterlegt ist" in rules.refusal_hint(t1, one["payload"], det403)
        assert rules.refusal_hint(t1, {"title": "x"}, det403) == "" and rules.refusal_hint(t1, one["payload"], "HTTP 200: ok") == ""
        t1.accesskey_user_enc = "x"
        assert "trotzdem abgelehnt" in rules.refusal_hint(t1, one["payload"], det403)
    rules.httpx.post = keep_post
    # Schlüsselprüfung
    class _G:
        def __init__(self, code, data): self.status_code, self._d, self.text = code, data, "x"
        def json(self): return self._d
    keep_get = rules.httpx.get
    rules.httpx.get = lambda url, params=None, timeout=None: (_G(200, {"success": True, "data": {"user": {"firstname": "Gate", "lastname": "Way"}, "cluster": {"consumer": {"1": {}, "2": {}}}}})
                                                                if params["accesskey"] == "geheim123" else _G(403, {"message": "Nicht autorisiert"}))
    kc = c.post("/tenants/1/keycheck", data={"csrf": tok}).text
    assert "angenommen (HTTP 200)" in kc and "Benutzer: Gate Way, 2 Personen sichtbar" in kc and "nicht hinterlegt" in kc and "geheim123" not in kc
    assert rules.check_key("falsch") == {"status": 403, "ok": False, "info": "Nicht autorisiert"}
    rules.httpx.get = keep_get
    used = []
    rules.send_divera = lambda key, payload: used.append(key) or (True, "ok")
    c.post("/rules/send-test", data=dict(NEWS, ric="", ucr=["501"], push="0", confirm="ja"))
    assert used == ["geheim123"], "ohne persönlichen Schlüssel wird der Einheiten-Schlüssel versucht"
    r = c.post("/tenants/save", data={"csrf": tok, "id": "1", "name": "FF Musterstadt", "accesskey_user": "persoenlich456", "active": "on", "test_mode": "on"})
    assert "persoenlich456" not in r.text and "persoenlich456" not in c.get("/tenants/1/edit").text
    c.post("/rules/send-test", data=dict(NEWS, ric="", ucr=["501"], push="0", confirm="ja"))
    c.post("/rules/send-test", data=dict(NEWS, confirm="ja"))   # alter Weg mit RIC
    assert used == ["geheim123", "persoenlich456", "geheim123"], used
    assert c.post("/rules/preview", data=dict(NEWS, ric="", ucr=["501"], push="0")).json()["user_key"] is True
    rules.send_divera = real_send
    askn = c.post("/rules/send-test", data=dict(NEWS, ric="", ucr=["501"], push="0")).text
    assert "Mitteilung ohne Push gesendet" in askn and "nur die angekreuzten Personen" in askn and "Muster, Max" in askn
    assert "Geht an alle Mitglieder der Einheit" in c.post("/rules/send-test", data=dict(NEWS, ric="", push="0")).text
    c.post("/rules/save", data=dict(NEWS, ric="", ucr=["501"], push="0", t_subject="", t_from=""))
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).push is False
    assert "Mitteilung ohne Push" in c.get("/tenants/1").text and '<option value="0" selected>' in c.get("/rules/1/edit").text
    c.post("/rules/save", data=dict(RULE, t_subject="", t_from=""))
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).push is True and db.get(m.Rule, 1).kind == "alarm"

    # Übertragung: Listen als name[]=wert, damit bei DIVERA ein Array ankommt
    import httpx as _httpx
    wire = {}
    class _Resp:
        status_code, text = 200, '{"success":true}'
        def json(self): return {"success": True}
    def _post(url, params=None, data=None, timeout=None):
        wire.update(body=bytes(_httpx.Request("POST", url, data=data).read()).decode(), params=params); return _Resp()
    real_post, rules.httpx.post = rules.httpx.post, _post
    assert rules.send_divera("k", live3["payload"])[0]
    rules.httpx.post = real_post
    from urllib.parse import parse_qsl
    sent_pairs = parse_qsl(wire["body"])
    assert ("user_cluster_relation_ids[]", "501") in sent_pairs and ("user_cluster_relation_ids[]", "999") in sent_pairs, sent_pairs
    assert ("group_ids[]", "12") in sent_pairs and ("person", "501,999") in sent_pairs and ("title", "B2 Wohnungsbrand") in sent_pairs
    assert wire["params"] == {"accesskey": "k"} and "accesskey" not in wire["body"]
    assert live3["persons"] == ["Muster, Max", "ID 999"] and live3["groups"] == ["Löschzug 1"] and live3["has_recipient"]
    assert not c.post("/rules/preview", data=dict(RULE, ric="", extra_params="", t_subject="Alarm", t_body=body)).json()["has_recipient"]
    saved = c.post("/rules/save", data=PICK).text
    assert 'value="501" checked' in saved and "nicht mehr in der DIVERA-Liste" in saved and 'value="502" checked' not in saved
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).ucr_ids == "501,999" and db.get(m.Rule, 1).group_ids == "12"
    c.post("/rules/save", data=dict(RULE, t_subject="", t_from=""))  # Auswahl wieder leeren, RIC zurück
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).ucr_ids == "" and db.get(m.Rule, 1).ric == "LZ1"
    rules.fetch_directory = lambda key: (_ for _ in ()).throw(RuntimeError("DIVERA lehnt den Accesskey für diese Abfrage ab (HTTP 403)."))
    assert "konnten nicht geladen werden" in c.post("/tenants/1/directory", data={"csrf": tok}).text

    # Manueller Abruf je Löschgruppe
    calls = []
    def fake_poll(cfg, state):
        calls.append(cfg["mailbox"])
        now = dt.datetime.now(dt.timezone.utc)
        return [{"id": "m-1", "from": "ls@x.de", "subject": "Alarm manuell", "body": body, "date": "", "ts": now}], {"since": "x"}
    sources.POLLERS["m365"] = fake_poll
    home = c.get("/").text
    assert "Nächster Abruf" in home and "läuft gerade an" in home and "alle 30 Sekunden" in home and 'http-equiv="refresh"' in home
    assert 'http-equiv="refresh"' not in c.get("/logs").text
    assert "Jetzt abrufen" in home and 'action="/tenants/1/poll"' in home
    r = c.post("/tenants/1/poll", data={"csrf": tok, "back": "home"})
    assert "1 Postfach abgerufen, 1 neue Nachricht." in r.text and calls == ["a@b.de"] and "Alarm manuell" not in r.text
    assert "Letzte Ereignisse" not in r.text and "Alarm manuell" in c.get("/logs").text, "Ereignisse stehen nur noch im Protokoll"
    assert "läuft gerade an" not in r.text and re.search(r"<td>\s*\d\d\.\d\d\.\d{4} \d\d:\d\d:\d\d\s*<br><span class=\"hint\">alle 30", r.text), "nächster Abruf als Uhrzeit"
    again = c.post("/tenants/1/poll", data={"csrf": tok}).text
    assert "0 neue Nachrichten" in again and "nach dem Anlegen oder letzten Speichern" in again, "dieselbe Nachricht nicht doppelt"
    sources.POLLERS["m365"] = lambda cfg, state: (_ for _ in ()).throw(RuntimeError("kaputt"))
    assert "Fehler bei: Leitstelle" in c.post("/tenants/1/poll", data={"csrf": tok, "back": "home"}).text
    assert c.post("/tenants/1/poll", data={}).status_code == 403

    assert sources.html_to_text("<p>Hallo<br>Welt &amp; Co</p><style>x</style>") == "Hallo\nWelt & Co"
    assert rules.render("{a}-{fehlt}-{a.__class__}", {"a": "x"}) == "x--{a.__class__}"

    r = c.post("/users/save", data={"csrf": tok, "username": "zwei", "password": "kurz"})
    assert "mindestens 12" in r.text
    c.post("/users/save", data={"csrf": tok, "username": "zwei", "password": "lang-genug-12345"})
    assert "zwei" in c.get("/users").text

    hilfe = c.get("/help").text
    assert "In sieben Schritten" in hilfe and "Häufige Fragen" in hilfe and hilfe.count("<details>") >= 20 and 'href="/help"' in hilfe

    # ---------- Berechtigungen ----------
    from app import access
    with m.SessionLocal() as db:
        admin = db.query(m.User).filter_by(username="admin").one()
        assert admin.perms is None and access.role_of(admin) == "Administrator" and access.sees_all(admin), "altes Konto bleibt Administrator"
        zwei = db.query(m.User).filter_by(username="zwei").one()
        assert access.perms_of(zwei) == {"tenants": 1, "sources": 0, "rules": 0, "logs": 0, "users": 0, "send": False} and not access.sees_all(zwei)
    assert access.clean({"tenants": 0, "sources": 7, "logs": 2, "users": 1, "send": 1}) == {"tenants": 1, "sources": 0, "rules": 0, "logs": 0, "users": 0, "send": True}

    c.post("/tenants/save", data={"csrf": tok, "name": "Andere Wehr", "accesskey": "andererkey", "active": "on", "test_mode": "on"})
    c.post("/rules/save", data={"csrf": tok, "tenant_id": "2", "name": "Fremdregel", "match_subject": "alarm", "active": "on", "stop": "on"})
    c.post("/hook/%s" % hook, json={"subject": "Alarm Eigen", "body": body})
    with m.SessionLocal() as db:
        db.add(m.Log(tenant_id=2, tenant_name="Andere Wehr", subject="GEHEIM-FREMD", status="test")); db.commit()
        other_rule = db.query(m.Rule).filter_by(name="Fremdregel").one().id
    form_html = c.get("/users/new").text
    assert 'name="p_rules"' in form_html and "Administrator: darf alles" in form_html and 'name="tenant" value="2"' in form_html and "users.js" in form_html
    VIEW = {"csrf": tok, "p_tenants": "1", "p_sources": "1", "p_rules": "1", "p_logs": "1", "p_users": "0"}
    c.post("/users/save", data=dict(VIEW, username="leser", password="leser-passwort-1", tenant=["1"]))
    c.post("/users/save", data=dict(VIEW, username="bearb", password="bearb-passwort-1", p_sources="2", p_rules="2", p_send="on", tenant=["1"]))
    c.post("/users/save", data=dict(VIEW, username="eigen", password="eigen-passwort-1", p_rules="2", p_logs="0", all_tenants="on"))
    listing = c.get("/users").text
    assert "Betrachter" in listing and "Bearbeiter" in listing and "Angepasst" in listing and "FF Musterstadt" in listing
    with m.SessionLocal() as db:
        leser = db.query(m.User).filter_by(username="leser").one()
        assert access.role_of(leser) == "Betrachter" and access.tenant_ids(leser) == {1} and not access.sees_all(leser)
        leser_id, admin_id = leser.id, db.query(m.User).filter_by(username="admin").one().id
    # wer Rechte verwaltet, sieht immer alles; der letzte Verwalter lässt sich nicht entmachten
    c.post("/users/save", data=dict(VIEW, username="chef2", password="chef2-passwort-1", p_users="2", tenant=["1"]))
    with m.SessionLocal() as db:
        chef2 = db.query(m.User).filter_by(username="chef2").one()
        assert chef2.all_tenants is True and access.sees_all(chef2); chef2_id = chef2.id
    c.post(f"/users/{chef2_id}/delete", data={"csrf": tok})
    r = c.post("/users/save", data=dict(VIEW, id=str(admin_id)))
    assert "mindestens ein Benutzer übrig bleiben" in r.text
    with m.SessionLocal() as db:
        assert db.get(m.User, admin_id).perms is None, "Admin unverändert"
    assert "Leer lassen" in c.post("/users/save", data=dict(VIEW, id=str(leser_id), password="kurz", tenant=["1"])).text

    def login(name, password):
        client = TestClient(app, base_url="http://testserver")
        t = csrf(client.get("/login").text)
        page_ = client.post("/login", data={"csrf": t, "username": name, "password": password})
        return client, csrf(page_.text), page_.text

    # Übersicht für Administratoren: wer angemeldet ist, Erfolg und Fehler
    adm = c.get("/").text
    assert "Angemeldet" in adm and "Meldungen" in adm and "erfolgreich<br>in 24 Stunden" in adm and "Je Löschgruppe, letzte 7 Tage" in adm
    with m.SessionLocal() as db:
        ov = __import__("app.main", fromlist=["x"]).admin_overview(db, m.utcnow())
        assert ov["online"] == 1 and [p["name"] for p in ov["people"] if p["online"]] == ["admin"]
        total = ov["windows"][2][1]
        assert total["gesendet"] >= 1 and total["fehler"] >= 1 and total["test"] >= 1 and total == ov["windows"][0][1]
        assert dict(ov["per_tenant"])["FF Musterstadt"]["gesendet"] == total["gesendet"]

    # Betrachter, nur Löschgruppe 1
    v, vt, home = login("leser", "leser-passwort-1")
    assert "FF Musterstadt" in home and "Andere Wehr" not in home and "Löschgruppe anlegen" not in home and "Jetzt abrufen" not in home
    assert "GEHEIM-FREMD" not in home and "Alarm Eigen" not in home and ">Benutzer<" not in home and "Mein Konto" in home
    assert "Angemeldet" not in home and "in 24 Stunden" not in home, "Übersicht nur für Administratoren"
    with m.SessionLocal() as db:
        ov = __import__("app.main", fromlist=["x"]).admin_overview(db, m.utcnow())
        assert ov["online"] == 2 and {p["name"] for p in ov["people"] if p["online"]} == {"admin", "leser"}
        leser_now = db.query(m.User).filter_by(username="leser").one()
        assert leser_now.last_login is not None
        leser_now.last_seen = m.utcnow() - __import__("datetime").timedelta(minutes=20); db.commit()
        assert __import__("app.main", fromlist=["x"]).admin_overview(db, m.utcnow())["online"] == 1, "nach 15 Minuten ohne Aktivität nicht mehr angemeldet"
    assert v.get("/tenants/2").status_code == 404 and v.get(f"/rules/{other_rule}/edit").status_code == 404
    t1 = v.get("/tenants/1").text
    assert "Löschgruppe bearbeiten" not in t1 and "Regel anlegen" not in t1 and "Schlüssel prüfen" not in t1 and "/hook/" not in t1
    assert "Empfänger aus DIVERA laden" not in t1 and "Verbindung testen" in t1 and "Löschen" not in t1 and "/sources/new" not in t1
    for url in ("/tenants/1/edit", "/tenants/new", "/tenants/1/rules/new", "/sources/1/edit", "/users", "/users/new"):
        resp = v.get(url); assert resp.status_code == 403 and "Keine Berechtigung" in resp.text, url
    for url, data in (("/tenants/save", {"id": "1", "name": "Gekapert"}), ("/rules/save", dict(RULE)), ("/rules/1/delete", {}),
                      ("/rules/send-test", dict(RULE, t_subject="Alarm", t_body=body, confirm="ja")), ("/tenants/1/poll", {}),
                      ("/sources/1/process", {"ref": "x"}), ("/sources/1/delete", {}), ("/sources/2/token", {}), ("/sources/1/suggest", {"ref": "x"}),
                      ("/tenants/1/directory", {}), ("/tenants/1/keycheck", {}), ("/tenants/1/delete", {}),
                      ("/users/save", dict(VIEW, id=str(leser_id), p_users="2")), (f"/users/{admin_id}/delete", {})):
        resp = v.post(url, data=dict(data, csrf=vt)); assert resp.status_code == 403, (url, resp.status_code)
    with m.SessionLocal() as db:
        assert db.get(m.Tenant, 1).name == "FF Musterstadt" and db.get(m.Rule, 1) is not None and db.get(m.User, admin_id) is not None
        assert access.perms_of(db.get(m.User, leser_id))["users"] == 0
    ruleview = v.get("/rules/1/edit").text
    assert "Nur Ansicht" in ruleview and ">Speichern<" not in ruleview and "Testweise an DIVERA senden" not in ruleview and "Prüfen ohne Speichern" in ruleview
    assert v.post("/rules/preview", data=dict(RULE, csrf=vt, t_subject="Alarm", t_body=body)).json()["match"] is True
    assert v.post("/rules/preview", data=dict(RULE, csrf=vt, id=str(other_rule), t_subject="Alarm", t_body=body)).status_code == 404
    assert v.post("/rules/preview", data={"csrf": vt, "tenant_id": "2", "name": "x", "t_subject": "a"}).status_code == 404
    vlogs = v.get("/logs").text
    assert "Alarm Eigen" in vlogs and "GEHEIM-FREMD" not in vlogs and "Andere Wehr" not in vlogs
    assert "GEHEIM-FREMD" not in v.get("/logs?tenant=2").text
    stest = v.post("/sources/2/test", data={"csrf": vt}).text
    assert "Letzter Empfang" in stest and "Regel daraus vorschlagen" not in stest and "/hook/" not in stest
    assert "stimmt nicht" in v.post("/account", data={"csrf": vt, "current": "falsch", "password": "neues-passwort-12"}).text
    assert "Passwort geändert" in v.post("/account", data={"csrf": vt, "current": "leser-passwort-1", "password": "neues-passwort-12"}).text
    assert "Löschgruppen" in login("leser", "neues-passwort-12")[2]

    # Bearbeiter, nur Löschgruppe 1
    e, et, _ = login("bearb", "bearb-passwort-1")
    e1 = e.get("/tenants/1").text
    assert "Regel anlegen" in e1 and "Jetzt abrufen" in e1 and "/hook/" in e1 and "Löschgruppe bearbeiten" not in e1
    assert "Regel gespeichert" in e.post("/rules/save", data=dict(RULE, csrf=et, name="Vom Bearbeiter", t_subject="Alarm", t_body=body)).text
    assert e.post("/rules/save", data={"csrf": et, "tenant_id": "2", "name": "Eingeschleust"}).status_code == 404
    assert e.post("/rules/save", data=dict(RULE, csrf=et, id=str(other_rule))).status_code == 404
    assert e.post("/sources/save", data={"csrf": et, "tenant_id": "2", "type": "webhook", "name": "Fremd"}).status_code == 404
    assert e.post("/tenants/2/poll", data={"csrf": et}).status_code == 404
    assert e.post("/rules/save", data=dict(RULE, csrf=et, source_id="99")).status_code == 404
    assert e.get("/tenants/1/edit").status_code == 403 and e.get("/users").status_code == 403
    with m.SessionLocal() as db:
        assert db.get(m.Rule, 1).name == "Vom Bearbeiter" and db.query(m.Rule).filter_by(name="Eingeschleust").count() == 0
        assert db.get(m.Rule, other_rule).name == "Fremdregel"

    # Angepasst: Regeln bearbeiten, kein Protokoll, alle Löschgruppen
    g, gt, ghome = login("eigen", "eigen-passwort-1")
    assert "Andere Wehr" in ghome and ">Protokoll<" not in ghome and 'href="/logs"' not in ghome
    assert g.get("/logs").status_code == 403 and g.get(f"/rules/{other_rule}/edit").status_code == 200
    assert "Protokoll dieser Löschgruppe" not in g.get("/tenants/2").text

    # ---------- E-Mail-Adresse und Einladung ----------
    from app import mailer
    assert e.get("/settings").status_code == 403 and e.post("/settings", data={"csrf": et}).status_code == 403
    assert mailer.valid_address("a.b@wehr.example") and not mailer.valid_address("a@b") and not mailer.valid_address("a@b.de\nBcc: x@y.de")
    assert not mailer.valid_address("Name <a@b.de>") and not mailer.valid_address("a@b.de, c@d.de")
    NEWU = dict(VIEW, tenant=["1"])
    assert "noch nicht eingerichtet" in c.get("/users/new").text and "nicht eingerichtet" in c.get("/settings").text
    assert "noch nicht eingerichtet" in c.post("/users/save", data=dict(NEWU, username="neu1", email="neu1@wehr.example", send_invite="on")).text
    assert "Passwort vergeben oder die Einladung" in c.post("/users/save", data=dict(NEWU, username="neu1", email="neu1@wehr.example")).text
    assert "Absenderadresse ist ungültig" in c.post("/settings", data={"csrf": tok, "smtp_host": "mail.example", "mail_from": "kaputt"}).text
    assert "http:// oder https://" in c.post("/settings", data={"csrf": tok, "smtp_host": "mail.example", "mail_from": "gw@wehr.example", "base_url": "gateway"}).text
    SMTP = {"csrf": tok, "smtp_host": "mail.wehr.example", "smtp_port": "", "smtp_security": "starttls", "smtp_user": "gw", "smtp_password": "smtp-geheim",
            "mail_from": "gw@wehr.example", "base_url": "https://gw.wehr.example"}
    saved_page = c.post("/settings", data=SMTP).text
    assert "Einstellungen gespeichert" in saved_page and "eingerichtet" in saved_page and "smtp-geheim" not in saved_page
    with m.SessionLocal() as db:
        assert "smtp-geheim" not in db.get(m.Setting, "smtp_password").value and mailer.load(db)["smtp_password"] == "smtp-geheim"
    c.post("/settings", data={k: v for k, v in SMTP.items() if k != "smtp_password"})
    with m.SessionLocal() as db:
        assert mailer.load(db)["smtp_password"] == "smtp-geheim", "leeres Passwortfeld behält das gespeicherte"

    # echter Versandweg gegen einen nachgebildeten Mailserver
    import smtplib
    class FakeSMTP:
        calls = []
        def __init__(self, host, port, timeout=None): FakeSMTP.calls.append(("connect", host, port))
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): FakeSMTP.calls.append(("starttls",))
        def login(self, user, password): FakeSMTP.calls.append(("login", user, password))
        def send_message(self, msg): FakeSMTP.calls.append(("send", msg["From"], msg["To"], msg["Subject"], msg.get_content()))
    real_smtp, smtplib.SMTP = smtplib.SMTP, FakeSMTP
    r = c.post("/settings", data=dict(SMTP, send_test="1", test_to="admin@wehr.example"))
    assert "Testnachricht an admin@wehr.example verschickt" in r.text
    assert FakeSMTP.calls[:3] == [("connect", "mail.wehr.example", 587), ("starttls",), ("login", "gw", "smtp-geheim")]
    assert FakeSMTP.calls[3][1:4] == ("DIVERA Gateway <gw@wehr.example>", "admin@wehr.example", "Testnachricht vom DIVERA Gateway")
    class BadSMTP(FakeSMTP):
        def login(self, user, password): raise smtplib.SMTPAuthenticationError(535, b"nein")
    smtplib.SMTP = BadSMTP
    assert "Benutzername oder Passwort abgelehnt" in c.post("/settings", data=dict(SMTP, send_test="1", test_to="admin@wehr.example")).text
    smtplib.SMTP = real_smtp

    outbox = []
    real_deliver = mailer.deliver
    mailer.deliver = lambda settings, to, subject, body: outbox.append((to, subject, body))
    assert "ungültig" in c.post("/users/save", data=dict(NEWU, username="neu1", email="kein-at", send_invite="on")).text
    assert "fehlt die E-Mail-Adresse" in c.post("/users/save", data=dict(NEWU, username="neu1", send_invite="on")).text
    r = c.post("/users/save", data=dict(NEWU, username="neu1", email="neu1@wehr.example", send_invite="on"))
    assert "Die Einladung wurde an neu1@wehr.example geschickt" in r.text and "Einladung offen" in r.text and len(outbox) == 1
    to, subject, mailbody = outbox[0]
    assert to == "neu1@wehr.example" and "Benutzername: neu1" in mailbody and "admin hat für dich" in mailbody and "48 Stunden" in mailbody
    link = re.search(r"https://gw\.wehr\.example/invite/([\w-]+)", mailbody)
    assert link and "Passwort:" not in mailbody, "die Mail enthält einen Link, kein Passwort"
    token1 = link.group(1)
    with m.SessionLocal() as db:
        neu1 = db.query(m.User).filter_by(username="neu1").one()
        assert neu1.invite_hash and token1 not in neu1.invite_hash and neu1.email == "neu1@wehr.example"; neu1_id = neu1.id
    pub = TestClient(app, base_url="http://testserver")          # nicht angemeldet
    inv = pub.get(f"/invite/{token1}").text
    assert "Hallo <strong>neu1</strong>" in inv and "ungültig oder abgelaufen" in pub.get("/invite/falsch").text
    pt = csrf(inv)
    assert pub.post(f"/invite/{token1}", data={"password": "ein-neues-passwort", "repeat": "ein-neues-passwort"}).status_code == 403
    assert "beide Eingaben müssen gleich sein" in pub.post(f"/invite/{token1}", data={"csrf": pt, "password": "ein-neues-passwort", "repeat": "anders-anders-12"}).text
    assert "mindestens 12" in pub.post(f"/invite/{token1}", data={"csrf": pt, "password": "kurz", "repeat": "kurz"}).text
    done_inv = pub.post(f"/invite/{token1}", data={"csrf": pt, "password": "ein-neues-passwort", "repeat": "ein-neues-passwort"}).text
    assert "Passwort gespeichert" in done_inv
    assert "ungültig oder abgelaufen" in pub.get(f"/invite/{token1}").text, "Link funktioniert nur einmal"
    n1, n1t, n1home = login("neu1", "ein-neues-passwort")
    assert "FF Musterstadt" in n1home and "Andere Wehr" not in n1home and ">Einstellungen<" not in n1home
    assert "Einladung offen" not in c.get("/users").text

    # erneut senden macht den alten Link ungültig; abgelaufene Links gelten nicht
    assert "Link an neu1@wehr.example senden" in c.get(f"/users/{neu1_id}/edit").text
    c.post(f"/users/{neu1_id}/invite", data={"csrf": tok}); token2 = re.search(r"/invite/([\w-]+)", outbox[-1][2]).group(1)
    r = c.post(f"/users/{neu1_id}/invite", data={"csrf": tok}); token3 = re.search(r"/invite/([\w-]+)", outbox[-1][2]).group(1)
    assert "Link zum Festlegen des Passworts an neu1@wehr.example geschickt" in r.text and token2 != token3
    assert "ungültig oder abgelaufen" in pub.get(f"/invite/{token2}").text and "Hallo" in pub.get(f"/invite/{token3}").text
    assert "FF Musterstadt" in login("neu1", "ein-neues-passwort")[2], "altes Passwort bleibt gültig, bis ein neues gesetzt ist"
    with m.SessionLocal() as db:
        db.get(m.User, neu1_id).invite_expires = m.utcnow() - dt.timedelta(minutes=1); db.commit()
    assert "ungültig oder abgelaufen" in pub.get(f"/invite/{token3}").text
    assert n1.post(f"/users/{neu1_id}/invite", data={"csrf": n1t}).status_code == 403

    # Versand scheitert: Benutzer bleibt angelegt, Meldung nennt den Grund
    mailer.deliver = lambda *a: (_ for _ in ()).throw(RuntimeError("Der Mailserver hat die Empfängeradresse abgelehnt."))
    r = c.post("/users/save", data=dict(NEWU, username="neu2", email="neu2@wehr.example", send_invite="on"))
    assert "gespeichert, aber die Einladung ging nicht raus" in r.text and "Empfängeradresse abgelehnt" in r.text
    with m.SessionLocal() as db:
        assert db.query(m.User).filter_by(username="neu2").count() == 1
    mailer.deliver = real_deliver
    # ohne Einladung weiterhin mit festem Passwort
    c.post("/users/save", data=dict(NEWU, username="neu3", password="festes-passwort-1", email="neu3@wehr.example"))
    assert "FF Musterstadt" in login("neu3", "festes-passwort-1")[2] and len(outbox) == 3

    # ---------- Termine aus CSV ----------
    from app import events
    assert events.split_datetime("24.12.2026 19:00") == (dt.date(2026, 12, 24), dt.time(19, 0), "")
    assert events.split_datetime("2027-01-14T07:30:00")[:2] == (dt.date(2027, 1, 14), dt.time(7, 30))
    assert events.split_datetime("19 Uhr")[:2] == (None, dt.time(19, 0)) and events.split_datetime("19.30")[:2] == (None, dt.time(19, 30))
    assert events.split_datetime("5.2.27")[0] == dt.date(2027, 2, 5) and events.split_datetime("morgen")[2] and events.split_datetime("25:00")[2]
    CSV = ("Titel;Datum;Beginn;Ende;Ort;Beschreibung;Gruppen;ID\r\n"
           "Übungsdienst Atemschutz;14.01.2027;19:00;21:30;Gerätehaus;Belastungsübung;;2027-001\r\n"
           "Jahreshauptversammlung;05.02.2027;20:00;;DGH;;Löschzug 1, Führung;2027-002\r\n"
           "Zeltlager;17.07.2027;;;Zeltplatz;;;2027-003\r\n"
           "Nachtübung;20.03.2027;22:00;01:00;;;;\r\n"
           ";01.04.2027;18:00;;;;;\r\n"
           "Kaputtes Datum;irgendwann;18:00;;;;;\r\n"
           "Falsche Gruppe;02.04.2027;18:00;19:00;;;Gibtsnicht;\r\n"
           "\r\n")
    look = {"löschzug 1": 12, "führung": 13}
    parsed_csv = events.parse_csv(CSV.encode("cp1252"), look)     # Excel-Kodierung
    rws = parsed_csv["rows"]
    assert not parsed_csv["error"] and len(rws) == 7 and events.parse_csv(CSV.encode("utf-8-sig"), look)["rows"] == rws
    assert all(r["reminder_ts"] is None and r["response"] == "" for r in rws), "ohne die neuen Spalten bleibt alles leer"
    berlin = events.TZ
    assert rws[0]["ts_start"] == int(dt.datetime(2027, 1, 14, 19, 0, tzinfo=berlin).timestamp()) and rws[0]["when"] == "14.01.2027 19:00 bis 21:30"
    assert rws[0]["key"] == "2027-001" and rws[0]["address"] == "Gerätehaus" and not rws[0]["errors"] and not rws[0]["fullday"]
    assert rws[1]["group_ids"] == [12, 13] and rws[1]["ts_end"] - rws[1]["ts_start"] == 7200 and "2 Stunden angenommen" in rws[1]["notes"][0]
    assert rws[2]["fullday"] and rws[2]["when"] == "17.07.2027, ganztägig" and rws[2]["ts_end"] - rws[2]["ts_start"] == 23 * 3600 + 59 * 60
    assert rws[3]["ts_end"] - rws[3]["ts_start"] == 3 * 3600 and rws[3]["key"].startswith("gw-") and "Folgetag" in rws[3]["notes"][0]
    assert rws[4]["errors"] == ["Titel fehlt"] and "kein erkennbares Datum" in rws[5]["errors"][0] and "Gibtsnicht" in rws[6]["errors"][0]
    assert events.parse_csv(b"Name,Wann\nx,y")["error"].startswith("Keine Spalte für den Titel") and events.parse_csv(b"")["error"]
    comma = events.parse_csv("Termin,Beginn,Ende\nDienst,2027-03-01 18:00,2027-03-01 20:00\n".encode())["rows"][0]
    assert comma["when"] == "01.03.2027 18:00 bis 20:00" and not comma["errors"]
    dup = events.parse_csv("Titel;Datum;ID\nA;01.03.2027;7\nB;02.03.2027;7\n".encode())["rows"]
    assert dup[1]["errors"] == ["kommt in der Datei doppelt vor"]
    ev = events.build_event(rws[0], {"audience": "all"})
    assert ev == {"Event": {"foreign_id": "2027-001", "title": "Übungsdienst Atemschutz", "ts_start": rws[0]["ts_start"], "ts_end": rws[0]["ts_end"],
                            "fullday": False, "send_push": False, "send_sms": False, "send_call": False, "send_mail": False, "send_pager": False,
                            "text": "Belastungsübung", "address": "Gerätehaus", "notification_type": 2, "response_type": 0}, "instructions": {}}, ev
    at = lambda *a: int(dt.datetime(*a, tzinfo=berlin).timestamp())
    assert events.stamp("2027-01-13T18:00") == at(2027, 1, 13, 18, 0) and events.stamp("") is None and events.stamp("quatsch") is None
    BEFORE = {"reminder_mode": "before", "reminder_days": 1, "reminder_time": "18:30", "reminder_channels": ["push", "mail"]}
    ev2 = events.build_event(rws[1], dict(BEFORE, audience="persons", ucr_ids=[501], channels=["push", "mail", "sms"]))
    assert ev2["Event"]["notification_type"] == 3 and ev2["Event"]["group"] == [12, 13] and "user_cluster_relation" not in ev2["Event"]
    assert ev2["Reminder"] == {"ts": at(2027, 2, 4, 18, 30), "send_push": True, "send_mail": True}, ev2["Reminder"]
    assert (ev2["Event"]["send_push"], ev2["Event"]["send_sms"], ev2["Event"]["send_mail"], ev2["Event"]["send_call"], ev2["Event"]["send_pager"]) == (True, True, True, False, False)
    same_day = events.build_event(rws[0], dict(BEFORE, reminder_days=0, reminder_time="12:00", reminder_channels=["mail"]))
    assert same_day["Reminder"] == {"ts": at(2027, 1, 14, 12, 0), "send_push": False, "send_mail": True}
    assert "Reminder" not in events.build_event(rws[0], dict(BEFORE, reminder_days=0, reminder_time="19:00")), "Erinnerung nie zum oder nach dem Beginn"
    fixed = {"reminder_mode": "fixed", "reminder_ts": at(2027, 1, 20, 9, 0), "reminder_channels": ["push"]}
    assert "Reminder" not in events.build_event(rws[0], fixed) and events.build_event(rws[1], fixed)["Reminder"]["ts"] == at(2027, 1, 20, 9, 0)
    assert "läge nicht vor dem Termin" in events.summary(rws[0], fixed, events.build_event(rws[0], fixed))["reminder"]
    yes = events.build_event(rws[0], {"response": "yesno", "response_until": at(2027, 1, 10, 12, 0)})["Event"]
    assert yes["response_type"] == 1 and "custom_answers" not in yes and yes["response_until"] is True and yes["ts_response"] == at(2027, 1, 10, 12, 0)
    free = events.build_event(rws[0], {"response": "text", "response_until": at(2027, 2, 1, 12, 0)})["Event"]
    assert free["response_type"] == 1 and free["custom_answers"] is True and "ts_response" not in free, "Frist nach dem Termin wird weggelassen"
    CSV2 = ("Titel;Datum;Beginn;Erinnerung;Rückmeldung\nA;14.01.2027;19:00;13.01.2027 17:15;freitext\nB;14.01.2027;19:00;12.01.2027;nein\n"
            "C;14.01.2027;19:00;15.01.2027 10:00;ja\nD;14.01.2027;19:00;18:00;vielleicht\n")
    own = events.parse_csv(CSV2.encode())["rows"]
    assert own[0]["reminder_ts"] == at(2027, 1, 13, 17, 15) and own[0]["response"] == "text" and own[1]["reminder_ts"] == at(2027, 1, 12, 18, 0) and own[1]["response"] == "none"
    assert own[2]["errors"] == ["Erinnerung liegt nicht vor dem Termin"] and len(own[3]["errors"]) == 2
    mixed = events.build_event(own[0], dict(BEFORE, response="none"))   # Angaben der Zeile gehen vor
    assert mixed["Reminder"]["ts"] == at(2027, 1, 13, 17, 15) and mixed["Event"]["custom_answers"] is True
    assert events.build_event(own[1], {"response": "text"})["Event"]["response_type"] == 0
    info = events.summary(own[0], {"channels": ["push", "sms"]}, events.build_event(own[0], {"channels": ["push", "sms"]}))
    assert info == {"audience": "alle", "channels": "Push-Nachricht, SMS", "reminder": "13.01.2027 17:15", "response": "ja / nein und Freitext"}, info
    ev3 = events.build_event(rws[0], {"audience": "persons", "ucr_ids": [501]})
    assert ev3["Event"]["notification_type"] == 4 and ev3["Event"]["user_cluster_relation"] == [501] and ev3["instructions"] == {"user_cluster_relation": {"mapping": "id"}}

    with m.SessionLocal() as db:   # Gruppenliste und persönlicher Schlüssel der Löschgruppe 1 für den Ablauf
        t1 = db.get(m.Tenant, 1); t1.directory = json.dumps(parsed); t1.accesskey_user_enc = __import__("app.security", fromlist=["x"]).encrypt("persoenlich456"); db.commit()
    evpage = c.get("/tenants/1/events").text
    assert "CSV-Datei hochladen" in evpage and "termine-vorlage.csv" in evpage and "Noch nichts importiert" in evpage
    vorlage = c.get("/static/termine-vorlage.csv").content
    assert not any(r["errors"] for r in events.parse_csv(vorlage)["rows"]) and len(events.parse_csv(vorlage)["rows"]) == 3
    assert "Bitte eine CSV-Datei auswählen" in c.post("/tenants/1/events/upload", data={"csrf": tok}).text
    assert "Keine Spalte für den Titel" in c.post("/tenants/1/events/upload", data={"csrf": tok}, files={"file": ("x.csv", b"a;b\n1;2")}).text
    assert c.post("/tenants/1/events/upload", data={}, files={"file": ("x.csv", CSV.encode())}).status_code == 403
    prev = c.post("/tenants/1/events/upload", data={"csrf": tok}, files={"file": ("dienstplan.csv", CSV.encode("cp1252"))})
    assert "/events/batch/1" in str(prev.url) and "Vorschau: dienstplan.csv" in prev.text
    assert "4 Termine in DIVERA anlegen" in prev.text and "Titel fehlt" in prev.text and "Löschzug 1, Führung" in prev.text and "Muster, Max" in prev.text
    posted = []
    def fake_send(key, payload):
        posted.append((key, payload))
        return (False, "HTTP 500: kaputt") if payload["Event"]["title"] == "Zeltlager" else (True, 'HTTP 200: {"success":true}')
    real_event_send, events.send_event = events.send_event, fake_send
    assert "mindestens eine Person ankreuzen" in c.post("/events/batch/1/import", data={"csrf": tok, "audience": "persons"}).text and not posted
    assert "Datum und Uhrzeit wählen" in c.post("/events/batch/1/import", data={"csrf": tok, "reminder_mode": "fixed", "reminder_channel": ["push"]}).text
    assert "wie erinnert werden soll" in c.post("/events/batch/1/import", data={"csrf": tok, "reminder_mode": "before"}).text and not posted
    assert 'type="datetime-local" name="reminder_at"' in prev.text and 'name="channel" value="sms"' in prev.text and 'name="response" value="text"' in prev.text
    res = c.post("/events/batch/1/import", data={"csrf": tok, "audience": "persons", "ucr": ["501"], "reminder_mode": "before", "reminder_days": "1",
                                                 "reminder_time": "18:00", "reminder_channel": ["push", "mail"], "channel": ["mail", "boese"],
                                                 "response": "text", "response_until": "2027-01-10T12:00"})
    assert "ja / nein und Freitext, bis 10.01.2027 12:00" in res.text and "13.01.2027 18:00" in res.text and ">E-Mail<" in res.text
    assert "3 Termine in DIVERA angelegt" in res.text and "1 fehlgeschlagen" in res.text and "HTTP 500: kaputt" in res.text
    assert [p[0] for p in posted] == ["persoenlich456"] * 4 and len(posted) == 4, "nur die fehlerfreien Zeilen, mit dem persönlichen Schlüssel"
    assert posted[0][1]["Event"]["user_cluster_relation"] == [501] and posted[1][1]["Event"]["group"] == [12, 13] and posted[0][1]["Event"]["send_push"] is False
    assert posted[0][1]["Reminder"] == {"ts": at(2027, 1, 13, 18, 0), "send_push": True, "send_mail": True}
    assert posted[0][1]["Event"]["send_mail"] is True and posted[0][1]["Event"]["send_sms"] is False and posted[0][1]["Event"]["custom_answers"] is True
    assert posted[0][1]["Event"]["ts_response"] == at(2027, 1, 10, 12, 0)
    with m.SessionLocal() as db:
        assert {e.key for e in db.query(m.ImportedEvent)} == {"2027-001", "2027-002", rws[3]["key"]} and db.query(m.ImportBatch).count() == 1
    again_prev = c.get("/events/batch/1").text
    assert "1 Termin in DIVERA anlegen" in again_prev and again_prev.count("schon importiert</span>") == 3
    posted.clear()
    events.send_event = lambda key, payload: posted.append(payload) or (True, "HTTP 200: ok")
    assert "1 Termin in DIVERA angelegt" in c.post("/events/batch/1/import", data={"csrf": tok}).text and len(posted) == 1
    assert posted[0]["Event"]["title"] == "Zeltlager" and posted[0]["Event"]["notification_type"] == 2 and "Reminder" not in posted[0]
    assert posted[0]["Event"]["response_type"] == 0 and posted[0]["Event"]["send_push"] is False
    with m.SessionLocal() as db:
        assert db.query(m.ImportBatch).count() == 0 and db.query(m.ImportedEvent).count() == 4, "erledigte Datei wird gelöscht"
    assert c.get("/events/batch/1").status_code == 404
    # dieselbe Datei noch einmal: nichts Neues
    prev2 = c.post("/tenants/1/events/upload", data={"csrf": tok}, files={"file": ("dienstplan.csv", CSV.encode())})
    assert "0 Termine in DIVERA anlegen" in prev2.text
    assert "kein neuer Termin" in c.post(str(prev2.url).replace("http://testserver", "") + "/import", data={"csrf": tok}).text
    assert "Übungsdienst Atemschutz" in c.get("/tenants/1/events").text and "Terminimport" in c.get("/logs").text
    # DIVERA lehnt den Schlüssel ab: sofort abbrechen statt alle Zeilen durchzuprobieren
    posted.clear()
    events.send_event = lambda key, payload: posted.append(1) or (False, 'HTTP 403: {"message":"Nicht autorisiert"}')
    r403 = c.post("/tenants/1/events/upload", data={"csrf": tok}, files={"file": ("neu.csv", "Titel;Datum\nA;01.05.2027\nB;02.05.2027\nC;03.05.2027\n".encode())})
    stop = c.post(str(r403.url).replace("http://testserver", "") + "/import", data={"csrf": tok})
    assert len(posted) == 1 and "2 nicht mehr versucht" in stop.text and "trotzdem abgelehnt" in stop.text
    events.send_event = real_event_send
    # Rechte: ohne Senderecht kein Import, fremde Löschgruppe unsichtbar
    assert n1.get("/tenants/1/events").status_code == 403 and "Termine aus CSV importieren" not in n1.get("/tenants/1").text
    assert e.get("/tenants/1/events").status_code == 200 and e.get("/tenants/2/events").status_code == 404
    c.post("/tenants/2/events/upload", data={"csrf": tok}, files={"file": ("fremd.csv", "Titel;Datum\nFremd;01.06.2027\n".encode())})
    with m.SessionLocal() as db:
        foreign_batch = db.query(m.ImportBatch).filter_by(tenant_id=2).one().id
    assert e.get(f"/events/batch/{foreign_batch}").status_code == 404 and e.post(f"/events/batch/{foreign_batch}/import", data={"csrf": et}).status_code == 404

    # ---------- Meldung von Hand senden ----------
    assert "bitte wählen" in c.get("/send").text and 'href="/send"' in c.get("/").text
    sendform = c.get("/send?tenant=1").text
    assert "Meldung an FF Musterstadt" in sendform and "Muster, Max" in sendform and '<option value="news" selected>' in sendform
    assert "Meldung an FF Musterstadt" in e.get("/send").text, "bei nur einer Löschgruppe ist sie vorausgewählt"
    assert n1.get("/send").status_code == 403 and e.get("/send?tenant=2").status_code == 404 and ">Senden<" not in n1.get("/").text
    MAN = {"csrf": tok, "tenant_id": "1", "kind": "alarm", "notify": "default", "title": "Probe {subject}", "text": "Zeile 1\r\nZeile {x}", "address": "Gerätehaus",
           "ric": "LZ1", "priority": "on"}
    assert "Bitte ein Stichwort eintragen" in c.post("/send", data=dict(MAN, title="")).text
    hand = []
    keep_send = rules.send_divera
    rules.send_divera = lambda key, payload: hand.append((key, payload)) or (True, 'HTTP 200: {"success":true}')
    ask = c.post("/send", data=MAN).text
    assert "Wirklich an DIVERA senden?" in ask and "Achtung, echter Alarm" in ask and "Probe {subject}" in ask and 'formaction="/send"' in ask and not hand
    assert "Meldung von Hand" in ask and "Regel wird dabei nicht gespeichert" not in ask
    back = c.post("/send", data=dict(MAN, edit="1")).text
    assert 'value="Probe {subject}"' in back and '<option value="alarm" selected>' in back and "Zeile {x}" in back and not hand
    done = c.post("/send", data=dict(MAN, confirm="ja")).text
    assert "Alarm „Probe {subject}" in done and "an DIVERA gesendet" in done and len(hand) == 1
    assert hand[0] == ("geheim123", {"title": "Probe {subject}", "text": "Zeile 1\nZeile {x}", "address": "Gerätehaus", "ric": "LZ1", "priority": "1"}), hand[0]
    quiet = c.post("/send", data={"csrf": tok, "tenant_id": "1", "kind": "news", "notify": "custom", "title": "Info", "ucr": ["501"], "confirm": "ja"}).text
    assert "Mitteilung „Info" in quiet and hand[1][0] == "persoenlich456" and hand[1][1]["News"]["user_cluster_relation"] == [501]
    assert [hand[1][1]["News"][f"send_{n}"] for n in ("push", "sms", "call", "mail", "pager")] == [False] * 5, "nichts angekreuzt = still"
    # Benachrichtigungswege einzeln wählen, für Mitteilung und Alarm
    assert 'name="channel" value="pager"' in sendform and 'name="notify" value="custom"' in sendform
    CUSTOM = dict(MAN, notify="custom", channel=["push", "sms", "pager", "boese"], grp=["12"], ric="LZ1")
    askc = c.post("/send", data=CUSTOM).text
    assert "Push-Nachricht in der App, SMS, Pager" in askc and "nur die angekreuzten Gruppen" in askc and "RIC wird bei diesem Übertragungsweg nicht übertragen" in askc
    backc = c.post("/send", data=dict(CUSTOM, edit="1")).text
    assert 'name="channel" value="sms" checked' in backc and 'name="channel" value="mail" checked' not in backc and 'name="notify" value="custom" checked' in backc
    c.post("/send", data=dict(CUSTOM, confirm="ja"))
    key3, alarm3 = hand[2]
    assert key3 == "persoenlich456" and set(alarm3) == {"Alarm", "instructions"} and alarm3["instructions"] == {"group": {"mapping": "id"}}
    assert alarm3["Alarm"] == {"title": "Probe {subject}", "text": "Zeile 1\nZeile {x}", "notification_type": 3, "send_push": True, "send_sms": True,
                               "send_call": False, "send_mail": False, "send_pager": True, "address": "Gerätehaus", "priority": True, "group": [12]}, alarm3
    c.post("/send", data=dict(CUSTOM, kind="news", channel=["mail"], grp=[], ric="", confirm="ja"))
    assert hand[3][1]["News"]["notification_type"] == 2 and hand[3][1]["News"]["send_mail"] is True and "priority" not in hand[3][1]["News"]
    import httpx as _hx3
    seen_urls = []
    class _R3:
        status_code, text = 201, "{}"
        def json(self): return {}
    keep3, rules.httpx.post = rules.httpx.post, lambda url, params=None, data=None, json=None, timeout=None: seen_urls.append((url, json is not None)) or _R3()
    assert keep_send("k", alarm3)[0] and keep_send("k", hand[3][1])[0] and keep_send("k", {"title": "x"})[0]
    rules.httpx.post = keep3
    assert [u[0].rsplit("/", 1)[1] for u in seen_urls] == ["alarms", "news", "alarm"] and [u[1] for u in seen_urls] == [True, True, False]
    rules.send_divera = lambda key, payload: (False, "HTTP 500: kaputt")
    failed_send = c.post("/send", data=dict(MAN, confirm="ja")).text
    assert "Senden fehlgeschlagen" in failed_send and 'value="Probe {subject}"' in failed_send
    rules.send_divera = keep_send
    handlog = c.get("/logs").text
    assert "Meldung von Hand" in handlog and "ausgelöst von admin" in handlog
    assert e.post("/send", data=dict(MAN, csrf=et, tenant_id="2", confirm="ja")).status_code == 404
    assert n1.post("/send", data=dict(MAN, csrf=n1t, confirm="ja")).status_code == 403

    # ---------- Systemprotokoll ----------
    def sysrows(**where):
        with m.SessionLocal() as db:
            return [(r.level, r.category, r.message, r.detail, r.actor, r.tenant_name) for r in db.query(m.SystemEvent).filter_by(**where).order_by(m.SystemEvent.id)]
    logins = sysrows(category="Anmeldung")
    assert any(l[0] == "warnung" and "Fehlgeschlagene Anmeldung als „admin“" in l[2] and "falsches Passwort" in l[3] and "testclient" in l[3] for l in logins), logins[:3]
    assert any(l[0] == "info" and l[2] == "admin hat sich angemeldet" and l[4] == "admin" for l in logins)
    assert not any("test-passwort" in str(l) or "nein" == l[3] for l in sysrows()), "Passwörter stehen nie im Protokoll"
    groups_log = sysrows(category="Löschgruppe")
    assert groups_log[0][2] == "Löschgruppe „FF Musterstadt“: angelegt, Accesskey geändert" and "geheim123" not in str(groups_log)
    polls = [r for r in sysrows(category="Quelle") if "Leitstelle" in r[2]]
    assert sum("Abruf von „Leitstelle“ fehlgeschlagen" in r[2] for r in polls) == 1 and polls[-1][0] == "fehler" and "kaputt" in polls[-1][3] and polls[-1][5] == "FF Musterstadt"
    sources.POLLERS["m365"] = lambda cfg, state: (_ for _ in ()).throw(RuntimeError("kaputt"))
    worker.run_source(1); worker.run_source(1)
    assert sum("Abruf von „Leitstelle“ fehlgeschlagen" in r[2] for r in sysrows(category="Quelle")) == 1, "derselbe Fehler wird nicht bei jeder Abfrage neu protokolliert"
    sources.POLLERS["m365"] = lambda cfg, state: (_ for _ in ()).throw(RuntimeError("Anmeldung bei Microsoft fehlgeschlagen: Schlüssel abgelaufen"))
    worker.run_source(1)
    sources.POLLERS["m365"] = lambda cfg, state: ([], state)
    worker.run_source(1); worker.run_source(1)
    tail = [r[2] for r in sysrows(category="Quelle")][-2:]
    assert tail == ["Abruf von „Leitstelle“ fehlgeschlagen", "Verbindung zu „Leitstelle“ funktioniert wieder"], tail
    assert any("Schlüssel abgelaufen" in r[3] for r in sysrows(category="Quelle"))
    mails = sysrows(category="E-Mail-Versand")
    assert any(r[0] == "fehler" and "Einladung an „neu2“" in r[2] for r in mails) and any(r[0] == "info" and "Einladung an „neu1“ verschickt" in r[2] for r in mails)
    assert any(r[0] == "fehler" and "Testnachricht" in r[2] and "abgelehnt" in r[3] for r in mails)
    assert any("Benutzer „neu1“ angelegt" in r[2] and r[4] == "admin" for r in sysrows(category="Benutzer"))
    assert any("über den Einladungslink ein Passwort festgelegt" in r[2] for r in sysrows(category="Benutzer"))
    denied = sysrows(category="Berechtigung")
    assert any("Zugriff verweigert: GET /users" in r[2] and r[4] == "leser" for r in denied) and any(r[4] == "bearb" for r in denied)
    assert any(r[2].startswith("DIVERA Gateway") and "gestartet" in r[2] for r in sysrows(category="System"))
    assert any("Empfängerliste konnte nicht" in r[2] for r in sysrows(category="DIVERA"))
    keep_check, rules.check_key = rules.check_key, lambda key: {"status": 403, "ok": False, "info": "Nicht autorisiert"}
    c.post("/tenants/1/keycheck", data={"csrf": tok})
    rules.check_key = keep_check
    assert any(r[0] == "fehler" and "Schlüsselprüfung: Alarm-Accesskey der Einheit wurde abgelehnt" in r[2] and "HTTP 403" in r[3] for r in sysrows(category="DIVERA"))
    c.post("/tenants/save", data={"csrf": tok, "id": "1", "name": "FF Musterstadt", "active": "on"})   # Testmodus aus
    assert sysrows(category="Löschgruppe")[-1][:3] == ("warnung", "Löschgruppe", "Löschgruppe „FF Musterstadt“: Testmodus ausgeschaltet: ab jetzt wird an DIVERA gesendet")
    c.post("/tenants/save", data={"csrf": tok, "id": "1", "name": "FF Musterstadt", "active": "on", "test_mode": "on"})

    adminsys = c.get("/logs?view=system").text
    assert "Systemprotokoll" in adminsys and "Fehlgeschlagene Anmeldung" in adminsys and "funktioniert wieder" in adminsys and "Fehler in 24 Std." in adminsys
    assert "Fehlgeschlagene Anmeldung" not in c.get("/logs?view=system&category=Quelle").text and "Abruf von" in c.get("/logs?view=system&level=fehler").text
    assert "Fehler in 24 Stunden" in c.get("/").text
    with m.SessionLocal() as db:
        db.add(m.SystemEvent(level="fehler", category="Quelle", tenant_id=2, tenant_name="Andere Wehr", message="FREMDER-FEHLER")); db.commit()
    esys = e.get("/logs?view=system").text     # Bearbeiter, nur Löschgruppe 1, verwaltet keine Benutzer
    assert "Abruf von „Leitstelle“ fehlgeschlagen" in esys and "FREMDER-FEHLER" not in esys and "hat sich angemeldet" not in esys
    assert "Zugriff verweigert" not in esys and "Du siehst nur Einträge zu deinen Löschgruppen" in esys and "FREMDER-FEHLER" in adminsys.replace(adminsys, c.get("/logs?view=system").text)
    assert g.get("/logs?view=system").status_code == 403, "ohne Protokollrecht auch kein Systemprotokoll"
    # unerwarteter Programmfehler landet im Systemprotokoll
    import app.main as main_mod
    crash = TestClient(app, base_url="http://testserver", raise_server_exceptions=False)
    ct = csrf(crash.get("/login").text); crash.post("/login", data={"csrf": ct, "username": "neu3", "password": "festes-passwort-1"})
    real_directory = main_mod.directory_of
    main_mod.directory_of = lambda tenant: (_ for _ in ()).throw(ValueError("absichtlicher Testfehler"))
    boom = crash.get("/tenants/1")
    main_mod.directory_of = real_directory
    assert boom.status_code == 500 and "Systemprotokoll" in boom.text
    last_sys = sysrows(category="System")[-1]
    assert last_sys[0] == "fehler" and "Unerwarteter Fehler bei GET /tenants/1" in last_sys[2] and "absichtlicher Testfehler" in last_sys[3] and last_sys[4] == "neu3"

    # Rechte wirken sofort, auch in laufenden Sitzungen
    c.post("/users/save", data=dict(VIEW, id=str(leser_id), p_rules="0", tenant=["2"]))
    assert v.get("/tenants/1").status_code == 404 and v.get(f"/rules/{other_rule}/edit").status_code == 403
    assert "Regeln" not in v.get("/tenants/2").text.split("<main>")[1].replace("Regeln werden", "")
    c.post(f"/users/{leser_id}/delete", data={"csrf": tok})
    assert v.get("/", follow_redirects=False).status_code == 303, "gelöschter Benutzer ist abgemeldet"

    c.post("/logout", data={"csrf": tok})
    assert c.get("/logs", follow_redirects=False).status_code == 303 and c.get("/help", follow_redirects=False).status_code == 303
    with m.SessionLocal() as db:
        gone = db.query(m.User).filter_by(username="admin").one()
        assert gone.last_seen is None and gone.last_login is not None, "nach dem Abmelden sofort nicht mehr angemeldet"

print("Alle Prüfungen bestanden.")
