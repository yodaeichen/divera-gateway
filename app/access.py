"""Berechtigungen der Gateway-Benutzer: Einzelrechte je Bereich, Rollen als Vorlage, Beschränkung auf Löschgruppen."""
import json

# Bereich, Bezeichnung, erlaubte Stufen (0 = kein Zugriff, 1 = nur sehen, 2 = bearbeiten)
AREAS = [
    ("tenants", "Löschgruppen und Schlüssel", [(1, "nur sehen"), (2, "bearbeiten")],
     "Bearbeiten: Löschgruppen anlegen und löschen, Accesskeys, Testmodus, Empfängerliste laden, Schlüssel prüfen."),
    ("sources", "Quellen (Postfächer, Webhooks)", [(0, "kein Zugriff"), (1, "nur sehen"), (2, "bearbeiten")],
     "Sehen schließt „Verbindung testen“ ein und zeigt dabei Absender und Betreff der neuesten Nachrichten."),
    ("rules", "Regeln", [(0, "kein Zugriff"), (1, "nur sehen"), (2, "bearbeiten")],
     "Sehen: Regeln öffnen und in der Live-Ansicht ausprobieren, aber nicht speichern."),
    ("logs", "Protokoll", [(0, "kein Zugriff"), (1, "sehen")], "Zeigt nur Einträge der Löschgruppen, die der Benutzer sehen darf."),
    ("users", "Benutzer und Rechte", [(0, "kein Zugriff"), (2, "verwalten")],
     "Darf Benutzer anlegen, löschen und alle Rechte vergeben. Gilt immer für alle Löschgruppen."),
]
PRESETS = {
    "admin": {"tenants": 2, "sources": 2, "rules": 2, "logs": 1, "users": 2, "send": True},
    "editor": {"tenants": 1, "sources": 2, "rules": 2, "logs": 1, "users": 0, "send": True},
    "viewer": {"tenants": 1, "sources": 1, "rules": 1, "logs": 1, "users": 0, "send": False},
}
ROLE_NAMES = {"admin": "Administrator", "editor": "Bearbeiter", "viewer": "Betrachter"}
ROLE_HINTS = {
    "admin": "darf alles",
    "editor": "pflegt Quellen und Regeln und darf senden, aber nichts an Schlüsseln und Benutzern ändern",
    "viewer": "darf nur ansehen",
}
SEND_HINT = ("Die Menüpunkte „Alarme“, „Mitteilungen“ und „Termine“, „Testweise an DIVERA senden“, „Jetzt verarbeiten“, „Jetzt abrufen“ und der Import von Terminen. "
             "Ohne dieses Recht kann der Benutzer von Hand nichts an DIVERA auslösen.")


class Denied(Exception):
    def __init__(self, message: str = "Dafür fehlt dir die Berechtigung."):
        self.message = message


def clean(perms: dict) -> dict:
    """Bringt Rechte in gültige Form: nur bekannte Bereiche und erlaubte Stufen."""
    result = {}
    for area, _label, levels, _hint in AREAS:
        allowed = [level for level, _ in levels]
        try:
            value = int(perms.get(area, allowed[0]))
        except (TypeError, ValueError):
            value = allowed[0]
        result[area] = value if value in allowed else allowed[0]
    result["send"] = bool(perms.get("send"))
    return result


def perms_of(user) -> dict:
    """Rechte eines Benutzers. Konten aus der Zeit vor der Rechteverwaltung haben keine Angabe und gelten als Administrator."""
    if not user.perms:
        return dict(PRESETS["admin"])
    try:
        return clean(json.loads(user.perms))
    except ValueError:
        return clean({})


def sees_all(user) -> bool:
    return user.all_tenants is None or bool(user.all_tenants) or perms_of(user)["users"] == 2


def tenant_ids(user) -> set[int]:
    return {int(part) for part in (user.tenant_ids or "").split(",") if part.strip().isdigit()}


def allowed(user, tenant_id: int) -> bool:
    return sees_all(user) or tenant_id in tenant_ids(user)


def role_of(user) -> str:
    perms = perms_of(user)
    for key, preset in PRESETS.items():
        if perms == preset:
            return ROLE_NAMES[key]
    return "Angepasst"


def require(user, *needs: str):
    """needs wie "rules:2" oder "send". Löst Denied aus, wenn etwas fehlt."""
    perms = perms_of(user)
    for item in needs:
        area, _, level = item.partition(":")
        if area == "send":
            if not perms["send"]:
                raise Denied("Dafür brauchst du das Recht, von Hand an DIVERA zu senden.")
        elif perms[area] < int(level or 1):
            label = next(text for key, text, _l, _h in AREAS if key == area)
            raise Denied(f"Dafür fehlt dir die Berechtigung im Bereich „{label}“.")


def from_form(form) -> tuple[dict, bool, str]:
    """Liest Rechte, „alle Löschgruppen“ und die Liste der Löschgruppen aus dem Benutzerformular."""
    perms = clean({**{area: form.get(f"p_{area}") for area, *_ in AREAS}, "send": "p_send" in form})
    everything = "all_tenants" in form or perms["users"] == 2  # wer Rechte vergibt, könnte sich ohnehin alles freischalten
    ids = sorted({int(v) for v in form.getlist("tenant") if str(v).isdigit()})
    return perms, everything, ",".join(str(i) for i in ids)
