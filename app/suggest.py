"""Leitet aus einer Beispielnachricht einen Regelvorschlag ab.

Der Vorschlag ist ein Startpunkt zum Herantesten, keine fertige Regel: Er erkennt Zeilen der Form
"Bezeichnung: Wert" und ordnet bekannte Bezeichnungen dem Stichwort, der Adresse und dem Text zu.
"""
import re

RESERVED = {"from", "subject", "body", "date"}
MAX_FIELDS = 10
_KEY_VALUE = re.compile(r"^[ \t>*-]*([A-Za-zÄÖÜäöüß][\wÄÖÜäöüß .\-/()]{1,34}?)[ \t]*[:=][ \t]*(\S.*?)\s*$")

# Reihenfolge = Vorrang. Verglichen wird mit der kleingeschriebenen Bezeichnung.
TITLE_KEYS = ("einsatzstichwort", "alarmstichwort", "stichwort", "einsatzart", "schlagwort", "ereignis", "alarmart", "meldung")
STREET_KEYS = ("straße", "strasse", "adresse", "anschrift", "einsatzort", "objekt")
CITY_KEYS = ("ortsteil", "gemeinde", "stadt", "ort")
TEXT_KEYS = ("bemerkung", "sachverhalt", "freitext", "beschreibung", "hinweis", "zusatz", "info", "meldung", "text")


def slug(label: str, used: set[str]) -> str:
    """Macht aus einer Bezeichnung einen Platzhalternamen, z. B. 'Straße / Nr.' -> 'strasse_nr'."""
    name = label.lower()
    for umlaut, plain in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss")):
        name = name.replace(umlaut, plain)
    name = re.sub(r"[^a-z0-9]+", "_", name).strip("_")[:24].strip("_") or "feld"
    if name[0].isdigit():
        name = "f_" + name
    base, counter = name, 2
    while name in used or name in RESERVED:
        name, counter = f"{base}_{counter}", counter + 1
    used.add(name)
    return name


def line_regex(label: str, name: str) -> str:
    escaped = re.sub(r"([.^$*+?{}\[\]\\|()])", r"\\\1", label.strip())
    escaped = re.sub(r"\s+", r"\\s+", escaped)
    return rf"^[ \t>*-]*{escaped}[ \t]*[:=][ \t]*(?P<{name}>.+)$"


def stable_subject(subject: str) -> str:
    """Der Teil des Betreffs vor der ersten Zahl; Nummern und Uhrzeiten ändern sich meist je Mail."""
    subject = re.sub(r"^\s*((AW|WG|RE|FW|FWD)\s*:\s*)+", "", subject or "", flags=re.I)
    words = []
    for word in subject.split():
        if re.search(r"\d", word):
            break
        words.append(word)
    return " ".join(words).strip(" -:|#,;")[:60]


def _pick(fields: list[dict], keys: tuple[str, ...], taken: set[str]) -> dict | None:
    for key in keys:
        for field in fields:
            if field["name"] not in taken and key in field["label"].lower():
                taken.add(field["name"])
                return field
    return None


def suggest(msg: dict) -> dict:
    """Gibt vorgeschlagene Regelwerte und erklärende Hinweise zurück."""
    notes: list[str] = []
    used: set[str] = set()
    fields: list[dict] = []
    regex_lines: list[str] = []

    extra = msg.get("extra") or {}
    for key, value in list(extra.items())[:MAX_FIELDS]:  # Webhook: Felder sind schon Platzhalter
        used.add(key)
        fields.append({"label": key, "name": key, "value": str(value)})
    if not extra:
        seen_labels: set[str] = set()
        for line in (msg.get("body") or "").splitlines():
            found = _KEY_VALUE.match(line)
            if not found or found.group(2).startswith("//") or found.group(1).strip().lower() in seen_labels:
                continue
            label = found.group(1).strip()
            seen_labels.add(label.lower())
            name = slug(label, used)
            fields.append({"label": label, "name": name, "value": found.group(2)})
            regex_lines.append(line_regex(label, name))
            if len(fields) >= MAX_FIELDS:
                break

    taken: set[str] = set()
    title = _pick(fields, TITLE_KEYS, taken)
    street = _pick(fields, STREET_KEYS, taken)
    city = _pick(fields, CITY_KEYS, taken)
    text = _pick(fields, TEXT_KEYS, taken)

    subject_part = stable_subject(msg.get("subject", ""))
    result = {
        "name": ("Vorschlag: " + (subject_part or msg.get("from", "") or "neue Regel"))[:120],
        "match_from": "" if extra else (msg.get("from") or "")[:200],
        "match_subject": subject_part,
        "extract_regex": "\n".join(regex_lines),
        "title_tpl": "{%s}" % title["name"] if title else "{subject}",
        "address_tpl": ", ".join("{%s}" % f["name"] for f in (street, city) if f),
        "text_tpl": "{%s}" % text["name"] if text else "{body}",
    }

    if result["match_from"]:
        notes.append(f"Bedingung Absender: „{result['match_from']}“.")
    if subject_part:
        notes.append(f"Bedingung Betreff: „{subject_part}“ (der Teil vor der ersten Zahl). Prüfe, ob das bei allen gewünschten Mails vorkommt.")
    else:
        notes.append("Keine Betreff-Bedingung vorgeschlagen, weil der Betreff keinen festen Anfang erkennen lässt.")
    if fields:
        listed = ", ".join("{%s} = „%s“" % (f["name"], f["value"][:40]) for f in fields)
        notes.append(("Übergebene Felder: " if extra else "Im Text erkannte Zeilen: ") + listed + ".")
    else:
        notes.append("Im Text wurden keine Zeilen der Form „Bezeichnung: Wert“ erkannt. Stichwort und Text übernehmen deshalb Betreff und ganzen Mailtext.")
    if fields and not title:
        notes.append("Kein Feld sieht nach einem Stichwort aus, daher wird der Betreff als Stichwort verwendet.")
    if fields and not (street or city):
        notes.append("Kein Feld sieht nach einer Adresse aus, das Adressfeld bleibt leer.")
    return {"fields": result, "notes": notes}
