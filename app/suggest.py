"""Leitet aus einer Beispielnachricht einen Regelvorschlag ab.

Der Vorschlag ist ein Startpunkt zum Herantesten, keine fertige Regel: Er erkennt Zeilen der Form
"Bezeichnung: Wert" und ordnet bekannte Bezeichnungen dem Stichwort, der Adresse und dem Text zu.
"""
import re

from . import rules

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


# Kopfzeilen einer weitergeleiteten Mail sind keine Inhalte und sollen keine Platzhalter werden
FORWARD_LABELS = {"von", "gesendet", "an", "cc", "bcc", "betreff", "from", "sent", "to", "subject", "datum", "date", "wichtigkeit",
                  "priorität", "antwort an", "reply-to"}


def common_subject(subject: str, others: list[str]) -> str:
    """Der gemeinsame Anfang des Betreffs mit anderen Nachrichten desselben Absenders, wortweise verglichen.

    Nur was in mehreren Nachrichten gleich ist, taugt als Bedingung. Gibt es keine Vergleichsnachricht oder keinen
    gemeinsamen Anfang, bleibt die Bedingung leer, damit die Regel nicht nur auf die eine Beispielnachricht passt.
    """
    words = rules.clean_subject(subject).split()
    best: list[str] = []
    for other in others:
        candidate = []
        for mine, theirs in zip(words, rules.clean_subject(other).split()):
            if mine.lower() != theirs.lower() or re.search(r"\d", mine):
                break
            candidate.append(mine)
        if candidate and (not best or len(candidate) < len(best)):
            best = candidate          # der kürzeste gemeinsame Anfang passt auf die meisten Nachrichten
    return " ".join(best).strip(" -:|#,;/")[:60] if len(" ".join(best)) >= 4 else ""


_BRACKET_SUBJECT = re.compile(r"^(?P<head>[^()]{3,80}?)\s*\((?P<inner>.+)\)\s*$")
_DATE_PART = re.compile(r"\d{1,2}\.\d{1,2}\.")
_COMPANY_PART = re.compile(r"^(Fa\.|Firma)\s|\b(GmbH|AG|KG|GbR|OHG|e\.\s?K\.|UG)\b", re.I)
_MEASURE_PART = re.compile(r"sperrung|baustelle|umleitung|halteverbot|arbeiten|einengung|aufbruch", re.I)


def split_top_level(inner: str) -> list[str]:
    """Teilt 'a, b (c, d), e' an den Kommas außerhalb von Klammern."""
    parts, depth, current = [], 0, ""
    for char in inner:
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    parts.append(current.strip())
    return [p for p in parts if p]


def structured_subject(subject: str) -> dict | None:
    """Erkennt Betreffzeilen der Form „Art (Teil, Teil, Teil, …)“, wie Behörden sie oft verwenden, und baut einen
    Ausdruck, der die Teile als Platzhalter herausliest. Die Namen sind eine Vermutung nach Inhalt und Reihenfolge."""
    found = _BRACKET_SUBJECT.match(rules.clean_subject(subject))
    if not found:
        return None
    parts = split_top_level(found.group("inner"))
    if not 3 <= len(parts) <= 9 or any("(" in p and ")" not in p for p in parts):
        return None
    names: list[str | None] = [None] * len(parts)
    for index, part in enumerate(parts):
        if "zeitraum" not in names and _DATE_PART.search(part):
            names[index] = "zeitraum"
        elif "firma" not in names and _COMPANY_PART.search(part):
            names[index] = "firma"
        elif "massnahme" not in names and _MEASURE_PART.search(part):
            names[index] = "massnahme"
    places = [i for i, n in enumerate(names) if n is None and ("massnahme" not in names or i < names.index("massnahme"))]
    for index, name in zip(places, {3: ("stadt", "ortsteil", "strasse"), 2: ("ort", "strasse"), 1: ("ort",)}.get(len(places), ())):
        names[index] = name
    counter = 1
    for index, name in enumerate(names):
        if name is None:
            names[index], counter = f"teil{counter}", counter + 1
    head = re.sub(r"\s+", r"\\s+", re.sub(r"([.^$*+?{}\[\]\\|()])", r"\\\1", found.group("head").strip()))
    groups = r",\s*".join(f"(?P<{name}>[^,]+?)" if i < len(names) - 1 else f"(?P<{name}>[^,]+?)" for i, name in enumerate(names))
    return {"head": found.group("head").strip(), "names": names, "values": dict(zip(names, parts)),
            "regex": f"{head}\\s*\\({groups}\\)\\s*$"}


def _pick(fields: list[dict], keys: tuple[str, ...], taken: set[str]) -> dict | None:
    for key in keys:
        for field in fields:
            if field["name"] not in taken and key in field["label"].lower():
                taken.add(field["name"])
                return field
    return None


def suggest(msg: dict, others: list[str] | None = None) -> dict:
    """Gibt vorgeschlagene Regelwerte und erklärende Hinweise zurück.

    others: Betreffzeilen weiterer aktueller Nachrichten desselben Absenders, zum Vergleich.
    """
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
            if found.group(1).strip().lower() in FORWARD_LABELS:
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

    others = [o for o in (others or []) if o]
    subject_part = common_subject(msg.get("subject", ""), others)
    cleaned = rules.clean_subject(msg.get("subject", ""))
    shape = None if extra else structured_subject(msg.get("subject", ""))
    if shape and (not subject_part or len(subject_part) > len(shape["head"]) + 12 or not subject_part.lower().startswith(shape["head"].lower()[:8])):
        subject_part = shape["head"]        # die Art der Nachricht vor der Klammer ist die verlässlichste Bedingung
    result = {
        "name": ("Vorschlag: " + ((shape["head"] if shape else "") or subject_part or " ".join(cleaned.split()[:4]) or msg.get("from", "") or "neue Regel"))[:120],
        "match_from": "" if extra else (msg.get("from") or "")[:200],
        "match_subject": subject_part,
        "extract_regex": "\n".join(regex_lines),
        "title_tpl": "{%s}" % title["name"] if title else "{subject}",
        "address_tpl": ", ".join("{%s}" % f["name"] for f in (street, city) if f),
        "text_tpl": "{%s}" % text["name"] if text else "{body}",
    }

    if shape:
        got = shape["values"]
        used = {f["name"] for f in (title, street, city, text) if f}
        # Zeilen aus Signaturen (Tel, E-Mail, URL …) stehen nicht in jeder Nachricht dieser Art: nur verwendete bleiben
        regex_lines = [line for line in regex_lines if any("(?P<%s>" % name in line for name in used)]
        regex_lines.insert(0, shape["regex"])
        result["extract_regex"] = "\n".join(regex_lines)
        if not title:
            first = "massnahme" if "massnahme" in got else shape["names"][0]
            second = next((n for n in ("strasse", "ort", "ortsteil") if n in got), None)
            result["title_tpl"] = "{%s}" % first + (" {%s}" % second if second and second != first else "")
        if not (street or city):
            result["address_tpl"] = ", ".join("{%s}" % n for n in ("strasse", "ortsteil", "ort", "stadt") if n in got)
        if not text:
            lines = [label + ": {%s}" % n for n, label in (("zeitraum", "Zeitraum"), ("firma", "Firma")) if n in got]
            result["text_tpl"] = "\n".join(lines + ["", "{subject}"]).strip()
        notes.append("Der Betreff ist nach dem Muster „" + shape["head"] + " (Teil, Teil, …)“ aufgebaut. Die Teile werden einzeln herausgelesen: "
                     + ", ".join("{%s} = „%s“" % (n, got[n][:40]) for n in shape["names"])
                     + ". Die Namen sind nach Inhalt und Reihenfolge vermutet; passt einer nicht, benenne ihn im Ausdruck und in den Zielfeldern um.")
    if result["match_from"]:
        notes.append(f"Bedingung Absender: „{result['match_from']}“. Die Regel greift damit für jede Nachricht dieses Absenders"
                     + (", deren Betreff den Begriff unten enthält." if subject_part else "."))
    if subject_part and shape and subject_part == shape["head"]:
        notes.append(f"Bedingung Betreff: „{subject_part}“, die Art der Nachricht vor der Klammer. Damit greift die Regel für alle Nachrichten dieser Art, "
                     "egal welcher Ort oder Zeitraum in der Klammer steht.")
    elif subject_part:
        notes.append(f"Bedingung Betreff: „{subject_part}“. Das ist der Anfang, den {len(others) + 1} aktuelle Nachrichten dieses Absenders gemeinsam haben.")
    elif others:
        notes.append("Keine Betreff-Bedingung: Die aktuellen Nachrichten dieses Absenders haben keinen gemeinsamen Anfang im Betreff. "
                     "Soll die Regel nur für bestimmte Nachrichten gelten, trage bei „Betreff enthält“ ein Wort ein, das in allen vorkommt.")
    elif not extra:
        notes.append("Keine Betreff-Bedingung: Von diesem Absender liegt nur diese eine Nachricht vor, ein gemeinsames Muster lässt sich daraus nicht ablesen. "
                     "Soll die Regel nur für bestimmte Nachrichten gelten, trage bei „Betreff enthält“ ein Wort ein, das in allen vorkommt.")
    if cleaned != (msg.get("subject") or "").strip():
        notes.append(f"Der Betreff wird ohne Vorsätze übergeben: aus „{(msg.get('subject') or '')[:60]}“ wird „{cleaned[:60]}“.")
    notes.append("Mit „Gegen die letzten Nachrichten prüfen“ unten siehst du, auf welche der aktuellen Nachrichten die Regel greift.")
    if fields:
        listed = ", ".join("{%s} = „%s“" % (f["name"], f["value"][:40]) for f in fields)
        notes.append(("Übergebene Felder: " if extra else "Im Text erkannte Zeilen: ") + listed + ".")
    elif not shape:
        notes.append("Im Text wurden keine Zeilen der Form „Bezeichnung: Wert“ erkannt. Stichwort und Text übernehmen deshalb Betreff und ganzen Mailtext.")
    if fields and not title:
        notes.append("Kein Feld sieht nach einem Stichwort aus, daher wird der Betreff als Stichwort verwendet.")
    if fields and not (street or city):
        notes.append("Kein Feld sieht nach einer Adresse aus, das Adressfeld bleibt leer.")
    return {"fields": result, "notes": notes}
