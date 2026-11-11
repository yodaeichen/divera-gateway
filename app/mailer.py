"""E-Mail-Versand des Gateways (Einladungen an neue Benutzer) und die dazugehörigen Einstellungen."""
import re
import smtplib
import ssl
from email.message import EmailMessage

from . import db as m
from . import security as sec

FIELDS = ("smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password", "mail_from", "base_url")
_ADDRESS = re.compile(r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$")
INVITE_HOURS = 48


def valid_address(value: str) -> bool:
    return bool(_ADDRESS.match(value or "")) and len(value) <= 200


def load(db) -> dict:
    stored = {row.key: sec.decrypt(row.value) for row in db.query(m.Setting).all()}
    return {key: stored.get(key, "") for key in FIELDS}


def save(db, values: dict):
    for key in FIELDS:
        if key not in values:
            continue
        row = db.get(m.Setting, key) or m.Setting(key=key)
        row.value = sec.encrypt(values[key])
        db.add(row)
    db.commit()


def configured(settings: dict) -> bool:
    return bool(settings["smtp_host"] and valid_address(settings["mail_from"]))


def deliver(settings: dict, to: str, subject: str, body: str):
    """Verschickt eine Textmail. Löst bei Problemen eine Ausnahme mit verständlichem Text aus."""
    if not configured(settings):
        raise RuntimeError("Der E-Mail-Versand ist noch nicht eingerichtet (Einstellungen).")
    if not valid_address(to):
        raise RuntimeError("Die Empfängeradresse ist ungültig.")
    message = EmailMessage()
    message["From"] = f"DIVERA Gateway <{settings['mail_from']}>"
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    host, security = settings["smtp_host"], settings["smtp_security"] or "starttls"
    port = int(settings["smtp_port"] or (465 if security == "ssl" else 587))
    context = ssl.create_default_context()
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=20, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=context)
            if settings["smtp_user"]:
                server.login(settings["smtp_user"], settings["smtp_password"])
            server.send_message(message)
    except smtplib.SMTPAuthenticationError:
        raise RuntimeError("Der Mailserver hat Benutzername oder Passwort abgelehnt.") from None
    except smtplib.SMTPRecipientsRefused:
        raise RuntimeError("Der Mailserver hat die Empfängeradresse abgelehnt.") from None
    except (smtplib.SMTPException, OSError) as exc:
        raise RuntimeError(f"Versand fehlgeschlagen ({type(exc).__name__}: {str(exc)[:160]})") from None


def invite_text(username: str, link: str, base_url: str, inviter: str) -> tuple[str, str]:
    subject = "Dein Zugang zum DIVERA Gateway"
    body = (
        f"Hallo,\n\n"
        f"{inviter} hat für dich einen Zugang zum DIVERA Gateway angelegt.\n\n"
        f"Benutzername: {username}\n\n"
        f"Lege dein Passwort über diesen Link selbst fest:\n{link}\n\n"
        f"Der Link gilt {INVITE_HOURS} Stunden und funktioniert nur einmal. Danach meldest du dich hier an:\n{base_url}\n\n"
        f"Wenn du diese Nachricht nicht erwartet hast, kannst du sie ignorieren.\n"
    )
    return subject, body
