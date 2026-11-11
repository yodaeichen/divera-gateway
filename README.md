# DIVERA Gateway

Übergibt E-Mails und Webhook-Meldungen regelbasiert an DIVERA 24/7, als Mitteilung oder als Alarm.
Mandantenfähig: je Löschgruppe eigene DIVERA-Schlüssel, eigene Quellen und eigene Regeln.

Aktuelle Version und Änderungen: siehe [CHANGELOG.md](CHANGELOG.md). Die laufende Version steht unten auf jeder Seite.

## Funktionen

- **Quellen:** Microsoft-365-Postfächer (Microsoft Graph, auch Unterordner), IMAP-Postfächer, eingehende Webhooks
- **Regeln:** Bedingungen auf Absender, Betreff und Text, Werte per regulärem Ausdruck herauslesen, Vorlagen mit Platzhaltern
- **Hilfen beim Regelbau:** Regelvorschlag aus einer echten Nachricht, Live-Ansicht, Probelauf ohne Speichern, Testsendung an DIVERA
- **Ziele:** Mitteilung (mit oder ohne Push) oder Alarm, Empfänger über RIC, angekreuzte Gruppen oder einzelne Personen
- **Betrieb:** Protokoll, Verbindungstest, Schlüsselprüfung, manueller Abruf, Testmodus je Löschgruppe
- **Benutzer:** Rechte je Bereich, Rollen als Vorlage, Beschränkung auf einzelne Löschgruppen
- **Übersicht für Administratoren:** angemeldete Benutzer, erfolgreiche und fehlgeschlagene Meldungen
- **Hilfe im Gateway:** Schritte, Begriffe, Felder und häufige Fragen unter „Hilfe" in der Kopfzeile

## Installation auf Proxmox (Einzeiler)

Auf dem Proxmox-Host als root:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/divera-gateway/main/proxmox/install.sh)"
```

Das Skript legt einen unprivilegierten Debian-LXC an (1 Kern, 512 MB RAM, 4 GB Platte, DHCP),
installiert die Anwendung als systemd-Dienst und zeigt am Ende Adresse und Startpasswort an.
Docker wird dabei nicht verwendet.

Anpassen über Variablen vor dem Befehl:

```bash
CTID=150 STORAGE=local-zfs BRIDGE=vmbr1 IP=192.168.10.50/24 GW=192.168.10.1 \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/divera-gateway/main/proxmox/install.sh)"
```

| Variable | Standard | Bedeutung |
|---|---|---|
| `CTID` | nächste freie ID | Container-ID |
| `CT_HOSTNAME` | `divera-gateway` | Hostname |
| `STORAGE` | erster aktiver Container-Speicher | Speicher für die Platte |
| `TEMPLATE_STORAGE` | erster aktiver Vorlagen-Speicher | Speicher für die Debian-Vorlage |
| `CORES` / `MEMORY` / `SWAP` / `DISK` | 1 / 512 / 512 / 4 | Kerne, MB, MB, GB |
| `BRIDGE` / `VLAN` | `vmbr0` / leer | Netzwerk |
| `IP` / `GW` | `dhcp` / leer | feste Adresse im Format `192.168.1.50/24` plus Gateway |

**Danach:**

1. Mit dem angezeigten Startpasswort anmelden und es unter „Mein Konto" ändern.
2. Im Reverse Proxy (z. B. Nginx Proxy Manager) einen Host mit HTTPS auf `http://<Container-IP>:8000` legen.
3. Im Container in `/etc/divera-gateway.env` den Wert `COOKIE_SECURE=true` setzen und
   `systemctl restart divera-gateway` ausführen. Bis dahin läuft die Anmeldung unverschlüsselt im internen Netz.

### Aktualisieren

```bash
pct exec <CTID> -- /usr/local/bin/divera-gateway-update
```

Holt den aktuellen Stand von GitHub und startet den Dienst neu. Einstellungen und Daten bleiben erhalten,
die Datenbank wird bei Bedarf automatisch um neue Felder ergänzt.

### Wo liegt was im Container?

| Pfad | Inhalt |
|---|---|
| `/opt/divera-gateway` | Programm |
| `/var/lib/divera-gateway` | Datenbank |
| `/etc/divera-gateway.env` | Einstellungen und `SECRET_KEY` |
| `/root/divera-gateway-zugang.txt` | Startpasswort (nach der ersten Anmeldung löschen) |
| `journalctl -u divera-gateway` | Dienstprotokoll |

Dasselbe Installationsskript läuft auch auf jeder Debian- oder Ubuntu-Maschine ohne Proxmox:

```bash
curl -fsSL https://raw.githubusercontent.com/yodaeichen/divera-gateway/main/scripts/setup.sh | bash
```

## Installation mit Docker

```bash
cp .env.example .env
# SECRET_KEY (openssl rand -base64 48) und ADMIN_PASSWORD eintragen
mkdir -p data && sudo chown 10001 data
docker compose up -d --build
```

Die Anwendung lauscht danach auf `127.0.0.1:8080`. Im Reverse Proxy einen Host auf diesen Port
legen und ein Zertifikat erzwingen. Ohne HTTPS funktioniert die Anmeldung nicht, solange
`COOKIE_SECURE=true` gesetzt ist.

## Erste Schritte

1. Anmelden und eine Löschgruppe anlegen. Neue Löschgruppen stehen im **Testmodus**: Treffer werden nur protokolliert.
2. Den Alarm-Accesskey der Einheit eintragen (DIVERA: Verwaltung > Einstellungen > Schnittstellen > API).
3. Eine Quelle anlegen und „Verbindung testen". Der Test zeigt die neuesten Nachrichten.
4. Bei einer typischen Nachricht „Regel vorschlagen" klicken, die Regel in der Live-Ansicht anpassen und speichern.
5. Bei der Löschgruppe „Empfänger aus DIVERA laden", dann in der Regel Gruppen oder Personen ankreuzen (oder eine RIC eintragen).
6. Mit „Testweise an DIVERA senden" prüfen, ob die Meldung richtig ankommt. Zum Üben nur sich selbst ankreuzen.
7. Testmodus bei der Löschgruppe ausschalten. Ab dann wird im Betrieb an DIVERA gesendet.

## Die zwei DIVERA-Schlüssel

| Schlüssel | Wofür | Woher |
|---|---|---|
| **Alarm-Accesskey der Einheit** | Alarme und Mitteilungen mit Push (ältere Schnittstelle `api/alarm`) | Verwaltung > Einstellungen > Schnittstellen > API |
| **Persönlicher Accesskey** (optional) | Mitteilungen **ohne Push** (Schnittstelle `api/v2/news`) | API-Schlüssel eines System-Benutzers in DIVERA |

Der System-Benutzer braucht in DIVERA das Recht, Mitteilungen zu erstellen. Fehlt es, antwortet DIVERA mit
`HTTP 403 Nicht autorisiert`. **Schlüssel prüfen** auf der Seite der Löschgruppe zeigt, ob beide Schlüssel angenommen werden.

Beide Schlüssel werden verschlüsselt gespeichert und in der Oberfläche nie wieder angezeigt.

## Quellen

### Microsoft 365

1. Entra Admin Center > App-Registrierungen > Neue Registrierung (ein Mandant, keine Umleitungs-URI).
2. API-Berechtigungen > Microsoft Graph > **Anwendungsberechtigungen** > `Mail.Read` > Administratorzustimmung erteilen.
3. Zertifikate & Geheimnisse > Neuer geheimer Clientschlüssel. Den **Wert** kopieren (nicht die „Geheime ID") und das Ablaufdatum notieren.
4. Verzeichnis-ID, Anwendungs-ID, Schlüssel und Postfachadresse in der Quelle eintragen.
5. **Zugriff auf das eine Postfach beschränken.** Ohne diesen Schritt darf die App alle Postfächer des Mandanten lesen:

   ```powershell
   New-DistributionGroup -Name "DIVERA-Gateway-Postfaecher" -Type Security -Members alarm@example.de
   New-ApplicationAccessPolicy -AppId <Anwendungs-ID> -PolicyScopeGroupId "DIVERA-Gateway-Postfaecher" `
     -AccessRight RestrictAccess -Description "DIVERA Gateway nur Alarm-Postfach"
   Test-ApplicationAccessPolicy -AppId <Anwendungs-ID> -Identity alarm@example.de
   ```

   Microsoft löst diese Richtlinien schrittweise durch „RBAC for Applications" ab. Bitte in der
   aktuellen Microsoft-Dokumentation prüfen, welcher Weg für den Mandanten gilt.

**Ordner:** `inbox` oder `Posteingang` für den Posteingang, Unterordner als Pfad wie `Posteingang/Alarme/Leitstelle`,
Schreibweise wie in Outlook.

### IMAP

Server, Port, Verschlüsselung, Benutzername, Passwort und Ordner eintragen. Die Mails werden nur gelesen.

### Webhook

Jede Webhook-Quelle bekommt eine geheime Adresse. Andere Systeme schicken JSON oder Formulardaten dorthin:

```bash
curl -X POST https://divera-gw.example.de/hook/<token> \
  -H "Content-Type: application/json" \
  -d '{"subject":"BMA Auslösung","body":"Melder 12, Halle 3","objekt":"Werk Nord"}'
```

`subject`, `body` und `from` werden wie bei einer Mail behandelt, alle weiteren Felder stehen als Platzhalter
zur Verfügung (hier `{objekt}`). „Letzter Empfang" zeigt die zuletzt eingegangene Meldung. Die Adresse ist der
einzige Schutz dieses Eingangs; bei Verdacht auf Weitergabe „Adresse erneuern" drücken.

## Regeln

Regeln werden nach Rang geprüft, kleinste Zahl zuerst. Die Regelseite ist in vier Schritte gegliedert und
erklärt jedes Feld; oben lässt sich eine Legende aufklappen.

### 1. Bedingungen

Alle ausgefüllten Felder müssen zutreffen (UND). Innerhalb eines Feldes trennt ein **Semikolon** Alternativen (ODER):

```
Absender enthält:  leitstelle@kreis.de; @bma-dienst.de
Betreff enthält:   Alarmierung; Einsatz
```

Groß- und Kleinschreibung ist egal. Ein Komma trennt hier bewusst nicht, weil es Teil eines Suchbegriffs sein kann.

### 2. Ausdrücke

Je Zeile ein regulärer Ausdruck, der einen Wert aus Betreff und Text liest. Benannte Gruppen werden zu Platzhaltern:

```
^Einsatzstichwort:\s*(?P<stichwort>.+)$
^Ort:\s*(?P<ort>.+)$
```

### 3. Ziel

| Platzhalter | Inhalt |
|---|---|
| `{subject}` `{from}` `{body}` `{date}` | Betreff, Absender, ganzer Text, Empfangszeit |
| `{name}` | benannte Gruppe `(?P<name>...)` aus einem Ausdruck |
| `{feld}` | bei Webhooks jedes übergebene Feld der obersten Ebene |

DIVERA begrenzt: Stichwort 50 Zeichen (FREE 30), Text 1000, Adresse 200. Die Live-Ansicht zählt mit.

**Art:**

- **Mitteilung** (Vorgabe): reine Information ohne Alarmierung, wahlweise mit oder ohne Push.
- **Alarm:** Einsatz mit Alarmton und Rückmeldung. Muss bewusst ausgewählt werden; die Live-Ansicht warnt.

**Empfänger:**

- **RIC:** Alarmierungs-RIC der Gruppen wie in DIVERA hinterlegt, mehrere mit Komma (`LZ1,LZ2`).
- **Gruppen und Personen:** Nach „Empfänger aus DIVERA laden" bei der Löschgruppe zum Ankreuzen. Für eine Meldung an nur
  eine Person: diese Person ankreuzen, RIC und Gruppen leer lassen.
- **Weitere API-Parameter:** eine Zeile je `name=wert`, z. B. `alarmcode_id=5`.

**Welche Schnittstelle wird genommen?**

| Regel | Schnittstelle | Schlüssel |
|---|---|---|
| Alarm | `api/alarm` | Alarm-Accesskey |
| Mitteilung mit Push | `api/alarm` | Alarm-Accesskey |
| Mitteilung ohne Push | `api/v2/news` | Persönlicher Accesskey |

Bei „ohne Push" gelten die Regeln der v2-Schnittstelle: Eine RIC wird nicht übertragen; sind Gruppen und Personen
zugleich angekreuzt, zählen nur die Personen; ist nichts angekreuzt, geht die Mitteilung an alle Mitglieder der Einheit.
Die Live-Ansicht weist jeweils darauf hin.

### 4. Beispielnachricht und Live-Ansicht

Unten auf der Regelseite steht eine Beispielnachricht, am einfachsten übernommen über
**Verbindung testen > Regel vorschlagen**. Die Live-Ansicht rechts zeigt bei jeder Eingabe sofort, ob die Regel
greift, welche Bedingung scheitert, welche Platzhalter gefunden wurden und was an DIVERA gehen würde.
Dabei wird nichts gespeichert und nichts gesendet.

**Testweise an DIVERA senden** überträgt das Ergebnis wirklich, auch im Testmodus, nach einer Bestätigungsseite.

## Termine importieren

Auf der Seite einer Löschgruppe führt „Termine aus CSV importieren" zum Import, etwa für einen Dienstplan aus Excel.

1. Vorlage herunterladen oder eine eigene Tabelle als CSV speichern. Pflicht sind die Spalten **Titel** und **Datum**
   (oder **Beginn** mit Datum und Uhrzeit); möglich sind außerdem Ende, Enddatum, Ganztägig, Ort, Beschreibung, Gruppen und ID.
2. Datei hochladen. Die Vorschau zeigt jeden Termin mit Zustand: neu, schon importiert oder fehlerhaft mit Grund.
3. Empfänger wählen (alle, Gruppen oder Personen), Push und Erinnerung festlegen und den Import bestätigen.

Das Gateway merkt sich angelegte Termine über die Spalte ID, ersatzweise über Titel, Beginn und Ende. Ein erneuter
Import derselben Datei legt nur neue Zeilen an; vorhandene Termine werden nicht geändert. Der Import nutzt die
Schnittstelle `api/v2/events` und braucht den persönlichen Accesskey eines System-Benutzers, der in DIVERA Termine
erstellen darf. Im Gateway ist dafür das Recht „Von Hand an DIVERA senden" nötig.

## Benutzer und Rechte

Unter „Benutzer" legst du Konten an und vergibst Rechte je Bereich:

| Bereich | Stufen |
|---|---|
| Löschgruppen und Schlüssel | nur sehen, bearbeiten |
| Quellen | kein Zugriff, nur sehen, bearbeiten |
| Regeln | kein Zugriff, nur sehen, bearbeiten |
| Protokoll | kein Zugriff, sehen |
| Benutzer und Rechte | kein Zugriff, verwalten |
| Von Hand an DIVERA senden | erlaubt oder nicht |

- **Rollen als Vorlage:** Administrator, Bearbeiter und Betrachter füllen die Einzelrechte aus; danach lässt sich jedes Recht einzeln ändern.
- **Löschgruppen:** Ohne den Haken „Alle Löschgruppen" sieht ein Benutzer nur die angekreuzten Löschgruppen samt Quellen, Regeln und Protokoll.
- **Schutz vor Aussperren:** Der letzte Benutzer mit Rechteverwaltung lässt sich weder herabstufen noch löschen.
- **Eigenes Passwort:** Jeder ändert es unter „Mein Konto".
- **Einladung per E-Mail:** Ist unter „Einstellungen" ein Mailserver eingetragen, bekommt ein neuer Benutzer auf Wunsch
  eine E-Mail mit seinem Benutzernamen und einem Einmal-Link, über den er sein Passwort selbst festlegt. Der Link gilt
  48 Stunden. Ein Passwort wird nie per E-Mail verschickt. Beim Benutzer lässt sich der Link erneut senden, etwa wenn
  jemand sein Passwort vergessen hat.

### E-Mail-Versand einrichten

Unter „Einstellungen" (nur mit Rechteverwaltung sichtbar) Mailserver, Port, Verschlüsselung, Anmeldung und
Absenderadresse eintragen und mit „Speichern und Testnachricht senden" prüfen. Dort steht auch die Adresse, unter der
das Gateway für Benutzer erreichbar ist; sie wird für den Link in der Einladung verwendet. Exchange Online nimmt eine
einfache Anmeldung mit Benutzername und Passwort am SMTP-Server oft nicht mehr an; ein eigener Mailserver oder ein
SMTP-Relay ist dafür die einfachere Wahl.

Wer Benutzer und Rechte verwalten darf, sieht auf der Startseite zusätzlich, wer angemeldet ist und wie viele
Meldungen erfolgreich oder fehlgeschlagen sind.

## Verhalten, das man kennen sollte

- **Start bei null:** Beim Anlegen oder Speichern einer Quelle zählt nur, was danach eintrifft. Ältere Nachrichten
  lassen sich über „Verbindung testen > Jetzt verarbeiten" einzeln von Hand durch die Regeln schicken.
- **Kein Doppelalarm:** Eine Nachricht wird vor der Übergabe als verarbeitet vorgemerkt. Stürzt der Dienst genau
  in diesem Moment ab, geht diese eine Nachricht verloren, statt doppelt zu alarmieren.
- **Veraltete Nachrichten:** Was älter als `MAX_AGE_MINUTES` ist (z. B. nach einem Ausfall), wird nur protokolliert.
- **Postfächer bleiben unverändert:** Mails werden nur gelesen, nicht markiert, verschoben oder gelöscht.
- **Ein Prozess:** Der Dienst darf nicht mehrfach parallel laufen, sonst wird doppelt abgefragt.

## Fehlersuche

| Beobachtung | Ursache und Abhilfe |
|---|---|
| „0 neue Nachrichten" beim Abruf | Es ist seit dem Speichern der Quelle nichts eingegangen, oder die Mails landen in einem anderen Ordner. Zum Testen eine neue Mail schicken oder „Jetzt verarbeiten" nutzen. |
| Protokoll zeigt „ignoriert" | Keine Regel passt. Regel öffnen und mit der Nachricht in der Live-Ansicht prüfen. |
| `HTTP 403 Nicht autorisiert` bei Mitteilung ohne Push | Der System-Benutzer darf in DIVERA keine Mitteilungen erstellen, oder es ist kein persönlicher Accesskey hinterlegt. „Schlüssel prüfen" nutzen. |
| Microsoft-Test: `AADSTS7000215` | „Geheime ID" statt „Wert" kopiert, oder der Schlüssel ist abgelaufen. |
| Microsoft-Test: Graph-Fehler 403 | Administratorzustimmung fehlt, oder das Postfach ist nicht in der freigegebenen Gruppe. |
| Anmeldung springt immer zurück | `COOKIE_SECURE=true`, die Seite wird aber ohne HTTPS aufgerufen. |

## Sicherheit und Datenschutz

- Die Verwaltungsoberfläche per Access List nur aus dem eigenen Netz oder VPN freigeben. Von außen muss höchstens
  der Pfad `/hook/` erreichbar sein, und nur wenn Webhooks genutzt werden.
- Accesskeys, Postfach-Passwörter und Clientschlüssel liegen verschlüsselt in der Datenbank. Der Schlüssel dazu ist
  `SECRET_KEY`: nicht ändern und mitsichern, sonst sind die Zugangsdaten nicht mehr lesbar.
- Das Protokoll speichert Absender, Betreff und das Ergebnis, nicht den Mailtext. Bei Treffern steht der an DIVERA
  gesendete Inhalt im Protokoll. Aufbewahrung über `LOG_DAYS` (Standard 30 Tage).
- Nach „Empfänger aus DIVERA laden" liegen Namen der Mitglieder in der Gateway-Datenbank.
- Die Oberfläche lädt keine Inhalte von fremden Servern.
- **Sicherung:** bei Proxmox am einfachsten der ganze Container per Backup-Job.

## Einstellungen

In `/etc/divera-gateway.env` (Proxmox) bzw. `.env` (Docker):

| Variable | Standard | Bedeutung |
|---|---|---|
| `SECRET_KEY` | wird erzeugt | verschlüsselt gespeicherte Zugangsdaten |
| `COOKIE_SECURE` | `false` (Proxmox), `true` (Docker) | Anmeldung nur über HTTPS |
| `TZ` | `Europe/Berlin` | Zeitzone der Anzeige |
| `MAX_AGE_MINUTES` | `15` | ältere Nachrichten lösen nichts aus |
| `LOG_DAYS` | `30` | Aufbewahrung des Protokolls |

## Bekannte Grenzen

- Bei Mitteilungen ohne Push belegt das Gateway den Empfängertyp der v2-Schnittstelle so: 2 = alle, 3 = ausgewählte
  Gruppen, 4 = ausgewählte Personen. Die DIVERA-Dokumentation erklärt diese Werte nicht. Vor dem Einsatz mit einer
  Testsendung an sich selbst prüfen.
- In DIVERA 24/7 FREE überträgt die Alarm-Schnittstelle nur das Stichwort, und es ist nur ein Alarm je fünf Minuten möglich.
- Es gibt keine Redundanz: Fällt der Container aus, wird nichts übergeben.

## Kein Ersatz für die primäre Alarmierung

Das Gateway ist eine Zusatzalarmierung. E-Mail ist kein garantiert zeitnaher Übertragungsweg.
Die Erstalarmierung (Funkmeldeempfänger, Sirene) muss unabhängig davon funktionieren.

## Entwicklung

```bash
pip install -r requirements.txt
python tests/smoke_test.py
```

Der Test läuft ohne Netzwerk und prüft Anmeldung, Rechte, Quellen, Regeln, Live-Ansicht und die Übergabe an DIVERA
gegen nachgebildete Antworten. Bei jedem Push führt ihn eine GitHub Action aus. Bei einer neuen Version
`app/version.py` und `CHANGELOG.md` anpassen.

## Unterstützen

Das Projekt wird in der Freizeit gepflegt. Wer es unterstützen möchte: [GitHub Sponsors](https://github.com/sponsors/yodaeichen)
