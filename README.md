# DIVERA Gateway

Übergibt E-Mails und Webhook-Meldungen regelbasiert an die Alarm-API von DIVERA 24/7.
Mandantenfähig: je Kunde eigener DIVERA-Accesskey, eigene Quellen und eigene Regeln.

- **Quellen:** Microsoft-365-Postfächer (Microsoft Graph), IMAP-Postfächer, eingehende Webhooks
- **Regeln:** Bedingungen auf Absender, Betreff und Text, Werte per regulärem Ausdruck herauslesen, Vorlagen mit Platzhaltern
- **Ziele:** Alarm oder leise Mitteilung, Empfänger über RIC oder beliebige weitere API-Parameter
- **Betrieb:** Protokoll, Verbindungstest, Regel-Probelauf, Testmodus je Kunde

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

1. Mit dem angezeigten Startpasswort anmelden und es unter „Benutzer" ändern.
2. Im Reverse Proxy (z. B. Nginx Proxy Manager) einen Host mit HTTPS auf `http://<Container-IP>:8000` legen.
3. Im Container in `/etc/divera-gateway.env` den Wert `COOKIE_SECURE=true` setzen und
   `systemctl restart divera-gateway` ausführen. Bis dahin läuft die Anmeldung unverschlüsselt im internen Netz.

**Aktualisieren:** `pct exec <CTID> -- divera-gateway-update`

**Wo liegt was im Container?**

| Pfad | Inhalt |
|---|---|
| `/opt/divera-gateway` | Programm |
| `/var/lib/divera-gateway` | Datenbank |
| `/etc/divera-gateway.env` | Einstellungen und `SECRET_KEY` |
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

## Absicherung

Die Verwaltungsoberfläche per Access List nur aus dem eigenen Netz oder VPN freigeben.
Von außen muss nur der Pfad `/hook/` erreichbar sein, und auch nur, wenn Webhooks genutzt werden.

**Sicherung:** Datenbank zusammen mit `SECRET_KEY` sichern (bei Proxmox am einfachsten der ganze
Container per Backup-Job). Ohne den Schlüssel sind die gespeicherten Zugangsdaten nicht lesbar.

## Erste Schritte

1. Anmelden, Kunde anlegen, DIVERA-Accesskey eintragen
   (DIVERA: Verwaltung > Einstellungen > Schnittstellen > API). Neue Kunden stehen im **Testmodus**.
2. Quelle anlegen und „Verbindung testen".
3. Regel anlegen und unten auf der Regelseite mit einer echten Beispielmail ausprobieren.
4. Im Protokoll prüfen, ob eingehende Nachrichten wie erwartet erkannt werden (Status `test`).
5. Testmodus beim Kunden ausschalten. Ab dann wird an DIVERA gesendet.

## Microsoft 365 einrichten

1. Entra Admin Center > App-Registrierungen > Neue Registrierung (ein Mandant, keine Umleitungs-URI).
2. API-Berechtigungen > Microsoft Graph > **Anwendungsberechtigungen** > `Mail.Read` > Administratorzustimmung erteilen.
3. Zertifikate & Geheimnisse > Neuer geheimer Clientschlüssel. Ablaufdatum im Kalender notieren.
4. Verzeichnis-ID, Anwendungs-ID, Schlüssel und Postfachadresse in der Quelle eintragen.
5. **Zugriff auf das eine Postfach beschränken.** Ohne diesen Schritt darf die App alle Postfächer
   des Mandanten lesen. In Exchange Online PowerShell:

   ```powershell
   New-DistributionGroup -Name "DIVERA-Gateway-Postfaecher" -Type Security -Members alarm@example.de
   New-ApplicationAccessPolicy -AppId <Anwendungs-ID> -PolicyScopeGroupId "DIVERA-Gateway-Postfaecher" `
     -AccessRight RestrictAccess -Description "DIVERA Gateway nur Alarm-Postfach"
   Test-ApplicationAccessPolicy -AppId <Anwendungs-ID> -Identity alarm@example.de
   ```

   Microsoft löst diese Richtlinien schrittweise durch „RBAC for Applications" ab. Bitte in der
   aktuellen Microsoft-Dokumentation prüfen, welcher Weg für den Mandanten gilt.

## Regeln und Platzhalter

Regeln werden nach Rang geprüft. Alle ausgefüllten Bedingungen müssen zutreffen.

| Platzhalter | Inhalt |
|---|---|
| `{subject}` `{from}` `{body}` `{date}` | Betreff, Absender, Text, Empfangszeit |
| `{name}` | benannte Gruppe `(?P<name>...)` aus dem regulären Ausdruck |
| `{feld}` | bei Webhooks jedes übergebene Feld der obersten Ebene |

Beispiel für eine Leitstellen-Mail:

```
Ausdruck:   Stichwort:\s*(?P<stichwort>.+)\nOrt:\s*(?P<ort>.+)
Stichwort:  {stichwort}
Adresse:    {ort}
```

DIVERA kürzt bzw. begrenzt: Stichwort 50 Zeichen (FREE 30), Text 1000, Adresse 200.
In der FREE-Version ist nur ein Alarm je fünf Minuten möglich.

## Webhook

```bash
curl -X POST https://divera-gw.example.de/hook/<token> \
  -H "Content-Type: application/json" \
  -d '{"subject":"BMA Auslösung","body":"Melder 12, Halle 3","objekt":"Werk Nord"}'
```

Die Adresse enthält ein geheimes Token und ist der einzige Schutz dieses Eingangs. Bei Verdacht
auf Weitergabe beim Kunden „Adresse erneuern" drücken.

## Verhalten, das man kennen sollte

- **Start bei null:** Beim Anlegen oder Ändern einer Quelle zählt nur, was danach eintrifft. Alte Mails lösen nichts aus.
- **Kein Doppelalarm:** Eine Nachricht wird vor der Übergabe als verarbeitet vorgemerkt. Stürzt der Dienst
  genau in diesem Moment ab, geht diese eine Nachricht verloren, statt doppelt zu alarmieren.
- **Veraltete Nachrichten:** Was älter als `MAX_AGE_MINUTES` ist (z. B. nach einem Ausfall), wird nur protokolliert.
- **Postfächer bleiben unverändert:** Mails werden nur gelesen, nicht markiert, verschoben oder gelöscht.
- **Datenschutz:** Das Protokoll speichert Absender, Betreff und das Ergebnis, nicht den Mailtext. Bei Treffern
  steht der an DIVERA gesendete Inhalt im Protokoll. Aufbewahrung über `LOG_DAYS`.
- **Ein Prozess:** Der Container darf nicht mehrfach parallel gestartet werden, sonst wird doppelt abgefragt.

## Kein Ersatz für die primäre Alarmierung

Das Gateway ist eine Zusatzalarmierung. E-Mail ist kein garantiert zeitnaher Übertragungsweg,
und dieser Dienst hat keine Redundanz. Die Erstalarmierung (Funkmeldeempfänger, Sirene) muss unabhängig davon funktionieren.

## Test ohne Docker

```bash
pip install -r requirements.txt
python tests/smoke_test.py
```
