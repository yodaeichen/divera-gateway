# Änderungen

Die Versionsnummer steht in `app/version.py` und wird unten auf jeder Seite des Gateways angezeigt.

## 1.22.0

- Umbenennung in der gesamten Oberfläche: „Kunde" heißt jetzt „Löschgruppe"

## 1.21.0

- Hilfeseite im Gateway: die Schritte bis zur ersten Meldung, Begriffe, alle Felder im Überblick und häufige Fragen

## 1.20.0

- E-Mail-Adresse je Benutzer und Einladung per E-Mail: neue Benutzer legen ihr Passwort über einen Einmal-Link selbst fest
- Einstellungen für den E-Mail-Versand (SMTP) mit Testnachricht
- Link zum Festlegen des Passworts lässt sich beim Benutzer erneut senden

## 1.19.0

- Versionsnummer eingeführt: Anzeige in der Fußzeile, im Startprotokoll und unter `/healthz`
- README und diese Änderungsliste auf den aktuellen Stand gebracht

## 1.18.0

- Übersicht für Administratoren auf der Startseite: angemeldete Benutzer sowie erfolgreiche und fehlgeschlagene Meldungen (24 Stunden, 7 Tage, gesamt, je Löschgruppe)

## 1.17.0

- Schriftzug „powered by yodaeichen", Sponsor-Link in Kopf- und Fußzeile

## 1.16.0

- Rechteverwaltung: Einzelrechte je Bereich, Rollen als Vorlage, Beschränkung auf einzelne Löschgruppen
- Seite „Mein Konto" zum Ändern des eigenen Passworts

## 1.12.0 bis 1.15.0

- Mitteilungen ohne Push über die DIVERA-Schnittstelle v2
- Zweiter Schlüssel je Löschgruppe für die v2-Schnittstelle (System-Benutzer)
- Schlüsselprüfung bei der Löschgruppe, genauere Fehlermeldungen bei Ablehnung durch DIVERA

## 1.9.0 bis 1.11.0

- Einzelne Nachrichten aus dem Verbindungstest von Hand verarbeiten
- Testsendung an DIVERA direkt von der Regelseite, mit Bestätigungsseite
- Personen und Gruppen werden als Liste an DIVERA übergeben

## 1.5.0 bis 1.8.0

- Knopf „Jetzt abrufen" je Löschgruppe, Anzeige von letztem und nächstem Abruf
- Empfänger aus DIVERA laden und in Regeln als Personen oder Gruppen ankreuzen
- Neue Regeln stehen standardmäßig auf „Mitteilung" statt „Alarm"

## 1.1.0 bis 1.4.0

- Unterordner eines Microsoft-365-Postfachs als Pfad angeben
- Verbindungstest zeigt die neuesten Nachrichten
- Regelvorschläge aus einer Nachricht, Probelauf ohne Speichern
- Live-Ansicht der Regel, Erklärung zu jedem Feld, Legende
- Mehrere Suchbegriffe je Bedingung mit Semikolon, mehrere Ausdrücke (einer je Zeile)

## 1.0.0

- Erste Version: Löschgruppen, Quellen (Microsoft 365, IMAP, Webhook), Regeln, Protokoll, Installation auf Proxmox und mit Docker
