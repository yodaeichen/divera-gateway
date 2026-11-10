#!/usr/bin/env bash
# DIVERA Gateway: Installation ohne Docker auf Debian oder Ubuntu (LXC, VM oder Server).
# Wird vom Proxmox-Einzeiler im Container aufgerufen, läuft aber auch für sich:
#   curl -fsSL https://raw.githubusercontent.com/yodaeichen/divera-gateway/main/scripts/setup.sh | bash
# Ein zweiter Aufruf aktualisiert die Anwendung; Einstellungen und Daten bleiben erhalten.
set -Eeuo pipefail

main() {
  REPO="${REPO:-yodaeichen/divera-gateway}"
  BRANCH="${BRANCH:-main}"
  REPO_URL="${REPO_URL:-https://github.com/${REPO}.git}"
  PORT="${PORT:-8000}"
  APP_DIR=/opt/divera-gateway
  DATA_DIR=/var/lib/divera-gateway
  ENV_FILE=/etc/divera-gateway.env
  CRED_FILE=/root/divera-gateway-zugang.txt
  SERVICE_USER=divera-gw

  say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
  [ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen." >&2; exit 1; }
  command -v apt-get >/dev/null || { echo "Dieses Skript braucht Debian oder Ubuntu (apt-get)." >&2; exit 1; }

  say "Installiere Systempakete"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq git python3 python3-venv ca-certificates openssl >/dev/null

  id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$DATA_DIR"

  if [ -d "$APP_DIR/.git" ]; then
    say "Aktualisiere Programmdateien"
    git -C "$APP_DIR" fetch --quiet --depth 1 origin "$BRANCH"
    git -C "$APP_DIR" reset --quiet --hard FETCH_HEAD
  else
    say "Lade Programmdateien"
    git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
  fi

  say "Richte Python-Umgebung ein"
  [ -x "$APP_DIR/.venv/bin/python" ] || python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
  "$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

  FIRST_INSTALL=0
  if [ ! -f "$ENV_FILE" ]; then
    FIRST_INSTALL=1
    ADMIN_PASSWORD="$(openssl rand -hex 10)"
    ( umask 077
      cat > "$ENV_FILE" <<EOF
# DIVERA Gateway. Nach Änderungen: systemctl restart divera-gateway
# SECRET_KEY verschlüsselt die gespeicherten Zugangsdaten. Nicht ändern und mitsichern.
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_USER=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
# Auf true stellen, sobald die Seite nur noch über HTTPS (Reverse Proxy) aufgerufen wird.
COOKIE_SECURE=${COOKIE_SECURE:-false}
TZ=${TZ:-Europe/Berlin}
MAX_AGE_MINUTES=15
LOG_DAYS=30
EOF
      printf 'DIVERA Gateway, erster Zugang\nBenutzer: admin\nPasswort: %s\nBitte nach der ersten Anmeldung unter "Benutzer" ändern und diese Datei löschen.\n' "$ADMIN_PASSWORD" > "$CRED_FILE"
    )
  fi

  cat > /usr/local/bin/divera-gateway-update <<EOF
#!/usr/bin/env bash
# Holt die aktuelle Version und startet den Dienst neu.
exec env REPO='${REPO}' BRANCH='${BRANCH}' REPO_URL='${REPO_URL}' PORT='${PORT}' bash "${APP_DIR}/scripts/setup.sh"
EOF
  chmod 755 /usr/local/bin/divera-gateway-update

  if [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/divera-gateway.service <<EOF
[Unit]
Description=DIVERA Gateway
After=network-online.target
Wants=network-online.target

[Service]
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
Environment=DATA_DIR=${DATA_DIR}
# Genau ein Prozess: der Hintergrunddienst darf nicht mehrfach laufen.
ExecStart=${APP_DIR}/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips=*
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --quiet divera-gateway
    systemctl restart divera-gateway

    say "Warte auf den Dienst"
    OK=0
    for _ in $(seq 1 20); do
      if "$APP_DIR/.venv/bin/python" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:${PORT}/healthz', timeout=2)" 2>/dev/null; then OK=1; break; fi
      sleep 1
    done
    [ "$OK" = 1 ] || { echo "Der Dienst antwortet nicht. Prüfen mit: journalctl -u divera-gateway -n 50" >&2; exit 1; }
  else
    echo "Kein systemd gefunden: Programm installiert, aber kein Dienst eingerichtet und nicht gestartet." >&2
    exit 1
  fi

  ADDR="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo
  say "DIVERA Gateway läuft: http://${ADDR:-<IP>}:${PORT}"
  if [ "$FIRST_INSTALL" = 1 ]; then
    echo "    Benutzer: admin"
    echo "    Passwort: ${ADMIN_PASSWORD}   (steht auch in ${CRED_FILE})"
    echo "    Bitte nach der ersten Anmeldung ändern."
    echo "    Für den Betrieb einen Reverse Proxy mit HTTPS davorsetzen und danach in"
    echo "    ${ENV_FILE} COOKIE_SECURE=true setzen."
  else
    echo "    Aktualisiert. Einstellungen und Daten wurden beibehalten."
  fi
}

main "$@"
