#!/usr/bin/env bash
# DIVERA Gateway: legt auf einem Proxmox-VE-Host einen LXC-Container an und installiert die Anwendung.
#
# Aufruf auf dem Proxmox-Host (als root):
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/divera-gateway/main/proxmox/install.sh)"
#
# Anpassen über Umgebungsvariablen, z. B.:
#   CTID=150 STORAGE=local-zfs BRIDGE=vmbr1 IP=192.168.10.50/24 GW=192.168.10.1 bash -c "$(curl ...)"
set -Eeuo pipefail

main() {
  REPO="${REPO:-yodaeichen/divera-gateway}"
  BRANCH="${BRANCH:-main}"
  CT_HOSTNAME="${CT_HOSTNAME:-divera-gateway}"
  CORES="${CORES:-1}"
  MEMORY="${MEMORY:-512}"
  SWAP="${SWAP:-512}"
  DISK="${DISK:-4}"            # GB
  BRIDGE="${BRIDGE:-vmbr0}"
  IP="${IP:-dhcp}"             # oder z. B. 192.168.1.50/24
  GW="${GW:-}"                 # nur bei fester IP
  VLAN="${VLAN:-}"

  say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
  fail() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

  [ "$(id -u)" -eq 0 ] || fail "Bitte als root auf dem Proxmox-Host ausführen."
  for tool in pct pveam pvesh pvesm; do
    command -v "$tool" >/dev/null || fail "'$tool' nicht gefunden. Dieses Skript läuft nur auf einem Proxmox-VE-Host."
  done
  if [ "$IP" != "dhcp" ] && [ -z "$GW" ]; then fail "Bei fester IP bitte auch GW=<Gateway> angeben."; fi

  CTID="${CTID:-$(pvesh get /cluster/nextid)}"
  if pct status "$CTID" >/dev/null 2>&1; then fail "Container-ID $CTID ist schon vergeben."; fi

  pick_storage() { # $1 = Inhaltstyp; bevorzugt den ersten aktiven Speicher
    pvesm status -content "$1" 2>/dev/null | awk 'NR>1 && $3=="active" {print $1; exit}'
  }
  STORAGE="${STORAGE:-$(pick_storage rootdir)}"
  TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-$(pick_storage vztmpl)}"
  [ -n "$STORAGE" ] || fail "Kein Speicher für Container gefunden. Bitte STORAGE=<name> angeben."
  [ -n "$TEMPLATE_STORAGE" ] || fail "Kein Speicher für Vorlagen gefunden. Bitte TEMPLATE_STORAGE=<name> angeben."

  say "Suche Debian-Vorlage"
  pveam update >/dev/null || true
  TEMPLATE="$(pveam available -section system | awk '{print $2}' | grep -E '^debian-12-standard_.*_amd64' | sort -V | tail -n1 || true)"
  [ -n "$TEMPLATE" ] || TEMPLATE="$(pveam available -section system | awk '{print $2}' | grep -E '^debian-1[3-9]-standard_.*_amd64' | sort -V | tail -n1 || true)"
  [ -n "$TEMPLATE" ] || fail "Keine Debian-Vorlage gefunden (pveam available)."
  if ! pveam list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE"; then
    say "Lade $TEMPLATE"
    pveam download "$TEMPLATE_STORAGE" "$TEMPLATE" >/dev/null
  fi

  NET="name=eth0,bridge=${BRIDGE},ip=${IP}"
  [ "$IP" = "dhcp" ] || NET="${NET},gw=${GW}"
  [ -z "$VLAN" ] || NET="${NET},tag=${VLAN}"

  say "Lege Container $CTID ($CT_HOSTNAME) auf $STORAGE an"
  pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" \
    --hostname "$CT_HOSTNAME" --cores "$CORES" --memory "$MEMORY" --swap "$SWAP" \
    --rootfs "${STORAGE}:${DISK}" --net0 "$NET" \
    --unprivileged 1 --features nesting=1 --onboot 1 --ostype debian \
    --description "DIVERA Gateway, https://github.com/${REPO}" >/dev/null
  CREATED=1
  pct start "$CTID"

  say "Warte auf Netzwerk"
  for _ in $(seq 1 30); do
    if pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1; then ONLINE=1; break; fi
    sleep 2
  done
  [ "${ONLINE:-0}" = 1 ] || fail "Der Container erreicht das Internet nicht (DNS). Netzwerk prüfen, danach: pct destroy $CTID --purge"

  say "Installiere die Anwendung im Container (dauert ein bis zwei Minuten)"
  pct exec "$CTID" -- bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null"
  pct exec "$CTID" -- bash -c "curl -fsSL 'https://raw.githubusercontent.com/${REPO}/${BRANCH}/scripts/setup.sh' | REPO='${REPO}' BRANCH='${BRANCH}' bash"

  say "Fertig. Container-ID: $CTID  (Konsole: pct enter $CTID, Aktualisieren: pct exec $CTID -- divera-gateway-update)"
}

on_error() {
  printf '\033[1;31mInstallation abgebrochen.\033[0m\n' >&2
  if [ "${CREATED:-0}" = 1 ]; then
    printf 'Der Container %s wurde angelegt und bleibt zur Fehlersuche bestehen.\nEntfernen mit: pct stop %s; pct destroy %s --purge\n' "$CTID" "$CTID" "$CTID" >&2
  fi
}
trap on_error ERR

main "$@"
