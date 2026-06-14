#!/usr/bin/env bash
#
# install_uf.sh — CHIMERA P06
# Install & configure the Splunk Universal Forwarder (UF) to ship honeypot/sensor
# logs from the host Docker volumes into the local Splunk Enterprise indexer.
#
# Idempotent-ish: safe to re-run. Re-running re-applies config and restarts the UF.
#
# UF version : 10.4.0 (build f798d4d49089) — matched to the indexer build exactly.
# Download   : PUBLIC, no Splunk.com auth required:
#   https://download.splunk.com/products/universalforwarder/releases/10.4.0/linux/splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
#
# ---- KEY DECISIONS (learned while building P06) --------------------------------
#  1. PERMISSIONS: honeypot logs live under /var/lib/docker/volumes/*/_data and the
#     parent /var/lib/docker/volumes is mode 700 root. We do NOT run the UF as root.
#     Instead the UF runs under its native `splunkfwd` user via the systemd unit that
#     `splunk enable boot-start` generates — that unit carries
#         AmbientCapabilities=CAP_DAC_READ_SEARCH
#     which lets splunkd bypass DAC read/traverse checks and read the root-owned JSON
#     files without changing any host permissions. Cleaner + least-privilege.
#  2. MGMT PORT: the indexer (Splunk Enterprise) already owns 8089, so the UF mgmt
#     port is moved to 127.0.0.1:8090 (web.conf) before first start to avoid a clash.
#  3. The UF is systemd-managed; start/stop/restart go through `systemctl`
#     (the splunk CLI delegates to it). Boot-start is therefore already enabled.
#
# Run as a user with passwordless sudo:  sudo bash scripts/install_uf.sh
#
# CREDENTIALS: never hardcoded. Read from the repo-root .env (gitignored). Copy
# .env.example -> .env and fill SPLUNK_ADMIN_USER / SPLUNK_ADMIN_PASSWORD first.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load .env (KEY=VALUE lines) so SPLUNK_ADMIN_* are available. `set -a` exports
# every var defined while sourcing; survives the sudo re-exec via `sudo -E`.
if [[ -f "${REPO_DIR}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${REPO_DIR}/.env"
  set +a
fi

# ----- config -------------------------------------------------------------
UF_HOME="/opt/splunkforwarder"
UF_BIN="${UF_HOME}/bin/splunk"
DEB_NAME="splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb"
# Staged .deb (owned by the human user). Resolve a sensible default when run via sudo.
INSTALLER_DIR="${INSTALLER_DIR:-/home/hi/chimera-host/installers}"
UF_DEB="${INSTALLER_DIR}/${DEB_NAME}"
UF_URL="https://download.splunk.com/products/universalforwarder/releases/10.4.0/linux/${DEB_NAME}"
ADMIN_USER="${SPLUNK_ADMIN_USER:?set SPLUNK_ADMIN_USER in .env (copy .env.example)}"
ADMIN_PASS="${SPLUNK_ADMIN_PASSWORD:?set SPLUNK_ADMIN_PASSWORD in .env (copy .env.example)}"
INDEXER_RECEIVER="localhost:9997"
UF_MGMT_PORT="8090"

# Indexer (Splunk Enterprise) — to enable receiving on 9997
SPLUNK_ENT_BIN="/opt/splunk/bin/splunk"

INPUTS_SRC="${REPO_DIR}/infra/forwarder/inputs.conf"
PROPS_SRC="${REPO_DIR}/infra/forwarder/props.conf"

# Re-exec under sudo if not root (install needs root; splunkd itself runs as splunkfwd).
if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

echo "==> [1/8] Ensure UF .deb is staged"
if [[ ! -f "${UF_DEB}" ]]; then
  echo "    .deb not found at ${UF_DEB}; downloading from Splunk (public)…"
  mkdir -p "$(dirname "${UF_DEB}")"
  curl -fsSL -o "${UF_DEB}" "${UF_URL}"
fi
ls -la "${UF_DEB}"

echo "==> [2/8] Install UF package (skip if already installed)"
if [[ -x "${UF_BIN}" ]]; then
  echo "    UF already present at ${UF_HOME}; skipping dpkg install."
else
  dpkg -i "${UF_DEB}"
fi

echo "==> [3/8] Move UF mgmt port to ${UF_MGMT_PORT} (indexer owns 8089)"
mkdir -p "${UF_HOME}/etc/system/local"
cat > "${UF_HOME}/etc/system/local/web.conf" <<EOF
[settings]
mgmtHostPort = 127.0.0.1:${UF_MGMT_PORT}
EOF

echo "==> [4/8] First-time init: accept license + seed admin password"
# user-seed.conf (consumed on first start) sets the admin password non-interactively.
if [[ ! -f "${UF_HOME}/etc/passwd" ]]; then
  # Hash the password with the UF's own tooling so we don't store plaintext logic here.
  HASH="$(${UF_BIN} hash-passwd "${ADMIN_PASS}" 2>/dev/null || true)"
  if [[ -n "${HASH}" ]]; then
    cat > "${UF_HOME}/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
HASHED_PASSWORD = ${HASH}
EOF
  else
    cat > "${UF_HOME}/etc/system/local/user-seed.conf" <<EOF
[user_info]
USERNAME = ${ADMIN_USER}
PASSWORD = ${ADMIN_PASS}
EOF
  fi
fi

echo "==> [5/8] Enable boot-start (generates systemd unit, runs as splunkfwd w/ CAP_DAC_READ_SEARCH)"
# This unit's AmbientCapabilities=CAP_DAC_READ_SEARCH is exactly what lets the UF
# read the root-owned Docker volume log files without running as root.
chown -R splunkfwd:splunkfwd "${UF_HOME}"
if [[ ! -f /usr/lib/systemd/system/SplunkForwarder.service && ! -f /etc/systemd/system/SplunkForwarder.service ]]; then
  "${UF_BIN}" enable boot-start -user splunkfwd -systemd-managed 1 --accept-license --answer-yes --no-prompt
fi
systemctl daemon-reload || true

echo "==> [6/8] Enable receiving on the indexer (9997, loopback only — no firewall rule)"
sudo -u splunk "${SPLUNK_ENT_BIN}" enable listen 9997 -auth "${ADMIN_USER}:${ADMIN_PASS}" 2>&1 \
  | grep -v cliVerifyServerName || echo "    (listen may already be enabled — continuing)"

echo "==> [7/8] Lay down outputs.conf + inputs.conf + props.conf"
cat > "${UF_HOME}/etc/system/local/outputs.conf" <<EOF
[tcpout]
defaultGroup = chimera_indexers

[tcpout:chimera_indexers]
server = ${INDEXER_RECEIVER}

[tcpout-server://${INDEXER_RECEIVER}]
EOF
cp "${INPUTS_SRC}" "${UF_HOME}/etc/system/local/inputs.conf"
cp "${PROPS_SRC}"  "${UF_HOME}/etc/system/local/props.conf"
chown -R splunkfwd:splunkfwd "${UF_HOME}/etc/system/local"

echo "==> [8/8] (Re)start the UF via systemd"
systemctl reset-failed SplunkForwarder 2>/dev/null || true
systemctl restart SplunkForwarder
sleep 4
systemctl is-active SplunkForwarder

echo
echo "==> Done. Verify connection:"
echo "    sudo ${UF_BIN} list forward-server -auth ${ADMIN_USER}:<pass>"
echo "    -> should list ${INDEXER_RECEIVER} under 'Active forwards'."
