#!/usr/bin/env bash
#
# smoke_test.sh — CHIMERA P08 Tier-1 end-to-end smoke test (verifier harness).
#
# Proves the full Tier-1 loop works:
#   attacker -> Cowrie honeypot -> Universal Forwarder -> idx_honeypot
#            -> orchestrator (MCP read) -> idx_deception decision (REST write)
#
# Flow:
#   1. Bring up the docker honeypot stack (idempotent; fine if already up).
#   2. Start the orchestrator loop in the background; capture its PID + log.
#   3. Run seed_attacker.sh (a human SSH attacker against Cowrie).
#   4. Wait for ingestion latency + orchestrator processing.
#   5. Assert via Splunk:
#        a. idx_honeypot has recent Cowrie events from src_ip 172.30.0.1.
#        b. idx_deception has >=1 chimera:decision for that src_ip, written
#           AFTER this test started (proves THIS run's loop produced it).
#   6. Kill the orchestrator; LEAVE the docker stack up (Tier-2 reuses it).
#   7. Print PASS/FAIL and exit 0/non-zero.
#
# Assertions query Splunk via the REST search API on the management port
# (https://localhost:8089) — the SAME data plane the orchestrator's MCP client
# reads from. (The local `splunk search` CLI auth path returns no rows in this
# environment even though the data is present; REST/MCP is authoritative, so the
# smoke test asserts against the path the architecture actually uses.)
set -uo pipefail

# ----- config -----------------------------------------------------------------
REPO_ROOT="/home/hi/chimera"
COMPOSE_FILE="${REPO_ROOT}/infra/docker-compose.yml"
ORCH_DIR="${REPO_ROOT}/orchestrator"
SEED="${REPO_ROOT}/scripts/seed_attacker.sh"

# CREDENTIALS: never hardcoded. Read from the repo-root .env (gitignored).
# Copy .env.example -> .env and fill SPLUNK_ADMIN_USER / SPLUNK_ADMIN_PASSWORD.
if [ -f "${REPO_ROOT}/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "${REPO_ROOT}/.env"
  set +a
fi

SPLUNK_MGMT="https://localhost:8089"   # self-signed -> curl -k
SPLUNK_USER="${SPLUNK_ADMIN_USER:?set SPLUNK_ADMIN_USER in .env (copy .env.example)}"
SPLUNK_PASS="${SPLUNK_ADMIN_PASSWORD:?set SPLUNK_ADMIN_PASSWORD in .env (copy .env.example)}"
ATTACKER_SRC_IP="172.30.0.1"   # docker gateway = src_ip Cowrie records for host SSH

# Timing
ORCH_WARMUP_SECONDS=8          # let MCP connect + first poll happen
INGEST_WAIT_SECONDS=45         # UF ingest latency (~10-40s) + orchestrator poll (5s)
DECISION_POLL_TRIES=8          # extra retries while polling for the decision
DECISION_POLL_INTERVAL=8

UF=~/.local/bin/uv
ORCH_LOG="$(mktemp -t chimera_orch.XXXXXX.log)"
ORCH_PID=""
TEST_START_EPOCH="$(date +%s)"

# ----- helpers ----------------------------------------------------------------
say()  { printf '\n=== %s ===\n' "$*"; }
info() { printf '[smoke] %s\n' "$*"; }
fail() { printf '\n[smoke] FAIL: %s\n' "$*" >&2; }

cleanup() {
  if [ -n "${ORCH_PID}" ] && kill -0 "${ORCH_PID}" 2>/dev/null; then
    info "stopping orchestrator (pid ${ORCH_PID})"
    kill -TERM "${ORCH_PID}" 2>/dev/null || true
    # give it a moment to shut down cleanly, then force
    for _ in 1 2 3 4 5; do
      kill -0 "${ORCH_PID}" 2>/dev/null || break
      sleep 1
    done
    kill -9 "${ORCH_PID}" 2>/dev/null || true
    wait "${ORCH_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# Run an SPL `... | stats count` search via the Splunk REST oneshot API and
# echo the integer count (0 on any error/empty). $1 = SPL, $2 = earliest_time
# (epoch or relative like -10m). This is the same management-port search plane
# the orchestrator's MCP client reads from.
splunk_count() {
  local spl="$1"
  local earliest="$2"
  local json
  json="$(timeout 120 curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
            "${SPLUNK_MGMT}/services/search/jobs" \
            --data-urlencode "search=${spl}" \
            -d output_mode=json -d exec_mode=oneshot \
            -d "earliest_time=${earliest}" 2>/dev/null)"
  printf '%s' "${json}" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    r = d.get("results") or []
    print(int(r[0]["count"]) if r else 0)
except Exception:
    print(0)
' 2>/dev/null
}

# ----- 1. bring up the stack --------------------------------------------------
say "1/6 bring up honeypot stack"
if sudo docker compose -f "${COMPOSE_FILE}" up -d 2>&1 | sed 's/^/[compose] /'; then
  info "docker compose up -d ok (already-running services are a no-op)"
else
  fail "docker compose up failed"
  exit 1
fi
# brief settle for Cowrie to be listening
sleep 3

# ----- 2. start orchestrator --------------------------------------------------
say "2/6 start orchestrator loop (background)"
( cd "${ORCH_DIR}" && exec "${UF}" run python -m chimera.loop ) >"${ORCH_LOG}" 2>&1 &
ORCH_PID=$!
info "orchestrator pid=${ORCH_PID}, log=${ORCH_LOG}"
sleep "${ORCH_WARMUP_SECONDS}"
if ! kill -0 "${ORCH_PID}" 2>/dev/null; then
  fail "orchestrator exited during warmup; log follows:"
  sed 's/^/[orch] /' "${ORCH_LOG}" >&2
  exit 1
fi
# Sanity: confirm it connected to MCP (best-effort; not fatal if log format differs)
if grep -q "mcp_connected\|orchestrator_start" "${ORCH_LOG}" 2>/dev/null; then
  info "orchestrator started and connected"
else
  info "orchestrator running (no connect marker yet; continuing)"
fi

# ----- 3. run the human attacker seed -----------------------------------------
say "3/6 run seed_attacker.sh (human SSH attacker vs Cowrie)"
if bash "${SEED}" 2>&1 | sed 's/^/  /'; then
  info "seed_attacker.sh completed"
else
  fail "seed_attacker.sh returned non-zero"
  exit 1
fi

# ----- 4. wait for ingestion + processing -------------------------------------
say "4/6 wait for ingestion + orchestrator processing (~${INGEST_WAIT_SECONDS}s)"
sleep "${INGEST_WAIT_SECONDS}"

# ----- 5. assertions ----------------------------------------------------------
say "5/6 assert via Splunk"

# 5a. Cowrie events from the attacker present in idx_honeypot (recent window).
HONEYPOT_SPL="search index=idx_honeypot src_ip=${ATTACKER_SRC_IP} | stats count"
hp_count="$(splunk_count "${HONEYPOT_SPL}" "-10m")"
info "idx_honeypot cowrie events from ${ATTACKER_SRC_IP} (last 10m): ${hp_count}"
if [ "${hp_count}" -lt 1 ]; then
  fail "no Cowrie events for src_ip=${ATTACKER_SRC_IP} in idx_honeypot — UF ingest path broken?"
  echo "--- orchestrator log tail ---" >&2
  tail -n 40 "${ORCH_LOG}" | sed 's/^/[orch] /' >&2
  exit 1
fi

# 5b. >=1 orchestrator decision for that src_ip written AFTER test start.
#     Use a generous lookback then filter by _time >= test start so we only
#     count decisions produced by THIS run's orchestrator.
DECISION_SPL="search index=idx_deception sourcetype=chimera:decision src_ip=${ATTACKER_SRC_IP} | stats count"
dec_count=0
for try in $(seq 1 "${DECISION_POLL_TRIES}"); do
  dec_count="$(splunk_count "${DECISION_SPL}" "${TEST_START_EPOCH}")"
  info "attempt ${try}/${DECISION_POLL_TRIES}: idx_deception decisions for ${ATTACKER_SRC_IP} since test start: ${dec_count}"
  [ "${dec_count}" -ge 1 ] && break
  sleep "${DECISION_POLL_INTERVAL}"
done

if [ "${dec_count}" -lt 1 ]; then
  fail "no chimera:decision in idx_deception for src_ip=${ATTACKER_SRC_IP} since test start"
  echo "--- orchestrator log tail ---" >&2
  tail -n 60 "${ORCH_LOG}" | sed 's/^/[orch] /' >&2
  exit 1
fi

# Show a sample decision for the report (via the same REST search plane).
say "sample decision event"
timeout 120 curl -sk -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
  "${SPLUNK_MGMT}/services/search/jobs" \
  --data-urlencode "search=search index=idx_deception sourcetype=chimera:decision src_ip=${ATTACKER_SRC_IP} | head 1 | table _time src_ip decision confidence note source_index" \
  -d output_mode=json -d exec_mode=oneshot -d "earliest_time=${TEST_START_EPOCH}" 2>/dev/null \
  | python3 -c 'import sys,json
try:
    r=(json.load(sys.stdin).get("results") or [])
    print("  "+json.dumps(r[0], indent=2).replace("\n","\n  ") if r else "  (none)")
except Exception as e:
    print("  (could not render sample:", e, ")")' 2>/dev/null || true

# ----- 6. teardown ------------------------------------------------------------
say "6/6 teardown"
cleanup
ORCH_PID=""   # prevent double-kill in EXIT trap
info "orchestrator stopped. Docker stack LEFT UP for subsequent Tier-2 packets."

# ----- summary ----------------------------------------------------------------
say "RESULT"
echo "  idx_honeypot events (src ${ATTACKER_SRC_IP}): ${hp_count}"
echo "  idx_deception decisions (src ${ATTACKER_SRC_IP}, this run): ${dec_count}"
echo ""
echo "  PASS — Tier-1 end-to-end loop verified:"
echo "         attacker -> Cowrie -> UF -> idx_honeypot -> orchestrator -> idx_deception"
exit 0
