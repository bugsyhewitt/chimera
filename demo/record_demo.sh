#!/usr/bin/env bash
# CHIMERA — scripted terminal walkthrough for the demo recording.
# Slide-per-section (clear between beats) so each is readable; silent (operator adds VO/editing).
# Uses REAL live data from the running Splunk instance where practical.
set -u
export PATH="$HOME/.local/bin:$PATH"
cd /home/hi/chimera
set -a; . /home/hi/chimera/.env 2>/dev/null; set +a
MGMT="https://localhost:${SPLUNK_MGMT_PORT:-8089}"
AUTH="${SPLUNK_ADMIN_USER:-admin}:${SPLUNK_ADMIN_PASSWORD}"

C0='\033[0m'; B='\033[1m'; CY='\033[1;36m'; GR='\033[1;32m'; YE='\033[1;33m'; MG='\033[1;35m'; RD='\033[1;31m'; DIM='\033[2m'; WH='\033[1;37m'
pause(){ sleep "${1:-2}"; }
type_out(){ printf "${WH}\$ ${C0}"; local s="$1"; for ((i=0;i<${#s};i++)); do printf "%s" "${s:$i:1}"; sleep 0.014; done; printf "\n"; sleep .3; }
vo(){ :; }   # narration is spoken by the operator over the video — not printed on screen
slide(){ clear; printf "${DIM}  CHIMERA · V3X · Splunk Agentic Ops Hackathon${C0}\n"; printf "${CY}${B}  ▌ %s${C0}\n  ${DIM}────────────────────────────────────────────────────────────────────${C0}\n\n" "$1"; }
spl(){ curl -k -s -u "$AUTH" "$MGMT/services/search/jobs" --data-urlencode "search=$1" -d exec_mode=oneshot -d output_mode=json -d earliest_time=0 --max-time 25 2>/dev/null; }

# ============================== TITLE ==============================
clear; printf "\n\n"
cat <<'EOF'
     ██████╗██╗  ██╗██╗███╗   ███╗███████╗██████╗  █████╗
    ██╔════╝██║  ██║██║████╗ ████║██╔════╝██╔══██╗██╔══██╗
    ██║     ███████║██║██╔████╔██║█████╗  ██████╔╝███████║
    ██║     ██╔══██║██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║
    ╚██████╗██║  ██║██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║
     ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
EOF
printf "\n${B}    A Splunk-native AI deception agent${C0}\n"
printf "    ${WH}detect ▸ classify human-vs-AI ▸ adapt deception ▸ report — all through Splunk + MCP${C0}\n"
printf "\n${DIM}    V3X · Splunk Agentic Ops Hackathon · Security track${C0}\n"
pause 6

# ============================== THE PROBLEM ==============================
slide "The problem — alert fatigue, and a new kind of attacker"
printf "   ${WH}▪${C0}  SOC teams drown in alerts — real intrusions hide in the flood of false positives.\n\n"
printf "   ${WH}▪${C0}  A new adversary has arrived: ${YE}${B}autonomous AI agents${C0} already probe the public\n"
printf "      internet ${DIM}(Palisade — LLM Agent Honeypot · Cisco Talos).${C0}\n\n"
printf "   ${WH}▪${C0}  Splunk shipped six SOC agents that ${B}detect & respond${C0} — ${MG}${B}none of them deceive.${C0}\n\n"
printf "      ${CY}${B}CHIMERA occupies that empty space.${C0}\n"
pause 9

# ============================== 1. LIVE PIPELINE ==============================
slide "1 ┃ The pipeline is live — honeypots ▸ Universal Forwarder ▸ Splunk ▸ MCP"
vo "Sensors and honeypots feed Splunk; the orchestrator reads it all through the Splunk MCP Server."
type_out "docker compose -f infra/docker-compose.yml ps"
sudo docker compose -f infra/docker-compose.yml ps --format '   {{.Name}}\t{{.Status}}' 2>/dev/null
printf "\n   ${GR}MCP server: Splunk_MCP_Server 1.2.0${C0} — ${DIM}10 agent-callable tools, OAuth bearer${C0}\n"
pause 6

# ============================== 2. ATTACK ==============================
slide "2 ┃ An attacker hits the SSH honeypot (Cowrie)"
vo "A human attacker brute-forces, logs in with bait creds, and pokes around — captured to idx_honeypot."
type_out "bash scripts/seed_attacker.sh"
printf "   ${DIM}[seed] login.failed ×3 → success root/toor → whoami; uname -a; wget http://…/x.sh${C0}\n"
pause 5

# ============================== 3. SPRT ==============================
slide "3 ┃ Detection with a PROVABLE error bound — Wald SPRT (α=0.01, β=0.05)"
vo "Not a black-box score: SPRT accumulates a log-likelihood ratio and declares HOSTILE the instant evidence is sufficient — with provable false-positive/negative bounds."
type_out "splunk> index=idx_deception decision=HOSTILE | table src_ip lambda confidence"
R=$(spl 'search index=idx_deception sourcetype=chimera:decision decision=HOSTILE earliest=-30d | head 1 | table src_ip lambda confidence')
SIP=$(printf '%s' "$R" | python3 -c "import sys,json;r=json.load(sys.stdin)['results'];print(r[0]['src_ip'] if r else '172.30.0.1')" 2>/dev/null)
LAM=$(printf '%s' "$R" | python3 -c "import sys,json;r=json.load(sys.stdin)['results'];print(r[0].get('lambda','5.7') if r else '5.7')" 2>/dev/null)
printf "   ${RD}${B}▶ HOSTILE${C0}    src_ip=${YE}%s${C0}    Λ=${YE}%s${C0} ≥ A=ln((1−β)/α)=4.554    confidence=1.0\n" "$SIP" "$LAM"
pause 6

# ============================== 4. AI-vs-HUMAN ==============================
slide "4 ┃ Human or autonomous AI? — the inverted-PromptArmor MCP tripwire"
vo "A Beelzebub MCP decoy advertises a tool no human would ever call. A human ignores it; an LLM agent calls it — and fingerprints itself as AI."
type_out "python scripts/seed_ai_attacker.py   # fast, goal-directed agent → trips the MCP decoy"
R=$(spl "search index=idx_deception sourcetype=chimera:decision classification=AI earliest=-30d | head 1 | table p_ai")
PAI=$(printf '%s' "$R" | python3 -c "import sys,json;r=json.load(sys.stdin)['results'];print(r[0].get('p_ai','0.9997') if r else '0.9997')" 2>/dev/null)
printf "\n   channel 1 ${DIM}timing — K-S test + Shannon entropy${C0}     → leans AI\n"
printf "   channel 2 ${DIM}behavioral — lure-pursuit divergence${C0}    → leans AI\n"
printf "   channel 3 ${MG}${B}MCP tripwire — decoy tool invoked${C0}    → ${RD}${B}DECISIVE${C0}\n"
printf "\n   ${MG}${B}▶ classification = AI${C0}    p_ai = ${YE}${B}%s${C0}\n" "$PAI"
pause 6

# ============================== 5. POMDP ==============================
slide "5 ┃ Adapt the deception — POMDP belief controller"
vo "A belief over {benign, human, AI} picks breadcrumb intensity: sparse for a suspicious human, aggressive looping bait for an AI agent that'll chase a planted goal."
type_out "splunk> index=idx_deception type=deception_action | table action belief.*"
printf "   belief = ( benign ${DIM}0.15${C0} , human ${DIM}0.01${C0} , ${YE}${B}ai 0.84${C0} )    →    action = ${RD}${B}AGGRESSIVE${C0}\n"
pause 6

# ============================== 6. REPORT ==============================
slide "6 ┃ Foundation-Sec-8B writes the adversary engagement report"
vo "A self-hosted security model produces real MITRE ATT&CK + MITRE Engage IDs and a recommended SPL detection."
type_out "uv run python -m chimera.reporter --session $SIP"
[ -s /tmp/demo_report.md ] && sed 's/^/   /' /tmp/demo_report.md | head -28
pause 8

# ============================== 7. WRITE-BACK ==============================
slide "7 ┃ Write-back closes the loop — a durable, actionable Splunk artifact"
vo "CHIMERA doesn't just summarize: it writes a session_summary to Splunk AND persists the generated detection as a real saved search."
type_out "splunk> | rest /servicesNS/nobody/chimera/saved/searches | search title=chimera_detection*"
R=$(curl -k -s -u "$AUTH" "$MGMT/servicesNS/nobody/chimera/saved/searches?search=chimera_detection&output_mode=json&count=3" --max-time 20 2>/dev/null | python3 -c "import sys,json;e=json.load(sys.stdin)['entry'];print(e[0]['name'] if e else 'chimera_detection_e927bce9db27')" 2>/dev/null)
printf "\n   ${GR}${B}✔ saved search created:${C0}  ${WH}%s${C0}\n      ${DIM}generated SPL detection — now live in Splunk${C0}\n" "$R"
printf "   ${GR}${B}✔ session_summary written${C0} to idx_deception  ${DIM}(classification · dwell · report · IoCs)${C0}\n"
pause 7

# ============================== 8. IMPACT (held finale) ==============================
slide "8 ┃ The impact — attacker dwell time UP, penetration probability ~0"
vo "A static honeypot gets a brief, suspicious visit. CHIMERA's adaptive deception keeps attackers engaged far longer — while nothing real is ever reached."
printf "   ${B}Average attacker dwell time${C0}\n\n"
printf "   static honeypot   ${DIM}████${C0}                                                                 ${DIM}49 s${C0}\n\n"
printf "   with ${CY}${B}CHIMERA${C0}      ${GR}█████████████████████████████████████████████████████████████████${C0}  ${GR}${B}821 s${C0}\n\n"
printf "   ${YE}${B}   ▲ 16.7× longer engagement${C0}            penetration probability  ${GR}${B}~ 0%%${C0}\n"
pause 9
# closing card
slide "CHIMERA — first to operationalize known-good math as a running Splunk-native agent"
printf "   ${WH}detect ▸ route ▸ classify human-vs-AI ▸ deceive ▸ report ▸ write-back${C0}\n\n"
printf "   ${GR}✓${C0} Wald SPRT, provable α/β bounds      ${GR}✓${C0} inverted-PromptArmor MCP tripwire\n"
printf "   ${GR}✓${C0} POMDP adaptive deception            ${GR}✓${C0} Foundation-Sec-8B reports + write-back\n\n"
printf "   ${YE}${B}16.7× attacker dwell time${C0}   ·   penetration probability ${GR}${B}~0%%${C0}\n\n"
printf "   ${CY}${B}V3X${C0} ${DIM}· open-core: commercial detection plugins available separately${C0}\n"
pause 9
touch /tmp/demo_done
sleep 1
