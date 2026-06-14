# CHIMERA — Project Brain

## What this is
Splunk-native AI agent that detects intruders via SPRT, routes hostile traffic to honeypots (Cowrie/Galah/Beelzebub), classifies AI vs human attackers via three channels (timing/behavioral/MCP tripwire), and adapts deception via a POMDP belief controller. Foundation-Sec-8B generates engagement reports. Splunk MCP Server is the data plane.

## Prime directives
- Build to Tier 1 (must ship), then Tier 2 (wedge), then Tier 3 (polish). Tier order is law.
- Verify before claiming done.
- Use the subagent team. Worktree isolation for code writers.
- Update STATUS.md after every packet.

## V3X identity
This is a public open-source submission by V3X. The orchestration framework is the submission. V3X's commercial detection plugins are NOT in this repo — they plug in via the documented backend interface in `orchestrator/chimera/`. Do not copy Pho3nix, AlienClaw, or other V3X-proprietary code into this repo.

## Stack
- Ubuntu Server 24.04
- Splunk Enterprise (60-day trial) + Splunk MCP Server app + (optional) Splunk AI Assistant for SPL
- Python 3.12, uv, mcp SDK, asyncio
- Docker compose: Suricata, Cowrie, Galah, Beelzebub
- Ollama serving Foundation-Sec-8B (FenkoHQ port)
- Splunk Universal Forwarder for log ingestion

## SPRT parameters
- α (false positive rate) = 0.01
- β (false negative rate) = 0.05
- Wald thresholds (computed in `chimera/sprt.py`):
  - Upper `A = ln((1-β)/α) ≈ +4.554` → declare **HOSTILE** when Λ ≥ A
  - Lower `B = ln(β/(1-α)) ≈ -2.986` → declare **BENIGN** when Λ ≤ B
    (NB: the plan note quoted B ≈ -3.64; that uses a different denominator. We
    use the canonical Wald formula `ln(β/(1-α))`. The verdict logic only needs
    B < 0, so this does not affect HOSTILE detection.)
- Verdicts are **sticky** per `src_ip` (first crossing wins; Λ frozen after).
- Confidence (0..1) is mapped from Λ vs the crossed threshold (1.0 at/after A
  for HOSTILE, at/after B for BENIGN; a 0..0.5 progress signal while UNDECIDED).

### Likelihood ratio table (per-event log-LR), authoritative copy of `chimera/sprt.py:LIKELIHOOD_TABLE`
Each value = log( P(evidence|hostile) / P(evidence|benign) ). Positive ⇒ hostile.

| Evidence type (table key)        | log-LR | Source / rationale |
|----------------------------------|-------:|--------------------|
| `port_scan_signature`            |  +2.5  | Suricata: strong recon indicator |
| `auth_failure_burst`             |  +1.5  | Suricata: brute-force signature |
| `anomalous_user_agent`           |  +1.0  | Suricata: scanner-like UA |
| `normal_http`                    |  -0.5  | Suricata: ordinary HTTP ⇒ benign pull |
| `cowrie.login.failed`            |  +1.5  | Cowrie: brute-force attempt |
| `cowrie.login.success`           |  +2.0  | Cowrie: accepted bait creds (weightier than a failure) |
| `cowrie.command.input`           |  +1.0  | Cowrie: hands-on-keyboard shell activity |
| `cowrie.session.connect`         |  +0.3  | Cowrie: touching the honeypot at all is mildly suspicious (weak alone) |
| `cowrie.session.file_download`   |  +2.5  | Cowrie: wget/curl payload staging |
| `cowrie.session.closed`          |  +0.1  | Cowrie: near-neutral |
| `unknown` (fallback)             |  +0.1  | Anything reaching the honeypot is faintly suspicious; kept tiny |

Calibration: the smoke-test attacker (3× failed = 4.5, 1× success = 2.0, plus
connects/commands) clears A ≈ 4.554 well before the run ends — even failures +
success alone (6.5) cross it. A single benign connect (+0.3) stays UNDECIDED.
Live-verified: src_ip 172.30.0.1 reached HOSTILE at Λ=5.7 (confidence 1.0).

### Topology / evidence-source note (critical)
Suricata can't see Cowrie traffic in the single-host Docker setup, so
`idx_network` stays empty during attacks — the real signal lands in
`idx_honeypot` (Cowrie JSON). The Splunk MCP server only auto-extracts a few KV
fields (notably `src_ip`); the discriminating fields (`eventid`, `event_type`,
`signature`, `input`) live inside the JSON in `_raw`. `chimera/sprt.classify_event`
therefore parses `_raw` JSON when those fields are absent at the top level.

## Router / deception gateway (P11 — `orchestrator/chimera/router.py`)
When SPRT declares a `src_ip` **HOSTILE**, the router decides which honeypot to
steer it to and records/enforces that routing. Wired into `loop.py` at the same
HOSTILE transition that writes the SPRT verdict (one route decision per src_ip,
deduped; never raises into the loop).

- **Routing rule** (`route_for(src_ip, evidence) -> Route`): derive "shape" from
  the per-evidence-type tally SPRT already keeps (`SPRTState.evidence`). Sum
  counts into an SSH bucket (`cowrie.*` eventids + Suricata `auth_failure_burst`)
  and a WEB bucket (`port_scan_signature`, `anomalous_user_agent`, `normal_http`,
  Galah/`http`). Heavier bucket wins. SSH-shaped → **Cowrie** (port 2222);
  web/scanner-shaped → **Galah** (port 8080); empty/tie → **Cowrie** (default:
  SSH brute-force is the dominant threat model and the calibrated smoke-test
  attacker is SSH-shaped).
- **Modes** (`CHIMERA_ROUTER_MODE` in `.env`, default `simulate`):
  - `simulate` (DEFAULT, what runs here): writes a `type="route"` event to
    idx_deception — `{type:"route", src_ip, decision:"route", honeypot, port,
    mode:"simulate", reason, ts}`. The smoke test asserts this event.
  - `enforce` (real code, NOT executed on this box): adds the src_ip to nftables
    set `chimera_route_cowrie`/`chimera_route_galah` (table `inet chimera`); a
    pre-existing DNAT rule from each set redirects to the honeypot port. Command
    shape (pure, unit-tested via `render_nft_commands`):
    `nft add element inet chimera chimera_route_cowrie { <ip> }`. `enforce_route`
    is the only shell-out and is guarded — it raises unless mode==`enforce`.
- **WHY simulate is default here:** this host is the operator's workstation and
  Docker owns the host iptables/nftables chains — issuing host nft rules would
  fight Docker and risk the demo. Mid-stream TCP redirection of an established
  connection is out of scope; the realistic model is per-source routing applied
  to the attacker's *next* connection (exactly what nftables-set DNAT does in a
  real deployment). So here we record the would-route decision (fully demoable,
  lands in Splunk) and keep `enforce` as audited, tested, but un-executed code.
- Live-verified: drove 172.30.0.1 (HOSTILE, Cowrie SSH evidence) → route event
  in idx_deception with honeypot=cowrie, port=2222, mode=simulate.

## POMDP belief controller (P14 — `orchestrator/chimera/pomdp.py`)
First Tier-3 packet: the adaptive-deception brain. Formalises §5.3 ("fewer clues
for humans, more for AI") as a small POMDP with a **hand-tuned, belief-thresholded
policy** — NO deep RL.

- **Hidden state space** `{benign, human_attacker, ai_attacker}`. **Belief** `b`
  is a 3-vector on the simplex (indices: benign=0, human=1, ai=2). One belief per
  src_ip/session, started from a benign-heavy prior `[0.8, 0.1, 0.1]`.
- **Bayesian update** `update(belief, obs)`: `b'(s) ∝ P(obs|s)·b(s)`, renormalised
  onto the simplex; numerically stable (clamps ≥0, floors the normaliser, falls
  back to prior if an obs is impossible under all states). Two observation kinds,
  cleanly separated (SPRT = "attacker or not", classifier = "which kind"):
  - **SPRT verdict** likelihood table `P(verdict | state)` indexed [benign,human,ai]:
    `HOSTILE → (0.02, 0.90, 0.90)` (pulls mass off benign onto BOTH attacker states
    equally — SPRT doesn't distinguish human/AI); `BENIGN → (0.90, 0.05, 0.05)`
    (reinforces benign); `UNDECIDED → (1,1,1)` (no-op). Values are illustrative
    likelihoods (shape, not exact α/β) — only matter up to a per-row constant.
  - **Classifier posterior** (`p_ai`): likelihood `(1.0, p_human, p_ai)` — benign
    is uninformative (SPRT owns that call); attacker mass splits by p_ai/p_human.
- **Action space** (breadcrumb intensity): `{none, subtle, moderate, aggressive}`.
- **Policy** `policy(b)` (threshold 0.7): `b[ai] > 0.7 → aggressive` (AI agents
  chase planted goals → heavy looping breadcrumbs); `b[human] > 0.7 → subtle`
  (humans get suspicious fast → sparse breadcrumbs); `b[benign] > 0.7 → none`;
  else `moderate` (hedge). Reward framing (narrative only, not optimised):
  `R = engagement_value(dwell) − penetration_risk_penalty`.
- **SCOPE LIMIT (v1):** the action is **recorded, not physically enforced** on the
  honeypot. We do NOT swap honeypot configs. On each meaningful belief/action
  change `BeliefController.observe_and_write` writes a `{type:"deception_action",
  src_ip, session, belief:{benign,human,ai}, action, ts}` event to idx_deception
  (sourcetype `chimera:decision`) via DeceptionWriter. The actuator (enforcing
  breadcrumb intensity on the live honeypot) is future work.
- **Loop wiring** (`loop.py`): one `BeliefController` for the run. On a SPRT
  HOSTILE/BENIGN transition we feed `Observation.from_verdict(verdict)`; in
  `classify_and_write` we feed `Observation.from_classification(result)` (p_ai).
  Identical consecutive belief/action pairs are deduped (quantised to 4dp) so we
  don't spam idx_deception; the controller never raises into the loop (write
  failures logged, treated as not-emitted so they retry on the next change).
- Live-verified: drove 172.30.0.1 (HOSTILE → p_ai=0.99) → `deception_action`
  events in idx_deception: HOSTILE gave `action=moderate` b=(0.082,0.459,0.459);
  the high-p_ai split drove `b[ai]=0.841 > 0.7 → action=aggressive`. The dotted
  subfields `belief.ai|human|benign` auto-extract in SPL.

## Mistakes log
(Append below as you find them. This is how the next session learns.)
