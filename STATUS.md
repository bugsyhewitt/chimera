# CHIMERA — Build Status

**Last updated:** 2026-06-10 (ALL BUILD PACKETS DONE — at gate G3)
**Current phase:** Tier 3 complete → awaiting G3 approval to submit

## ⮕ ALL TIERS COMPLETE — AT GATE G3 (awaiting operator + 2 operator tasks)
P01–P18 are built, verified, and committed. The full deception loop is live and the repo is public-ready (MIT, secret-scrubbed, README + ARCHITECTURE + diagram). **135 orchestrator tests pass; smoke test EXIT=0.**

**Demo video:** A raw **80-second silent terminal walkthrough** was auto-produced (`demo/record_demo.sh`, recorded on an Xvfb virtual display, driven by real live Splunk data) and sent to the operator for voiceover + editing. It covers the full loop with real values (HOSTILE Λ, MCP tripwire → AI p_ai=0.9997, POMDP aggressive, Foundation-Sec report w/ ATT&CK+Engage, write-back + saved search, 821s-vs-49s money chart). The live Splunk-dashboard footage was NOT auto-captured (snap-confined Firefox won't render on Xvfb) — operator can screen-grab the live dashboards via RustDesk if desired.

**Remaining operator tasks before/at submission:**
1. **Edit + voice the video** (or re-shoot beats via `demo/record_demo.sh`), upload unlisted, paste the link into README (`<!-- TODO: video link -->`).
2. **Public GitHub push (P19) — operator chose: SQUASH to fresh history.** The git *history* contains the dev Splunk admin password (committed pre-scrub). I'll create a clean single-commit snapshot of the current tree for the public repo so the password never appears in any published commit (local full history stays on this host).

Then fill the Devpost form from the README and submit.

## ⮕ TIER 2/3 (G1+G2 approved) — history below
**The wedge is built and live-verified end-to-end.** For a real seeded attacker (src 172.30.0.1), the orchestrator produces the complete chain in idx_deception:
**SPRT → HOSTILE** (Λ=5.7) → **route → Cowrie** (deception gateway) → **3-channel classify → AI** (p_ai=0.9997, decided by the inverted-PromptArmor MCP tripwire firing on real Beelzebub decoy data) → **Foundation-Sec-8B engagement report** (real ATT&CK T1078/T1059/T1105 + SPL) → **session_summary write-back** + a **real generated Splunk saved search** (`chimera_detection_e927bce9db27`). 106 orchestrator tests pass. All four mandatory math/feature layers (SPRT, 3-channel classifier, router, write-back) operational.
**Operator: reply to approve starting Tier 3 (polish — POMDP belief controller, Tier-3 dashboards incl. the dwell-time/penetration money chart, MITRE Engage mapping, demo script + architecture SVG, README + video).**

### Known minor items for Tier 3 (non-blocking)
- Classification events lack a consistent `type` field (route/session_summary have one) — Tier-3 dashboard (P15) will normalize field shapes. Data is all present.
- One pre-fix buggy session_summary record left in idx_deception (honest artifact; current code can't reproduce it).
- mcp SDK deprecation warning (`streamablehttp_client`); cosmetic.

## Operator gates
- [ ] G0: Splunk install confirmation (BEFORE P02)
- [x] G1: Tier 1 complete approval (AFTER P08) — **APPROVED 2026-06-10. Tier 2 started.**
- [x] G2: Tier 2 complete approval (AFTER P13) — **APPROVED 2026-06-10. Tier 3 started.**
- [~] G3: Ready to submit (AFTER P18) — **REACHED, awaiting operator (+ 2 operator tasks: record video, public push)**

## Packets

### Tier 1
- [x] P01 — Repo scaffold ✅ (verified: `tree -L 2 ~/chimera` shows full structure; `git log` → `f059feb initial scaffold` on main; 24 files tracked, 0 secrets)
- [x] P02 — Splunk + MCP Server install ✅ **DONE** (G0 approved; clock started 2026-06-09 12:44 CDT → ~2026-08-08)
- [x] P03 — Splunk app skeleton ✅ (chimera app symlinked + loaded; idx_network/idx_honeypot/idx_deception all registered; verified via REST + live MCP `splunk_run_query`)
- [x] P04 — Docker compose sensors+honeypots ✅ (Suricata 8.0.4 "Engine started"+eve.json, Cowrie "Ready to accept" on 127.0.0.1:2222 + cowrie.json, Galah built from upstream v1.1.1 on :8080 + galah.json; isolated `chimera_dmz` 172.30/16. Lead re-verified Cowrie banner.)
- [x] P05 — Orchestrator skeleton + MCP client ✅ (uv project; config/mcp_client/loop; live MCP integration test **3 passed** — sees idx_network/honeypot/deception; loop runs 30s clean. Lead re-ran: 3 passed.)
- [x] P06 — UF ingestion ✅ (UF 10.4.0 installed, fwd→9997 active; Cowrie/Galah→idx_honeypot, Suricata→idx_network with parsed JSON fields. Lead re-verified: idx_honeypot 95 cowrie+1 galah, idx_network 29 suricata. UF runs least-privilege via CAP_DAC_READ_SEARCH; mgmt port 8090 to avoid 8089 clash.)
- [x] P07 — Tier 1 dashboard ✅ (chimera_overview.xml, 3 panels, 30s refresh; well-formed XML; app `_reload`'d non-disruptively; view registered via REST 200; renders against empty indexes without error)
- [x] P08 — E2E smoke test ✅ **PASSES** (verifier ran 2×, lead re-ran 1×, all EXIT=0; 114 cowrie events + 1 fresh decision for attacker src_ip)

### Tier 2
- [x] P09 — SPRT classifier ✅ (Wald SPRT α=0.01/β=0.05; 20 tests; live: attacker→HOSTILE Λ=5.7. Verdicts → idx_deception.)
- [x] P10 — 3-channel AI/human classifier ✅ (timing K-S+entropy / behavioral lure-pursuit / tripwire; Bayesian log-LR fusion; 59 tests. **Live e2e: src→AI p_ai=0.9997**.)
- [x] P10a — Beelzebub MCP decoy ✅ (MCP decoy `user-account-manager` on 127.0.0.1:8092; tools/call → idx_honeypot `beelzebub:json`, live-verified. Channel 3 reconciled to its event.* shape + live-fires log-LR 8.0.)
- [x] P11 — Router / deception gateway ✅ (route_for → Cowrie/Galah from SPRT evidence; real nftables enforce code gated behind simulate-default; 76 tests; live route event honeypot=cowrie.)
- [x] P12 — Foundation-Sec-8B integration ✅ (reporter.py → Ollama /api/generate; live report with real ATT&CK T1078/T1059/T1105 + SPL; 86 tests. Galah LLM-generation also fixed.)
- [x] P13 — Write-back + generated detections ✅ (session_summary → idx_deception + generated SPL persisted as REAL Splunk saved search via REST; 106 tests; live session_summary classification=AI + chimera_detection_* saved search.)

### Tier 3
- [x] P14 — POMDP belief controller ✅ (belief over {benign,human,ai}, threshold policy → breadcrumb intensity; 125 tests; live deception_action b[ai]=0.84→aggressive)
- [x] P15 — Tier 3 dashboard ✅ (chimera_metrics.xml: dwell-over-time, penetration gauge ~0, live belief table, money chart CHIMERA 821s vs baseline 49s; honest synthetic cohorts)
- [x] P16 — MITRE Engage mapping ✅ (reporter appends Engage section: EAC0005/0016/0006/... verified vs mitre/engage v1.0; 135 tests)
- [x] P17 — Demo script + architecture SVG ✅ (demo_script.md 3-min/396 words; architecture.svg layered, rendered+visually verified legible)
- [x] P18 — README + repo polish + video prep ✅ (README + ARCHITECTURE + .env.example; **secret scrub: no password/token in any tracked file**; sanitized scripts re-pass smoke test EXIT=0; recording_notes.md. Video recording = operator task.)
- [ ] P19 — Submit to Devpost (operator: record video, push public repo, submit)

## Bugs
(verifier files them here)
- **NOTE (P05, low):** mcp SDK 1.27.2 emits `DeprecationWarning: Use streamable_http_client instead` (we import `streamablehttp_client`). Harmless now; rename when convenient.
- **NOTE (P04→P12):** Galah's LLM backend is non-functional until P12: Ollama has no model pulled AND binds `127.0.0.1` only (unreachable from the `chimera_dmz` bridge). P12 must `ollama pull FenkoHQ/Foundation-Sec-8B` and set `OLLAMA_HOST=0.0.0.0` (or otherwise expose Ollama to the bridge) so Galah can generate responses. Galah still logs every request as JSON without it.
- **NOTE (Tier1→P06):** honeypots bind to 127.0.0.1 only (safe). idx_network/honeypot are empty until P06 wires the Universal Forwarder to ship Cowrie/Galah/Suricata logs into Splunk.

## Decisions log
(autonomous decisions — what and why, one line each)
- 2026-06-09: P01 — used `claude-opus-4-7` model in agent defs exactly as the master plan specifies (verbatim agent definitions), even though the host's lead model differs; the plan is the truth source for agent frontmatter.
- 2026-06-09: P01 — `.worktreeinclude` includes `.env` so worktree code-writer subagents can run verification against live Splunk/Ollama.
- 2026-06-09: P02 — Splunk started/run **as the `splunk` user** (not root); chown'd `/opt/splunk` to splunk:splunk (root-owned files from a failed root-start attempt + dpkg libs). Boot-start is systemd-managed (`Splunkd.service`).
- 2026-06-09: P02 — MCP token minted with **+90d** expiry (covers the event with margin) for `admin`. Rotated the server RSA keypair once before minting (clean key).
- 2026-06-09: P02 — **AI Assistant for SPL skipped** (not available on Enterprise trial; no `saia_*` tools). Generation duties go to Ollama Foundation-Sec-8B. See MCP Server facts section.
- 2026-06-09: P03 — added `splunk` user to group `hi` so splunkd can traverse `/home/hi` (mode 750) to follow the `splunk-app` symlink. Group-scoped, not world-exposing. App is a **symlink** (per plan) so repo edits reflect live after a reload/restart.
- 2026-06-09: P06 — UF runs as `splunkfwd` with `CAP_DAC_READ_SEARCH` (systemd ambient cap) to read root-owned docker-volume logs — least-privilege, no host perm changes, no root. UF mgmt port = 8090 (indexer owns 8089). JSON fields parsed via per-sourcetype `INDEXED_EXTRACTIONS=json` in `infra/forwarder/props.conf`.
- 2026-06-09: P06 note — default Cowrie accepts most creds (logs `login.success`); `root/root`+ denied → `login.failed`. P08 smoke test uses `root/toor` which SUCCEEDS in Cowrie default (matches plan). A custom userdb (P04 territory) would be needed to force failures for a demo.
- 2026-06-09: Orchestration — ran P03 in the **lead session** (not a subagent) to get Splunk's one disruptive restart done before fanning out P04/P05/P07, since all share the single Splunk instance. Subagents for P04/P05/P07 write to disjoint dirs and do **not** git-commit (lead reviews + commits) to avoid git-index races without needing worktrees from a non-repo cwd.

## MCP Server facts (P02 — read before P05/P06/P08)
- **Endpoint:** `https://localhost:8089/services/mcp` (persistent REST handler on the Splunk mgmt port, **not** a separate port). Streamable HTTP, JSON-RPC. Self-signed TLS → clients must allow the Splunk cert (verify=false or the Splunk CA at `/opt/splunk/etc/auth/`).
- **Auth:** `Authorization: Bearer <SPLUNK_MCP_TOKEN>`. Token is RSA-encrypted (audience=mcp), minted via GET `/services/mcp_token?username=admin&expires_on=+90d`; key rotation is POST `…?action=rotate`. `require_encrypted_token=true`. Token + endpoint are in `~/chimera/.env` (gitignored). **Expires ~2026-09-07 (+90d)** — well past submission.
- **Capabilities:** `mcp_tool_execute` + `mcp_tool_admin` already enabled on `role_admin` by the app's default authorize.conf. Splunk token-auth already enabled (`disabled=False`).
- **Verified live:** `initialize` → 200 (serverInfo Splunk_MCP_Server 1.2.0); `tools/list` → 10 tools; `tools/call splunk_get_indexes` → returned real indexes. End-to-end RBAC confirmed.
- **10 tools exposed (real names):** `splunk_get_info`, `splunk_get_indexes`, `splunk_get_index_info`, `splunk_get_user_list`, `splunk_get_user_info`, `splunk_run_query`, `splunk_get_metadata`, `splunk_get_kv_store_collections`, `splunk_get_knowledge_objects`, `splunk_run_saved_search`. **Core read path = `splunk_run_query` + `splunk_get_indexes` + `splunk_run_saved_search`.**
- **AI Assistant for SPL: NOT available** on this Enterprise trial — no `saia_*` tools present (only a disabled `splunk-ai-canvas` app ships). **Decision: skip AI Assistant** per plan ("if not freely available on Enterprise, document and skip"). Write-back SPL generation (P13) and reports (P12/P16) use **Ollama Foundation-Sec-8B** instead — already the primary model path. The "Best Use of Hosted Models" prize rests on Foundation-Sec, not saia_, so no prize impact. Revisit only if a Splunk Cloud trial is later added.

## Carryover from Phase 0 host setup (read before P02–P06)
- **Splunk is already `dpkg`-installed (v10.4.0) but NEVER started** → 60-day trial clock has NOT started; gate G0 intact. P02 skips `dpkg -i` and starts at `splunk start --accept-license` (after G0).
- **Host mgmt IP is `192.168.1.12/24` on Wi-Fi (`wlp0s20f3`)** — workstation, not headless server. Scope Splunk Web firewall to `192.168.1.0/24` (`ufw allow from 192.168.1.0/24 to any port 8000`). P04 DMZ must account for Wi-Fi-only topology (Suricata capture interface).
- **UFW is active, default-deny incoming.** Any new listening port (Splunk 8000/8089/9997, honeypots) needs an explicit, LAN-scoped ufw allow.
- **Splunk Universal Forwarder is NOT staged** — no UF `.deb` on host. P06 must download it.
- **Ollama 0.30.7 installed, no models pulled.** P12 pulls `FenkoHQ/Foundation-Sec-8B`.
- **Docker 29.5.3 + compose v5.1.4**, user `hi` in docker group. **uv 0.11.19** at `~/.local/bin/uv`.
- Full host detail: `~/chimera-host/SETUP_LOG.md`.

## Host-level changes (not in repo — capture for reproducibility / fresh deploy)
- **P02:** `splunk` user added to group `hi`; `/opt/splunk` chowned to splunk:splunk; systemd `Splunkd.service`; UFW `allow from 192.168.1.0/24 to 8000`.
- **P06:** UF installed at `/opt/splunkforwarder` (mgmt :8090), `CAP_DAC_READ_SEARCH`, indexer `enable listen 9997`.
- **P12:** Ollama systemd override `/etc/systemd/system/ollama.service.d/override.conf` → `OLLAMA_HOST=0.0.0.0`; UFW `allow from 172.30.0.0/16 to any port 11434` (lets the chimera_dmz bridge reach Ollama for Galah; UFW still blocks 11434 off-host). Foundation-Sec-8B model pulled (16GB).
- These belong in a future provisioning script / README quickstart (P18). Full host detail in `~/chimera-host/SETUP_LOG.md`.

## Blockers

### BLOCKER-1 (P02) — RESOLVED ✅
Splunk MCP Server app required Splunk.com creds to download (Splunkbase 401 on anonymous). Operator provided Splunk.com credentials → authenticated to Splunkbase API, pulled `Splunk MCP Server` 1.2.0 `.tgz` (staged at `~/chimera-host/installers/`), installed and configured it. No longer blocking.
