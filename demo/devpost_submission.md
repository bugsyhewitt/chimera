# CHIMERA — Devpost submission draft

Paste-ready copy for the Devpost form. (Fill the two links once the video is uploaded and the public repo is pushed.)

---

**Project name:** CHIMERA

**Tagline (one line):**
A Splunk-native AI agent that detects intruders with a *provable* error bound, works out whether it's facing a human or an autonomous AI agent, and adapts its honeypot deception to waste each one's time — while keeping the chance of a real breach near zero.

**Tracks claimed:** Grand Prize · Best of Security · Best Use of MCP Server · Best Use of Hosted Models

**Links:**
- Demo video: `<TODO: unlisted YouTube URL>`
- Public repo: `<TODO: github.com/<V3X org>/chimera>`

---

## Inspiration
Security teams are drowning in alerts, and a new attacker just arrived: the autonomous AI agent. Palisade Research's *LLM Agent Honeypot* showed these agents already probe the public internet, and Cisco Talos is tracking the threat. Splunk shipped six SOC agents at RSAC 2026 — all of which **detect and respond**. None of them **deceive**. CHIMERA occupies exactly that empty space.

## What it does
CHIMERA runs a closed deception loop, entirely from Splunk data and wired through the Splunk MCP Server:
**detect → SPRT test → route → classify human-vs-AI → adapt (POMDP) → Foundation-Sec report → write-back.**
- **Provable detection.** A Wald Sequential Probability Ratio Test (α=0.01, β=0.05) declares a source HOSTILE with bounded false-positive/negative rates — a tunable, defensible error rate instead of a black-box score.
- **Human-vs-AI classification** across three channels, the standout being an **inverted-PromptArmor MCP tripwire**: a Beelzebub MCP decoy advertises a tool no human would ever call; an LLM agent calls it and fingerprints itself. (Live: classified AI at p_ai=0.9997.)
- **Adaptive deception** via a POMDP belief controller: sparse breadcrumbs for a suspicious human, aggressive looping bait for an AI agent that will chase a planted goal.
- **A durable artifact.** Foundation-Sec-8B writes the engagement report (real MITRE ATT&CK + MITRE Engage IDs + a recommended SPL detection), which CHIMERA persists as a real Splunk saved search — not just a summary, an action.
- **Impact:** attacker dwell time ≈821s with CHIMERA vs ≈49s for a static honeypot (16.7×), at ~0% penetration probability.

## How we built it
Splunk Enterprise 10.4 + the Splunk MCP Server app (the orchestrator is an MCP client; both the read path and the detection write-back go through MCP/Splunk). Suricata/Zeek sensors and Cowrie/Galah/Beelzebub honeypots run on an isolated Docker network; a Universal Forwarder ships their logs into three indexes. An async Python 3.12 orchestrator runs the math (SPRT, the three-channel classifier, the POMDP controller) and calls a self-hosted Foundation-Sec-8B via Ollama for deceptive content and engagement reports. Two Splunk dashboards surface the live loop and the dwell-time "money chart." 135 orchestrator tests pass.

## Challenges we ran into
- The Splunk MCP server is read-only, so write-back had to go through Splunk's REST receiver and saved-search API rather than MCP.
- In a single-host Docker setup Suricata can't see the intra-bridge honeypot traffic, so the real attack signal lands in the honeypot index — the SPRT and classifier were built to consume that evidence.
- Foundation-Sec-8B is a completion model, not a chat model; the reporter prompt had to be shaped accordingly.

## Accomplishments we're proud of
Operationalizing known-good math (Wald's SPRT, sequential AI/human classification, a POMDP engagement policy) as a single running Splunk-native agent — and inverting a 2026 defense (PromptArmor) into an offensive AI-attacker fingerprint via an MCP decoy.

## What's next
Physically actuating the POMDP breadcrumb policy on the live honeypots (v1 records the chosen action), a Splunk Cloud demo to add the hosted AI Assistant SPL tools, and the V3X commercial detection plugins that snap into the documented open-core backend interface.

## Built with
splunk, splunk-mcp-server, model-context-protocol, python, asyncio, docker, cowrie, galah, beelzebub, suricata, ollama, foundation-sec-8b, mitre-attack, mitre-engage
