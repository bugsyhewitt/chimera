# CHIMERA — 3-Minute Demo Video Script

**Submission:** Splunk Agentic Ops Hackathon, Security track
**Runtime target:** 3:00. Spoken word count ≈ 430 (see footer).
**Format:** Each beat lists **[SCREEN]** (what the viewer sees) and **[VO]** (spoken narration). Read the VO aloud at a natural pace; the time budget assumes ~150 wpm.

---

## 0:00–0:20 — The problem (≈ 50 words)

**[SCREEN]** Open on a noisy SOC: a wall of Splunk alerts scrolling, an analyst rubbing their eyes. Lower-third citations fade in: *"Palisade Research — LLM Agent Honeypot"* and *"Cisco Talos — AI threat reporting."*

**[VO]**
"Security teams are drowning in alerts. And a new attacker just showed up: the autonomous AI agent. Palisade's LLM Agent Honeypot proved they're already probing the internet; Cisco Talos is tracking the threat. They never tire, never get suspicious. CHIMERA builds on that prior art — and turns it on the attacker."

---

## 0:20–0:50 — CHIMERA in 30 seconds (≈ 70 words)

**[SCREEN]** Cut to the architecture diagram (`architecture.svg`). Animate the loop lighting up stage by stage: **detect → test → route → classify → adapt → report**. Highlight the Splunk MCP Server in the core as the spine.

**[VO]**
"This is CHIMERA — a Splunk-native AI agent wired through the Splunk MCP Server. Splunk shipped six SOC agents; they detect and respond. None of them *deceive*. That's the empty space CHIMERA fills. It detects an intruder with a provable error bound, routes them into a honeypot, works out whether it's facing a human or an AI agent, and adapts its deception to waste each one's time — while keeping a real breach near zero."

---

## 0:50–2:30 — Live demo: human vs AI, same honeypot (≈ 230 words)

**[SCREEN]** Split screen. Two terminals side by side over the Cowrie SSH honeypot. **Left = HUMAN**, **right = AI agent**.

**[VO]**
"Let's run two attackers against the *same* honeypot. On the left, a human."

**[SCREEN — left]** Run `scripts/seed_attacker.sh`. Slow, human-paced: three failed logins, then `root/toor` succeeds, then `whoami`, `uname -a`, `wget…` with pauses between.

**[VO]**
"On the right, an autonomous agent."

**[SCREEN — right]** Run `scripts/seed_ai_attacker.py`. Fast, uniform machine cadence ripping through a goal-directed plan — `cat /etc/passwd`, grep for passwords, chasing planted credential files.

**[SCREEN]** Cut to the orchestrator log. SPRT log-likelihood climbs and crosses the HOSTILE threshold. Callout: **"SPRT → HOSTILE · Λ=5.7 · α=0.01, β=0.05 · provable error bounds."**

**[VO]**
"First, the sequential probability ratio test. Each event moves a log-likelihood ratio; when it crosses the Wald bound, CHIMERA declares HOSTILE — with a provable false-positive and false-negative rate. No black-box score. Both sources route to Cowrie."

**[SCREEN]** Zoom the AI side: a Beelzebub MCP decoy advertises a tool — `user-account-manager`. The agent *calls it*. Tripwire fires. Callout: **"MCP tripwire fired → classified AI · p_ai = 0.9997."** The human side never touches it.

**[VO]**
"But routing isn't enough — we need to know *who* we're holding. Now the classifier. Three channels — timing, lure-pursuit, and the standout: an inverted-PromptArmor MCP tripwire. PromptArmor was built to defend agents against prompt injection; we run it backwards as a sensor. Our Beelzebub decoy exposes a tool no human would ever call. The AI agent calls it and fingerprints itself — classified AI at p-point-nine-nine-nine-seven. The human is judged human."

**[SCREEN]** POMDP belief panel updates: AI session → belief over AI crosses 0.7 → **action = aggressive** (looping breadcrumbs). Human session → **action = subtle**.

**[VO]**
"A POMDP belief controller adapts the deception: aggressive, looping breadcrumbs for the AI agent that'll chase a planted goal — sparse and subtle for the human, who'd get suspicious."

**[SCREEN]** Foundation-Sec-8B report renders: observed TTPs, real MITRE ATT&CK IDs, MITRE Engage IDs, and a recommended SPL detection. Then the orchestrator writes a `session_summary` to `idx_deception` and persists the detection as a real Splunk saved search. Cut to the `chimera_overview` dashboard.

**[VO]**
"On session end, Foundation-Sec-8B writes the engagement report — ATT&CK, MITRE Engage, and a detection in SPL — which CHIMERA persists as a real Splunk saved search. It doesn't just summarize; it leaves a durable artifact and an action."

---

## 2:30–3:00 — The impact chart (≈ 80 words)

**[SCREEN]** Cut to `chimera_metrics` — the money chart. Two bars: **WITH CHIMERA ≈ 821s** towering over **WITHOUT (static honeypot) ≈ 49s**. Beside it the penetration-probability gauge sits at **~0%**, green.

**[VO]**
"Here's the payoff. Attacker dwell time with CHIMERA: about 821 seconds, versus 49 for a static honeypot — sixteen-point-seven times longer engagement — while penetration probability stays near zero. That single chart maps to all four prize tracks: a novel deception wedge with provable-error math, blue-team deception mapped to MITRE Engage, an MCP-client orchestrator whose tripwire is itself an MCP decoy, and a hosted model doing real analyst work. CHIMERA. Detect, deceive, adapt."

**[SCREEN]** End card: **CHIMERA.** Sub-line: *"Open framework; detection plugins integrate via the backend interface."*

---

### Section / time / word budget

| Section | Time | Spoken words |
|---|---|---|
| The problem | 0:00–0:20 | ≈ 50 |
| CHIMERA in 30s | 0:20–0:50 | ≈ 70 |
| Live demo | 0:50–2:30 | ≈ 230 |
| Impact chart | 2:30–3:00 | ≈ 80 |
| **Total** | **3:00** | **≈ 430** |

At ~150 words/minute, ≈ 430 spoken words fits a 3-minute runtime with room for the on-screen action to breathe.
