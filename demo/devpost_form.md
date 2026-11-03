# CHIMERA — Devpost form answers (paste-ready)

Fill the two blanks: **YouTube URL** and **public repo URL**. Personal/factual fields (country, government status, submitter type) are yours to set — recommendations noted.

---

## General info

**Project name:**
```
CHIMERA
```

**Elevator pitch (tagline):**
```
A Splunk-native AI agent that detects intruders with a provable error bound, tells human attackers from autonomous AI agents, and adapts its honeypot deception to waste each one's time — keeping a real breach near zero.
```

---

## Project Story → About the project (Markdown)

## Inspiration

Security teams are drowning in alerts — and a new kind of attacker just showed up: the **autonomous AI agent**. Palisade Research's *LLM Agent Honeypot* showed these agents already probe the public internet, and Cisco Talos is tracking the threat. Meanwhile Splunk shipped six agentic SOC agents — Detection Builder, Triage, Guided Response, SOP, Malware Reversing, Automation Builder — and every one of them *detects and responds*. **None of them deceive.** That gap is the whole opportunity: an attacker you've *engaged* is an attacker who isn't breaching anything, and an AI attacker in particular can be made to chase a planted goal indefinitely. We set out to build the deception agent Splunk doesn't have.

## What it does

CHIMERA runs one closed loop, entirely from Splunk data, wired through the **Splunk MCP Server**:

**detect → SPRT test → route → classify human-vs-AI → adapt (POMDP) → Foundation-Sec report → write-back.**

- It reads live sensor and honeypot events from Splunk as an **MCP client**.
- It decides *hostile vs. benign* with a **provable false-positive/false-negative bound** (Wald's SPRT), not a black-box score.
- It routes a hostile source into the right honeypot (Cowrie for SSH, Galah for HTTP).
- It works out **human vs. autonomous AI** across three channels — the standout being an **inverted-PromptArmor MCP tripwire**: a Beelzebub MCP decoy advertises a tool no human would ever call; an LLM agent calls it and fingerprints itself. (Live run: classified AI at `p_ai = 0.9997`.)
- It **adapts the deception** with a POMDP belief controller — sparse breadcrumbs for a suspicious human, aggressive looping bait for an AI agent.
- It uses a **self-hosted Foundation-Sec-8B** model to write the adversary engagement report — real MITRE ATT&CK + MITRE Engage technique IDs, IoCs, and a recommended SPL detection — and to generate Galah's deceptive content.
- It **closes the loop**: writing a `session_summary` back to Splunk and persisting the generated detection as a **real Splunk saved search**. The impact, on the dashboard: attacker dwell time of **≈821 s with CHIMERA vs ≈49 s** for a static honeypot (**16.7×**), at **~0% penetration probability**.

## How we built it

A Splunk Enterprise 10.4 instance with the **Splunk MCP Server** app is the reasoning plane. Suricata + Zeek sensors and **Cowrie / Galah / Beelzebub** honeypots run on an isolated Docker network; a **Universal Forwarder** ships their logs into three indexes (`idx_network`, `idx_honeypot`, `idx_deception`). The submission itself is an **async Python 3.12 orchestrator** (managed with `uv`): an MCP client that runs the math and writes decisions back. A custom Splunk app provides the indexes, saved searches, and two dashboards. 135 tests cover the orchestrator, and the whole loop was verified end-to-end against the live instance.

## The math (named methods, not freeform LLM)

The contribution is operationalizing *known-good math* as a running agent. Detection is Wald's Sequential Probability Ratio Test, accumulating a log-likelihood ratio over a stream of events:

$$\Lambda = \sum_i \log \frac{P(e_i \mid \text{hostile})}{P(e_i \mid \text{benign})}$$

with the decision rule \\( \Lambda \ge A = \ln\frac{1-\beta}{\alpha} \Rightarrow \textbf{HOSTILE} \\), \\( \Lambda \le B = \ln\frac{\beta}{1-\alpha} \Rightarrow \textbf{BENIGN} \\). With \\( \alpha=0.01 \\) and \\( \beta=0.05 \\), those error rates are guaranteed *by construction* — the "provable" claim. The human-vs-AI classifier fuses three channel log-LRs into a posterior `p_ai`; the POMDP keeps a belief over `{benign, human, AI}` and a threshold policy picks breadcrumb intensity.

## Challenges we ran into

- **The Splunk MCP server is read-only**, so write-back had to go through Splunk's REST receiver and saved-search API rather than MCP.
- In a single-host Docker setup, **Suricata can't see the intra-bridge honeypot traffic**, so the real attack signal lands in the honeypot index — we built SPRT and the classifier to consume that evidence (and to parse the discriminating fields out of `_raw`, since MCP only auto-extracts a few).
- **Foundation-Sec-8B is a completion model, not a chat model**; the reporter prompt had to be shaped (instruction folded into the prompt, answer primed) to get a full structured report.
- The **Beelzebub MCP decoy nests its fields under an `event` object**, so the tripwire channel had to match that exact shape to fire on real data.

## Accomplishments we're proud of

Operationalizing Wald's SPRT, sequential AI/human classification, and a POMDP engagement policy as a *single running Splunk-native agent* — and **inverting a 2026 defense (PromptArmor) into an offensive AI-attacker fingerprint** via an MCP decoy. The agent produces a durable artifact and an action (a saved Splunk detection), not just a summary.

## What we learned

That the strongest agentic-SOC story isn't "we invented an algorithm in four weeks" — it's "we wired proven statistics end-to-end through Splunk's newest tooling, with a provable error bound under every decision." And that an MCP decoy is a surprisingly clean way to fingerprint an autonomous attacker.

## What's next

Physically actuating the POMDP breadcrumb policy on the live honeypots (v1 records the chosen action), a Splunk Cloud demo to add the hosted AI Assistant SPL tools, and detection plugins that snap into the documented open-core backend interface.

---

**Built with:**
```
python, asyncio, uv, splunk, splunk-enterprise, splunk-mcp-server, model-context-protocol, mcp, docker, docker-compose, suricata, zeek, cowrie, galah, beelzebub, ollama, foundation-sec-8b, mitre-att&ck, mitre-engage, pydantic, scipy, pytest
```

**"Try it out" links:**
- GitHub repo: `<paste public repo URL>`
- Demo video: https://www.youtube.com/watch?v=i3tzNBW3Vyo

---

## Additional info (judges/organizers)

- **Submitter Type:** *Your call.* Submitting as the team → **Organization**; solo → **Individual**.
- **Organization name:** `N/A` (individual submission).
- **Government / state-owned entity:** `No` *(confirm — this is a factual question only you can answer).*
- **Country of Residence:** `<your country>`
- **Canada province:** `N/A` *(unless you reside in Canada).*
- **New or existing prior to May 18, 2026:** **New.** The CHIMERA codebase was created during the submission period (repo initialized June 2026); all source is fresh — no pre-existing/proprietary code (see the open-core notice in the README).
- **If Existing, explain:** `N/A`
- **Which track:** **Security.**
- **URL to your PUBLIC code repository:** `<paste public repo URL>`
- **Did you include an open source license at the top of the repository page (About section)?** **Yes** — MIT `LICENSE` file at root; GitHub auto-detects it and shows "MIT License" in the About sidebar. *(After pushing, glance at the repo's About panel to confirm it shows.)*
- **Did you include an architecture diagram at the root, named architecture_diagram (md|pdf|png)?** **Yes** — `architecture_diagram.png` at the repo root.
- **Repo includes 1) clear README, 2) setup/run instructions, 3) required dependencies, 4) example configs/datasets:** **Yes** — `README.md` Quickstart, `.env.example`, `pyproject.toml` + `uv.lock`, `infra/docker-compose.yml`, and the seed scripts.
