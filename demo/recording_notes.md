# CHIMERA — Demo Recording Notes (OPERATOR task)

A concrete, shot-by-shot guide for recording the 3-minute submission video. This
pairs with [`demo_script.md`](demo_script.md) (the timed VO + screen beats) — read
that for the narration; this file is the **production checklist** (what to have open,
which commands to run live, OBS scenes, upload).

> **This is an operator task.** Recording requires OBS / screen capture / a mic and
> live Splunk + Docker credentials, none of which are available to the build agent.
> Do the recording on the build host, then drop the YouTube link into `README.md`
> where it says `<!-- TODO: video link -->`.

---

## Before you hit record (pre-flight)

Run these once so everything is warm and the demo is fast and deterministic:

```bash
cd /home/hi/chimera

# 0. Secrets present (never on screen). Confirm .env exists and is filled.
test -f .env && echo ".env present"      # do NOT show .env contents on camera

# 1. Honeypot/sensor stack up
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml ps   # all healthy

# 2. Ollama serving Foundation-Sec-8B
curl -s "${OLLAMA_BASE_URL:-http://localhost:11434}/api/tags" | grep -i foundation-sec

# 3. Seed the metrics dashboard so the money chart is populated and legible
#    (clearly-labeled SYNTHETIC cohorts; honest synthetic=true on every event)
python scripts/seed_p15_demo.py

# 4. Splunk Web reachable; log in ahead of time so no password is typed on camera
#    Open: Apps -> CHIMERA -> chimera_overview  AND  chimera_metrics (two tabs)

# 5. For a punchy live loop, set a short idle so sessions finalize on camera:
#    in .env -> CHIMERA_SESSION_IDLE_SECONDS=15   (then restart the loop)
```

Pre-flight checklist:
- [ ] `.env` filled; **never** visible on screen (close editors, clear scrollback).
- [ ] Docker stack healthy (Cowrie 2222, Galah 8080, Beelzebub MCP decoy 8000).
- [ ] Foundation-Sec-8B responds via Ollama.
- [ ] `chimera_metrics` shows the WITH vs WITHOUT bars (run the seeder if empty).
- [ ] Splunk already logged in; both dashboard tabs open.
- [ ] Terminal font large (≥ 18pt), high-contrast theme, window ~120 cols.

## Live commands to run on camera

| Beat | Command | What the viewer should see |
|---|---|---|
| Orchestrator loop | `cd orchestrator && uv run python -m chimera.loop` | structured logs streaming; the `mcp_connected` line |
| **Human** attacker (left) | `bash scripts/seed_attacker.sh` | slow, human-paced: 3 failed logins, then `root/toor` succeeds, `whoami`/`uname -a`/`wget …` with pauses |
| **AI** attacker (right) | `python scripts/seed_ai_attacker.py` | fast, uniform machine cadence ripping through a goal-directed plan, chasing planted lure files |

Tips:
- `seed_attacker.sh` honors `FAST=1` for a quicker take in rehearsal — but record the
  **normal** (slow) human pacing so the timing-channel contrast reads on camera.
- `seed_ai_attacker.py` takes `--host/--port/--user/--password`; defaults
  (`127.0.0.1:2222`, Cowrie creds) are correct for the demo. Don't use `--strict`.
- Run the loop first and let it print `mcp_connected` before launching attackers.

## Dashboard panels to feature

- **`chimera_overview`** — for the live loop: the SPRT verdict / Λ climbing and
  crossing the HOSTILE bound; the route decision; the `deception_action` belief rows
  (subtle for human, aggressive for AI); the Foundation-Sec report; the persisted
  saved search.
- **`chimera_metrics`** — the closer / money chart: **WITH CHIMERA ≈ 821s** towering
  over **WITHOUT (static honeypot) ≈ 49s** (16.7×), and the **penetration-probability
  gauge at ~0%** (green).

## OBS scene suggestions

1. **Scene: Intro/diagram** — full-screen `demo/architecture.svg` (open in a browser);
   use it for the 0:20–0:50 loop walkthrough. Optionally animate stage highlights in post.
2. **Scene: Split terminals** — two terminals side by side. Left labeled **HUMAN**,
   right labeled **AI AGENT** (use an OBS text source for the labels). This is the
   0:50–2:30 core.
3. **Scene: Orchestrator log** — single large terminal running `chimera.loop`; cut to
   it to show SPRT → HOSTILE and the MCP tripwire firing. Add a callout/text source:
   `SPRT → HOSTILE · Λ=5.7 · α=0.01, β=0.05` and `MCP tripwire fired → AI · p_ai=0.9997`.
4. **Scene: Splunk overview** — browser on `chimera_overview`.
5. **Scene: Splunk metrics** — browser on `chimera_metrics` for the closer.
6. **Scene: End card** — `CHIMERA — V3X` / "Open framework; commercial detection
   plugins available separately."

Capture at 1080p, 30fps; record system audio + mic separately if possible. Keep the
total at **3:00**; the VO budget (~430 words) is in `demo_script.md`.

## After recording — upload

- [ ] Trim to ≤ 3:00; verify no secret ever appears on screen (`.env`, tokens,
      passwords, MCP bearer token, Splunk login).
- [ ] Upload to YouTube **as Unlisted** (not Private — judges must be able to view via
      link; not Public unless the team decides).
- [ ] Title: `CHIMERA — Splunk Agentic Ops Hackathon (V3X)`.
- [ ] Paste the link into `README.md` at `<!-- TODO: video link -->` and remove the
      placeholder comment.
- [ ] Sanity-check the link in an incognito window before submitting.
