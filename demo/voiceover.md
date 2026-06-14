# CHIMERA — voiceover transcript (timed to the 80-second demo video)

Read one line per slide. ~185 words, ~140 wpm — comfortably fits each slide's on-screen time. Adjust freely; you can hold/extend any slide in editing.

| Time | Slide | Narration |
|---|---|---|
| 0:00 | Title | "CHIMERA — a Splunk-native AI agent that detects intruders, tells a human from an autonomous AI, and adapts its deception to waste each one's time." |
| 0:06 | The problem | "Security teams are drowning in alerts — and a new attacker has arrived: autonomous AI agents, already probing the internet. Splunk's six SOC agents detect and respond; none of them deceive. CHIMERA fills that gap." |
| 0:15 | 1 · Pipeline | "Sensors and honeypots feed Splunk, and the orchestrator reads all of it through the Splunk MCP Server." |
| 0:22 | 2 · Attack | "An attacker hits our SSH honeypot — brute-forces in with bait credentials and starts poking around. Every move lands in Splunk." |
| 0:28 | 3 · SPRT | "Detection isn't a black-box score. A Wald sequential test declares the source hostile the moment it's certain — with provable false-positive and false-negative bounds." |
| 0:36 | 4 · Tripwire | "Human, or AI? The decisive signal is a decoy MCP tool no human would ever call. The agent calls it — and fingerprints itself. Confidence: ninety-nine point nine seven percent." |
| 0:44 | 5 · POMDP | "A belief controller adapts the bait — sparse breadcrumbs for a wary human, aggressive ones for an AI agent chasing a planted goal." |
| 0:51 | 6 · Report | "Foundation-Sec — a self-hosted security model — writes the engagement report: real MITRE ATT&CK and Engage techniques, plus a recommended Splunk detection." |
| 1:00 | 7 · Write-back | "Then it closes the loop — writing the session back to Splunk and saving that generated detection as a real saved search. Not a summary, an action." |
| 1:08 | 8 · Impact | "The result: attacker dwell time jumps from forty-nine seconds to over eight hundred — sixteen times longer — while penetration probability stays near zero." |
| 1:17 | Closing | "CHIMERA: provable detection, AI-versus-human classification, and adaptive deception — operationalized as one running, Splunk-native agent." |

## Notes for reading
- Numbers to speak naturally: "Λ" → "the test statistic"; "p_ai = 0.9997" → "ninety-nine point nine seven percent"; "16.7×" → "about sixteen times"; "α / β" → "false-positive and false-negative rates."
- If you want a hard 3-minute cut instead, the longer beat-by-beat script with on-screen directions is in `demo/demo_script.md` — this file is the tighter version matched to the 80s recording.
- Pacing cushion: holding the Title and the Impact slides ~1–2s longer in editing gives the voice room without rushing.
