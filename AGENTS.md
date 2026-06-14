# CHIMERA — Subagent Registry

The CHIMERA build uses a team of specialized subagents, defined in `.claude/agents/*.md`.
The **lead session** coordinates: it dispatches packets to subagents, reviews their output,
and owns sequential/gating packets. **Code-writing subagents run with `isolation: worktree`**
so parallel work does not collide.

| Agent | Definition | Owns | Used for packets |
|---|---|---|---|
| **infra-builder** | [.claude/agents/infra-builder.md](.claude/agents/infra-builder.md) | `infra/`, `splunk-app/`, `scripts/install_uf.sh` | P03, P04, P06, P10a |
| **orchestrator-builder** | [.claude/agents/orchestrator-builder.md](.claude/agents/orchestrator-builder.md) | `orchestrator/chimera/`, `orchestrator/tests/`, `pyproject.toml` | P05, P09, P10, P11, P12, P13, P14, P16 |
| **dashboard-builder** | [.claude/agents/dashboard-builder.md](.claude/agents/dashboard-builder.md) | `splunk-app/default/data/ui/`, `savedsearches.conf` | P07, P15 |
| **demo-builder** | [.claude/agents/demo-builder.md](.claude/agents/demo-builder.md) | `README.md`, `ARCHITECTURE.md`, `demo/` | P17, P18 |
| **verifier** | [.claude/agents/verifier.md](.claude/agents/verifier.md) | `scripts/smoke_test.sh`, `scripts/seed_attacker.sh`, `scripts/seed_ai_attacker.py`, bug reports | P08, tier-gate verification |

## Dispatch rules
- Within a tier, packets marked `[P]` run in parallel via worktree subagents; `[S]` packets are sequential.
- The lead session owns P01 (scaffold) and P02 (Splunk install / gate G0).
- Subagents update `STATUS.md` when a packet completes, then exit. The lead reviews before marking the packet done.
- The verifier never writes production code — it writes tests + bug reports and files them back to the owning builder.
