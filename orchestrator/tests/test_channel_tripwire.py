"""Unit tests for the inverted-PromptArmor tripwire channel.

Synthetic ``beelzebub:json`` events only. A decoy-tool invocation must produce
a large positive (AI) log-LR; no events / no fire must degrade gracefully to 0.
"""

from __future__ import annotations

import json

import pytest

from chimera.channel_tripwire import (
    SINGLE_FIRE_LLR,
    _is_tool_invocation,
    fetch_tripwire_events,
    tripwire_log_lr_from_events,
)


def _beelz(payload: dict) -> dict:
    return {"_raw": json.dumps(payload), "src_ip": payload.get("src_ip", "10.0.0.9")}


def _beelz_v3(command: str, msg: str = "New MCP tool invocation", source_ip: str = "172.30.0.1") -> dict:
    """A real Beelzebub v3 event shape: discriminating fields nested under event.*"""
    raw = {
        "event": {"Protocol": "MCP", "Command": command, "Msg": msg, "SourceIp": source_ip,
                  "RemoteAddr": f"{source_ip}:40112"},
        "level": "info", "msg": "New Event",
    }
    return {"_raw": json.dumps(raw)}


def test_beelzebub_v3_nested_shape_fires() -> None:
    # The live decoy logs the tool inside event.Command="tool:<name>|map[...]".
    ev = _beelz_v3("tool:user-account-manager|map[action:list user_id:x]")
    fired, tool = _is_tool_invocation(ev)
    assert fired is True
    assert tool == "user-account-manager"
    llr, detail = tripwire_log_lr_from_events([ev])
    assert llr >= SINGLE_FIRE_LLR
    assert detail["fired"] is True


def test_no_events_is_zero() -> None:
    llr, detail = tripwire_log_lr_from_events([])
    assert llr == 0.0
    assert detail["fired"] is False
    assert detail["reason"] == "no_tripwire_evidence"


def test_decoy_tool_invocation_fires_strong_ai() -> None:
    events = [_beelz({"tool": "user-account-manager", "src_ip": "10.0.0.9"})]
    llr, detail = tripwire_log_lr_from_events(events)
    assert llr >= SINGLE_FIRE_LLR
    assert detail["fired"] is True
    assert detail["n_fires"] == 1
    assert "user-account-manager" in detail["tools"]


def test_mcp_tools_call_shape_fires() -> None:
    events = [
        _beelz(
            {
                "method": "tools/call",
                "params": {"name": "credential-vault"},
                "src_ip": "10.0.0.9",
            }
        )
    ]
    llr, detail = tripwire_log_lr_from_events(events)
    assert llr >= SINGLE_FIRE_LLR
    assert detail["fired"] is True


def test_multiple_fires_increase_llr() -> None:
    one = tripwire_log_lr_from_events(
        [_beelz({"tool": "user-account-manager"})]
    )[0]
    three = tripwire_log_lr_from_events(
        [_beelz({"tool": "user-account-manager"}) for _ in range(3)]
    )[0]
    assert three > one


def test_non_invocation_event_does_not_fire() -> None:
    # A Beelzebub connection log with no tool call -> no fire.
    events = [_beelz({"event": "connection", "src_ip": "10.0.0.9"})]
    llr, detail = tripwire_log_lr_from_events(events)
    assert llr == 0.0
    assert detail["fired"] is False


class _FakeClient:
    def __init__(self, rows, *, raise_exc=False):
        self._rows = rows
        self._raise = raise_exc
        self.last_query = None

    async def run_query(self, spl):
        self.last_query = spl
        if self._raise:
            raise RuntimeError("decoy not deployed")
        return self._rows


@pytest.mark.asyncio
async def test_fetch_degrades_gracefully_when_decoy_absent() -> None:
    client = _FakeClient([], raise_exc=True)
    rows = await fetch_tripwire_events(client, src_ip="10.0.0.9")
    assert rows == []


@pytest.mark.asyncio
async def test_fetch_queries_beelzebub_sourcetype() -> None:
    # src_ip is now a Python post-filter, not an SPL clause (Beelzebub nests the
    # source at event.SourceIp, which an SPL src_ip= clause can't match). The SPL
    # only scopes the sourcetype; the matching event is still returned.
    client = _FakeClient([_beelz({"tool": "user-account-manager"})])
    rows = await fetch_tripwire_events(client, src_ip="10.0.0.9")
    assert "sourcetype=beelzebub:json" in client.last_query
    assert 'src_ip="10.0.0.9"' not in client.last_query
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_fetch_filters_by_session() -> None:
    rows = [
        _beelz({"tool": "user-account-manager", "session": "abc", "src_ip": "10.0.0.9"}),
        _beelz({"tool": "user-account-manager", "session": "xyz", "src_ip": "10.0.0.9"}),
    ]
    client = _FakeClient(rows)
    out = await fetch_tripwire_events(client, src_ip="10.0.0.9", session="abc")
    assert len(out) == 1
