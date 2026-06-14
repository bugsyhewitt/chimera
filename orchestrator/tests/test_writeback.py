"""Unit tests for the P13 write-back loop closure (session-end + finalize).

Everything external is mocked — no slow model, no live Splunk:
  * the engagement reporter is monkeypatched to return canned markdown;
  * DeceptionWriter is a fake recording written events;
  * SavedSearchWriter is a fake recording create_detection calls;
  * classify_session is monkeypatched.

We assert both session-end triggers (terminal logout event AND idle timeout)
dispatch finalize exactly once, and that the resulting session_summary event
carries every required field (incl. dwell_seconds + report_md + generated_spl),
and that the saved search is created with the generated SPL.
"""

from __future__ import annotations

import json

import pytest

from chimera import finalize as finalize_mod
from chimera.finalize import (
    SessionTracker,
    finalize_session,
)


SESSION = "sess-deadbeef"
SRC_IP = "172.30.0.1"

CANNED_REPORT = (
    "# Adversary Engagement Report — session `sess-deadbeef`\n\n"
    "## Observed TTPs\n- brute force\n\n"
    "## MITRE ATT&CK Technique IDs\n- T1110\n\n"
    "## Recommended Detection Rule (SPL)\n"
    "```spl\n"
    "index=idx_honeypot sourcetype=cowrie:json eventid=\"cowrie.login.success\"\n"
    "| stats count by src_ip session\n"
    "```\n"
)


def _ev(eventid: str, ts: float, *, session: str = SESSION, src_ip: str = SRC_IP) -> dict:
    raw = {"eventid": eventid, "session": session, "src_ip": src_ip, "timestamp": None}
    raw.pop("timestamp")
    return {
        "_raw": json.dumps({"eventid": eventid, "session": session, "src_ip": src_ip}),
        "src_ip": src_ip,
        "_time": ts,
    }


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------
class _FakeWriter:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def write_decision(self, event: dict) -> None:
        self.events.append(event)


class _FakeSavedSearch:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def create_detection(self, spl, *, session=None, src_ip=None, description=None):  # noqa: ANN001
        self.calls.append(
            {"spl": spl, "session": session, "src_ip": src_ip, "description": description}
        )
        return {"name": f"chimera_detection_{session or src_ip}", "result": "created", "status": 201}


class _FakeClassResult:
    def __init__(self, value: str = "HUMAN") -> None:
        class _C:
            pass

        self.classification = _C()
        self.classification.value = value


@pytest.fixture(autouse=True)
def _patch_externals(monkeypatch):
    async def fake_report(session, *, src_ip=None, settings=None, client=None, **kw):
        return CANNED_REPORT

    async def fake_classify(client, src_ip, *, session=None, **kw):
        return _FakeClassResult("AI")

    monkeypatch.setattr(finalize_mod, "generate_engagement_report", fake_report)
    monkeypatch.setattr(finalize_mod, "classify_session", fake_classify)
    yield


# ---------------------------------------------------------------------------
# SessionTracker: end conditions
# ---------------------------------------------------------------------------
def test_tracker_records_first_last_and_count() -> None:
    t = SessionTracker(idle_seconds=300)
    t.observe(_ev("cowrie.session.connect", 1000.0), now=0.0)
    t.observe(_ev("cowrie.command.input", 1005.0), now=1.0)
    st = t.sessions[SESSION]
    assert st.event_count == 2
    assert st.first_ts == 1000.0
    assert st.last_ts == 1005.0
    assert st.src_ip == SRC_IP
    assert st.dwell_seconds() == pytest.approx(5.0)


def test_tracker_ends_on_terminal_event() -> None:
    t = SessionTracker(idle_seconds=99999)  # idle never fires
    t.observe(_ev("cowrie.session.connect", 1000.0), now=0.0)
    assert t.ended_sessions(now=0.0) == []  # not ended yet
    t.observe(_ev("cowrie.session.closed", 1010.0), now=1.0)
    ended = t.ended_sessions(now=1.0)
    assert len(ended) == 1
    assert ended[0].terminal is True
    assert ended[0].session == SESSION


def test_tracker_ends_on_idle() -> None:
    t = SessionTracker(idle_seconds=10)
    t.observe(_ev("cowrie.command.input", 1000.0), now=100.0)
    assert t.ended_sessions(now=105.0) == []  # only 5s idle
    ended = t.ended_sessions(now=111.0)  # 11s idle >= 10
    assert len(ended) == 1
    assert ended[0].terminal is False


def test_take_ended_sessions_dedupes() -> None:
    t = SessionTracker(idle_seconds=10)
    t.observe(_ev("cowrie.session.closed", 1000.0), now=0.0)
    first = t.take_ended_sessions(now=0.0)
    assert len(first) == 1
    # Second sweep: already finalized, returns nothing.
    assert t.take_ended_sessions(now=0.0) == []
    assert t.take_ended_sessions(now=99999.0) == []


# ---------------------------------------------------------------------------
# finalize_session: produces the session_summary + saved search
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_finalize_writes_session_summary_with_all_fields() -> None:
    t = SessionTracker(idle_seconds=10)
    t.observe(_ev("cowrie.session.connect", 1000.0), now=0.0)
    t.observe(_ev("cowrie.command.input", 1004.0), now=1.0)
    t.observe(_ev("cowrie.session.closed", 1010.0), now=2.0)
    state = t.take_ended_sessions(now=2.0)[0]

    writer = _FakeWriter()
    ss = _FakeSavedSearch()
    summary = await finalize_session(
        state, writer=writer, saved_search_writer=ss, client=object(), settings=None
    )

    # session_summary event written with all required fields.
    assert len(writer.events) == 1
    ev = writer.events[0]
    assert ev["type"] == "session_summary"
    assert ev["src_ip"] == SRC_IP
    assert ev["session"] == SESSION
    assert ev["classification"] == "AI"
    assert ev["dwell_seconds"] == pytest.approx(10.0)
    assert ev["event_count"] == 3
    assert ev["report_md"] == CANNED_REPORT
    assert "index=idx_honeypot" in ev["generated_spl"]
    assert "\n" not in ev["generated_spl"]  # one-lined for the saved search
    assert isinstance(ev["ts"], int)

    # saved search created with the generated SPL.
    assert len(ss.calls) == 1
    assert ss.calls[0]["session"] == SESSION
    assert "index=idx_honeypot" in ss.calls[0]["spl"]

    # returned summary mirrors the written event.
    assert summary["session"] == SESSION


@pytest.mark.asyncio
async def test_finalize_falls_back_when_report_raises(monkeypatch) -> None:
    async def boom(*a, **k):
        raise RuntimeError("ollama down")

    async def fake_fetch(client, *, session=None, src_ip=None, **kw):
        return [_ev("cowrie.command.input", 1000.0)]

    monkeypatch.setattr(finalize_mod, "generate_engagement_report", boom)
    monkeypatch.setattr(finalize_mod, "fetch_session_events", fake_fetch)

    t = SessionTracker(idle_seconds=1)
    t.observe(_ev("cowrie.command.input", 1000.0), now=0.0)
    state = t.take_ended_sessions(now=999.0)[0]

    writer = _FakeWriter()
    ss = _FakeSavedSearch()
    await finalize_session(
        state, writer=writer, saved_search_writer=ss, client=object(), settings=None
    )
    ev = writer.events[0]
    # Fallback report + a usable real-index SPL still produced.
    assert "fallback" in ev["report_md"].lower()
    assert "index=idx_honeypot" in ev["generated_spl"]
    assert len(ss.calls) == 1


@pytest.mark.asyncio
async def test_finalize_never_raises_even_if_classify_fails(monkeypatch) -> None:
    async def boom_classify(*a, **k):
        raise RuntimeError("classify exploded")

    monkeypatch.setattr(finalize_mod, "classify_session", boom_classify)

    t = SessionTracker(idle_seconds=1)
    t.observe(_ev("cowrie.session.closed", 1000.0), now=0.0)
    state = t.take_ended_sessions(now=0.0)[0]

    writer = _FakeWriter()
    ss = _FakeSavedSearch()
    summary = await finalize_session(
        state, writer=writer, saved_search_writer=ss, client=object(), settings=None
    )
    # classification degrades to UNDECIDED, finalize still completes.
    assert summary["classification"] == "UNDECIDED"
    assert len(writer.events) == 1
    assert len(ss.calls) == 1
