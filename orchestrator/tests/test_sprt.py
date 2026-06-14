"""Unit tests for the SPRT hostile/benign classifier (chimera.sprt).

No live Splunk is needed: synthetic Cowrie/Suricata-shaped events are fed
through :class:`SPRTClassifier`. Covers threshold math, the hostile-trending
smoke-test sequence reaching HOSTILE, a benign/insufficient sequence staying
UNDECIDED/BENIGN, verdict stickiness, and the event->evidence mapping.
"""

from __future__ import annotations

import math

from chimera.sprt import (
    A_THRESHOLD,
    ALPHA,
    B_THRESHOLD,
    BETA,
    LIKELIHOOD_TABLE,
    SPRTClassifier,
    Verdict,
    classify_event,
    event_log_lr,
)

ATTACKER_IP = "172.30.0.1"


# --------------------------------------------------------------------------
# Threshold math
# --------------------------------------------------------------------------
def test_thresholds_match_wald_formulas() -> None:
    assert A_THRESHOLD == math.log((1.0 - BETA) / ALPHA)
    assert B_THRESHOLD == math.log(BETA / (1.0 - ALPHA))
    # Sanity: A is the positive (HOSTILE) bound, B the negative (BENIGN) bound.
    assert A_THRESHOLD > 0 > B_THRESHOLD
    assert abs(A_THRESHOLD - 4.5539) < 1e-3
    assert abs(B_THRESHOLD - (-2.9857)) < 1e-3


# --------------------------------------------------------------------------
# Event -> evidence-type classification
# --------------------------------------------------------------------------
def test_classify_cowrie_eventids() -> None:
    assert classify_event({"eventid": "cowrie.login.failed"}) == "cowrie.login.failed"
    assert classify_event({"eventid": "cowrie.login.success"}) == "cowrie.login.success"
    assert classify_event({"eventid": "cowrie.command.input"}) == "cowrie.command.input"
    assert classify_event({"eventid": "cowrie.session.connect"}) == "cowrie.session.connect"
    # file_download family folds onto the download key.
    assert (
        classify_event({"eventid": "cowrie.session.file_download"})
        == "cowrie.session.file_download"
    )
    # Unknown cowrie.* still gets the faint "unknown" weight.
    assert classify_event({"eventid": "cowrie.log.closed.weird"}) == "unknown"


def test_classify_handles_multivalue_field() -> None:
    # Splunk can surface a repeated KV as a single-element list.
    assert classify_event({"eventid": ["cowrie.login.failed"]}) == "cowrie.login.failed"


def test_classify_suricata_events() -> None:
    assert (
        classify_event({"event_type": "alert", "signature": "ET SCAN Nmap port scan"})
        == "port_scan_signature"
    )
    assert (
        classify_event({"event_type": "alert", "signature": "SSH brute force attempt"})
        == "auth_failure_burst"
    )
    assert (
        classify_event({"event_type": "http", "http_user_agent": "Mozilla/5.0"})
        == "normal_http"
    )
    assert (
        classify_event({"event_type": "http", "http_user_agent": "sqlmap/1.5"})
        == "anomalous_user_agent"
    )


def test_classify_unknown_event() -> None:
    assert classify_event({"foo": "bar"}) == "unknown"


def test_classify_from_raw_json() -> None:
    # The Splunk MCP server only auto-extracts src_ip; the eventid lives inside
    # the Cowrie JSON in _raw. classify_event must parse it.
    raw = '{"eventid":"cowrie.login.failed","username":"root","password":"root"}'
    assert classify_event({"src_ip": "172.30.0.1", "_raw": raw}) == "cowrie.login.failed"
    # Suricata-shaped _raw too.
    raw2 = '{"event_type":"alert","signature":"ET SCAN Nmap"}'
    assert classify_event({"_raw": raw2}) == "port_scan_signature"
    # Top-level field wins over _raw if both present.
    assert (
        classify_event(
            {"eventid": "cowrie.login.success", "_raw": '{"eventid":"cowrie.login.failed"}'}
        )
        == "cowrie.login.success"
    )
    # Non-JSON _raw is a harmless no-op -> unknown.
    assert classify_event({"_raw": "not json at all"}) == "unknown"


def test_smoke_attacker_via_raw_reaches_hostile() -> None:
    # Same attacker but evidence delivered only via _raw (as live Splunk does).
    sprt = SPRTClassifier()
    raws = [
        '{"eventid":"cowrie.session.connect"}',
        '{"eventid":"cowrie.login.failed"}',
        '{"eventid":"cowrie.login.failed"}',
        '{"eventid":"cowrie.login.failed"}',
        '{"eventid":"cowrie.login.success"}',
        '{"eventid":"cowrie.command.input"}',
    ]
    final = Verdict.UNDECIDED
    for r in raws:
        final = sprt.update(ATTACKER_IP, {"src_ip": ATTACKER_IP, "_raw": r})
    assert final is Verdict.HOSTILE


def test_event_log_lr_matches_table() -> None:
    for key, val in LIKELIHOOD_TABLE.items():
        if key == "unknown":
            continue
        # Build a minimal event that classifies to this key where feasible.
    assert event_log_lr({"eventid": "cowrie.login.failed"}) == LIKELIHOOD_TABLE[
        "cowrie.login.failed"
    ]
    assert event_log_lr({"nope": 1}) == LIKELIHOOD_TABLE["unknown"]


# --------------------------------------------------------------------------
# Hostile-trending sequence reaches HOSTILE (the smoke-test attacker)
# --------------------------------------------------------------------------
def _smoke_attacker_events() -> list[dict]:
    """Mirror scripts/seed_attacker.sh: connect, 3 failed, 1 success, 3 cmds, wget."""
    return [
        {"eventid": "cowrie.session.connect", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.login.failed", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.login.failed", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.login.failed", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.login.success", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.command.input", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.command.input", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.session.file_download", "src_ip": ATTACKER_IP},
        {"eventid": "cowrie.command.input", "src_ip": ATTACKER_IP},
    ]


def test_smoke_attacker_reaches_hostile() -> None:
    sprt = SPRTClassifier()
    final = Verdict.UNDECIDED
    for ev in _smoke_attacker_events():
        final = sprt.update(ATTACKER_IP, ev)
    assert final is Verdict.HOSTILE
    state = sprt.get_state(ATTACKER_IP)
    assert state is not None
    assert state.log_lambda >= A_THRESHOLD
    assert sprt.confidence(ATTACKER_IP) == 1.0


def test_brute_force_alone_reaches_hostile() -> None:
    # 3 failed (4.5) + 1 success (2.0) = 6.5 >= A even without any commands.
    sprt = SPRTClassifier()
    seq = [
        {"eventid": "cowrie.login.failed"},
        {"eventid": "cowrie.login.failed"},
        {"eventid": "cowrie.login.failed"},
        {"eventid": "cowrie.login.success"},
    ]
    final = Verdict.UNDECIDED
    for ev in seq:
        final = sprt.update(ATTACKER_IP, ev)
    assert final is Verdict.HOSTILE


# --------------------------------------------------------------------------
# Benign / insufficient evidence
# --------------------------------------------------------------------------
def test_single_connect_stays_undecided() -> None:
    sprt = SPRTClassifier()
    v = sprt.update("10.0.0.5", {"eventid": "cowrie.session.connect"})
    assert v is Verdict.UNDECIDED
    assert sprt.log_lambda("10.0.0.5") == LIKELIHOOD_TABLE["cowrie.session.connect"]
    assert not sprt.is_decided("10.0.0.5")


def test_normal_http_trends_benign() -> None:
    # Repeated normal HTTP (negative log-LR) eventually crosses B -> BENIGN.
    sprt = SPRTClassifier()
    final = Verdict.UNDECIDED
    for _ in range(8):
        final = sprt.update("198.51.100.7", {"event_type": "http", "http_user_agent": "Mozilla/5.0"})
    assert final is Verdict.BENIGN
    assert sprt.log_lambda("198.51.100.7") <= B_THRESHOLD


def test_unseen_ip_is_undecided() -> None:
    sprt = SPRTClassifier()
    assert sprt.verdict("203.0.113.99") is Verdict.UNDECIDED
    assert sprt.confidence("203.0.113.99") == 0.0
    assert sprt.get_state("203.0.113.99") is None


# --------------------------------------------------------------------------
# Sticky verdict
# --------------------------------------------------------------------------
def test_verdict_is_sticky() -> None:
    sprt = SPRTClassifier()
    for ev in _smoke_attacker_events():
        sprt.update(ATTACKER_IP, ev)
    assert sprt.verdict(ATTACKER_IP) is Verdict.HOSTILE
    frozen_lambda = sprt.log_lambda(ATTACKER_IP)

    # Feed strongly-benign events; verdict and Λ must not change.
    for _ in range(20):
        v = sprt.update(ATTACKER_IP, {"event_type": "http", "http_user_agent": "Mozilla/5.0"})
        assert v is Verdict.HOSTILE
    assert sprt.log_lambda(ATTACKER_IP) == frozen_lambda
    # Evidence tally still increments for observability.
    assert sprt.get_state(ATTACKER_IP).evidence_count == len(_smoke_attacker_events()) + 20


# --------------------------------------------------------------------------
# Per-src_ip isolation + observability
# --------------------------------------------------------------------------
def test_states_are_isolated_per_src_ip() -> None:
    sprt = SPRTClassifier()
    sprt.update("1.1.1.1", {"eventid": "cowrie.login.failed"})
    sprt.update("2.2.2.2", {"eventid": "cowrie.session.connect"})
    assert sprt.log_lambda("1.1.1.1") == LIKELIHOOD_TABLE["cowrie.login.failed"]
    assert sprt.log_lambda("2.2.2.2") == LIKELIHOOD_TABLE["cowrie.session.connect"]
    assert set(sprt.known_src_ips()) == {"1.1.1.1", "2.2.2.2"}


def test_confidence_monotonic_toward_hostile() -> None:
    sprt = SPRTClassifier()
    last = -1.0
    for ev in _smoke_attacker_events():
        sprt.update(ATTACKER_IP, ev)
        c = sprt.confidence(ATTACKER_IP)
        assert c >= last - 1e-9  # non-decreasing as hostile evidence accrues
        last = c
    assert sprt.confidence(ATTACKER_IP) == 1.0
