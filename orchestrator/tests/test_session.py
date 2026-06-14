"""Unit tests for session grouping/parsing helpers (chimera.session)."""

from __future__ import annotations

import json

from chimera.session import (
    command_input,
    event_timestamp,
    eventid_of,
    session_id,
    src_ip_of,
)


def test_session_id_prefers_session_then_src_ip() -> None:
    raw = json.dumps({"eventid": "cowrie.command.input", "session": "abc123", "src_ip": "1.2.3.4"})
    assert session_id({"_raw": raw}) == "abc123"
    # No session -> fall back to src_ip.
    raw2 = json.dumps({"eventid": "cowrie.command.input", "src_ip": "5.6.7.8"})
    assert session_id({"_raw": raw2}) == "5.6.7.8"
    # Fallback disabled -> None.
    assert session_id({"_raw": raw2}, fallback_src_ip=False) is None


def test_command_input_from_raw() -> None:
    raw = json.dumps({"eventid": "cowrie.command.input", "input": "cat /etc/passwd"})
    assert command_input({"_raw": raw}) == "cat /etc/passwd"
    assert command_input({"_raw": json.dumps({"eventid": "cowrie.session.connect"})}) is None


def test_eventid_and_src_ip() -> None:
    raw = json.dumps({"eventid": "Cowrie.Login.Failed", "src_ip": "9.9.9.9"})
    assert eventid_of({"_raw": raw}) == "cowrie.login.failed"
    assert src_ip_of({"_raw": raw}) == "9.9.9.9"


def test_top_level_fields_win_over_raw() -> None:
    raw = json.dumps({"src_ip": "1.1.1.1", "session": "rawsess"})
    ev = {"_raw": raw, "src_ip": "2.2.2.2"}
    assert src_ip_of(ev) == "2.2.2.2"


def test_event_timestamp_iso_and_epoch() -> None:
    iso = json.dumps({"timestamp": "2026-06-09T12:00:00.000000Z"})
    t = event_timestamp({"_raw": iso})
    assert t is not None and t > 0
    # Epoch _time wins when no cowrie timestamp.
    assert event_timestamp({"_time": 1700000000.5}) == 1700000000.5
    # Numeric epoch string.
    assert event_timestamp({"_time": "1700000000"}) == 1700000000.0
    # Nothing parseable.
    assert event_timestamp({"foo": "bar"}) is None


def test_multivalue_fields_coerced() -> None:
    ev = {"_raw": [json.dumps({"eventid": "cowrie.login.failed", "src_ip": "3.3.3.3"})]}
    assert eventid_of(ev) == "cowrie.login.failed"
    assert src_ip_of(ev) == "3.3.3.3"
