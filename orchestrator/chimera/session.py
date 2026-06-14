"""Shared helpers for grouping and parsing a single attacker *session*.

The AI-vs-human classifier (P10) operates on a *session* rather than a bare
``src_ip``: a session is one continuous engagement, identified by the Cowrie
``session`` id when present and falling back to ``src_ip`` otherwise.

The Splunk MCP server only auto-extracts a few KV fields (notably ``src_ip``);
the discriminating Cowrie fields (``session``, ``eventid``, ``input``,
``timestamp``) live inside the JSON document in ``_raw``. These helpers reuse
the ``_raw``-merge approach from :mod:`chimera.sprt` so every channel sees the
real fields regardless of how Splunk surfaced them.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


def _scalar(value: Any) -> Any:
    """Coerce a possibly-multivalue Splunk field to a scalar (first element)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def merge_raw(event: dict[str, Any]) -> dict[str, Any]:
    """Return ``event`` with its Cowrie/Beelzebub JSON ``_raw`` merged in.

    Top-level extracted fields win over ``_raw`` on conflict. Non-JSON or
    missing ``_raw`` is a no-op. Mirrors ``sprt._merge_raw_json`` but always
    attempts the merge (we need ``session``/``input``/``timestamp``, which the
    MCP layer never extracts to the top level).
    """
    raw = _scalar(event.get("_raw"))
    if not isinstance(raw, str):
        return event
    raw = raw.strip()
    if not (raw.startswith("{") and raw.endswith("}")):
        return event
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return event
    if not isinstance(parsed, dict):
        return event
    merged = dict(parsed)
    merged.update(event)  # top-level extracted fields win
    return merged


def session_id(event: dict[str, Any], *, fallback_src_ip: bool = True) -> str | None:
    """Session identity: Cowrie ``session`` id, else ``src_ip`` (if allowed)."""
    merged = merge_raw(event)
    sid = _scalar(merged.get("session"))
    if sid is not None and str(sid).strip():
        return str(sid).strip()
    if fallback_src_ip:
        src = _scalar(merged.get("src_ip"))
        if src is not None and str(src).strip():
            return str(src).strip()
    return None


def src_ip_of(event: dict[str, Any]) -> str | None:
    src = _scalar(merge_raw(event).get("src_ip"))
    if src is None:
        return None
    src = str(src).strip()
    return src or None


def command_input(event: dict[str, Any]) -> str | None:
    """The shell command text for a Cowrie ``cowrie.command.input`` event."""
    merged = merge_raw(event)
    val = _scalar(merged.get("input"))
    if val is None:
        return None
    val = str(val).strip()
    return val or None


def eventid_of(event: dict[str, Any]) -> str | None:
    val = _scalar(merge_raw(event).get("eventid"))
    return str(val).strip().lower() if val is not None else None


# Accept a handful of common timestamp formats. Cowrie emits ISO-8601 with a
# trailing ``Z`` in ``timestamp``; Splunk surfaces an epoch ``_time``.
def _parse_iso(value: str) -> float | None:
    s = value.strip()
    if not s:
        return None
    # ``fromisoformat`` in 3.12 handles a trailing 'Z'? No — normalise it.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def event_timestamp(event: dict[str, Any]) -> float | None:
    """Best-effort epoch-seconds timestamp for an event.

    Order of preference: Cowrie ``timestamp`` (ISO-8601 in ``_raw``), then
    Splunk ``_time`` (epoch float or ISO string), then top-level ``ts``.
    """
    merged = merge_raw(event)
    for key in ("timestamp", "_time", "ts"):
        val = _scalar(merged.get(key))
        if val is None:
            continue
        if isinstance(val, (int, float)):
            return float(val)
        s = str(val).strip()
        if not s:
            continue
        # Numeric epoch string?
        try:
            return float(s)
        except ValueError:
            pass
        parsed = _parse_iso(s)
        if parsed is not None:
            return parsed
    return None
