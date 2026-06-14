"""Channel 3 of the AI-vs-human classifier: the inverted-PromptArmor tripwire.

This is the most novel signal in CHIMERA, and it inverts the usual defensive
framing. PromptArmor-style defences detect *prompt injection against your own
agent*. Here we run the same idea **offensively against the attacker's agent**:

We deploy a **Beelzebub MCP decoy** that advertises a tool no legitimate user
would ever invoke — e.g. ``user-account-manager``. The tool's name/description
is effectively a planted instruction sitting in the attacker's context. A human
attacker reads it, shrugs, and ignores it (it's obviously not their goal). An
**LLM agent**, dutifully pursuing whatever looks like a useful capability, will
*call the tool* — and that invocation is logged to Splunk as
``sourcetype=beelzebub:json`` in ``idx_honeypot``.

Therefore: **a logged decoy-tool invocation is a strong, near-decisive AI
signal.** No firing -> no evidence (log-LR ≈ 0); we never penalise a session
for *not* tripping the wire (a careful agent or a human both produce nothing).

This module is the *read/scoring* half. It is written to consume
``sourcetype=beelzebub:json`` events that the orchestrator's poll loop fetches;
the actual Beelzebub deployment is packet P10a and may not be live when this is
written, so the channel degrades gracefully to "no tripwire evidence" (0.0)
when no such events are present.

Public API:
  * :func:`tripwire_log_lr_from_events` — score from already-fetched events.
  * :func:`fetch_tripwire_events` — async helper that queries idx_honeypot for
    ``beelzebub:json`` invocations tied to a src_ip/session (used by the loop).
"""

from __future__ import annotations

from typing import Any

import structlog

from .session import merge_raw, src_ip_of

log = structlog.get_logger(__name__)

# A single decoy-tool invocation is strong evidence. We pick a magnitude large
# enough to dominate the combined posterior on its own (well past the AI
# decision threshold) but finite, so it is still a likelihood ratio and not a
# hard override — combination math, not a special case.
SINGLE_FIRE_LLR = 6.0
# Each additional invocation adds a little more certainty, saturating.
PER_EXTRA_FIRE_LLR = 1.0
MAX_LLR = 9.0

# Decoy tool names that should NEVER be invoked by a legitimate user. Tunable;
# matched case-insensitively against the invoked tool name.
DECOY_TOOL_NAMES: tuple[str, ...] = (
    "user-account-manager",
    "user_account_manager",
    "credential-vault",
    "credential_vault",
    "admin-backdoor",
)

# Sourcetype the Beelzebub MCP decoy writes to (idx_honeypot).
BEELZEBUB_SOURCETYPE = "beelzebub:json"


def _is_tool_invocation(event: dict[str, Any]) -> tuple[bool, str | None]:
    """Is this Beelzebub event a decoy *tool invocation*? Returns (fired, tool).

    Beelzebub's MCP protocol logs surface the invoked tool under a handful of
    possible keys depending on version; we check the common ones. A tool name
    matching :data:`DECOY_TOOL_NAMES` is a fire. If the event clearly is an MCP
    ``tools/call`` but the name is unknown, we still treat it as a fire (any
    call into the decoy MCP is suspicious) but record the raw name.
    """
    merged = merge_raw(event)

    def _scalar(v: Any) -> Any:
        if isinstance(v, list):
            return v[0] if v else None
        return v

    # Beelzebub v3 (the deployed decoy, P10a) nests everything under an ``event``
    # object and logs a tool invocation as:
    #   event.Msg     = "New MCP tool invocation"
    #   event.Protocol= "MCP"
    #   event.Command = "tool:user-account-manager|map[action:list user_id:...]"
    # The tool name is embedded in event.Command, not a top-level key. Detect
    # that shape first; fall back to the generic MCP shapes below.
    bz = merged.get("event")
    if isinstance(bz, dict):
        bz_msg = str(bz.get("Msg") or "").strip()
        bz_cmd = str(bz.get("Command") or "").strip()
        bz_proto = str(bz.get("Protocol") or "").strip().upper()
        if bz_cmd.lower().startswith("tool:") or "tool invocation" in bz_msg.lower():
            # Parse "tool:<name>|map[...]" -> "<name>".
            name = bz_cmd.split("|", 1)[0].strip()
            if name.lower().startswith("tool:"):
                name = name[len("tool:"):].strip()
            return True, (name or None)
        # Any MCP-protocol request reaching the decoy at all is suspicious; treat
        # an explicit tool-invocation message as a fire even without a parsed name.
        if bz_proto == "MCP" and "invocation" in bz_msg.lower():
            return True, None

    # Common shapes: {"tool":"..."} / {"tool_name":"..."} /
    # {"method":"tools/call","params":{"name":"..."}} / {"name":"..."}.
    tool = (
        _scalar(merged.get("tool"))
        or _scalar(merged.get("tool_name"))
        or _scalar(merged.get("toolName"))
        or _scalar(merged.get("name"))
    )
    params = merged.get("params")
    if tool is None and isinstance(params, dict):
        tool = params.get("name")
    method = _scalar(merged.get("method")) or _scalar(merged.get("mcp_method"))

    tool_str = str(tool).strip() if tool is not None else None
    method_str = str(method).strip().lower() if method is not None else ""

    if tool_str:
        low = tool_str.lower()
        if low in DECOY_TOOL_NAMES:
            return True, tool_str
        # An explicit MCP tools/call to *any* tool on the decoy is still a fire.
        if "tools/call" in method_str or method_str == "call_tool":
            return True, tool_str
    # A bare tools/call with no parseable name on the decoy still counts.
    if "tools/call" in method_str:
        return True, tool_str
    return False, tool_str


def tripwire_log_lr_from_events(
    events: list[dict[str, Any]],
) -> tuple[float, dict[str, Any]]:
    """Score the tripwire channel from Beelzebub ``beelzebub:json`` events.

    ``events`` should be the decoy-MCP events for this session/src_ip (the
    caller filters by source). Returns ``(log_lr, detail)``: a large positive
    log-LR when one or more decoy-tool invocations fired, 0.0 otherwise.
    Gracefully returns 0.0 on an empty list (P10a not live / no fire).
    """
    fires: list[str | None] = []
    for ev in events:
        fired, tool = _is_tool_invocation(ev)
        if fired:
            fires.append(tool)

    detail: dict[str, Any] = {
        "n_events": len(events),
        "n_fires": len(fires),
        "tools": [t for t in fires if t],
        "fired": bool(fires),
    }
    if not fires:
        detail["reason"] = "no_tripwire_evidence"
        return 0.0, detail

    log_lr = SINGLE_FIRE_LLR + PER_EXTRA_FIRE_LLR * (len(fires) - 1)
    log_lr = min(MAX_LLR, log_lr)
    detail["reason"] = "tripwire_fired"
    return log_lr, detail


async def fetch_tripwire_events(
    client: Any,
    *,
    src_ip: str | None = None,
    session: str | None = None,
    lookback: str = "-1h",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Query idx_honeypot for Beelzebub decoy events tied to a src_ip/session.

    Reads ``sourcetype=beelzebub:json`` and filters to events whose extracted
    or ``_raw``-embedded ``src_ip``/``session`` matches. Returns ``[]`` (and
    logs a debug line) on any query error or when the decoy isn't deployed yet,
    so the tripwire channel degrades gracefully to "no evidence".
    """
    # NOTE: Beelzebub v3 nests the source under ``event.SourceIp`` /
    # ``event.RemoteAddr`` (not a top-level ``src_ip`` field), so an SPL
    # ``src_ip="…"`` clause would never match. Fetch all recent decoy events and
    # post-filter on the nested source in Python.
    spl = (
        f"search index=idx_honeypot sourcetype={BEELZEBUB_SOURCETYPE} "
        f"earliest={lookback} | head {limit}"
    )
    try:
        rows = await client.run_query(spl)
    except Exception as e:  # noqa: BLE001 — graceful degrade, never kill the loop
        log.debug("tripwire_fetch_failed", error=str(e))
        return []

    if session is None and src_ip is None:
        return rows
    # Post-filter by session id (when present) else by source IP. The source for
    # a Beelzebub event lives at event.SourceIp / event.RemoteAddr (host:port).
    out: list[dict[str, Any]] = []
    for r in rows:
        merged = merge_raw(r)
        sid = merged.get("session")
        if isinstance(sid, list):
            sid = sid[0] if sid else None
        sid = str(sid).strip() if sid is not None else ""
        if session is not None and sid:
            if sid == session:
                out.append(r)
            continue
        if src_ip and _beelzebub_src_ip(merged) == src_ip:
            out.append(r)
    return out


def _beelzebub_src_ip(merged: dict[str, Any]) -> str | None:
    """Extract the attacker source IP from a (merged) Beelzebub event.

    Beelzebub v3 records it at ``event.SourceIp``; fall back to the host part of
    ``event.RemoteAddr`` ("ip:port"), then to the generic top-level extractor.
    """
    bz = merged.get("event")
    if isinstance(bz, dict):
        sip = bz.get("SourceIp")
        if sip:
            return str(sip).strip()
        remote = bz.get("RemoteAddr")
        if remote:
            return str(remote).rsplit(":", 1)[0].strip()
    return src_ip_of(merged)
