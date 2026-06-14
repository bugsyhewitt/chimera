"""P13: write-back loop closure — session-end detection + finalize path.

This is the Tier-2 payoff: when a honeypot *session* ends, the orchestrator
produces a **durable artifact + an action**, not just a running tally:

  1. an engagement **report** (Foundation-Sec-8B, via :mod:`chimera.reporter`),
  2. a ``type="session_summary"`` event written to ``idx_deception`` (dwell
     time, final AI/human classification, the full report markdown, the
     generated SPL detection), and
  3. a **real Splunk saved search** persisting the generated SPL detection
     (:mod:`chimera.saved_search`) — the MCP-can't-write workaround.

Session-end detection
----------------------
:class:`SessionTracker` watches the event stream the loop already polls and
maintains per-session bookkeeping (first/last event epoch, event count, src_ip,
whether a terminal Cowrie event was seen). A session is **ended** when EITHER:

  * a terminal event is observed (``cowrie.session.closed`` /
    ``cowrie.logout`` eventid), OR
  * no new events have arrived for ``CHIMERA_SESSION_IDLE_SECONDS`` (config,
    default 300; set low for demo/test).

``take_ended_sessions(now)`` returns the sessions that just ended and marks them
finalized so each finalizes exactly **once**.

The finalize itself (:func:`finalize_session`) is slow (real CPU model ~100s) but
must never raise into the poll loop, so every step is guarded and the report is
generated with a fallback if the model call fails.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from .classifier import ClassificationResult, classify_session
from .config import Settings
from .deception_writer import DeceptionWriter
from .reporter import (
    _fallback_spl,
    extract_attack_ids,  # noqa: F401  (re-exported for callers/tests)
    extract_spl,
    fetch_session_events,
    generate_engagement_report,
    summarize_session,
)
from .saved_search import SavedSearchWriter, normalize_spl
from .session import event_timestamp, eventid_of, session_id, src_ip_of

log = structlog.get_logger(__name__)

# Cowrie eventids that mark a session as terminated.
TERMINAL_EVENTIDS = frozenset(
    {"cowrie.session.closed", "cowrie.logout", "cowrie.session.logout"}
)


# ---------------------------------------------------------------------------
# Per-session bookkeeping
# ---------------------------------------------------------------------------
@dataclass
class SessionState:
    session: str
    src_ip: str | None = None
    first_ts: float | None = None
    last_ts: float | None = None
    # Wall-clock time we last *observed* an event for this session — used for the
    # idle-timeout end condition (event timestamps may be historical/replayed).
    last_seen_monotonic: float = field(default_factory=time.monotonic)
    event_count: int = 0
    terminal: bool = False
    finalized: bool = False

    def dwell_seconds(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, round(self.last_ts - self.first_ts, 3))


class SessionTracker:
    """Tracks honeypot sessions and detects when they end."""

    def __init__(self, idle_seconds: float = 300.0) -> None:
        self.idle_seconds = idle_seconds
        self.sessions: dict[str, SessionState] = {}

    def observe(self, event: dict[str, Any], *, now: float | None = None) -> None:
        """Fold one polled event into per-session state.

        ``now`` is a monotonic clock value (injectable for tests); defaults to
        :func:`time.monotonic`.
        """
        sid = session_id(event)
        if not sid:
            return
        mono = time.monotonic() if now is None else now
        st = self.sessions.get(sid)
        if st is None:
            st = SessionState(session=sid)
            self.sessions[sid] = st

        st.event_count += 1
        st.last_seen_monotonic = mono

        ip = src_ip_of(event)
        if ip and not st.src_ip:
            st.src_ip = ip

        ts = event_timestamp(event)
        if ts is not None:
            if st.first_ts is None or ts < st.first_ts:
                st.first_ts = ts
            if st.last_ts is None or ts > st.last_ts:
                st.last_ts = ts

        if eventid_of(event) in TERMINAL_EVENTIDS:
            st.terminal = True

    def ended_sessions(self, *, now: float | None = None) -> list[SessionState]:
        """Sessions that have ended (terminal seen OR idle) and not yet finalized."""
        mono = time.monotonic() if now is None else now
        out: list[SessionState] = []
        for st in self.sessions.values():
            if st.finalized:
                continue
            idle = (mono - st.last_seen_monotonic) >= self.idle_seconds
            if st.terminal or idle:
                out.append(st)
        return out

    def take_ended_sessions(self, *, now: float | None = None) -> list[SessionState]:
        """Like :meth:`ended_sessions` but marks them finalized (dedupe)."""
        ended = self.ended_sessions(now=now)
        for st in ended:
            st.finalized = True
        return ended


# ---------------------------------------------------------------------------
# Finalize path
# ---------------------------------------------------------------------------
async def _classify(
    client: Any, src_ip: str | None, session: str | None
) -> ClassificationResult | None:
    if client is None or not src_ip:
        return None
    try:
        return await classify_session(client, src_ip, session=session)
    except Exception as e:  # noqa: BLE001 — classification must not kill finalize
        log.warning("finalize_classify_failed", session=session, error=str(e))
        return None


async def _build_report(
    client: Any,
    settings: Settings | None,
    session: str | None,
    src_ip: str | None,
) -> tuple[str, str]:
    """Return ``(report_md, generated_spl)``.

    Tries the real Foundation-Sec-8B report; on any failure falls back to a
    derived report + SPL built from the session summary so the artifact is never
    structurally empty. The SPL is always normalized to a usable single-line
    search against the real index (``saved_search.normalize_spl``).
    """
    try:
        report_md = await generate_engagement_report(
            session, src_ip=src_ip, settings=settings, client=client
        )
        # Extract ONLY the SPL search out of the report (not the whole markdown),
        # then normalize it to a usable single-line search. If the model's SPL is
        # missing or unusable, derive a sane detection against the real index.
        raw_spl = extract_spl(report_md)
        generated_spl = normalize_spl(raw_spl) if raw_spl else None
        # A detection is "usable" only if it targets the REAL honeypot index;
        # the model often guesses ``index=main`` or a wrong sourcetype. If so (or
        # extraction failed / fell through to the generic fallback), derive a
        # session-shaped detection from the actual events against idx_honeypot.
        usable = bool(
            generated_spl
            and "idx_honeypot" in generated_spl
            and generated_spl != normalize_spl(None)
        )
        if not usable:
            try:
                events = await fetch_session_events(
                    client, session=session, src_ip=src_ip
                )
                summary = summarize_session(events)
                generated_spl = normalize_spl(_fallback_spl(summary))
            except Exception:  # noqa: BLE001
                generated_spl = generated_spl or normalize_spl(None)
        return report_md, generated_spl
    except Exception as e:  # noqa: BLE001 — never raise into the loop
        log.warning("finalize_report_failed", session=session, error=str(e))

    # Fallback: derive a minimal report + SPL from the raw session events.
    try:
        events = await fetch_session_events(client, session=session, src_ip=src_ip)
        summary = summarize_session(events)
        spl = normalize_spl(_fallback_spl(summary))
        report_md = (
            f"# Adversary Engagement Report (fallback) — session `{session}`\n\n"
            f"- Source IP: `{src_ip}`\n"
            f"- Events analysed: {summary['n_events']}\n\n"
            "_Model report unavailable; derived detection only._\n"
        )
        return report_md, spl
    except Exception as e:  # noqa: BLE001
        log.warning("finalize_fallback_report_failed", session=session, error=str(e))
        return (
            f"# Adversary Engagement Report (fallback) — session `{session}`\n",
            normalize_spl(None),
        )


async def finalize_session(
    state: SessionState,
    *,
    writer: DeceptionWriter,
    saved_search_writer: SavedSearchWriter,
    client: Any | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Run the full finalize path for one ended session.

    report -> session_summary write -> saved-search create. Returns the
    ``session_summary`` event dict that was written (handy for tests/logging).
    Never raises: each external step is independently guarded.
    """
    session = state.session
    src_ip = state.src_ip
    log.info(
        "finalize_start",
        session=session,
        src_ip=src_ip,
        terminal=state.terminal,
        event_count=state.event_count,
    )

    classification = "UNDECIDED"
    result = await _classify(client, src_ip, session)
    if result is not None:
        classification = result.classification.value

    report_md, generated_spl = await _build_report(client, settings, session, src_ip)

    summary_event: dict[str, Any] = {
        "type": "session_summary",
        "src_ip": src_ip,
        "session": session,
        "classification": classification,
        "dwell_seconds": state.dwell_seconds(),
        "event_count": state.event_count,
        "report_md": report_md,
        "generated_spl": generated_spl,
        "ts": int(time.time()),
    }
    await writer.write_decision(summary_event)
    log.info(
        "session_summary_written",
        session=session,
        src_ip=src_ip,
        classification=classification,
        dwell_seconds=summary_event["dwell_seconds"],
        report_chars=len(report_md),
    )

    ss_result = await saved_search_writer.create_detection(
        generated_spl,
        session=session,
        src_ip=src_ip,
        description=(
            f"CHIMERA auto-detection for session {session} "
            f"(src_ip={src_ip}, classification={classification})."
        ),
    )
    log.info(
        "finalize_done",
        session=session,
        saved_search=ss_result.get("name"),
        saved_search_result=ss_result.get("result"),
    )
    summary_event["_saved_search"] = ss_result
    return summary_event
