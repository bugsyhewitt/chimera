"""CHIMERA orchestrator main loop (Tier-2 SPRT write-back).

Polls ``idx_network`` and ``idx_honeypot`` every 5 seconds for recent events
via the Splunk MCP server, dedupes them, and feeds each honeypot/Suricata event
through Wald's SPRT (:mod:`chimera.sprt`) keyed by ``src_ip``. When a src_ip's
verdict *transitions* to HOSTILE or BENIGN, a real decision is written to
``idx_deception`` via :class:`DeceptionWriter` carrying the verdict, a
confidence mapped from ``Λ`` vs. the thresholds, ``Λ`` itself and the evidence
count.

This REPLACES the Tier-1 ``decision="observed"`` placeholder. So the smoke test
still always sees *something* per src_ip, the first time we encounter a src_ip
we also emit one ``decision="observed"`` accumulating event (confidence from the
running ``Λ``) even before a verdict is reached.

Runs indefinitely; exits cleanly on SIGINT/SIGTERM.

Run with::

    uv run python -m chimera.loop
"""

from __future__ import annotations

import asyncio
import signal
import time
from collections import deque
from typing import Any

import structlog

from .classifier import classify_session
from .config import get_settings
from .deception_writer import DeceptionWriter
from .finalize import SessionTracker, finalize_session
from .mcp_client import SplunkMCPClient
from .pomdp import BeliefController, Observation
from .router import Router
from .saved_search import SavedSearchWriter
from .session import session_id
from .sprt import SPRTClassifier, Verdict

log = structlog.get_logger("chimera.loop")

POLL_INTERVAL_SECONDS = 5.0
# Look back slightly further than the poll interval so events landing between
# polls (and Splunk indexing latency) are not missed.
LOOKBACK_SECONDS = 10
MAX_EVENTS_PER_POLL = 50
# Bounded dedupe memory: remember the last N event keys so we only log new ones.
DEDUPE_WINDOW = 2000
# Bounded dedupe memory for attacker src_ips we've already emitted a decision
# for this run (one decision per src_ip per run).
SRC_IP_WINDOW = 2000

NETWORK_QUERY = (
    f"search index=idx_network earliest=-{LOOKBACK_SECONDS}s "
    f"| head {MAX_EVENTS_PER_POLL}"
)
# Cowrie events carry ``src_ip``; pull recent ones so we can emit a decision per
# distinct source. We over-fetch slightly vs. the network lookback because
# honeypot sessions span multiple sub-events.
HONEYPOT_QUERY = (
    f"search index=idx_honeypot earliest=-{LOOKBACK_SECONDS}s src_ip=* "
    f"| head {MAX_EVENTS_PER_POLL}"
)


def _extract_src_ip(event: dict[str, Any]) -> str | None:
    """Robustly pull a single ``src_ip`` string from an event.

    The MCP layer can surface ``src_ip`` as a multivalue list (Splunk returns
    repeated fields as arrays); take the first element in that case.
    """
    val = event.get("src_ip")
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return None
    val = str(val).strip()
    return val or None


def _event_key(event: dict[str, Any]) -> str:
    """Stable identity for an event for dedupe purposes."""
    cid = event.get("_cid")
    if cid:
        return str(cid)
    return f"{event.get('_time', '')}|{event.get('_raw', '')}"


async def poll_network_once(
    client: SplunkMCPClient,
    sprt: SPRTClassifier,
    writer: DeceptionWriter,
    seen: set[str],
    seen_order: deque[str],
    seen_ips: set[str],
    seen_ip_order: deque[str],
    classified_ips: set[str],
    router: Router,
    controller: BeliefController,
) -> int:
    """Poll ``idx_network`` (Suricata) and drive SPRT. Returns decisions written.

    In the single-host Docker topology this index is typically empty during
    attacks (Suricata can't see Cowrie traffic), but the path is wired so any
    Suricata signal that *does* land contributes to the same per-src_ip SPRT
    state as the honeypot evidence.
    """
    try:
        rows = await client.run_query(NETWORK_QUERY)
    except Exception as e:  # noqa: BLE001 — keep the loop alive on transient errors
        log.warning("network_poll_failed", error=str(e))
        return 0

    written = await process_events(
        rows,
        sprt,
        writer,
        seen,
        seen_order,
        seen_ips,
        seen_ip_order,
        classified_ips,
        router,
        controller,
        source_index="idx_network",
        client=client,
    )
    log.info("network_poll_complete", fetched=len(rows), written=written)
    return written


async def process_events(
    rows: list[dict[str, Any]],
    sprt: SPRTClassifier,
    writer: DeceptionWriter,
    seen: set[str],
    seen_order: deque[str],
    seen_ips: set[str],
    seen_ip_order: deque[str],
    classified_ips: set[str],
    router: Router,
    controller: BeliefController,
    *,
    source_index: str,
    client: SplunkMCPClient | None = None,
    tracker: SessionTracker | None = None,
) -> int:
    """Feed each NEW event through SPRT and write decisions on verdict change.

    Per-event dedupe (so each distinct Cowrie sub-event nudges ``Λ`` exactly
    once across polls). For each src_ip we emit:
      * one ``decision="observed"`` event the first time we ever see it (so the
        smoke test always finds *a* decision per src_ip), and
      * one decision event each time the verdict *transitions* to HOSTILE or
        BENIGN (carrying ``lambda``, ``confidence``, ``evidence_count``,
        ``sprt: true``).

    Returns the number of decision events written.
    """
    written = 0
    for event in rows:
        key = _event_key(event)
        if key in seen:
            continue
        seen.add(key)
        seen_order.append(key)
        if len(seen_order) > DEDUPE_WINDOW:
            seen.discard(seen_order.popleft())

        # P13: fold every new honeypot event into per-session bookkeeping so we
        # can detect session-end (terminal event or idle) and finalize once.
        if tracker is not None:
            tracker.observe(event)

        src_ip = _extract_src_ip(event)
        if not src_ip:
            continue

        # First time we ever see this src_ip: emit an "observed" decision so the
        # smoke test (and dashboards) always get at least one event per src_ip,
        # even before SPRT reaches a verdict.
        if src_ip not in seen_ips:
            seen_ips.add(src_ip)
            seen_ip_order.append(src_ip)
            if len(seen_ip_order) > SRC_IP_WINDOW:
                seen_ips.discard(seen_ip_order.popleft())
            await writer.write_decision(
                {
                    "src_ip": src_ip,
                    "decision": "observed",
                    "confidence": 0.0,
                    "lambda": 0.0,
                    "evidence_count": 0,
                    "sprt": True,
                    "ts": int(time.time()),
                    "source_index": source_index,
                }
            )
            written += 1
            log.info("attacker_seen", src_ip=src_ip, source_index=source_index)

        prev = sprt.verdict(src_ip)
        verdict = sprt.update(src_ip, event)

        # Only write on a *transition* into a terminal verdict (sticky => fires
        # exactly once per src_ip).
        if verdict != prev and verdict in (Verdict.HOSTILE, Verdict.BENIGN):
            state = sprt.get_state(src_ip)
            assert state is not None
            await writer.write_decision(
                {
                    "src_ip": src_ip,
                    "decision": verdict.value,
                    "confidence": round(sprt.confidence(src_ip), 4),
                    "lambda": round(state.log_lambda, 4),
                    "evidence_count": state.evidence_count,
                    "sprt": True,
                    "ts": int(time.time()),
                    "source_index": source_index,
                }
            )
            written += 1
            log.info(
                "sprt_verdict",
                src_ip=src_ip,
                decision=verdict.value,
                lambda_=round(state.log_lambda, 4),
                evidence_count=state.evidence_count,
            )

            # P14: feed the SPRT verdict into the POMDP belief controller. A
            # HOSTILE verdict shifts belief mass off `benign` onto the attacker
            # states; BENIGN reinforces `benign`. On a meaningful belief/action
            # change this writes a `deception_action` event to idx_deception
            # (deduped internally; never raises into the loop).
            await controller.observe_and_write(
                Observation.from_verdict(verdict),
                writer=writer,
                src_ip=src_ip,
                session=session_id(event),
            )

            # P11: once a source is HOSTILE, steer it to a honeypot. In simulate
            # mode (default here) this writes a type="route" event; in enforce
            # mode it would add the src_ip to an nftables set. Dedupes per src_ip
            # internally and never raises into the loop. Uses the SPRT evidence
            # tally to pick Cowrie (SSH) vs Galah (web/scanner).
            if verdict is Verdict.HOSTILE:
                await router.route(src_ip, state.evidence)

            # P10: once a source is HOSTILE, run the three-channel AI/human
            # classifier (once per src_ip). Needs the read client to pull the
            # full session + any Beelzebub tripwire events.
            if (
                verdict is Verdict.HOSTILE
                and client is not None
                and src_ip not in classified_ips
            ):
                classified_ips.add(src_ip)
                written += await classify_and_write(
                    client,
                    writer,
                    src_ip,
                    session_id(event),
                    source_index,
                    controller,
                )

    return written


async def classify_and_write(
    client: SplunkMCPClient,
    writer: DeceptionWriter,
    src_ip: str,
    session: str | None,
    source_index: str,
    controller: BeliefController,
) -> int:
    """Run the three-channel classifier for a HOSTILE ``src_ip`` and write a
    ``type="classification"`` event to ``idx_deception``. Returns 1 if an event
    was written, else 0. Never raises into the poll loop.

    Also feeds the classifier posterior (``p_ai``/``p_human``) into the P14
    POMDP belief controller, which splits the attacker belief mass and may emit
    a ``deception_action`` event (e.g. high ``p_ai`` -> belief b[ai] > 0.7 ->
    action ``aggressive``).
    """
    try:
        result = await classify_session(client, src_ip, session=session)
    except Exception as e:  # noqa: BLE001 — classification must not kill the loop
        log.warning("classify_failed", src_ip=src_ip, error=str(e))
        return 0

    event = result.to_event()
    event["source_index"] = source_index
    await writer.write_decision(event)

    # P14: split attacker belief mass with the classifier posterior.
    await controller.observe_and_write(
        Observation.from_classification(result),
        writer=writer,
        src_ip=src_ip,
        session=session,
    )
    log.info(
        "classification_written",
        src_ip=src_ip,
        session=session,
        classification=result.classification.value,
        p_ai=round(result.p_ai, 4),
        channels={k: round(v, 3) for k, v in result.channels.items()},
    )
    return 1


async def sweep_finalize(
    tracker: SessionTracker,
    writer: DeceptionWriter,
    saved_search_writer: SavedSearchWriter,
    client: SplunkMCPClient,
    settings: Any,
) -> int:
    """P13: finalize any sessions that just ended (terminal event or idle).

    Each ended session is finalized **once** (the tracker marks it taken). The
    finalize path is slow (real model ~100s) but never raises into the loop. We
    fire each finalize as its own task so a slow report doesn't block the poll
    cadence; tasks are tracked on the tracker so they aren't garbage-collected.
    Returns the number of sessions for which finalize was dispatched.
    """
    ended = tracker.take_ended_sessions()
    if not ended:
        return 0

    async def _run_one(state: Any) -> None:
        try:
            await finalize_session(
                state,
                writer=writer,
                saved_search_writer=saved_search_writer,
                client=client,
                settings=settings,
            )
        except Exception as e:  # noqa: BLE001 — finalize must never kill the loop
            log.warning("finalize_failed", session=state.session, error=str(e))

    for state in ended:
        log.info(
            "session_ended",
            session=state.session,
            src_ip=state.src_ip,
            terminal=state.terminal,
            event_count=state.event_count,
        )
        task = asyncio.create_task(_run_one(state))
        _FINALIZE_TASKS.add(task)
        task.add_done_callback(_FINALIZE_TASKS.discard)
    return len(ended)


# Strong refs to in-flight finalize tasks so they aren't GC'd mid-flight.
_FINALIZE_TASKS: set[asyncio.Task[None]] = set()


async def poll_honeypot_once(
    client: SplunkMCPClient,
    sprt: SPRTClassifier,
    writer: DeceptionWriter,
    seen: set[str],
    seen_order: deque[str],
    seen_ips: set[str],
    seen_ip_order: deque[str],
    classified_ips: set[str],
    router: Router,
    controller: BeliefController,
    tracker: SessionTracker | None = None,
) -> int:
    """Poll ``idx_honeypot`` and drive SPRT. Returns decisions written."""
    try:
        rows = await client.run_query(HONEYPOT_QUERY)
    except Exception as e:  # noqa: BLE001 — keep the loop alive on transient errors
        log.warning("honeypot_poll_failed", error=str(e))
        return 0

    written = await process_events(
        rows,
        sprt,
        writer,
        seen,
        seen_order,
        seen_ips,
        seen_ip_order,
        classified_ips,
        router,
        controller,
        source_index="idx_honeypot",
        client=client,
        tracker=tracker,
    )
    log.info("honeypot_poll_complete", fetched=len(rows), written=written)
    return written


async def run(stop: asyncio.Event) -> None:
    settings = get_settings()
    log.info(
        "orchestrator_start",
        endpoint=settings.splunk_mcp_endpoint,
        interval_s=POLL_INTERVAL_SECONDS,
        network_query=NETWORK_QUERY,
        honeypot_query=HONEYPOT_QUERY,
    )

    # Per-index event dedupe (so SPRT sees each sub-event once); src_ip dedupe
    # is shared across indexes because SPRT state is keyed by src_ip.
    net_seen: set[str] = set()
    net_seen_order: deque[str] = deque()
    hp_seen: set[str] = set()
    hp_seen_order: deque[str] = deque()
    seen_ips: set[str] = set()
    seen_ip_order: deque[str] = deque()
    # src_ips for which the AI/human classifier has already run (once each).
    classified_ips: set[str] = set()

    sprt = SPRTClassifier()
    # P13: per-session tracker for session-end detection + write-back closure.
    tracker = SessionTracker(idle_seconds=settings.session_idle_seconds)
    # P14: per src_ip/session POMDP belief controller (adaptive deception).
    controller = BeliefController()

    async with (
        SplunkMCPClient.from_settings(settings) as client,
        DeceptionWriter.from_settings(settings) as writer,
        SavedSearchWriter.from_settings(settings) as saved_search_writer,
    ):
        indexes = await client.list_indexes()
        log.info("indexes_available", indexes=indexes)

        # P11: router steers HOSTILE sources to a honeypot. Mode comes from
        # CHIMERA_ROUTER_MODE (default "simulate" => write a would-route event;
        # never touches host networking on this workstation).
        router = Router.from_settings(writer, settings)
        log.info("router_ready", mode=router.mode)
        log.info("session_tracker_ready", idle_seconds=tracker.idle_seconds)

        while not stop.is_set():
            # idx_network poll is harmless when empty; honeypot drives write-back.
            await poll_network_once(
                client, sprt, writer, net_seen, net_seen_order,
                seen_ips, seen_ip_order, classified_ips, router, controller,
            )
            await poll_honeypot_once(
                client, sprt, writer, hp_seen, hp_seen_order,
                seen_ips, seen_ip_order, classified_ips, router, controller,
                tracker,
            )
            # P13: finalize any sessions that ended (terminal event or idle).
            # Dispatched as background tasks so a slow report (~100s on the real
            # model) doesn't stall the poll cadence.
            await sweep_finalize(
                tracker, writer, saved_search_writer, client, settings
            )
            # Sleep but wake immediately if a stop was requested.
            try:
                await asyncio.wait_for(stop.wait(), timeout=POLL_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                pass

    log.info("orchestrator_stopped")


def main() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ]
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    stop = asyncio.Event()

    def _request_stop() -> None:
        log.info("shutdown_signal_received")
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_stop)
        except NotImplementedError:  # pragma: no cover — non-Unix
            signal.signal(sig, lambda *_: _request_stop())

    try:
        loop.run_until_complete(run(stop))
    finally:
        loop.close()


if __name__ == "__main__":
    main()
