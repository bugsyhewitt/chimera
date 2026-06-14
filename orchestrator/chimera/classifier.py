"""P10: the three-channel AI-vs-human attacker classifier.

A source is classified **only after** SPRT (:mod:`chimera.sprt`) declares it
HOSTILE. We then ask a second question — *is the hostile operator a human or an
LLM agent?* — by fusing three independent channels, each emitting a
log-likelihood ratio ``log P(obs|AI) / P(obs|human)``:

  1. :mod:`chimera.channel_timing` — command-timing (KS vs. a human lognormal
     baseline + interval entropy + speed). A *screen*, small magnitude.
  2. :mod:`chimera.channel_behavioral` — lure-pursuit persistence (does the
     session chase planted credential breadcrumbs?). Medium magnitude.
  3. :mod:`chimera.channel_tripwire` — the inverted-PromptArmor Beelzebub MCP
     decoy. A logged decoy-tool invocation is near-decisive. Large magnitude.

Combination (Bayesian / SPRT-style accumulation)
-------------------------------------------------
The three channels are treated as conditionally independent evidence, so their
log-LRs simply **add** to a combined log-LR ``Λ`` on top of a log-prior::

    Λ = log(prior_ai / prior_human) + L_timing + L_behavioral + L_tripwire

The posterior probability of AI is then the logistic of ``Λ``::

    p_ai = sigmoid(Λ) = 1 / (1 + e^-Λ);   p_human = 1 - p_ai

This is exactly a (one-shot) sequential probability ratio test on the fused
evidence — identical machinery to P09's SPRT, applied to a different question.

Decision thresholds (Wald-style, tunable)
------------------------------------------
We reuse Wald's bounds for target error rates α=β=0.05 on the AI/human call::

    AI_THRESHOLD    = log((1-β)/α) ≈ +2.944  -> declare AI    when Λ >= this
    HUMAN_THRESHOLD = log(β/(1-α)) ≈ -2.944  -> declare HUMAN  when Λ <= this

(With α=β=0.05 the two bounds are symmetric at ±2.944.)

Between the bounds the verdict is UNDECIDED (keep observing). A neutral prior
(prior_ai = 0.5) means Λ starts at 0. The tripwire alone (≈ +6) clears the AI
bound decisively; behavioral lure-pursuit (up to ≈ +2.6) plus the timing screen
can also cross it when they agree; timing alone (clamped to ±1.2) never can.

Public API: :func:`classify` (pure, from already-fetched events) and
:func:`classify_session` (async, fetches the session's events via the MCP
client). Both return a :class:`Classification`.
"""

from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

import structlog

from .channel_behavioral import behavioral_log_lr_from_events
from .channel_timing import timing_log_lr_from_events
from .channel_tripwire import (
    fetch_tripwire_events,
    tripwire_log_lr_from_events,
)
from .session import session_id, src_ip_of

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Error rates and Wald thresholds for the AI/human call (tunable).
# ---------------------------------------------------------------------------
ALPHA = 0.05  # P(declare AI | actually human)
BETA = 0.05  # P(declare HUMAN | actually AI)
AI_THRESHOLD = math.log((1.0 - BETA) / ALPHA)  # ≈ +2.944
HUMAN_THRESHOLD = math.log(BETA / (1.0 - ALPHA))  # ≈ -2.944

# Default prior over {AI, human}. Neutral by default -> log-prior 0.
DEFAULT_PRIOR_AI = 0.5


class Classification(str, Enum):
    AI = "AI"
    HUMAN = "HUMAN"
    UNDECIDED = "UNDECIDED"


def _sigmoid(x: float) -> float:
    # Numerically stable logistic.
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


@dataclass
class ClassificationResult:
    """Outcome of the three-channel classifier for one session."""

    src_ip: str | None
    session: str | None
    classification: Classification
    p_ai: float
    p_human: float
    combined_log_lr: float
    channels: dict[str, float]
    detail: dict[str, Any] = field(default_factory=dict)

    def to_event(self) -> dict[str, Any]:
        """Shape the result as the idx_deception classification event."""
        return {
            "src_ip": self.src_ip,
            "session": self.session,
            "classification": self.classification.value,
            "p_ai": round(self.p_ai, 6),
            "p_human": round(self.p_human, 6),
            "combined_log_lr": round(self.combined_log_lr, 6),
            "channels": {k: round(v, 6) for k, v in self.channels.items()},
            "ts": int(time.time()),
            "type": "classification",
        }

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["classification"] = self.classification.value
        return d


def combine_log_lrs(
    timing: float,
    behavioral: float,
    tripwire: float,
    *,
    prior_ai: float = DEFAULT_PRIOR_AI,
) -> tuple[float, float, Classification]:
    """Fuse three channel log-LRs into ``(combined_log_lr, p_ai, verdict)``.

    Channels are conditionally independent evidence, so their log-LRs add to a
    log-prior. ``p_ai`` is the logistic of the combined log-LR; the verdict is
    the Wald decision against :data:`AI_THRESHOLD` / :data:`HUMAN_THRESHOLD`.
    """
    prior_ai = min(max(prior_ai, 1e-6), 1.0 - 1e-6)
    log_prior = math.log(prior_ai / (1.0 - prior_ai))
    combined = log_prior + timing + behavioral + tripwire
    p_ai = _sigmoid(combined)
    if combined >= AI_THRESHOLD:
        verdict = Classification.AI
    elif combined <= HUMAN_THRESHOLD:
        verdict = Classification.HUMAN
    else:
        verdict = Classification.UNDECIDED
    return combined, p_ai, verdict


def classify(
    events: list[dict[str, Any]],
    *,
    tripwire_events: list[dict[str, Any]] | None = None,
    src_ip: str | None = None,
    session: str | None = None,
    prior_ai: float = DEFAULT_PRIOR_AI,
    lure_patterns: tuple[str, ...] | list[str] | None = None,
) -> ClassificationResult:
    """Classify a session from its (already-fetched) events.

    ``events`` are the session's Cowrie events (idx_honeypot). ``tripwire_events``
    are the Beelzebub ``beelzebub:json`` decoy events for the same session, if
    any (pass ``None``/``[]`` when the decoy isn't deployed — the tripwire
    channel then contributes 0). ``src_ip``/``session`` override the values
    inferred from the events.
    """
    if src_ip is None:
        for e in events:
            src_ip = src_ip_of(e)
            if src_ip:
                break
    if session is None:
        for e in events:
            session = session_id(e)
            if session:
                break

    l_timing, d_timing = timing_log_lr_from_events(events)
    l_behavioral, d_behavioral = behavioral_log_lr_from_events(
        events, patterns=lure_patterns
    )
    l_tripwire, d_tripwire = tripwire_log_lr_from_events(tripwire_events or [])

    combined, p_ai, verdict = combine_log_lrs(
        l_timing, l_behavioral, l_tripwire, prior_ai=prior_ai
    )

    result = ClassificationResult(
        src_ip=src_ip,
        session=session,
        classification=verdict,
        p_ai=p_ai,
        p_human=1.0 - p_ai,
        combined_log_lr=combined,
        channels={
            "timing": l_timing,
            "behavioral": l_behavioral,
            "tripwire": l_tripwire,
        },
        detail={
            "timing": d_timing,
            "behavioral": d_behavioral,
            "tripwire": d_tripwire,
            "n_events": len(events),
            "prior_ai": prior_ai,
            "ai_threshold": AI_THRESHOLD,
            "human_threshold": HUMAN_THRESHOLD,
        },
    )
    log.debug(
        "classification",
        src_ip=src_ip,
        session=session,
        classification=verdict.value,
        p_ai=round(p_ai, 4),
        timing=round(l_timing, 3),
        behavioral=round(l_behavioral, 3),
        tripwire=round(l_tripwire, 3),
    )
    return result


# ---------------------------------------------------------------------------
# Async session-level entry point (used by the loop).
# ---------------------------------------------------------------------------
SESSION_QUERY_TEMPLATE = (
    'search index=idx_honeypot src_ip="{src_ip}" earliest={lookback} '
    "| head {limit}"
)


async def fetch_session_events(
    client: Any,
    src_ip: str,
    *,
    lookback: str = "-1h",
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Fetch a session's Cowrie events from idx_honeypot by src_ip."""
    spl = SESSION_QUERY_TEMPLATE.format(src_ip=src_ip, lookback=lookback, limit=limit)
    try:
        return await client.run_query(spl)
    except Exception as e:  # noqa: BLE001 — keep the loop alive
        log.warning("session_fetch_failed", src_ip=src_ip, error=str(e))
        return []


async def classify_session(
    client: Any,
    src_ip: str,
    *,
    session: str | None = None,
    lookback: str = "-1h",
    limit: int = 200,
    prior_ai: float = DEFAULT_PRIOR_AI,
    lure_patterns: tuple[str, ...] | list[str] | None = None,
) -> ClassificationResult:
    """Fetch a HOSTILE source's events + decoy events and classify it.

    This is the orchestrator entry point: given the MCP read ``client`` and a
    ``src_ip`` that SPRT just declared HOSTILE, pull the session's Cowrie events
    and any Beelzebub tripwire events, then run :func:`classify`. Degrades
    gracefully if the decoy isn't deployed (tripwire channel contributes 0).
    """
    events = await fetch_session_events(
        client, src_ip, lookback=lookback, limit=limit
    )
    tripwire_events = await fetch_tripwire_events(
        client, src_ip=src_ip, session=session, lookback=lookback
    )
    return classify(
        events,
        tripwire_events=tripwire_events,
        src_ip=src_ip,
        session=session,
        prior_ai=prior_ai,
        lure_patterns=lure_patterns,
    )
