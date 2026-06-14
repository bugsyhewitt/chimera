"""Channel 1 of the AI-vs-human classifier: command-timing analysis.

Given the Cowrie events of a single attacker *session* we look at the
inter-arrival intervals between successive command/events and ask: do they look
like a human at a keyboard, or an automated agent?

Discriminating physics
- A *human* types and reads. Inter-command gaps follow a heavy-tailed, highly
  variable distribution centred on a couple of seconds (think, read output,
  type the next command). We model this as a lognormal baseline with median
  ``exp(mu)`` ≈ 2 s and shape ``sigma`` ≈ 1.5 (so the distribution spans
  sub-second to tens of seconds). High Shannon entropy.
- An *LLM agent / bot* emits commands as fast as the network and its own
  decode loop allow: tightly clustered, often sub-second, periodic intervals.
  Low variance, low entropy.

Two statistics, combined into one modest log-LR:
  * **KS test** of the observed intervals against the human lognormal baseline.
    A small p-value (intervals are *unlikely* to be human) pushes toward AI.
  * **Shannon entropy** of the (binned) interval distribution. Low entropy
    (very regular timing) pushes toward AI; high entropy pushes toward human.
  * A **speed** term: a median interval well under a second is itself bot-like.

This channel is deliberately a *screen, never a verdict*: its output is clamped
to a small magnitude (``MAX_ABS_LLR``) so it can nudge the combined posterior
but never decide a case on its own (a fast human on a good link, or a slow bot,
must not be condemned by timing alone). The strong signal lives in the
behavioral and tripwire channels.

Public API: :func:`timing_log_lr` (pure, takes a list of epoch timestamps) and
:func:`timing_log_lr_from_events` (takes raw Splunk/Cowrie event dicts).
"""

from __future__ import annotations

import math
from typing import Any

import numpy as np
from scipy import stats

from .session import event_timestamp

# ---------------------------------------------------------------------------
# Human baseline (lognormal) — tunable.
# ---------------------------------------------------------------------------
# median inter-command gap ≈ exp(HUMAN_MU) ≈ 2.0 s; HUMAN_SIGMA controls spread.
HUMAN_MU = math.log(2.0)  # ≈ 0.693 -> median 2 s
HUMAN_SIGMA = 1.5

# A median interval at/below this many seconds is itself a bot tell.
FAST_MEDIAN_THRESHOLD_S = 1.0

# Entropy (in bits) at/above this looks human-variable; at/below LOW looks
# bot-regular. Computed over a fixed number of log-spaced histogram bins.
ENTROPY_BINS = 8
HIGH_ENTROPY_BITS = 2.0
LOW_ENTROPY_BITS = 1.0

# Per-term weights (kept small) and the overall clamp. Sum of the three term
# maxima is ~1.5; the clamp keeps |output| <= 1.2 so timing is always a screen.
W_KS = 0.6
W_ENTROPY = 0.5
W_SPEED = 0.5
MAX_ABS_LLR = 1.2

# Need at least this many intervals (== events-1) to say anything.
MIN_INTERVALS = 3


def inter_arrival_intervals(timestamps: list[float]) -> list[float]:
    """Sorted positive inter-arrival gaps (seconds) between successive events."""
    ts = sorted(t for t in timestamps if t is not None)
    intervals = [b - a for a, b in zip(ts, ts[1:]) if (b - a) > 0]
    return intervals


def interval_entropy_bits(intervals: list[float]) -> float:
    """Shannon entropy (bits) of the interval distribution over log-spaced bins.

    Log-spaced bins because human gaps span orders of magnitude; a regular bot
    piles all mass into one or two bins (low entropy), a human spreads out
    (high entropy). Returns 0.0 for degenerate input.
    """
    if len(intervals) < 2:
        return 0.0
    arr = np.asarray(intervals, dtype=float)
    lo, hi = arr.min(), arr.max()
    if hi <= lo:
        return 0.0
    # Work in log space so the bins are even across magnitudes.
    edges = np.logspace(math.log10(lo), math.log10(hi), ENTROPY_BINS + 1)
    counts, _ = np.histogram(arr, bins=edges)
    total = counts.sum()
    if total == 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def timing_log_lr(timestamps: list[float]) -> tuple[float, dict[str, Any]]:
    """Compute the timing channel log-LR from a session's event timestamps.

    Returns ``(log_lr, detail)`` where ``log_lr`` is log P(obs|AI)/P(obs|human)
    (positive ⇒ AI-like: fast/periodic/low-entropy) clamped to ``±MAX_ABS_LLR``,
    and ``detail`` carries the component statistics for observability.
    """
    intervals = inter_arrival_intervals(timestamps)
    detail: dict[str, Any] = {
        "n_intervals": len(intervals),
        "median_interval_s": None,
        "entropy_bits": None,
        "ks_pvalue": None,
        "insufficient": False,
    }
    if len(intervals) < MIN_INTERVALS:
        detail["insufficient"] = True
        return 0.0, detail

    arr = np.asarray(intervals, dtype=float)
    median = float(np.median(arr))
    detail["median_interval_s"] = round(median, 4)

    # --- KS term: how unlikely are these intervals under the human baseline? ---
    # scipy lognorm params: shape s = sigma, scale = exp(mu).
    ks = stats.kstest(arr, "lognorm", args=(HUMAN_SIGMA, 0.0, math.exp(HUMAN_MU)))
    pvalue = float(ks.pvalue)
    detail["ks_pvalue"] = round(pvalue, 6)
    # Map p-value -> [-1, +1]: p>=0.5 (consistent with the human baseline) ->
    # -1 (human); p<=1e-3 (very inconsistent) -> +1 (AI); linear in log10(p)
    # between. log10(0.5) ≈ -0.301, log10(1e-3) = -3.
    if pvalue >= 0.5:
        ks_term = -1.0
    elif pvalue <= 1e-3:
        ks_term = 1.0
    else:
        logp = math.log10(pvalue)
        # frac: 0 at p=0.5, 1 at p=1e-3.
        frac = (math.log10(0.5) - logp) / (math.log10(0.5) - math.log10(1e-3))
        ks_term = max(-1.0, min(1.0, 2.0 * frac - 1.0))

    # --- Entropy term: low entropy (regular) -> AI, high -> human. ---
    entropy = interval_entropy_bits(intervals)
    detail["entropy_bits"] = round(entropy, 4)
    if entropy <= LOW_ENTROPY_BITS:
        ent_term = 1.0
    elif entropy >= HIGH_ENTROPY_BITS:
        ent_term = -1.0
    else:
        frac = (entropy - LOW_ENTROPY_BITS) / (HIGH_ENTROPY_BITS - LOW_ENTROPY_BITS)
        ent_term = 1.0 - 2.0 * frac  # +1 at LOW, -1 at HIGH

    # --- Speed term: very fast median -> AI. ---
    if median <= FAST_MEDIAN_THRESHOLD_S:
        speed_term = 1.0
    elif median >= 2.0 * FAST_MEDIAN_THRESHOLD_S:
        speed_term = -1.0
    else:
        frac = (median - FAST_MEDIAN_THRESHOLD_S) / FAST_MEDIAN_THRESHOLD_S
        speed_term = 1.0 - 2.0 * frac

    raw = W_KS * ks_term + W_ENTROPY * ent_term + W_SPEED * speed_term
    log_lr = max(-MAX_ABS_LLR, min(MAX_ABS_LLR, raw))
    detail["ks_term"] = round(ks_term, 4)
    detail["entropy_term"] = round(ent_term, 4)
    detail["speed_term"] = round(speed_term, 4)
    return log_lr, detail


def timing_log_lr_from_events(
    events: list[dict[str, Any]],
) -> tuple[float, dict[str, Any]]:
    """Same as :func:`timing_log_lr` but extracts timestamps from raw events."""
    timestamps = [t for t in (event_timestamp(e) for e in events) if t is not None]
    return timing_log_lr(timestamps)
