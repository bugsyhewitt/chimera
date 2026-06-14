"""Unit tests for the timing channel (chimera.channel_timing).

Synthetic timestamp sequences only — no live Splunk. Fast/periodic intervals
should lean AI (positive log-LR); slow/variable intervals should lean human
(negative); too-few intervals yield 0 (no evidence). The channel is a screen,
so its magnitude is clamped.
"""

from __future__ import annotations

import json

from chimera.channel_timing import (
    MAX_ABS_LLR,
    inter_arrival_intervals,
    interval_entropy_bits,
    timing_log_lr,
    timing_log_lr_from_events,
)


def _periodic(n: int, gap: float, start: float = 1_000_000.0) -> list[float]:
    return [start + i * gap for i in range(n)]


def test_intervals_basic() -> None:
    assert inter_arrival_intervals([10.0, 11.0, 12.5]) == [1.0, 1.5]
    # Unsorted input is sorted first; non-positive (duplicate-timestamp) gaps
    # are dropped. [5,5,4,6] -> sorted [4,5,5,6] -> gaps [1,0,1] -> [1.0,1.0].
    assert inter_arrival_intervals([5.0, 5.0, 4.0, 6.0]) == [1.0, 1.0]


def test_fast_periodic_leans_ai() -> None:
    # 20 commands, 0.2s apart: fast, perfectly periodic, low entropy.
    ts = _periodic(20, 0.2)
    llr, detail = timing_log_lr(ts)
    assert llr > 0.5, detail
    assert detail["median_interval_s"] <= 1.0


def test_slow_variable_leans_human() -> None:
    # Human-like: median ~2s, high variance spanning sub-second to tens of s.
    ts = [1_000_000.0]
    for g in [3.1, 8.0, 2.0, 0.5, 15.0, 5.5, 1.2, 20.0, 2.0, 4.0, 9.0]:
        ts.append(ts[-1] + g)
    llr, detail = timing_log_lr(ts)
    assert llr < 0.0, detail


def test_clamped_magnitude() -> None:
    # Extremely fast + perfectly periodic still cannot exceed the clamp.
    ts = _periodic(50, 0.05)
    llr, _ = timing_log_lr(ts)
    assert -MAX_ABS_LLR <= llr <= MAX_ABS_LLR
    assert llr <= MAX_ABS_LLR


def test_insufficient_intervals_is_zero() -> None:
    llr, detail = timing_log_lr([1_000_000.0, 1_000_001.0])  # 1 interval
    assert llr == 0.0
    assert detail["insufficient"] is True


def test_entropy_low_for_periodic_high_for_variable() -> None:
    periodic = [0.2] * 20
    variable = [0.1, 0.5, 1.2, 3.0, 8.0, 0.3, 15.0, 2.0, 6.0, 0.4]
    assert interval_entropy_bits(periodic) <= interval_entropy_bits(variable)


def test_from_events_parses_raw_timestamps() -> None:
    events = []
    for i in range(6):
        ts = f"2026-06-09T00:00:0{i}.000000Z"
        events.append(
            {"_raw": json.dumps({"eventid": "cowrie.command.input", "timestamp": ts})}
        )
    llr, detail = timing_log_lr_from_events(events)
    # 1s periodic gaps -> 5 intervals, median 1.0.
    assert detail["n_intervals"] == 5
    assert detail["median_interval_s"] == 1.0
