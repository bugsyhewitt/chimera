"""Unit tests for the POMDP belief controller (chimera.pomdp).

Synthetic observations only — no live Splunk. Verifies:
  * the belief starts benign-heavy and the prior maps to action NONE;
  * a HOSTILE verdict + high-p_ai observation drives b[ai] > 0.7 -> AGGRESSIVE;
  * a HOSTILE verdict + high-p_human observation -> SUBTLE;
  * benign reinforcement keeps/returns belief benign-heavy -> NONE;
  * an ambiguous attacker belief (no state > 0.7) -> MODERATE;
  * the belief is always a valid simplex vector (in [0,1], sums to 1);
  * the update is monotonic in the obvious direction;
  * the controller dedupes identical consecutive belief/action pairs.
"""

from __future__ import annotations

import math

import pytest

from chimera.classifier import Classification, ClassificationResult
from chimera.pomdp import (
    AI,
    BENIGN,
    DEFAULT_PRIOR,
    HUMAN,
    POLICY_THRESHOLD,
    Action,
    BeliefController,
    Observation,
    normalize,
    policy,
    uniform_attacker_split,
    update,
)
from chimera.sprt import Verdict


def _is_simplex(belief) -> bool:
    return (
        len(belief) == 3
        and all(0.0 <= b <= 1.0 for b in belief)
        and math.isclose(sum(belief), 1.0, abs_tol=1e-9)
    )


def _classification(p_ai: float) -> ClassificationResult:
    cls = Classification.AI if p_ai >= 0.5 else Classification.HUMAN
    return ClassificationResult(
        src_ip="172.30.0.1",
        session="s1",
        classification=cls,
        p_ai=p_ai,
        p_human=1.0 - p_ai,
        combined_log_lr=0.0,
        channels={},
    )


# ---------------------------------------------------------------------------
# Prior / starting state.
# ---------------------------------------------------------------------------
def test_prior_is_benign_heavy_simplex() -> None:
    assert _is_simplex(DEFAULT_PRIOR)
    assert DEFAULT_PRIOR[BENIGN] == max(DEFAULT_PRIOR)
    assert DEFAULT_PRIOR[BENIGN] > POLICY_THRESHOLD
    assert policy(DEFAULT_PRIOR) is Action.NONE


def test_controller_starts_benign() -> None:
    ctrl = BeliefController()
    assert _is_simplex(ctrl.belief_of("1.2.3.4"))
    assert ctrl.belief_of("1.2.3.4")[BENIGN] > POLICY_THRESHOLD
    assert ctrl.action_of("1.2.3.4") is Action.NONE


# ---------------------------------------------------------------------------
# Bayesian update behaviour.
# ---------------------------------------------------------------------------
def test_hostile_shifts_mass_off_benign_onto_attackers() -> None:
    b0 = DEFAULT_PRIOR
    b1 = update(b0, Observation.from_verdict(Verdict.HOSTILE))
    assert _is_simplex(b1)
    # Monotonic: benign mass drops, attacker mass rises.
    assert b1[BENIGN] < b0[BENIGN]
    assert (b1[HUMAN] + b1[AI]) > (b0[HUMAN] + b0[AI])
    # SPRT alone doesn't distinguish human vs AI -> they stay equal.
    assert math.isclose(b1[HUMAN], b1[AI], abs_tol=1e-9)


def test_benign_reinforces_benign() -> None:
    # Start from an ambiguous belief, then a BENIGN verdict pulls back to benign.
    b0 = uniform_attacker_split(0.6)
    b1 = update(b0, Observation.from_verdict(Verdict.BENIGN))
    assert _is_simplex(b1)
    assert b1[BENIGN] > b0[BENIGN]  # monotonic toward benign
    assert b1[BENIGN] > POLICY_THRESHOLD
    assert policy(b1) is Action.NONE


def test_undecided_is_a_noop() -> None:
    b0 = DEFAULT_PRIOR
    b1 = update(b0, Observation.from_verdict(Verdict.UNDECIDED))
    assert all(math.isclose(a, b, abs_tol=1e-9) for a, b in zip(b0, b1))


def test_classifier_splits_attacker_mass_toward_ai() -> None:
    b0 = uniform_attacker_split(0.8)  # 0.4 human / 0.4 ai
    b1 = update(b0, Observation(p_ai=0.95))
    assert _is_simplex(b1)
    assert b1[AI] > b0[AI]  # monotonic toward AI
    assert b1[HUMAN] < b0[HUMAN]


def test_classifier_splits_attacker_mass_toward_human() -> None:
    b0 = uniform_attacker_split(0.8)
    b1 = update(b0, Observation(p_ai=0.05))
    assert _is_simplex(b1)
    assert b1[HUMAN] > b0[HUMAN]  # monotonic toward human
    assert b1[AI] < b0[AI]


def test_update_always_returns_simplex_over_many_observations() -> None:
    b = DEFAULT_PRIOR
    seq = [
        Observation.from_verdict(Verdict.HOSTILE),
        Observation(p_ai=0.99),
        Observation(p_ai=0.01),
        Observation.from_verdict(Verdict.BENIGN),
        Observation.from_verdict(Verdict.UNDECIDED),
    ]
    for obs in seq:
        b = update(b, obs)
        assert _is_simplex(b)


def test_normalize_handles_degenerate_vectors() -> None:
    assert _is_simplex(normalize((0.0, 0.0, 0.0)))  # falls back to prior
    assert _is_simplex(normalize((-1.0, 5.0, 0.0)))  # clamps negatives
    assert normalize((0.0, 0.0, 0.0)) == DEFAULT_PRIOR


def test_impossible_observation_leaves_belief_unchanged() -> None:
    # A belief with no mass on attacker states; a classifier obs (which only
    # touches attacker states) must not zero the vector — benign keeps its mass.
    b0 = (1.0, 0.0, 0.0)
    b1 = update(b0, Observation(p_ai=0.99))
    assert _is_simplex(b1)
    assert b1[BENIGN] == 1.0


# ---------------------------------------------------------------------------
# Policy thresholds (the headline behaviour).
# ---------------------------------------------------------------------------
def test_hostile_plus_high_p_ai_drives_aggressive() -> None:
    ctrl = BeliefController()
    ctrl.observe(Observation.from_verdict(Verdict.HOSTILE), src_ip="172.30.0.1")
    belief, action, _ = ctrl.observe(
        Observation(p_ai=0.99), src_ip="172.30.0.1"
    )
    assert _is_simplex(belief)
    assert belief[AI] > POLICY_THRESHOLD
    assert action is Action.AGGRESSIVE


def test_hostile_plus_high_p_human_drives_subtle() -> None:
    ctrl = BeliefController()
    ctrl.observe(Observation.from_verdict(Verdict.HOSTILE), src_ip="10.0.0.9")
    belief, action, _ = ctrl.observe(Observation(p_ai=0.01), src_ip="10.0.0.9")
    assert belief[HUMAN] > POLICY_THRESHOLD
    assert action is Action.SUBTLE


def test_benign_reinforcement_yields_none() -> None:
    ctrl = BeliefController()
    belief, action, _ = ctrl.observe(
        Observation.from_verdict(Verdict.BENIGN), src_ip="8.8.8.8"
    )
    assert belief[BENIGN] > POLICY_THRESHOLD
    assert action is Action.NONE


def test_ambiguous_belief_yields_moderate() -> None:
    # Attacker is likely but the human/AI split is even -> no state clears 0.7.
    ctrl = BeliefController()
    ctrl.observe(Observation.from_verdict(Verdict.HOSTILE), src_ip="5.5.5.5")
    belief, action, _ = ctrl.observe(
        Observation(p_ai=0.5), src_ip="5.5.5.5"
    )
    assert max(belief) <= POLICY_THRESHOLD
    assert action is Action.MODERATE


def test_policy_thresholds_directly() -> None:
    assert policy((0.1, 0.1, 0.8)) is Action.AGGRESSIVE
    assert policy((0.1, 0.8, 0.1)) is Action.SUBTLE
    assert policy((0.8, 0.1, 0.1)) is Action.NONE
    assert policy((0.34, 0.33, 0.33)) is Action.MODERATE


# ---------------------------------------------------------------------------
# Event shape + dedupe + write path.
# ---------------------------------------------------------------------------
def test_action_event_shape() -> None:
    ctrl = BeliefController()
    ctrl.observe(Observation.from_verdict(Verdict.HOSTILE), src_ip="172.30.0.1", session="abc")
    ctrl.observe(Observation(p_ai=0.99), src_ip="172.30.0.1", session="abc")
    ev = ctrl.action_event("172.30.0.1", "abc")
    assert ev["type"] == "deception_action"
    assert ev["src_ip"] == "172.30.0.1"
    assert ev["session"] == "abc"
    assert ev["action"] == "aggressive"
    assert set(ev["belief"]) == {"benign", "human", "ai"}
    assert math.isclose(sum(ev["belief"].values()), 1.0, abs_tol=1e-3)
    assert isinstance(ev["ts"], int)


class _RecordingWriter:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def write_decision(self, event: dict) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_observe_and_write_dedupes_identical_consecutive_states() -> None:
    ctrl = BeliefController()
    w = _RecordingWriter()

    # First HOSTILE moves the belief -> writes.
    wrote1 = await ctrl.observe_and_write(
        Observation.from_verdict(Verdict.HOSTILE), writer=w, src_ip="172.30.0.1"
    )
    assert wrote1 is True
    n_after_first = len(w.events)
    assert n_after_first == 1

    # An UNDECIDED verdict is a no-op update -> belief/action unchanged ->
    # deduped, no new event written.
    wrote2 = await ctrl.observe_and_write(
        Observation.from_verdict(Verdict.UNDECIDED), writer=w, src_ip="172.30.0.1"
    )
    assert wrote2 is False
    assert len(w.events) == n_after_first

    # A high-p_ai observation changes belief/action -> writes again.
    wrote3 = await ctrl.observe_and_write(
        Observation(p_ai=0.99), writer=w, src_ip="172.30.0.1"
    )
    assert wrote3 is True
    assert len(w.events) == n_after_first + 1
    assert w.events[-1]["action"] == "aggressive"


@pytest.mark.asyncio
async def test_observe_and_write_swallows_writer_errors() -> None:
    class _BoomWriter:
        async def write_decision(self, event: dict) -> None:
            raise RuntimeError("splunk down")

    ctrl = BeliefController()
    # Must not raise; returns False and stays un-emitted (so it retries later).
    wrote = await ctrl.observe_and_write(
        Observation.from_verdict(Verdict.HOSTILE), writer=_BoomWriter(), src_ip="1.1.1.1"
    )
    assert wrote is False


def test_full_classification_result_observation() -> None:
    ctrl = BeliefController()
    ctrl.observe(Observation.from_verdict(Verdict.HOSTILE), src_ip="172.30.0.1")
    belief, action, _ = ctrl.observe(
        Observation.from_classification(_classification(0.98)), src_ip="172.30.0.1"
    )
    assert action is Action.AGGRESSIVE
    assert belief[AI] > POLICY_THRESHOLD
