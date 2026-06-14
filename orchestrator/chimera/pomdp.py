"""P14: the POMDP belief controller — CHIMERA's adaptive-deception brain.

This is the first Tier-3 packet. It formalises the spec's "fewer clues for
humans, more for AI" intuition (§5.3) as a small Partially-Observable Markov
Decision Process and ships a **hand-tuned, belief-thresholded policy** over a
3-state hidden space. There is deliberately **no deep RL** here: the value of
this packet is the *framing* (belief over hidden intent, Bayesian updates from
the detection signals we already produce, an interpretable policy) and a clean
seam where a learned policy could drop in later.

Hidden state space (what we're really facing)
---------------------------------------------
    benign          — not an attacker (legit-looking traffic, noise)
    human_attacker  — a hands-on-keyboard human operator
    ai_attacker     — an autonomous LLM/agent operator

Belief ``b`` is a probability distribution over those three states (a 3-vector
on the simplex: each entry in [0,1], summing to 1). We hold one belief per
src_ip/session and start from a benign-heavy prior ``[0.8, 0.1, 0.1]`` (most
sources are noise until proven otherwise).

Observations and the Bayesian update
-------------------------------------
Observations come from the detection stack we already built:

  * SPRT verdict (``chimera.sprt``): HOSTILE / BENIGN. A HOSTILE verdict is
    strong evidence we're facing *an attacker* (human or AI) and shifts mass off
    ``benign``. A BENIGN verdict reinforces ``benign``.
  * Classifier posterior (``chimera.classifier``): ``p_ai`` / ``p_human``. Given
    that we're facing an attacker, this splits the attacker mass between
    ``human_attacker`` and ``ai_attacker``.

We treat each observation as evidence with a per-state likelihood
``P(observation | state)`` and apply Bayes' rule::

    b'(s) ∝ P(obs | s) · b(s)            then renormalise so Σ b' = 1.

The likelihoods live in small, documented tables (:data:`SPRT_LIKELIHOOD` and a
parametric classifier likelihood) so the behaviour is auditable. The update is
numerically stable (it floors the normaliser and falls back to the prior belief
if an observation is impossible under every state) and always returns a valid
simplex vector.

Actions and the policy
----------------------
Action space — breadcrumb intensity::

    none < subtle < moderate < aggressive

Hand-tuned threshold policy (:func:`policy`):

    b[ai_attacker]     > 0.7  -> aggressive   (AI agents chase planted goals;
                                                flood looping breadcrumbs)
    b[human_attacker]  > 0.7  -> subtle       (humans get suspicious fast;
                                                sparse, deniable breadcrumbs)
    b[benign]          > 0.7  -> none         (don't tip our hand to noise)
    otherwise                 -> moderate     (hedged, we're not sure yet)

Reward framing (narrative only, not optimised here):
``R = engagement_value(dwell) − penetration_risk_penalty`` — heavier breadcrumbs
buy dwell time on AI agents (good) but raise penetration risk on humans (bad),
which is exactly what the thresholds above trade off by hand.

Action effect — SCOPE LIMIT (Tier-3 v1)
---------------------------------------
We do **not** physically swap honeypot configs. The chosen action and the belief
that produced it are *recorded* as deception state in ``idx_deception`` (a
``type="deception_action"`` event via :class:`DeceptionWriter`). Enforcing the
breadcrumb intensity on the live honeypot is out of scope for v1; this packet
delivers the brain (belief + policy + recorded decision), not the actuator.

Public API: :class:`BeliefController` (stateful, per src_ip/session) plus the
pure helpers :func:`update`, :func:`policy`, and :func:`uniform_attacker_split`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from .classifier import ClassificationResult
from .sprt import Verdict

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# State space, belief vector layout, prior.
# ---------------------------------------------------------------------------
# The belief is a 3-vector; these indices fix its layout everywhere.
BENIGN = 0
HUMAN = 1
AI = 2
STATE_NAMES = ("benign", "human_attacker", "ai_attacker")
N_STATES = 3

# Benign-heavy prior: most sources are noise until evidence accrues.
DEFAULT_PRIOR: tuple[float, float, float] = (0.8, 0.1, 0.1)

# Numerical floor so a degenerate observation never zeroes the whole vector and
# we never divide by ~0 when renormalising.
_EPS = 1e-12


class Action(str, Enum):
    """Breadcrumb intensity. ``str`` mixin so it JSON-serialises cleanly."""

    NONE = "none"
    SUBTLE = "subtle"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"


# Policy threshold: a single state must own > this fraction of belief to trigger
# its decisive action; otherwise we hedge to MODERATE.
POLICY_THRESHOLD = 0.7


# ---------------------------------------------------------------------------
# Observation likelihood tables.
# ---------------------------------------------------------------------------
# SPRT verdict observation: P(verdict | state), one row per verdict, indexed by
# [benign, human_attacker, ai_attacker].
#
# Rationale:
#   * A HOSTILE verdict is *unlikely* for a benign source (SPRT's α≈0.01 false-
#     positive rate) but *likely* for either attacker flavour — so it pulls mass
#     strongly off benign and onto the two attacker states (equally; the SPRT
#     doesn't distinguish human vs AI — the classifier does that).
#   * A BENIGN verdict is *likely* for a benign source and *unlikely* for an
#     attacker (SPRT's β≈0.05 false-negative rate), so it reinforces benign.
# Values are illustrative likelihoods (not the exact α/β, but the same shape):
# they only matter up to a per-row constant after renormalisation.
SPRT_LIKELIHOOD: dict[Verdict, tuple[float, float, float]] = {
    #              benign  human   ai
    Verdict.HOSTILE: (0.02, 0.90, 0.90),
    Verdict.BENIGN: (0.90, 0.05, 0.05),
    # UNDECIDED carries no information -> flat likelihood -> a no-op update.
    Verdict.UNDECIDED: (1.0, 1.0, 1.0),
}

# Classifier observation: we use the classifier's posterior p_ai/p_human as the
# likelihood ratio that splits the *attacker* mass. For the hidden states we set
#   P(classifier obs | benign)         = 1            (uninformative about benign;
#                                                       SPRT owns the benign call)
#   P(classifier obs | human_attacker) = p_human
#   P(classifier obs | ai_attacker)    = p_ai
# so a confident p_ai pushes attacker mass to ai_attacker and vice-versa, while
# leaving the benign/attacker split to the SPRT observation. This keeps the two
# observation types cleanly separated (SPRT = "attacker or not", classifier =
# "which kind of attacker"), exactly mirroring how the detection stack works.


# ---------------------------------------------------------------------------
# Observation value object.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Observation:
    """One observation fed to the belief update.

    Exactly one of ``verdict`` / ``classification`` is normally set per
    observation, but both may be present; each contributes its own Bayesian
    factor. ``verdict`` is an SPRT :class:`~chimera.sprt.Verdict`; the classifier
    posterior is given as ``p_ai`` (with ``p_human = 1 - p_ai``).
    """

    verdict: Verdict | None = None
    p_ai: float | None = None  # classifier posterior P(AI); p_human = 1 - p_ai

    @classmethod
    def from_verdict(cls, verdict: Verdict) -> "Observation":
        return cls(verdict=verdict)

    @classmethod
    def from_classification(cls, result: ClassificationResult) -> "Observation":
        return cls(p_ai=result.p_ai)


# ---------------------------------------------------------------------------
# Pure belief math.
# ---------------------------------------------------------------------------
def normalize(vec: tuple[float, float, float] | list[float]) -> tuple[float, float, float]:
    """Project ``vec`` onto the probability simplex (clamp ≥0, renormalise).

    Numerically stable: negatives are clamped to 0 and if the total is ~0 (a
    degenerate vector) we fall back to the prior so we always return a valid
    distribution.
    """
    a = max(0.0, float(vec[0]))
    b = max(0.0, float(vec[1]))
    c = max(0.0, float(vec[2]))
    total = a + b + c
    if total <= _EPS:
        return DEFAULT_PRIOR
    return (a / total, b / total, c / total)


def update(
    belief: tuple[float, float, float],
    observation: Observation,
) -> tuple[float, float, float]:
    """Bayesian belief update: ``b'(s) ∝ P(obs | s) · b(s)``, renormalised.

    Applies the SPRT-verdict factor (if any) and the classifier factor (if any)
    multiplicatively to the prior belief, then renormalises onto the simplex.
    Always returns a valid distribution; an observation that is impossible under
    every state (would zero the vector) leaves the belief unchanged.
    """
    likelihood = [1.0, 1.0, 1.0]

    if observation.verdict is not None:
        row = SPRT_LIKELIHOOD.get(observation.verdict, (1.0, 1.0, 1.0))
        for i in range(N_STATES):
            likelihood[i] *= row[i]

    if observation.p_ai is not None:
        p_ai = min(max(observation.p_ai, 0.0), 1.0)
        p_human = 1.0 - p_ai
        # benign: uninformative (SPRT owns the benign call); attackers split.
        classifier_row = (1.0, p_human, p_ai)
        for i in range(N_STATES):
            likelihood[i] *= classifier_row[i]

    posterior = [likelihood[i] * belief[i] for i in range(N_STATES)]
    total = sum(posterior)
    if total <= _EPS:
        # Observation impossible under the current belief support: don't move.
        return normalize(belief)
    return normalize(posterior)


def uniform_attacker_split(p_attacker: float) -> tuple[float, float, float]:
    """Convenience prior: ``p_attacker`` mass split evenly across attacker states.

    Handy for tests/seeding. ``1 - p_attacker`` goes to benign; the rest splits
    evenly between human_attacker and ai_attacker.
    """
    p_attacker = min(max(p_attacker, 0.0), 1.0)
    half = p_attacker / 2.0
    return normalize((1.0 - p_attacker, half, half))


def policy(belief: tuple[float, float, float]) -> Action:
    """Hand-tuned threshold policy: belief -> breadcrumb intensity.

    See module docstring for the rationale. A single state owning > 0.7 of the
    belief triggers its decisive action; otherwise we hedge to MODERATE.
    """
    if belief[AI] > POLICY_THRESHOLD:
        return Action.AGGRESSIVE
    if belief[HUMAN] > POLICY_THRESHOLD:
        return Action.SUBTLE
    if belief[BENIGN] > POLICY_THRESHOLD:
        return Action.NONE
    return Action.MODERATE


def belief_dict(belief: tuple[float, float, float]) -> dict[str, float]:
    """The belief vector as a JSON-friendly ``{benign, human, ai}`` dict."""
    return {
        "benign": round(belief[BENIGN], 6),
        "human": round(belief[HUMAN], 6),
        "ai": round(belief[AI], 6),
    }


# ---------------------------------------------------------------------------
# Stateful per-src_ip/session controller.
# ---------------------------------------------------------------------------
@dataclass
class _Track:
    """Per-key belief state for the controller."""

    key: str
    src_ip: str | None
    session: str | None
    belief: tuple[float, float, float] = DEFAULT_PRIOR
    action: Action = Action.NONE
    # Last belief/action we *emitted*, for dedupe of identical consecutive states.
    last_emitted: tuple[tuple[float, float, float], Action] | None = field(
        default=None
    )


def _quantize(belief: tuple[float, float, float]) -> tuple[int, int, int]:
    """Quantise a belief for dedupe (so float jitter doesn't spam events)."""
    return tuple(round(b, 4) for b in belief)  # type: ignore[return-value]


class BeliefController:
    """Stateful POMDP belief controller, keyed by src_ip/session.

    Maintains one belief per key, applies Bayesian updates from SPRT verdicts and
    classifier results, derives the policy action, and (when wired with a writer)
    records ``type="deception_action"`` events on each *meaningful* belief/action
    change. Deduplicates identical consecutive belief/action pairs to avoid
    spamming ``idx_deception``.

    All public methods are safe to call from the poll loop: failures in the
    optional write path are swallowed (logged, never raised).
    """

    def __init__(self, *, prior: tuple[float, float, float] = DEFAULT_PRIOR) -> None:
        self._prior = normalize(prior)
        self._tracks: dict[str, _Track] = {}

    @staticmethod
    def _key(src_ip: str | None, session: str | None) -> str:
        # Prefer the session id (one engagement); fall back to src_ip.
        return str(session or src_ip or "unknown")

    def _track(self, src_ip: str | None, session: str | None) -> _Track:
        key = self._key(src_ip, session)
        track = self._tracks.get(key)
        if track is None:
            track = _Track(key=key, src_ip=src_ip, session=session, belief=self._prior)
            self._tracks[key] = track
        else:
            # Backfill identity if a later observation carries more info.
            if track.src_ip is None and src_ip is not None:
                track.src_ip = src_ip
            if track.session is None and session is not None:
                track.session = session
        return track

    def belief_of(self, src_ip: str | None, session: str | None = None) -> tuple[float, float, float]:
        track = self._tracks.get(self._key(src_ip, session))
        return track.belief if track else self._prior

    def action_of(self, src_ip: str | None, session: str | None = None) -> Action:
        track = self._tracks.get(self._key(src_ip, session))
        return track.action if track else policy(self._prior)

    def observe(
        self,
        observation: Observation,
        *,
        src_ip: str | None = None,
        session: str | None = None,
    ) -> tuple[tuple[float, float, float], Action, bool]:
        """Apply ``observation``, recompute the policy action, and report change.

        Returns ``(belief, action, changed)`` where ``changed`` is True iff the
        quantised belief or the action differs from what was last *emitted* for
        this key (i.e. an event is warranted). Pure/synchronous — the write is
        done separately by :meth:`observe_and_write`.
        """
        track = self._track(src_ip, session)
        track.belief = update(track.belief, observation)
        track.action = policy(track.belief)

        signature = (_quantize(track.belief), track.action)
        if track.last_emitted is None:
            changed = True
        else:
            prev_q = _quantize(track.last_emitted[0])
            changed = signature != (prev_q, track.last_emitted[1])
        return track.belief, track.action, changed

    def _mark_emitted(self, src_ip: str | None, session: str | None) -> None:
        track = self._track(src_ip, session)
        track.last_emitted = (track.belief, track.action)

    def action_event(self, src_ip: str | None, session: str | None) -> dict[str, Any]:
        """Shape the ``type="deception_action"`` event for the current state."""
        track = self._track(src_ip, session)
        return {
            "type": "deception_action",
            "src_ip": track.src_ip,
            "session": track.session,
            "belief": belief_dict(track.belief),
            "action": track.action.value,
            "ts": int(time.time()),
        }

    async def observe_and_write(
        self,
        observation: Observation,
        *,
        writer: Any,
        src_ip: str | None = None,
        session: str | None = None,
    ) -> bool:
        """Apply an observation and, if the belief/action *changed*, write the
        ``deception_action`` event via ``writer`` (a :class:`DeceptionWriter`).

        Returns True if an event was written. Never raises into the caller: a
        write failure is logged by the writer and treated as "not emitted" so we
        retry on the next meaningful change.
        """
        _belief, action, changed = self.observe(
            observation, src_ip=src_ip, session=session
        )
        if not changed:
            return False
        event = self.action_event(src_ip, session)
        try:
            await writer.write_decision(event)
        except Exception as e:  # noqa: BLE001 — controller must not kill the loop
            log.warning(
                "deception_action_write_failed",
                src_ip=src_ip,
                session=session,
                error=str(e),
            )
            return False
        self._mark_emitted(src_ip, session)
        log.info(
            "deception_action",
            src_ip=src_ip,
            session=session,
            action=action.value,
            belief=belief_dict(self.belief_of(src_ip, session)),
        )
        return True
