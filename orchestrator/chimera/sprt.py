"""Wald's Sequential Probability Ratio Test (SPRT) hostile/benign classifier.

This is the mathematical core of CHIMERA's Tier-2 detection. For each attacker
``src_ip`` we maintain a running log-likelihood ratio ``Λ`` accumulated from a
stream of evidence events. Each event contributes a fixed per-event
log-likelihood ratio (log-LR) drawn from :data:`LIKELIHOOD_TABLE`. When ``Λ``
crosses the upper threshold ``A`` we declare ``HOSTILE``; when it crosses the
lower threshold ``B`` we declare ``BENIGN``; otherwise the verdict is
``UNDECIDED`` and we keep accumulating.

Why SPRT (vs. a fixed-window threshold)?
- It is the optimal sequential test: for the target error rates it minimises the
  expected number of observations needed to reach a decision.
- It is naturally online/streaming, which matches the poll loop: each new
  honeypot/Suricata event nudges ``Λ`` and may flip the verdict.

Thresholds (Wald):
    A = ln((1 - β) / α)   -> declare HOSTILE when Λ >= A
    B = ln(β / (1 - α))   -> declare BENIGN  when Λ <= B
with α (false-positive rate) = 0.01 and β (false-negative rate) = 0.05, giving
A ≈ +4.554 and B ≈ -2.986. (Note: B uses the canonical Wald formula
ln(β/(1-α)); an earlier plan note quoted ≈ -3.64, which corresponds to a
different denominator — we use the formula, not the quoted number, and the
verdict logic only requires B < 0.)

Topology note (drives calibration): in CHIMERA's single-host Docker setup
Suricata cannot see Cowrie traffic, so ``idx_network`` stays empty during
attacks and the real attacker signal lands in ``idx_honeypot`` (Cowrie JSON).
A source that brute-forces and runs commands against a honeypot is *very*
strong hostile evidence — legitimate users never touch a honeypot at all — so
the Cowrie eventids carry positive log-LRs. The Suricata types are kept for the
day Suricata gains visibility (or other sensors feed in).

The public API is :class:`SPRTClassifier` (stateful, per-``src_ip``) plus the
pure helpers :func:`classify_event` and :func:`event_log_lr`.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Error rates and Wald thresholds
# ---------------------------------------------------------------------------
ALPHA = 0.01  # false-positive rate: P(declare HOSTILE | actually benign)
BETA = 0.05  # false-negative rate: P(declare BENIGN | actually hostile)

# Upper threshold: accumulate to here -> HOSTILE. ≈ +4.554
A_THRESHOLD = math.log((1.0 - BETA) / ALPHA)
# Lower threshold: accumulate to here -> BENIGN. ≈ -2.986
B_THRESHOLD = math.log(BETA / (1.0 - ALPHA))


# ---------------------------------------------------------------------------
# Evidence likelihood table (per-event log-likelihood ratios)
# ---------------------------------------------------------------------------
# Each value is log( P(evidence | hostile) / P(evidence | benign) ). A positive
# value is evidence FOR hostile; a negative value is evidence FOR benign.
#
# Calibration target (the smoke-test attacker, scripts/seed_attacker.sh):
#   3x cowrie.login.failed  (1.5)  = +4.5
#   1x cowrie.login.success (2.0)  = +2.0
#   ~3x cowrie.command.input(1.0)  = +3.0
#   1x cowrie.session.file_download (wget) (2.5) = +2.5
#   + session.connect (0.3) each
# Even the failures + the success alone (4.5 + 2.0 = 6.5) clear A ≈ 4.554, so a
# real brute-force-then-shell attacker reaches HOSTILE quickly and decisively.
# A single benign-looking probe (one session.connect = +0.3, or one normal_http
# = -0.5) stays far from A and does not trip a verdict on its own.
LIKELIHOOD_TABLE: dict[str, float] = {
    # ----- Suricata / network sensor types (idx_network; per the plan) -----
    # A port-scan signature is a strong recon indicator.
    "port_scan_signature": 2.5,
    # A burst of auth failures (e.g. an IDS brute-force signature).
    "auth_failure_burst": 1.5,
    # Suspicious / scanner-like user agent.
    "anomalous_user_agent": 1.0,
    # Ordinary HTTP looks benign -> negative log-LR pulls Λ toward BENIGN.
    "normal_http": -0.5,
    # ----- Cowrie SSH honeypot eventids (idx_honeypot; the real signal) -----
    # Each failed login against the honeypot is brute-force evidence.
    "cowrie.login.failed": 1.5,
    # A "successful" login to a honeypot means the attacker accepted bait creds:
    # weightier than a failure.
    "cowrie.login.success": 2.0,
    # Running shell commands inside the honeypot = hands-on-keyboard / tooling.
    "cowrie.command.input": 1.0,
    # Merely connecting to the honeypot is mildly suspicious (no legit reason to
    # touch it) but weak on its own — must not declare HOSTILE from one connect.
    "cowrie.session.connect": 0.3,
    # Fetching a remote file (wget/curl) inside the shell = payload staging.
    "cowrie.session.file_download": 2.5,
    # Closing a session is neutral-ish; tiny positive (they were here at all).
    "cowrie.session.closed": 0.1,
    # ----- fallback -----
    # Unknown/unclassified evidence: small positive nudge (anything reaching the
    # honeypot is faintly suspicious) but kept tiny so noise can't decide a case.
    "unknown": 0.1,
}

# Returned by classify_event() when an event maps to nothing meaningful and we
# want it to contribute the explicit "unknown" weight.
UNKNOWN_EVIDENCE = "unknown"


class Verdict(str, Enum):
    """SPRT decision for a src_ip. ``str`` mixin so it JSON-serialises cleanly."""

    HOSTILE = "HOSTILE"
    BENIGN = "BENIGN"
    UNDECIDED = "UNDECIDED"


# ---------------------------------------------------------------------------
# Event -> evidence-type classification (pure functions)
# ---------------------------------------------------------------------------
def _merge_raw_json(event: dict[str, Any]) -> dict[str, Any]:
    """Return ``event`` with the Cowrie/Suricata JSON in ``_raw`` merged in.

    The Splunk MCP server only auto-extracts a few KV fields (notably ``src_ip``)
    at search time; the full Cowrie/Suricata JSON document lives in the ``_raw``
    string. When the discriminating fields (``eventid`` / ``event_type``) are
    absent at the top level, we parse ``_raw`` as JSON and overlay its keys (top
    level wins on conflict) so the classifier sees the real fields. Non-JSON or
    missing ``_raw`` is a no-op.
    """
    if event.get("eventid") or event.get("event_type"):
        return event
    raw = event.get("_raw")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
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


def classify_event(event: dict[str, Any]) -> str:
    """Map a raw Splunk event dict to a :data:`LIKELIHOOD_TABLE` key.

    Handles both Cowrie-shaped events (``eventid`` like ``cowrie.login.failed``)
    and Suricata-shaped events (``event_type``/``alert`` with a ``signature``).
    When those fields aren't extracted at the top level, the Cowrie/Suricata
    JSON in ``_raw`` is parsed and merged first (see :func:`_merge_raw_json`).
    Falls back to :data:`UNKNOWN_EVIDENCE` so every event contributes *some*
    defined weight rather than silently dropping out of the test.

    Splunk sometimes surfaces a field as a single-element list (repeated KV);
    we coerce to a scalar before matching.
    """
    event = _merge_raw_json(event)

    def scalar(key: str) -> str:
        val = event.get(key)
        if isinstance(val, list):
            val = val[0] if val else None
        return "" if val is None else str(val).strip()

    # --- Cowrie: the eventid IS (almost) the table key ---
    eventid = scalar("eventid").lower()
    if eventid:
        if eventid in LIKELIHOOD_TABLE:
            return eventid
        # Known Cowrie families we fold onto an existing key.
        if eventid.startswith("cowrie.command"):
            return "cowrie.command.input"
        if eventid.startswith("cowrie.session.file_download") or eventid.startswith(
            "cowrie.session.file_upload"
        ):
            return "cowrie.session.file_download"
        if eventid == "cowrie.client.version" or eventid.startswith("cowrie.direct-tcpip"):
            return "cowrie.session.connect"
        # Any other cowrie.* event still reached the honeypot -> faint suspicion.
        if eventid.startswith("cowrie."):
            return UNKNOWN_EVIDENCE

    # --- Suricata: event_type + signature ---
    etype = scalar("event_type").lower()
    if etype:
        signature = (scalar("signature") or scalar("alert.signature")).lower()
        if etype == "alert":
            if "scan" in signature or "port" in signature:
                return "port_scan_signature"
            if "brute" in signature or "login" in signature or "auth" in signature:
                return "auth_failure_burst"
            if "user-agent" in signature or "user_agent" in signature or "agent" in signature:
                return "anomalous_user_agent"
            # An alert we can't name is still an alert: treat as auth burst-ish
            # weak hostile signal rather than benign.
            return "anomalous_user_agent"
        if etype == "http":
            ua = scalar("http_user_agent") or scalar("http.http_user_agent")
            if ua and _looks_like_scanner(ua):
                return "anomalous_user_agent"
            return "normal_http"

    return UNKNOWN_EVIDENCE


_SCANNER_UA_MARKERS = (
    "nmap",
    "masscan",
    "sqlmap",
    "nikto",
    "zgrab",
    "curl",
    "wget",
    "python-requests",
    "go-http-client",
)


def _looks_like_scanner(user_agent: str) -> bool:
    ua = user_agent.lower()
    return any(marker in ua for marker in _SCANNER_UA_MARKERS)


def event_log_lr(event: dict[str, Any]) -> float:
    """Per-event log-likelihood ratio for ``event`` (via :func:`classify_event`)."""
    etype = classify_event(event)
    return LIKELIHOOD_TABLE.get(etype, LIKELIHOOD_TABLE[UNKNOWN_EVIDENCE])


# ---------------------------------------------------------------------------
# Per-src_ip state + the classifier
# ---------------------------------------------------------------------------
@dataclass
class SPRTState:
    """Accumulated SPRT state for one ``src_ip``."""

    src_ip: str
    log_lambda: float = 0.0
    evidence_count: int = 0
    verdict: Verdict = Verdict.UNDECIDED
    # Tally of evidence types seen, for observability/debugging.
    evidence: dict[str, int] = field(default_factory=dict)

    @property
    def decided(self) -> bool:
        return self.verdict in (Verdict.HOSTILE, Verdict.BENIGN)


def confidence_from_lambda(log_lambda: float, verdict: Verdict) -> float:
    """Map ``Λ`` to a 0..1 confidence given the (decided) verdict.

    For HOSTILE we report how far past the upper threshold we are, saturating at
    1.0 once Λ >= A. For BENIGN we mirror that against the lower threshold. For
    UNDECIDED we report a 0..~0.5 progress signal from 0 toward whichever
    threshold Λ is heading to, which is handy for dashboards.
    """
    if verdict is Verdict.HOSTILE:
        # 0 at Λ=0, 1.0 at Λ>=A.
        return max(0.0, min(1.0, log_lambda / A_THRESHOLD))
    if verdict is Verdict.BENIGN:
        # 0 at Λ=0, 1.0 at Λ<=B (B is negative).
        return max(0.0, min(1.0, log_lambda / B_THRESHOLD))
    # UNDECIDED: distance traveled toward the nearer threshold, capped at 0.5.
    if log_lambda >= 0:
        prog = log_lambda / A_THRESHOLD if A_THRESHOLD else 0.0
    else:
        prog = log_lambda / B_THRESHOLD if B_THRESHOLD else 0.0
    return max(0.0, min(0.5, 0.5 * prog))


class SPRTClassifier:
    """Stateful, per-``src_ip`` Wald SPRT hostile/benign classifier.

    Verdicts are *sticky*: once a ``src_ip`` is declared HOSTILE or BENIGN,
    subsequent events for it do not change the verdict (we still tally evidence
    for observability, but ``Λ`` is frozen at the crossing value).
    """

    def __init__(
        self,
        *,
        a_threshold: float = A_THRESHOLD,
        b_threshold: float = B_THRESHOLD,
    ) -> None:
        self.a_threshold = a_threshold
        self.b_threshold = b_threshold
        self._states: dict[str, SPRTState] = {}

    # ---- public API ----
    def update(self, src_ip: str, event: dict[str, Any]) -> Verdict:
        """Feed one event for ``src_ip`` into the test; return current verdict.

        Returns the (possibly newly-crossed) verdict. Use :meth:`get_state` /
        :meth:`just_decided` around the call to detect a *transition*.
        """
        state = self._states.get(src_ip)
        if state is None:
            state = SPRTState(src_ip=src_ip)
            self._states[src_ip] = state

        etype = classify_event(event)
        state.evidence[etype] = state.evidence.get(etype, 0) + 1
        state.evidence_count += 1

        # Sticky: do not move Λ once decided, but keep the evidence tally above.
        if state.verdict in (Verdict.HOSTILE, Verdict.BENIGN):
            return state.verdict

        state.log_lambda += LIKELIHOOD_TABLE.get(
            etype, LIKELIHOOD_TABLE[UNKNOWN_EVIDENCE]
        )

        if state.log_lambda >= self.a_threshold:
            state.verdict = Verdict.HOSTILE
        elif state.log_lambda <= self.b_threshold:
            state.verdict = Verdict.BENIGN
        else:
            state.verdict = Verdict.UNDECIDED

        log.debug(
            "sprt_update",
            src_ip=src_ip,
            evidence_type=etype,
            log_lambda=round(state.log_lambda, 4),
            verdict=state.verdict.value,
            count=state.evidence_count,
        )
        return state.verdict

    def get_state(self, src_ip: str) -> SPRTState | None:
        """Return the current state for ``src_ip`` (or ``None`` if unseen)."""
        return self._states.get(src_ip)

    def verdict(self, src_ip: str) -> Verdict:
        state = self._states.get(src_ip)
        return state.verdict if state else Verdict.UNDECIDED

    def log_lambda(self, src_ip: str) -> float:
        state = self._states.get(src_ip)
        return state.log_lambda if state else 0.0

    def is_decided(self, src_ip: str) -> bool:
        state = self._states.get(src_ip)
        return bool(state and state.verdict in (Verdict.HOSTILE, Verdict.BENIGN))

    def confidence(self, src_ip: str) -> float:
        state = self._states.get(src_ip)
        if state is None:
            return 0.0
        return confidence_from_lambda(state.log_lambda, state.verdict)

    def known_src_ips(self) -> list[str]:
        return list(self._states.keys())
