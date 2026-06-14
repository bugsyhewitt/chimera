"""CHIMERA router / deception gateway controller (Tier-2, packet P11).

Once Wald's SPRT (:mod:`chimera.sprt`) declares a ``src_ip`` **HOSTILE**, the
router decides *which* honeypot that source should be steered to and either
records the decision (``simulate`` mode, the default here) or enforces it via
nftables (``enforce`` mode, real code but NOT executed on this workstation).

Routing rule (the "shape" of the evidence we've seen for the src_ip drives it):

    SSH-shaped intent   -> Cowrie  (port 2222)
        evidence dominated by Cowrie SSH events (``cowrie.*`` eventids:
        login/command/session/file_download) or Suricata auth-brute signatures.
    HTTP/scanner-shaped -> Galah   (port 8080)
        evidence dominated by web-scanner signals: Galah/``http`` events, a
        Suricata ``port_scan_signature``/``anomalous_user_agent``, or
        ``normal_http``.
    default             -> Cowrie  (port 2222)
        no usable evidence, or a tie -> Cowrie (SSH brute-force is the dominant
        threat model and the calibrated smoke-test attacker is SSH-shaped).

"Shape" is computed from the per-evidence-type tally that ``SPRTClassifier``
already keeps (``SPRTState.evidence``), so the router needs no extra polling: it
maps each evidence type to SSH or WEB and picks the heavier bucket.

Two modes (``CHIMERA_ROUTER_MODE`` in ``.env``, default ``simulate``):

* ``simulate`` — the demoable path that runs on this operator workstation. We do
  NOT touch host networking. Instead a ``type="route"`` event is written to
  ``idx_deception`` via :class:`~chimera.deception_writer.DeceptionWriter`:
  ``{type:"route", src_ip, decision:"route", honeypot, port, mode:"simulate",
  reason, ts}``. The smoke test asserts this event.

* ``enforce`` — real, correct nftables wiring (NOT executed here; guarded by the
  mode). We maintain two nftables sets, ``chimera_route_cowrie`` /
  ``chimera_route_galah``, add the src_ip to the appropriate set, and rely on
  pre-existing DNAT rules that redirect those sets to the honeypot ports. The
  command construction is factored into the pure
  :func:`render_nft_commands` so it is unit-testable without executing anything;
  :func:`enforce_route` is the only function that shells out and it refuses to
  run unless ``mode == "enforce"``.

Why ``simulate`` is the default *here* (see CLAUDE.md "Router" note): this host
is the operator's workstation and Docker owns its iptables/nftables chains —
issuing host nft rules would fight Docker and risk the demo. Mid-stream TCP
redirection of an already-established connection is out of scope; the realistic
model is per-source routing applied to the attacker's *next* connection, which
nftables-set DNAT does cleanly in a real deployment. So on this box we record
the would-route decision (fully demoable, lands in Splunk) and keep ``enforce``
as audited, tested, but un-executed code.
"""

from __future__ import annotations

import subprocess  # nosec B404 — only used in enforce mode, guarded; see enforce_route
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

import structlog

from .config import Settings, get_settings
from .deception_writer import DeceptionWriter

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Honeypots, ports, and nftables set names
# ---------------------------------------------------------------------------
class Honeypot(str, Enum):
    """Target honeypot for a routed source. ``str`` mixin for clean JSON."""

    COWRIE = "cowrie"
    GALAH = "galah"


# Ingress port each honeypot listens on (the DNAT target in a real deployment).
HONEYPOT_PORTS: dict[Honeypot, int] = {
    Honeypot.COWRIE: 2222,
    Honeypot.GALAH: 8080,
}

# nftables set names that hold routed source IPs per honeypot. Pre-existing DNAT
# rules in the real deployment redirect packets from members of these sets to the
# corresponding honeypot port.
NFT_SETS: dict[Honeypot, str] = {
    Honeypot.COWRIE: "chimera_route_cowrie",
    Honeypot.GALAH: "chimera_route_galah",
}

# nftables table + family the sets live in (a real deployment provisions these
# out of band; the router only adds *elements*).
NFT_TABLE = "chimera"
NFT_FAMILY = "inet"

# Router operating modes.
MODE_SIMULATE = "simulate"
MODE_ENFORCE = "enforce"


# ---------------------------------------------------------------------------
# Evidence-shape classification
# ---------------------------------------------------------------------------
# Evidence types (LIKELIHOOD_TABLE keys, plus a few markers) bucketed by the
# honeypot they imply. SSH-shaped -> Cowrie; web/scanner-shaped -> Galah.
_SSH_EVIDENCE = frozenset(
    {
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.session.connect",
        "cowrie.session.file_download",
        "cowrie.session.closed",
        "auth_failure_burst",  # Suricata brute-force signature ⇒ SSH brute
    }
)
_WEB_EVIDENCE = frozenset(
    {
        "port_scan_signature",
        "anomalous_user_agent",
        "normal_http",
        "galah",  # Galah HTTP honeypot marker (if ever surfaced as an evtype)
        "http",
    }
)


def _is_ssh_shaped(etype: str) -> bool:
    e = etype.lower()
    return e in _SSH_EVIDENCE or e.startswith("cowrie.")


def _is_web_shaped(etype: str) -> bool:
    e = etype.lower()
    return e in _WEB_EVIDENCE or e.startswith("galah") or e.startswith("http")


@dataclass(frozen=True)
class Route:
    """A routing decision for a hostile ``src_ip``."""

    honeypot: Honeypot
    port: int
    reason: str

    def as_event(self, src_ip: str, *, mode: str, ts: int | None = None) -> dict[str, Any]:
        """Render the ``type="route"`` decision event for ``idx_deception``."""
        return {
            "type": "route",
            "src_ip": src_ip,
            "decision": "route",
            "honeypot": self.honeypot.value,
            "port": self.port,
            "mode": mode,
            "reason": self.reason,
            "ts": ts if ts is not None else int(time.time()),
        }


# ---------------------------------------------------------------------------
# Routing decision (pure)
# ---------------------------------------------------------------------------
def route_for(src_ip: str, evidence: Mapping[str, int] | None) -> Route:
    """Decide which honeypot ``src_ip`` should be steered to from its evidence.

    ``evidence`` is the per-evidence-type tally kept by ``SPRTClassifier``
    (``SPRTState.evidence``): a mapping of evidence-type key -> count. We sum the
    counts into an SSH bucket and a WEB bucket and pick the heavier one; an
    empty/missing tally or an exact tie falls back to Cowrie (SSH is the dominant
    threat model and the calibrated attacker is SSH-shaped).
    """
    evidence = evidence or {}
    ssh_score = 0
    web_score = 0
    for etype, count in evidence.items():
        try:
            c = int(count)
        except (TypeError, ValueError):
            c = 0
        if c <= 0:
            continue
        if _is_ssh_shaped(etype):
            ssh_score += c
        elif _is_web_shaped(etype):
            web_score += c
        # Unknown/neutral evidence (e.g. "unknown") contributes to neither bucket.

    if web_score > ssh_score:
        return Route(
            honeypot=Honeypot.GALAH,
            port=HONEYPOT_PORTS[Honeypot.GALAH],
            reason=(
                f"web/scanner-shaped evidence (web={web_score} > ssh={ssh_score}) "
                f"-> Galah HTTP honeypot"
            ),
        )
    if ssh_score > 0:
        return Route(
            honeypot=Honeypot.COWRIE,
            port=HONEYPOT_PORTS[Honeypot.COWRIE],
            reason=(
                f"SSH-shaped evidence (ssh={ssh_score} >= web={web_score}) "
                f"-> Cowrie SSH honeypot"
            ),
        )
    # No usable directional evidence at all -> default to Cowrie.
    return Route(
        honeypot=Honeypot.COWRIE,
        port=HONEYPOT_PORTS[Honeypot.COWRIE],
        reason="no directional evidence -> default Cowrie SSH honeypot",
    )


# ---------------------------------------------------------------------------
# enforce mode: nftables command construction (pure) + guarded execution
# ---------------------------------------------------------------------------
def render_nft_commands(route: Route, src_ip: str) -> list[str]:
    """Build the exact ``nft`` commands to route ``src_ip`` to ``route.honeypot``.

    Pure: returns the command strings without executing anything, so it is fully
    unit-testable. The commands add ``src_ip`` as an element of the honeypot's
    nftables set (idempotent: ``add element`` on an existing member is a no-op in
    nftables). Pre-existing DNAT rules from each set to the honeypot port do the
    actual redirect; the router only manages set membership.

    Example for a Cowrie route of 172.30.0.1::

        nft add element inet chimera chimera_route_cowrie { 172.30.0.1 }
    """
    set_name = NFT_SETS[route.honeypot]
    return [
        f"nft add element {NFT_FAMILY} {NFT_TABLE} {set_name} {{ {src_ip} }}",
    ]


def render_nft_argv(route: Route, src_ip: str) -> list[list[str]]:
    """Same as :func:`render_nft_commands` but as argv lists for ``subprocess``.

    Avoids a shell entirely (no ``shell=True``), so ``src_ip`` cannot be
    interpreted as shell metacharacters.
    """
    set_name = NFT_SETS[route.honeypot]
    return [
        ["nft", "add", "element", NFT_FAMILY, NFT_TABLE, set_name, "{", src_ip, "}"],
    ]


def enforce_route(route: Route, src_ip: str, *, mode: str) -> list[str]:
    """Add ``src_ip`` to the honeypot's nftables set — ONLY when mode==enforce.

    This is the only function in the module that shells out. It is guarded: if
    ``mode`` is not ``"enforce"`` it raises ``RuntimeError`` and runs nothing, so
    accidental invocation under the default ``simulate`` mode can never touch host
    networking. Returns the list of commands that were executed (for logging).

    NOTE: this is intentionally NOT exercised on the operator workstation (Docker
    owns the host nftables chains); it is real, tested-by-construction code for a
    real deployment where the ``chimera`` table + DNAT rules are provisioned.
    """
    if mode != MODE_ENFORCE:
        raise RuntimeError(
            f"enforce_route called in mode={mode!r}; refusing to touch host "
            f"networking (guard: only runs when mode=={MODE_ENFORCE!r})"
        )
    commands = render_nft_commands(route, src_ip)
    for argv in render_nft_argv(route, src_ip):
        log.info("router_enforce_exec", argv=argv, src_ip=src_ip)
        subprocess.run(argv, check=True)  # nosec B603 — fixed argv, no shell
    return commands


# ---------------------------------------------------------------------------
# Router: ties routing decision to a mode (simulate writes; enforce shells out)
# ---------------------------------------------------------------------------
class Router:
    """Decides + applies routing for hostile sources, honoring the configured mode.

    Dedupes per ``src_ip`` (one route decision per source for the lifetime of the
    instance). In ``simulate`` mode it writes a ``type="route"`` event via the
    provided :class:`DeceptionWriter`; in ``enforce`` mode it adds the src_ip to
    the appropriate nftables set. Routing never raises into the caller (the poll
    loop): exceptions are caught and logged.
    """

    def __init__(self, writer: DeceptionWriter, *, mode: str = MODE_SIMULATE) -> None:
        self._writer = writer
        self._mode = mode.strip().lower() if mode else MODE_SIMULATE
        self._routed: set[str] = set()

    @classmethod
    def from_settings(
        cls, writer: DeceptionWriter, settings: Settings | None = None
    ) -> "Router":
        s = settings or get_settings()
        return cls(writer, mode=s.router_mode)

    @property
    def mode(self) -> str:
        return self._mode

    def already_routed(self, src_ip: str) -> bool:
        return src_ip in self._routed

    async def route(
        self, src_ip: str, evidence: Mapping[str, int] | None
    ) -> Route | None:
        """Route a HOSTILE ``src_ip``. Returns the :class:`Route` taken, or None.

        Idempotent per ``src_ip`` (returns ``None`` on a duplicate). Never raises:
        any error is logged and ``None`` is returned so the poll loop stays alive.
        """
        if src_ip in self._routed:
            return None
        try:
            route = route_for(src_ip, evidence)
            if self._mode == MODE_ENFORCE:
                # Real path (NOT on this workstation). enforce_route is guarded.
                commands = enforce_route(route, src_ip, mode=self._mode)
                log.info(
                    "router_enforced",
                    src_ip=src_ip,
                    honeypot=route.honeypot.value,
                    port=route.port,
                    commands=commands,
                )
            else:
                # Default simulate path: record the would-route decision.
                event = route.as_event(src_ip, mode=MODE_SIMULATE)
                await self._writer.write_decision(event)
                log.info(
                    "router_simulated",
                    src_ip=src_ip,
                    honeypot=route.honeypot.value,
                    port=route.port,
                    reason=route.reason,
                )
            self._routed.add(src_ip)
            return route
        except Exception as e:  # noqa: BLE001 — routing must never kill the loop
            log.warning("router_failed", src_ip=src_ip, mode=self._mode, error=str(e))
            return None
