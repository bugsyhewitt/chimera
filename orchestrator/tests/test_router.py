"""Unit tests for the CHIMERA router / deception gateway (chimera.router).

No host changes and no live Splunk are needed: routing is a pure function of an
evidence tally, ``render_nft_commands`` is pure, and the simulate path is tested
against a fake :class:`DeceptionWriter`. The enforce-mode guard is verified to
NOT shell out under the default simulate mode.
"""

from __future__ import annotations

import pytest

from chimera.router import (
    MODE_ENFORCE,
    MODE_SIMULATE,
    NFT_SETS,
    Honeypot,
    Route,
    Router,
    enforce_route,
    render_nft_argv,
    render_nft_commands,
    route_for,
)

# Mark only the async tests (sync tests below are collected normally).
asyncio_test = pytest.mark.asyncio

ATTACKER_IP = "172.30.0.1"


# --------------------------------------------------------------------------
# Fake writer: records events without touching Splunk.
# --------------------------------------------------------------------------
class FakeWriter:
    def __init__(self) -> None:
        self.events: list[dict] = []

    async def write_decision(self, event: dict) -> None:
        self.events.append(event)


# --------------------------------------------------------------------------
# route_for: shape -> honeypot
# --------------------------------------------------------------------------
def test_ssh_evidence_routes_to_cowrie() -> None:
    # The calibrated smoke-test attacker is SSH-shaped (Cowrie eventids).
    evidence = {
        "cowrie.login.failed": 3,
        "cowrie.login.success": 1,
        "cowrie.command.input": 2,
        "cowrie.session.connect": 1,
    }
    route = route_for(ATTACKER_IP, evidence)
    assert route.honeypot is Honeypot.COWRIE
    assert route.port == 2222
    assert "ssh" in route.reason.lower()


def test_web_scanner_evidence_routes_to_galah() -> None:
    evidence = {
        "port_scan_signature": 2,
        "anomalous_user_agent": 3,
        "normal_http": 1,
    }
    route = route_for(ATTACKER_IP, evidence)
    assert route.honeypot is Honeypot.GALAH
    assert route.port == 8080
    assert "web" in route.reason.lower() or "galah" in route.reason.lower()


def test_default_routes_to_cowrie_on_no_evidence() -> None:
    assert route_for(ATTACKER_IP, None).honeypot is Honeypot.COWRIE
    assert route_for(ATTACKER_IP, {}).honeypot is Honeypot.COWRIE
    # Only neutral/unknown evidence (no SSH/web direction) -> default Cowrie.
    assert route_for(ATTACKER_IP, {"unknown": 5}).honeypot is Honeypot.COWRIE


def test_tie_breaks_to_cowrie() -> None:
    # Equal SSH and web counts -> SSH wins (default threat model).
    evidence = {"cowrie.login.failed": 2, "port_scan_signature": 2}
    assert route_for(ATTACKER_IP, evidence).honeypot is Honeypot.COWRIE


def test_web_majority_beats_ssh_minority() -> None:
    evidence = {"cowrie.session.connect": 1, "port_scan_signature": 5}
    assert route_for(ATTACKER_IP, evidence).honeypot is Honeypot.GALAH


def test_suricata_auth_burst_is_ssh_shaped() -> None:
    assert route_for(ATTACKER_IP, {"auth_failure_burst": 3}).honeypot is Honeypot.COWRIE


def test_zero_and_bad_counts_ignored() -> None:
    # Non-positive / non-int counts must not vote.
    evidence = {"cowrie.login.failed": 0, "port_scan_signature": 4, "http": "x"}
    assert route_for(ATTACKER_IP, evidence).honeypot is Honeypot.GALAH


# --------------------------------------------------------------------------
# render_nft_commands / render_nft_argv: pure command construction
# --------------------------------------------------------------------------
def test_render_nft_commands_cowrie_set() -> None:
    route = route_for(ATTACKER_IP, {"cowrie.login.failed": 3})
    cmds = render_nft_commands(route, ATTACKER_IP)
    assert cmds == [
        f"nft add element inet chimera chimera_route_cowrie {{ {ATTACKER_IP} }}"
    ]
    # The command targets the Cowrie set, never the Galah set.
    assert NFT_SETS[Honeypot.COWRIE] in cmds[0]
    assert NFT_SETS[Honeypot.GALAH] not in cmds[0]


def test_render_nft_commands_galah_set() -> None:
    route = route_for(ATTACKER_IP, {"port_scan_signature": 4})
    cmds = render_nft_commands(route, ATTACKER_IP)
    assert cmds == [
        f"nft add element inet chimera chimera_route_galah {{ {ATTACKER_IP} }}"
    ]


def test_render_nft_argv_is_shell_free() -> None:
    route = Route(honeypot=Honeypot.COWRIE, port=2222, reason="x")
    argv = render_nft_argv(route, ATTACKER_IP)
    assert argv == [
        ["nft", "add", "element", "inet", "chimera",
         "chimera_route_cowrie", "{", ATTACKER_IP, "}"]
    ]


# --------------------------------------------------------------------------
# simulate mode: writes a well-formed route event via the writer
# --------------------------------------------------------------------------
@asyncio_test
async def test_simulate_writes_route_event() -> None:
    writer = FakeWriter()
    router = Router(writer, mode=MODE_SIMULATE)  # type: ignore[arg-type]
    route = await router.route(ATTACKER_IP, {"cowrie.login.failed": 3})

    assert route is not None and route.honeypot is Honeypot.COWRIE
    assert len(writer.events) == 1
    ev = writer.events[0]
    assert ev["type"] == "route"
    assert ev["src_ip"] == ATTACKER_IP
    assert ev["decision"] == "route"
    assert ev["honeypot"] == "cowrie"
    assert ev["port"] == 2222
    assert ev["mode"] == "simulate"
    assert isinstance(ev["reason"], str) and ev["reason"]
    assert isinstance(ev["ts"], int)


@asyncio_test
async def test_simulate_dedupes_per_src_ip() -> None:
    writer = FakeWriter()
    router = Router(writer, mode=MODE_SIMULATE)  # type: ignore[arg-type]
    first = await router.route(ATTACKER_IP, {"cowrie.login.failed": 3})
    second = await router.route(ATTACKER_IP, {"cowrie.login.failed": 3})
    assert first is not None
    assert second is None  # duplicate -> no-op
    assert len(writer.events) == 1
    assert router.already_routed(ATTACKER_IP)


@asyncio_test
async def test_simulate_galah_route_event() -> None:
    writer = FakeWriter()
    router = Router(writer, mode=MODE_SIMULATE)  # type: ignore[arg-type]
    await router.route("10.0.0.9", {"port_scan_signature": 5})
    ev = writer.events[0]
    assert ev["honeypot"] == "galah"
    assert ev["port"] == 8080


# --------------------------------------------------------------------------
# enforce-mode guard: never shells out under simulate
# --------------------------------------------------------------------------
def test_enforce_route_guard_rejects_simulate_mode() -> None:
    route = route_for(ATTACKER_IP, {"cowrie.login.failed": 3})
    with pytest.raises(RuntimeError):
        enforce_route(route, ATTACKER_IP, mode=MODE_SIMULATE)


@asyncio_test
async def test_simulate_router_never_calls_subprocess(monkeypatch) -> None:
    # Belt-and-braces: if simulate mode ever shelled out, this would fail loudly.
    import chimera.router as router_mod

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003
        raise AssertionError("simulate mode must not invoke subprocess.run")

    monkeypatch.setattr(router_mod.subprocess, "run", _boom)
    writer = FakeWriter()
    router = Router(writer, mode=MODE_SIMULATE)  # type: ignore[arg-type]
    route = await router.route(ATTACKER_IP, {"cowrie.login.failed": 3})
    assert route is not None
    assert len(writer.events) == 1


def test_enforce_route_executes_only_in_enforce_mode(monkeypatch) -> None:
    # Verify the enforce path uses the constructed argv (without a real nft host).
    import chimera.router as router_mod

    calls: list[list[str]] = []

    def _fake_run(argv, **kwargs):  # noqa: ANN001, ANN003
        calls.append(argv)

        class _R:
            returncode = 0

        return _R()

    monkeypatch.setattr(router_mod.subprocess, "run", _fake_run)
    route = route_for(ATTACKER_IP, {"cowrie.login.failed": 3})
    cmds = enforce_route(route, ATTACKER_IP, mode=MODE_ENFORCE)
    assert cmds == render_nft_commands(route, ATTACKER_IP)
    assert calls == render_nft_argv(route, ATTACKER_IP)


@asyncio_test
async def test_router_route_never_raises_on_writer_error() -> None:
    class BoomWriter:
        async def write_decision(self, event: dict) -> None:
            raise RuntimeError("splunk down")

    router = Router(BoomWriter(), mode=MODE_SIMULATE)  # type: ignore[arg-type]
    # Must swallow the error and return None, not propagate into the loop.
    assert await router.route(ATTACKER_IP, {"cowrie.login.failed": 1}) is None
    # And it should NOT mark the ip routed, so a later retry can succeed.
    assert not router.already_routed(ATTACKER_IP)
