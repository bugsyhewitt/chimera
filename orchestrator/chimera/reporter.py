"""P12: Foundation-Sec-8B adversary-engagement reporter.

Given a honeypot *session* (Cowrie ``session`` id, or a ``src_ip`` as a
fallback selector), pull its events from ``idx_honeypot`` via the Splunk MCP
read client, compactly summarise the session (logins, commands, eventids,
timestamps), and ask Foundation-Sec-8B (served by Ollama) to produce a
structured analyst report:

  1. observed TTPs
  2. MITRE ATT&CK technique IDs (``T####`` / ``T####.###``)
  3. IoCs
  4. a one-paragraph summary
  5. a recommended detection rule as SPL

The model is called over the **Ollama HTTP API** (``POST
{ollama_base_url}/api/generate``) with ``stream=false``, *not* the ``ollama``
CLI. This is CPU inference on an 8B model, so it is SLOW (tens of seconds to a
few minutes per report). We therefore use a long httpx timeout, bound the
output with ``options.num_predict``, and keep the temperature low for
determinism.

The report is returned as markdown. We post-process *minimally*: the model's
text is used as-is for the body, but we defensively guarantee the deliverable
contract the spec asks for — at least one ATT&CK technique id and at least one
SPL snippet — by extracting whatever the model emitted and, only if the model
omitted them, appending a derived fallback. This keeps the report honest
(model-generated when the model cooperates) while never returning a structurally
empty artifact.

CLI::

    uv run python -m chimera.reporter --session d0bb649bffb7
    uv run python -m chimera.reporter --src-ip 172.30.0.1
"""

from __future__ import annotations

import argparse
import asyncio
import re
from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from .config import Settings, get_settings
from .mcp_client import SplunkMCPClient
from .session import (
    command_input,
    event_timestamp,
    eventid_of,
    merge_raw,
    session_id,
    src_ip_of,
)

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Ollama call parameters. CPU inference on an 8B model is slow, so the timeout
# is generous; num_predict bounds the output; low temperature keeps the report
# deterministic and on-task.
# ---------------------------------------------------------------------------
OLLAMA_TIMEOUT_S = 600.0
OLLAMA_NUM_PREDICT = 700
OLLAMA_TEMPERATURE = 0.2

# How many of a session's events to feed as context (compact-most-relevant),
# so we never blow the context window on a noisy session.
MAX_EVENTS_IN_PROMPT = 80
MAX_COMMANDS_IN_PROMPT = 40

# Patterns to honour the deliverable contract.
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# An SPL snippet, for our purposes, is a fenced code block OR a line that looks
# like a Splunk search (contains a pipe-stage or `index=` / `search `).
_SPL_FENCE_RE = re.compile(r"```(?:spl|splunk)?\s*\n.*?\n```", re.IGNORECASE | re.DOTALL)
_SPL_LINE_RE = re.compile(r"^\s*(?:search\s+)?index\s*=|^\s*\|\s*\w+", re.MULTILINE)

# NOTE: Foundation-Sec-8B (FenkoHQ GGUF port) is a *completion* model, NOT a
# chat/instruct tune (Ollama reports capabilities=["completion"]). Two empirical
# pitfalls, both of which produce an immediate end-of-text after ~1-3 tokens:
#   1. Passing a separate ``system`` field activates the GGUF chat template and
#      the model stops at once. So we fold the instruction INTO the prompt and
#      send no ``system`` field.
#   2. Asking it to emit a fenced ``` code block makes it open a fence and stop.
# With the instruction in-prompt and the answer *primed* with the first heading,
# the model reliably streams a full, well-structured report (headed sections +
# an SPL block of its own). We extract ATT&CK ids / SPL from that text.
INSTRUCTION = (
    "You are a security analyst. Given the honeypot session events above, "
    "produce a structured report with these five sections: "
    "(1) observed TTPs, (2) MITRE ATT&CK technique IDs, (3) IoCs, "
    "(4) a one-paragraph summary, and (5) a recommended detection rule written "
    "in Splunk SPL. Use the exact MITRE ATT&CK technique id format such as "
    "T1059, T1078, or T1110.001."
)
# Primes the model's answer so a completion model continues rather than stops.
ANSWER_PREFIX = "## Observed TTPs\n"

# Kept as a module attribute for tests / introspection (mirror of INSTRUCTION).
SYSTEM_PROMPT = INSTRUCTION


# ===========================================================================
# MITRE Engage technique mapping (P16)
# ===========================================================================
# The deception-side counterpart to ATT&CK. Foundation-Sec-8B knows ATT&CK far
# better than Engage, so we DO NOT ask the model for Engage IDs — we derive the
# Engage section deterministically from what CHIMERA actually did in the session
# and append it to the report. This guarantees the IDs are real and present.
#
# IDs/names/approaches below are taken from the AUTHORITATIVE machine-readable
# MITRE Engage v1.0 framework data:
#   * Activities:           github.com/mitre/engage  Data/json/activities.json
#   * Approach mappings:    github.com/mitre/engage  Data/json/approach_activity_mappings.json
#   * Approaches:           github.com/mitre/engage  Data/json/approaches.json
#                           (also mirrored at https://engage.mitre.org/matrix/ and
#                            https://misp-galaxy.org/mitre-engage-framework/)
# Verified IDs/approaches (activity -> approaches it appears under):
#   EAC0005 Lures                 -> Detect, Direct, Disrupt
#   EAC0011 Pocket Litter         -> Reassure
#   EAC0014 Software Manipulation -> Collect, Direct, Disrupt
#   EAC0016 Network Manipulation  -> Prevent, Direct, Disrupt
#   EAC0006 Application Diversity -> Reassure, Motivate
#   EAC0021 Attack Vector Migration -> Direct
#   EAC0002 Network Monitoring    -> Collect
# (Engage uses "Approaches"/"Activities" rather than ATT&CK "Tactics"/"Techniques";
#  activity IDs are the EAC#### form. SAC#### IDs exist for the strategic
#  Plan/Analyze approaches but are out of scope for per-session technique tagging.)


@dataclass(frozen=True)
class EngageTechnique:
    """A single MITRE Engage activity (technique) reference."""

    id: str
    name: str
    approach: str  # primary Engage approach we are exercising it under
    rationale: str  # why this CHIMERA deception action maps here


# CHIMERA deception action -> MITRE Engage technique(s).
# Keys are stable internal action names (NOT the model's vocabulary).
ENGAGE_MAPPING: dict[str, tuple[EngageTechnique, ...]] = {
    # Planting decoy credentials / lure files (Cowrie bait creds + the planted
    # /home/admin/credentials.txt-style lures). Lures is the canonical Engage
    # activity for "decoys, breadcrumbs, or bait"; Pocket Litter covers the
    # supporting on-disk artifacts that sell the engagement narrative.
    "lures": (
        EngageTechnique(
            "EAC0005",
            "Lures",
            "Direct",
            "Cowrie bait credentials and planted lure files "
            "(e.g. /home/admin/credentials.txt) act as decoys/breadcrumbs to "
            "elicit and steer adversary activity.",
        ),
        EngageTechnique(
            "EAC0011",
            "Pocket Litter",
            "Reassure",
            "Planted credential/secret files are realistic on-disk artifacts "
            "that support the engagement narrative.",
        ),
    ),
    # The Beelzebub MCP decoy tool: a fake software capability/tool surface the
    # adversary (or their AI agent) interacts with. It is both a Lure and a
    # Software Manipulation (a manipulated software function presented as bait).
    "mcp_decoy": (
        EngageTechnique(
            "EAC0005",
            "Lures",
            "Direct",
            "The Beelzebub MCP decoy tool is bait presented to an AI agent to "
            "elicit tool-use behaviour (MCP tripwire).",
        ),
        EngageTechnique(
            "EAC0014",
            "Software Manipulation",
            "Direct",
            "The MCP decoy alters the software/tool surface the adversary sees "
            "to achieve a desired (revealing) response.",
        ),
    ),
    # Routing a hostile source into a honeypot (the deception gateway). The
    # router changes network reachability/properties to steer the adversary's
    # traffic onto the engagement system -> Network Manipulation. Attack Vector
    # Migration is the closely-related Direct activity (moving the attack onto
    # an engagement system) and is included as the secondary mapping.
    "route": (
        EngageTechnique(
            "EAC0016",
            "Network Manipulation",
            "Direct",
            "The deception gateway changes network properties (DNAT / nftables "
            "set) to steer a HOSTILE src_ip onto a honeypot.",
        ),
        EngageTechnique(
            "EAC0021",
            "Attack Vector Migration",
            "Direct",
            "Routing migrates the adversary's attack onto a controlled "
            "engagement system (the honeypot).",
        ),
    ),
    # Adapting breadcrumb intensity (POMDP controller, action in
    # none/subtle/moderate/aggressive). Varying the planted artifacts/services
    # by belief is Application Diversity (present a varied artifact surface to
    # keep the adversary engaged and reveal targeting); the act of changing the
    # presented breadcrumbs is also Software Manipulation under the Direct
    # approach.
    "adapt_breadcrumbs": (
        EngageTechnique(
            "EAC0006",
            "Application Diversity",
            "Motivate",
            "The POMDP controller varies breadcrumb intensity/artifacts by "
            "belief to sustain engagement (heavier for AI, sparser for humans).",
        ),
        EngageTechnique(
            "EAC0014",
            "Software Manipulation",
            "Direct",
            "Adapting the deception surface changes presented software "
            "properties to achieve a desired engagement effect.",
        ),
    ),
}


@dataclass
class DeceptionFacts:
    """What CHIMERA actually did, deception-wise, for one session.

    Drives the deterministic Engage section. ``lures_active`` defaults True
    because any Cowrie engagement is, by construction, a lure: the honeypot and
    its bait credentials are the lure. ``routed`` / ``mcp_decoy`` /
    ``breadcrumb_action`` are filled from idx_deception session facts when
    available (route + deception_action events), else conservatively False/None.
    """

    lures_active: bool = True
    routed: bool = False
    route_honeypot: str | None = None
    mcp_decoy: bool = False
    breadcrumb_action: str | None = None  # none|subtle|moderate|aggressive

    @property
    def breadcrumbs_adapted(self) -> bool:
        """True if the POMDP controller actually changed breadcrumb intensity
        beyond the inert baseline (anything other than ``none``)."""
        a = (self.breadcrumb_action or "").strip().lower()
        return a in {"subtle", "moderate", "aggressive"}


def engage_techniques_for(facts: DeceptionFacts) -> list[EngageTechnique]:
    """Resolve the ordered, de-duplicated Engage techniques for a session.

    Pure function of :class:`DeceptionFacts` so it is fully unit-testable and
    deterministic. Lures are always included for a honeypot engagement; the
    rest are gated on what actually happened in the session.
    """
    keys: list[str] = []
    if facts.lures_active:
        keys.append("lures")
    if facts.mcp_decoy:
        keys.append("mcp_decoy")
    if facts.routed:
        keys.append("route")
    if facts.breadcrumbs_adapted:
        keys.append("adapt_breadcrumbs")

    out: list[EngageTechnique] = []
    seen: set[str] = set()
    for key in keys:
        for tech in ENGAGE_MAPPING.get(key, ()):  # noqa: B007
            # De-dup by (id, approach) so e.g. Software Manipulation appearing
            # via both mcp_decoy and adapt_breadcrumbs is listed once.
            dk = f"{tech.id}|{tech.approach}"
            if dk in seen:
                continue
            seen.add(dk)
            out.append(tech)
    return out


def render_engage_section(facts: DeceptionFacts) -> str:
    """Render the ``## MITRE Engage Techniques`` markdown section."""
    techs = engage_techniques_for(facts)
    lines = ["## MITRE Engage Techniques"]
    if not techs:
        lines.append("")
        lines.append("_(no deception actions recorded for this session)_")
        return "\n".join(lines)
    lines.append("")
    lines.append(
        "Deception-side mapping (MITRE Engage v1.0) of the active-defense "
        "actions CHIMERA took in this engagement:"
    )
    lines.append("")
    for t in techs:
        lines.append(f"- **{t.id} {t.name}** ({t.approach}) — {t.rationale}")
    return "\n".join(lines)


def deception_facts_from_events(
    summary: dict[str, Any],
    deception_events: list[dict[str, Any]] | None = None,
) -> DeceptionFacts:
    """Derive :class:`DeceptionFacts` from the session summary + any
    idx_deception events (``type="route"`` / ``type="deception_action"``).

    Lures are always active for a Cowrie engagement. When idx_deception facts
    are provided we light up routing / breadcrumb-adaptation from the real
    events; the strongest (most aggressive) recorded breadcrumb action wins.
    """
    facts = DeceptionFacts(lures_active=True)

    # A successful login on the bait creds confirms the lure was taken (still
    # Lures either way, but useful as a guard for empty sessions).
    if not summary.get("logins") and not summary.get("commands") and not summary.get(
        "eventid_counts"
    ):
        facts.lures_active = False

    intensity_rank = {"none": 0, "subtle": 1, "moderate": 2, "aggressive": 3}
    best_rank = -1
    for ev in deception_events or []:
        merged = merge_raw(ev)
        etype = merged.get("type")
        if etype == "route":
            facts.routed = True
            hp = merged.get("honeypot")
            if hp:
                facts.route_honeypot = str(hp)
        elif etype == "deception_action":
            action = str(merged.get("action", "")).strip().lower()
            rank = intensity_rank.get(action, -1)
            if rank > best_rank:
                best_rank = rank
                facts.breadcrumb_action = action
        elif etype in ("mcp_tripwire", "mcp_decoy"):
            facts.mcp_decoy = True
    return facts


# ---------------------------------------------------------------------------
# Session fetch + compaction
# ---------------------------------------------------------------------------
# A wide pull, then filtered in-process by the session field (which the MCP
# layer doesn't extract to the top level — it lives in _raw). We can't reliably
# filter on `session` server-side, so we pull by src_ip when known (cheap +
# narrow) or do a bounded recent pull and filter locally by session id.
_BY_SRC_QUERY = (
    'search index=idx_honeypot sourcetype=cowrie:json src_ip="{src_ip}" '
    "earliest={lookback} | head {limit}"
)
_RECENT_QUERY = (
    "search index=idx_honeypot sourcetype=cowrie:json "
    "earliest={lookback} | head {limit}"
)
# idx_deception session facts (route / deception_action events) for the Engage
# section. Filtered by src_ip when known; bounded recent pull otherwise.
_DECEPTION_BY_SRC_QUERY = (
    'search index=idx_deception sourcetype=chimera:decision src_ip="{src_ip}" '
    "earliest={lookback} | head {limit}"
)
_DECEPTION_RECENT_QUERY = (
    "search index=idx_deception sourcetype=chimera:decision "
    "earliest={lookback} | head {limit}"
)


async def fetch_session_events(
    client: Any,
    *,
    session: str | None = None,
    src_ip: str | None = None,
    lookback: str = "-30d",
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Pull a session's Cowrie events from idx_honeypot.

    Selection precedence:
      * ``src_ip`` known -> narrow server-side pull by src_ip, then (if a
        ``session`` is also given) filter locally to that session.
      * only ``session`` known -> bounded recent pull, filtered locally by the
        ``session`` field parsed out of ``_raw``.
    """
    if src_ip:
        spl = _BY_SRC_QUERY.format(src_ip=src_ip, lookback=lookback, limit=limit)
    else:
        spl = _RECENT_QUERY.format(lookback=lookback, limit=limit)

    rows = await client.run_query(spl)

    if session is None:
        return rows

    matched: list[dict[str, Any]] = []
    for r in rows:
        if session_id(r, fallback_src_ip=False) == session:
            matched.append(r)
    return matched


async def fetch_deception_events(
    client: Any,
    *,
    session: str | None = None,
    src_ip: str | None = None,
    lookback: str = "-30d",
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Pull this session's CHIMERA decision events from idx_deception.

    These ``type="route"`` / ``type="deception_action"`` events feed the
    deterministic MITRE Engage section. Best-effort: any failure (e.g. index
    missing on this box) returns ``[]`` so the report still renders with the
    Lures baseline. When a ``session`` is given we filter locally to it.
    """
    if src_ip:
        spl = _DECEPTION_BY_SRC_QUERY.format(
            src_ip=src_ip, lookback=lookback, limit=limit
        )
    else:
        spl = _DECEPTION_RECENT_QUERY.format(lookback=lookback, limit=limit)
    try:
        rows = await client.run_query(spl)
    except Exception as exc:  # noqa: BLE001 - best-effort, never fail the report
        log.warning("deception_events_fetch_failed", error=str(exc))
        return []

    if session is None:
        return rows
    matched: list[dict[str, Any]] = []
    for r in rows:
        merged = merge_raw(r)
        if merged.get("session") == session:
            matched.append(r)
    # If the session field wasn't recorded on a deception event, keep src_ip
    # matches too (route events are keyed on src_ip, not session).
    if not matched and src_ip:
        return rows
    return matched


def summarize_session(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compact a session's events into a prompt-friendly summary dict."""
    src_ips: set[str] = set()
    sessions: set[str] = set()
    eventids: dict[str, int] = {}
    commands: list[str] = []
    logins: list[str] = []
    downloads: list[str] = []
    timestamps: list[float] = []

    for e in events:
        merged = merge_raw(e)
        ip = src_ip_of(e)
        if ip:
            src_ips.add(ip)
        sid = session_id(e, fallback_src_ip=False)
        if sid:
            sessions.add(sid)
        ev = eventid_of(e)
        if ev:
            eventids[ev] = eventids.get(ev, 0) + 1
        cmd = command_input(e)
        if cmd:
            commands.append(cmd)
        if ev in ("cowrie.login.success", "cowrie.login.failed"):
            user = merged.get("username")
            pw = merged.get("password")
            outcome = "success" if ev.endswith("success") else "failed"
            logins.append(f"{outcome} user={user} pass={pw}")
        url = merged.get("url")
        if ev == "cowrie.session.file_download" or url:
            if url:
                downloads.append(str(url))
        ts = event_timestamp(e)
        if ts is not None:
            timestamps.append(ts)

    timestamps.sort()
    return {
        "src_ips": sorted(src_ips),
        "sessions": sorted(sessions),
        "n_events": len(events),
        "eventid_counts": dict(sorted(eventids.items(), key=lambda kv: -kv[1])),
        "commands": commands[:MAX_COMMANDS_IN_PROMPT],
        "logins": logins[:MAX_COMMANDS_IN_PROMPT],
        "downloads": downloads[:MAX_COMMANDS_IN_PROMPT],
        "first_ts": timestamps[0] if timestamps else None,
        "last_ts": timestamps[-1] if timestamps else None,
        "duration_s": (
            round(timestamps[-1] - timestamps[0], 2)
            if len(timestamps) >= 2
            else 0.0
        ),
    }


def build_prompt(summary: dict[str, Any]) -> str:
    """Render the compact session summary into the model prompt body."""
    lines: list[str] = []
    lines.append("HONEYPOT SESSION (Cowrie SSH/Telnet)")
    lines.append(f"src_ip(s): {', '.join(summary['src_ips']) or 'unknown'}")
    lines.append(f"session id(s): {', '.join(summary['sessions']) or 'unknown'}")
    lines.append(f"event count: {summary['n_events']}")
    if summary["first_ts"] is not None:
        lines.append(
            f"time window (epoch): {summary['first_ts']} .. {summary['last_ts']} "
            f"({summary['duration_s']}s)"
        )
    lines.append("")
    lines.append("eventid tally:")
    for ev, n in summary["eventid_counts"].items():
        lines.append(f"  {ev}: {n}")
    if summary["logins"]:
        lines.append("")
        lines.append("login attempts:")
        for li in summary["logins"]:
            lines.append(f"  - {li}")
    if summary["commands"]:
        lines.append("")
        lines.append("shell commands (in order):")
        for c in summary["commands"]:
            lines.append(f"  $ {c}")
    if summary["downloads"]:
        lines.append("")
        lines.append("file download / fetch URLs:")
        for d in summary["downloads"]:
            lines.append(f"  - {d}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Ollama HTTP call
# ---------------------------------------------------------------------------
async def call_foundation_sec(
    prompt: str,
    *,
    settings: Settings,
    timeout: float = OLLAMA_TIMEOUT_S,
    num_predict: int = OLLAMA_NUM_PREDICT,
    temperature: float = OLLAMA_TEMPERATURE,
) -> str:
    """POST the prompt to Ollama's /api/generate and return the model text.

    ``stream=false`` so we get a single JSON body with the full ``response``.
    The long timeout reflects CPU inference on an 8B model.
    """
    url = f"{settings.ollama_base_url.rstrip('/')}/api/generate"
    # Fold the instruction into the prompt (no `system` field) and prime the
    # answer with the first heading; see the INSTRUCTION note above for why.
    full_prompt = f"{prompt}\n\n{INSTRUCTION}\n\n{ANSWER_PREFIX}"
    payload = {
        "model": settings.foundation_sec_model,
        "prompt": full_prompt,
        "stream": False,
        "options": {
            "num_predict": num_predict,
            "temperature": temperature,
        },
    }
    log.info(
        "ollama_generate_start",
        model=settings.foundation_sec_model,
        url=url,
        num_predict=num_predict,
    )
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
    text = str(data.get("response", "")).strip()
    log.info(
        "ollama_generate_done",
        chars=len(text),
        done_reason=data.get("done_reason"),
        eval_count=data.get("eval_count"),
    )
    # The model continues from ANSWER_PREFIX, so prepend it back to recover the
    # full first heading (only if the model didn't already echo it).
    if text and not text.lstrip().startswith("##"):
        text = ANSWER_PREFIX + text
    return text


# ---------------------------------------------------------------------------
# Minimal post-processing / deliverable-contract enforcement
# ---------------------------------------------------------------------------
def extract_attack_ids(text: str) -> list[str]:
    """Return de-duplicated MITRE ATT&CK technique ids found in ``text``."""
    seen: list[str] = []
    for m in ATTACK_ID_RE.findall(text):
        if m not in seen:
            seen.append(m)
    return seen


def has_spl_snippet(text: str) -> bool:
    """True if ``text`` contains a fenced SPL block or a search-like line."""
    return bool(_SPL_FENCE_RE.search(text) or _SPL_LINE_RE.search(text))


def extract_spl(text: str) -> str | None:
    """Pull the *generated SPL detection* out of a report's markdown.

    Precedence:
      1. A fenced ```spl ... ``` block (inner text), if present.
      2. Otherwise, the contiguous run of search-like lines (``index=`` /
         leading ``|``) — so we get just the search, NOT the whole report.

    Returns ``None`` if no SPL-looking content is found (caller should fall back
    to a derived detection). This deliberately returns only the search text so
    callers don't accidentally persist prose (e.g. a session id that Splunk's
    SearchParser would misread as a macro reference).
    """
    fence = _SPL_FENCE_RE.search(text)
    if fence:
        inner = fence.group(0)
        # Strip the ``` fences, keep the body.
        body = re.sub(r"^```(?:spl|splunk)?\s*\n", "", inner, flags=re.IGNORECASE)
        body = re.sub(r"\n```$", "", body)
        body = body.strip()
        if body:
            return body

    # No fence: collect the contiguous block of search-like lines.
    lines = text.splitlines()
    collected: list[str] = []
    started = False
    for ln in lines:
        is_search = bool(
            re.match(r"^\s*(?:search\s+)?index\s*=", ln, re.IGNORECASE)
            or re.match(r"^\s*\|\s*\w+", ln)
        )
        if is_search:
            collected.append(ln.strip())
            started = True
        elif started:
            # Continuation lines of a multi-line search start with `|` (already
            # caught) — a non-search, non-blank line ends the block.
            if ln.strip() == "":
                continue
            break
    if collected:
        return "\n".join(collected).strip()
    return None


def _fallback_attack_ids(summary: dict[str, Any]) -> list[str]:
    """Derive plausible ATT&CK ids from the session shape (last-resort only)."""
    ids: list[str] = []
    evs = summary["eventid_counts"]
    if summary["commands"]:
        ids.append("T1059")  # Command and Scripting Interpreter
    if any("cowrie.login" in e for e in evs):
        ids.append("T1110")  # Brute Force
    if "cowrie.login.success" in evs:
        ids.append("T1078")  # Valid Accounts
    if summary["downloads"] or any(
        "wget" in c or "curl" in c for c in summary["commands"]
    ):
        ids.append("T1105")  # Ingress Tool Transfer
    return ids or ["T1059"]


def _fallback_spl(summary: dict[str, Any]) -> str:
    """A derived SPL detection rule (last-resort only)."""
    ips = summary["src_ips"]
    ip_clause = f' src_ip="{ips[0]}"' if ips else ""
    return (
        "```spl\n"
        f"index=idx_honeypot sourcetype=cowrie:json{ip_clause}\n"
        '  eventid IN ("cowrie.login.success","cowrie.command.input",'
        '"cowrie.session.file_download")\n'
        "| stats count values(input) as commands by src_ip session\n"
        "| where count > 1\n"
        "```"
    )


def assemble_report(
    model_text: str,
    summary: dict[str, Any],
    *,
    session: str | None,
    src_ip: str | None,
    deception_facts: DeceptionFacts | None = None,
) -> str:
    """Wrap the model output in a stable markdown header and guarantee the
    deliverable contract (>=1 ATT&CK id, >=1 SPL snippet).

    The deterministic ``## MITRE Engage Techniques`` section is always appended
    (code-derived from ``deception_facts`` — defaults to a Lures-only baseline
    for any honeypot engagement so it is never absent)."""
    sid = session or (summary["sessions"][0] if summary["sessions"] else "unknown")
    ip = src_ip or (summary["src_ips"][0] if summary["src_ips"] else "unknown")

    header = [
        f"# Adversary Engagement Report — session `{sid}`",
        "",
        f"- **Source IP:** `{ip}`",
        f"- **Events analysed:** {summary['n_events']}",
        f"- **Model:** Foundation-Sec-8B",
        "",
        "---",
        "",
    ]

    body = model_text.strip() or "_(model returned no content)_"

    appended: list[str] = []
    if not extract_attack_ids(body):
        ids = _fallback_attack_ids(summary)
        appended.append(
            "\n## MITRE ATT&CK Technique IDs (derived)\n"
            + "\n".join(f"- {i}" for i in ids)
        )
    if not has_spl_snippet(body):
        appended.append(
            "\n## Recommended Detection Rule (SPL, derived)\n"
            + _fallback_spl(summary)
        )

    # Deterministic MITRE Engage section — always present (the model isn't
    # trusted to know Engage IDs). Defaults to a Lures baseline if no richer
    # deception facts were supplied.
    facts = deception_facts or deception_facts_from_events(summary, None)
    appended.append("\n" + render_engage_section(facts))

    return "\n".join(header) + body + ("\n" + "\n".join(appended) if appended else "")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
async def generate_engagement_report(
    session_id_arg: str | None = None,
    *,
    src_ip: str | None = None,
    settings: Settings | None = None,
    client: Any | None = None,
    lookback: str = "-30d",
) -> str:
    """Generate the markdown engagement report for one honeypot session.

    Provide ``session_id_arg`` (Cowrie session id) and/or ``src_ip`` as the
    selector. A caller may inject an already-connected MCP ``client`` (the loop
    does); otherwise one is created from ``settings``.
    """
    if not session_id_arg and not src_ip:
        raise ValueError("generate_engagement_report requires a session id or src_ip")

    settings = settings or get_settings()

    async def _run(c: Any) -> str:
        events = await fetch_session_events(
            c, session=session_id_arg, src_ip=src_ip, lookback=lookback
        )
        if not events:
            sel = session_id_arg or src_ip
            raise RuntimeError(
                f"no idx_honeypot events found for selector {sel!r} "
                f"(lookback={lookback})"
            )
        summary = summarize_session(events)
        # Best-effort idx_deception facts for the Engage section. Selector for
        # the deception pull is the session's own src_ip when we have one.
        dec_src = src_ip or (summary["src_ips"][0] if summary["src_ips"] else None)
        deception_events = await fetch_deception_events(
            c, session=session_id_arg, src_ip=dec_src, lookback=lookback
        )
        facts = deception_facts_from_events(summary, deception_events)
        prompt = build_prompt(summary)
        model_text = await call_foundation_sec(prompt, settings=settings)
        return assemble_report(
            model_text,
            summary,
            session=session_id_arg,
            src_ip=src_ip,
            deception_facts=facts,
        )

    if client is not None:
        return await _run(client)
    async with SplunkMCPClient.from_settings(settings) as c:
        return await _run(c)


# Backwards/spec-friendly alias matching the spec's single positional signature.
async def generate_engagement_report_for_session(session_id: str) -> str:  # noqa: D401
    return await generate_engagement_report(session_id)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m chimera.reporter",
        description="Generate a Foundation-Sec-8B adversary engagement report "
        "for a honeypot session.",
    )
    p.add_argument("--session", help="Cowrie session id selector.")
    p.add_argument("--src-ip", dest="src_ip", help="src_ip selector (fallback).")
    p.add_argument(
        "--lookback",
        default="-30d",
        help="Splunk earliest= window for the event pull (default: -30d).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ]
    )
    args = _build_arg_parser().parse_args(argv)
    if not args.session and not args.src_ip:
        log.error("reporter_no_selector", msg="provide --session or --src-ip")
        return 2

    report = asyncio.run(
        generate_engagement_report(
            args.session, src_ip=args.src_ip, lookback=args.lookback
        )
    )
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
