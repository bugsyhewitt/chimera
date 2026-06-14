"""Channel 2 of the AI-vs-human classifier: behavioral lure-pursuit.

We plant *lures* in the honeypot's fake filesystem — credential-looking paths
and "next-step" breadcrumbs that a curious intruder might chase. The
discriminating behaviour:

- A *human* attacker gets bored, distracted, or suspicious. They poke at one or
  two things and disengage; a too-convenient ``credentials.txt`` makes a
  seasoned human *more* wary, not less.
- An *LLM agent* doggedly pursues the planted goal. Given a credentials file it
  will ``cat`` it, then try to *use* what it found, following the breadcrumb
  chain with machine persistence and little suspicion.

So: **the more a session pursues planted lures, the more AI-like it is.** We
score lure-pursuit persistence from the session's ``cowrie.command.input``
events and emit a log-LR that is positive (AI) when lures are chased and mildly
negative (human) when the session touches the shell but ignores every lure.

The lure-path list is configurable (:data:`DEFAULT_LURE_PATTERNS`); detection is
by matching the command ``input`` text, so it works whether or not the fake
files actually exist in Cowrie's FS.
"""

from __future__ import annotations

import re
from typing import Any

from .session import command_input, eventid_of

# ---------------------------------------------------------------------------
# Lure patterns — tunable. Each is a substring/regex matched against the
# (lower-cased) command input. These are the planted credential-looking paths
# and breadcrumb artifacts.
# ---------------------------------------------------------------------------
DEFAULT_LURE_PATTERNS: tuple[str, ...] = (
    r"/home/admin/credentials\.txt",
    r"\.ssh/id_rsa",
    r"/root/\.aws/credentials",
    r"/root/\.aws/config",
    r"\.bash_history",
    r"/var/backups/",
    r"/home/\w+/credentials",
    r"vault[_-]?token",
    r"\.env\b",
    r"todo\.txt",
    r"readme_first\.txt",
    r"next[_-]?step",
)

# Commands that count as "inspecting" a lure (reading/searching/exfil).
INSPECT_COMMANDS = (
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "ls",
    "find",
    "cp",
    "scp",
    "curl",
    "wget",
    "ssh",
    "vi",
    "nano",
    "strings",
    "xxd",
    "base64",
)

# Per-lure-hit weight and saturation. Three+ distinct lure interactions is a
# decisive behavioural tell; we saturate so a loop spamming one lure can't run
# the score away.
PER_HIT_LLR = 1.1
MAX_POSITIVE_LLR = 2.6
# Touched the shell (>=1 command) but ignored every lure -> mild human pull.
NO_PURSUIT_LLR = -0.6
# Distinct-lure bonus: chasing *several different* breadcrumbs is more
# agent-like than re-reading one file.
DISTINCT_BONUS = 0.4


_COMPILED = [re.compile(p, re.IGNORECASE) for p in DEFAULT_LURE_PATTERNS]


def _compile(patterns: tuple[str, ...] | list[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def _command_word(cmd: str) -> str:
    """First bare word of a command line (the program being run)."""
    cmd = cmd.strip()
    if not cmd:
        return ""
    # Strip leading env assignments / sudo.
    parts = cmd.split()
    head = parts[0]
    if head in ("sudo", "env") and len(parts) > 1:
        head = parts[1]
    return head.rsplit("/", 1)[-1].lower()


def behavioral_log_lr(
    commands: list[str],
    *,
    patterns: tuple[str, ...] | list[str] | None = None,
) -> tuple[float, dict[str, Any]]:
    """Score lure-pursuit from a session's command-input strings.

    Returns ``(log_lr, detail)``. ``log_lr`` is log P(obs|AI)/P(obs|human):
    positive (AI) the more distinct planted lures the session inspects, mildly
    negative (human) if the session ran commands but chased no lure, and 0 if
    no shell commands were seen at all (no evidence).
    """
    compiled = _compile(tuple(patterns)) if patterns is not None else _COMPILED

    n_commands = len(commands)
    hits: list[str] = []
    matched_patterns: set[str] = set()
    n_inspect_hits = 0
    for cmd in commands:
        word = _command_word(cmd)
        is_inspect = word in INSPECT_COMMANDS
        for pat in compiled:
            if pat.search(cmd):
                # A lure path referenced by any command is a pursuit signal;
                # an inspect/exfil verb (cat/grep/scp/...) is the meaningful
                # case and is tracked separately for observability.
                hits.append(cmd)
                matched_patterns.add(pat.pattern)
                if is_inspect:
                    n_inspect_hits += 1
                break

    detail: dict[str, Any] = {
        "n_commands": n_commands,
        "n_lure_hits": len(hits),
        "n_inspect_hits": n_inspect_hits,
        "n_distinct_lures": len(matched_patterns),
        "matched_patterns": sorted(matched_patterns),
    }

    if n_commands == 0:
        detail["reason"] = "no_commands"
        return 0.0, detail

    if not hits:
        detail["reason"] = "shell_activity_no_lure_pursuit"
        return NO_PURSUIT_LLR, detail

    score = PER_HIT_LLR * len(hits)
    if len(matched_patterns) >= 2:
        score += DISTINCT_BONUS * (len(matched_patterns) - 1)
    log_lr = min(MAX_POSITIVE_LLR, score)
    detail["reason"] = "lure_pursuit"
    return log_lr, detail


def behavioral_log_lr_from_events(
    events: list[dict[str, Any]],
    *,
    patterns: tuple[str, ...] | list[str] | None = None,
) -> tuple[float, dict[str, Any]]:
    """Same as :func:`behavioral_log_lr` but extracts commands from raw events.

    Only ``cowrie.command.input`` events contribute commands; their ``input``
    field is the shell line.
    """
    commands: list[str] = []
    for ev in events:
        eid = eventid_of(ev)
        if eid and eid.startswith("cowrie.command"):
            cmd = command_input(ev)
            if cmd:
                commands.append(cmd)
        else:
            # Some feeds put the command in ``input`` without a strict eventid.
            cmd = command_input(ev)
            if cmd and eid is None:
                commands.append(cmd)
    return behavioral_log_lr(commands, patterns=patterns)
