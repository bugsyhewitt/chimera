"""Unit tests for the behavioral lure-pursuit channel (chimera.channel_behavioral)."""

from __future__ import annotations

import json

from chimera.channel_behavioral import (
    MAX_POSITIVE_LLR,
    NO_PURSUIT_LLR,
    behavioral_log_lr,
    behavioral_log_lr_from_events,
)


def test_no_commands_is_zero() -> None:
    llr, detail = behavioral_log_lr([])
    assert llr == 0.0
    assert detail["reason"] == "no_commands"


def test_shell_activity_no_lure_leans_human() -> None:
    llr, detail = behavioral_log_lr(["ls", "pwd", "whoami", "uname -a"])
    assert llr == NO_PURSUIT_LLR
    assert detail["n_lure_hits"] == 0
    assert detail["reason"] == "shell_activity_no_lure_pursuit"


def test_lure_pursuit_leans_ai() -> None:
    cmds = [
        "ls -la /home/admin",
        "cat /home/admin/credentials.txt",
        "cat /root/.aws/credentials",
        "cat .ssh/id_rsa",
    ]
    llr, detail = behavioral_log_lr(cmds)
    assert llr > 1.0
    assert detail["n_lure_hits"] >= 3
    assert detail["n_distinct_lures"] >= 3
    assert detail["reason"] == "lure_pursuit"


def test_lure_pursuit_saturates() -> None:
    cmds = ["cat /home/admin/credentials.txt"] * 20
    llr, _ = behavioral_log_lr(cmds)
    assert llr <= MAX_POSITIVE_LLR


def test_distinct_lures_score_higher_than_repeats() -> None:
    repeats = ["cat /home/admin/credentials.txt"] * 3
    distinct = [
        "cat /home/admin/credentials.txt",
        "cat /root/.aws/credentials",
        "cat .ssh/id_rsa",
    ]
    llr_rep, _ = behavioral_log_lr(repeats)
    llr_dist, _ = behavioral_log_lr(distinct)
    assert llr_dist >= llr_rep


def test_custom_patterns() -> None:
    llr, detail = behavioral_log_lr(
        ["cat /opt/secret_flag"], patterns=(r"secret_flag",)
    )
    assert llr > 0
    assert detail["n_lure_hits"] == 1


def test_from_events_only_uses_command_input() -> None:
    events = [
        {"_raw": json.dumps({"eventid": "cowrie.session.connect"})},
        {"_raw": json.dumps({"eventid": "cowrie.login.success"})},
        {
            "_raw": json.dumps(
                {"eventid": "cowrie.command.input", "input": "cat /root/.aws/credentials"}
            )
        },
        {
            "_raw": json.dumps(
                {"eventid": "cowrie.command.input", "input": "cat .ssh/id_rsa"}
            )
        },
    ]
    llr, detail = behavioral_log_lr_from_events(events)
    assert detail["n_commands"] == 2
    assert detail["n_lure_hits"] == 2
    assert llr > 1.0
