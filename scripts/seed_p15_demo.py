#!/usr/bin/env python3
"""
P15 demo seeder — CHIMERA Tier-3 metrics dashboard.

Seeds idx_deception with two clearly-labeled SYNTHETIC cohorts so the
"money chart" (dwell WITH CHIMERA vs WITHOUT) is legible. Real live seeds
so far have sub-second dwell, so this provides representative comparison data.

HONESTY: every event carries synthetic=true and a scenario field
({baseline_static_honeypot | chimera_adaptive}). penetration_escaped is 0 for
every session by design (containment holds in both cohorts; the win is dwell).

Each event embeds an epoch `ts` spread across the last 24h. The Splunk
receivers/simple endpoint stamps ingest-time as _time, so the dashboard's
over-time panels do `eval _time=ts` to plot the honest 24h spread. The
single-value / money-chart / table panels do not depend on _time spread.

sourcetype: chimera:decision  (same as orchestrator output)
source:     chimera:demo_seed
"""
import json
import os
import random
import sys
import time
import urllib.request
import ssl
from pathlib import Path


def _load_dotenv() -> None:
    """Load repo-root .env (KEY=VALUE) into os.environ without extra deps.

    Credentials are never hardcoded: copy .env.example -> .env and fill
    SPLUNK_ADMIN_USER / SPLUNK_ADMIN_PASSWORD. Existing env vars win.
    """
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


_load_dotenv()

_host = os.environ.get("SPLUNK_HOST", "localhost")
_mgmt = os.environ.get("SPLUNK_MGMT_PORT", "8089")
SPLUNK = f"https://{_host}:{_mgmt}"
USER = os.environ["SPLUNK_ADMIN_USER"]
PASSWORD = os.environ["SPLUNK_ADMIN_PASSWORD"]
INDEX = "idx_deception"
SOURCETYPE = "chimera:decision"
SOURCE = "chimera:demo_seed"

random.seed(1515)  # deterministic demo

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

import base64
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


def post_event(event: dict):
    url = (f"{SPLUNK}/services/receivers/simple?index={INDEX}"
           f"&sourcetype={SOURCETYPE}&source={SOURCE}")
    body = json.dumps(event).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", AUTH)
    with urllib.request.urlopen(req, context=ctx) as r:
        return r.status


NOW = int(time.time())
DAY = 24 * 3600


def spread_ts(i, n):
    """Spread session i of n roughly evenly across the last 24h (with jitter)."""
    base = NOW - DAY + int((i + 0.5) * DAY / n)
    return base + random.randint(-600, 600)


def make_session_summary(scenario, idx, total, classification, dwell, src_ip, session):
    return {
        "ts": spread_ts(idx, total),
        "type": "session_summary",
        "src_ip": src_ip,
        "session": session,
        "classification": classification,
        "dwell_seconds": dwell,
        "event_count": random.randint(3, 40),
        "report_md": f"Synthetic {scenario} demo session ({classification}).",
        "generated_spl": "index=idx_deception | head 1",
        "penetration_escaped": 0,          # containment held by design
        "synthetic": True,
        "scenario": scenario,
    }


def seed():
    events = []

    # ---- Baseline cohort: static honeypot. Short dwell; attackers bail fast. ----
    # 13 sessions: classification mix, dwell 20-90s.
    baseline_specs = [
        ("AI", 25), ("AI", 31), ("AI", 22), ("HUMAN", 80),
        ("HUMAN", 65), ("HUMAN", 90), ("HUMAN", 48), ("AI", 28),
        ("HUMAN", 72), ("UNDECIDED", 35), ("AI", 19), ("HUMAN", 55),
        ("UNDECIDED", 41),
    ]
    n = len(baseline_specs)
    for i, (cls, dwell) in enumerate(baseline_specs):
        dwell = dwell + random.randint(-5, 8)
        ip = f"203.0.113.{10 + i}"
        events.append(make_session_summary(
            "baseline_static_honeypot", i, n, cls, dwell, ip, f"base-{i:02d}"))

    # ---- CHIMERA cohort: adaptive breadcrumbs keep attackers engaged longer. ----
    # AI under aggressive: 600-1800s. HUMAN under subtle: 120-400s. Still contained.
    chimera_specs = [
        ("AI", 1450), ("AI", 1720), ("AI", 980), ("AI", 1320),
        ("HUMAN", 240), ("HUMAN", 360), ("HUMAN", 180), ("HUMAN", 310),
        ("AI", 1610), ("HUMAN", 150), ("AI", 760), ("HUMAN", 400),
        ("AI", 1180),
    ]
    n = len(chimera_specs)
    actions_by_cls = {"AI": "aggressive", "HUMAN": "subtle", "UNDECIDED": "moderate"}
    for i, (cls, dwell) in enumerate(chimera_specs):
        dwell = dwell + random.randint(-30, 40)
        ip = f"198.51.100.{10 + i}"
        sess = f"chim-{i:02d}"
        events.append(make_session_summary(
            "chimera_adaptive", i, n, cls, dwell, ip, sess))
        # Companion deception_action event so the live-belief table has CHIMERA rows.
        action = actions_by_cls[cls]
        if cls == "AI":
            b = {"benign": 0.04, "human": 0.12, "ai": 0.84}
        elif cls == "HUMAN":
            b = {"benign": 0.06, "human": 0.80, "ai": 0.14}
        else:
            b = {"benign": 0.20, "human": 0.45, "ai": 0.35}
        events.append({
            "ts": spread_ts(i, n) + 5,
            "type": "deception_action",
            "src_ip": ip,
            "session": sess,
            "action": action,
            "belief": b,
            "synthetic": True,
            "scenario": "chimera_adaptive",
        })

    ok = 0
    for ev in events:
        try:
            if post_event(ev) == 200:
                ok += 1
        except Exception as e:
            print(f"FAILED event: {e}", file=sys.stderr)
    print(f"seeded {ok}/{len(events)} events "
          f"(baseline=13 session_summary, chimera=13 session_summary + 13 deception_action)")


if __name__ == "__main__":
    seed()
