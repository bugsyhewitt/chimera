"""Live round-trip test for the DeceptionWriter write-back path.

Writes a placeholder decision event to ``idx_deception`` via the REST simple
receiver, then confirms (via the MCP read client) that an event with the same
unique sentinel ``src_ip`` appears in the index. Indexing is async, so the
readback polls/retries up to ~30s.

The sentinel src_ip is drawn from the TEST-NET-3 block (203.0.113.0/24,
RFC 5737 documentation range) with a random last octet, making the test
self-verifying and idempotent across runs.
"""

from __future__ import annotations

import asyncio
import random
import time

import pytest

from chimera.config import get_settings
from chimera.deception_writer import SOURCETYPE, DeceptionWriter
from chimera.mcp_client import SplunkMCPClient

pytestmark = pytest.mark.asyncio

READBACK_TIMEOUT_S = 30.0
READBACK_INTERVAL_S = 3.0


async def test_write_decision_round_trips_into_idx_deception() -> None:
    sentinel_ip = f"203.0.113.{random.randint(2, 250)}"
    settings = get_settings()

    decision = {
        "src_ip": sentinel_ip,
        "decision": "observed",
        "confidence": 0.0,
        "ts": int(time.time()),
        "source_index": "idx_honeypot",
        "note": "tier1-placeholder",
    }

    async with DeceptionWriter.from_settings(settings) as writer:
        await writer.write_decision(decision)

    spl = (
        f'index=idx_deception sourcetype={SOURCETYPE} src_ip="{sentinel_ip}" '
        f"earliest=-10m | head 5"
    )

    deadline = time.monotonic() + READBACK_TIMEOUT_S
    rows: list = []
    async with SplunkMCPClient.from_settings(settings) as client:
        while time.monotonic() < deadline:
            rows = await client.run_query(spl)
            if rows:
                break
            await asyncio.sleep(READBACK_INTERVAL_S)

    assert rows, (
        f"no idx_deception event found for sentinel src_ip={sentinel_ip} "
        f"within {READBACK_TIMEOUT_S}s"
    )

    # Confirm the round-tripped event carries our fields.
    matched = any(
        (str(r.get("src_ip")) == sentinel_ip)
        or (sentinel_ip in str(r.get("_raw", "")))
        for r in rows
    )
    assert matched, f"sentinel {sentinel_ip} not present in returned rows: {rows}"
