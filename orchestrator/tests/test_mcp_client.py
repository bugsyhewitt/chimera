"""Live integration tests against the running Splunk MCP server.

These connect to the real Splunk MCP server defined in ``/home/hi/chimera/.env``
and verify the CHIMERA indexes are visible. This is intentional: it doubles as
the P05 verification that the MCP transport + auth + parsing all work end-to-end.
"""

from __future__ import annotations

import pytest

from chimera.config import get_settings
from chimera.mcp_client import SplunkMCPClient

pytestmark = pytest.mark.asyncio

CHIMERA_INDEXES = {"idx_network", "idx_honeypot", "idx_deception"}


async def test_list_indexes_includes_chimera_indexes() -> None:
    async with SplunkMCPClient.from_settings(get_settings()) as client:
        indexes = await client.list_indexes()

    assert isinstance(indexes, list)
    assert indexes, "expected at least one index from splunk_get_indexes"
    missing = CHIMERA_INDEXES - set(indexes)
    assert not missing, f"missing CHIMERA indexes: {missing}; saw: {sorted(indexes)}"


async def test_list_tools_exposes_query_and_indexes() -> None:
    async with SplunkMCPClient.from_settings(get_settings()) as client:
        tools = await client.list_tools()

    assert "splunk_run_query" in tools
    assert "splunk_get_indexes" in tools


async def test_run_query_returns_list() -> None:
    async with SplunkMCPClient.from_settings(get_settings()) as client:
        rows = await client.run_query("index=idx_network earliest=-1h | head 5")

    assert isinstance(rows, list)
    for row in rows:
        assert isinstance(row, dict)
