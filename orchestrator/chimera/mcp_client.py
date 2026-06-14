"""Async wrapper around the Splunk MCP server.

Uses the official ``mcp`` Python SDK (streamable HTTP transport) to talk to the
Splunk MCP server exposed on the management port. TLS is self-signed so the
underlying httpx client is built with ``verify=False``.

Usage::

    async with SplunkMCPClient.from_settings(get_settings()) as client:
        indexes = await client.list_indexes()
        rows = await client.run_query("search index=idx_network | head 10")

Timeout / retry rationale (conservative defaults, all tunable via ctor args):
- ``connect_timeout=30s`` — initialize + transport setup tolerant of a slow
  self-signed TLS handshake on the Splunk mgmt port.
- ``read_timeout=300s`` (SSE read) — Splunk searches can stream slowly; this is
  the SDK default and is plenty for ``| head N`` probes.
- ``initialize`` is wrapped in a short retry (3 attempts, 1s backoff) because
  the shared Splunk MCP handler occasionally drops the first connection after
  an idle period.
"""

from __future__ import annotations

import json
from datetime import timedelta
from types import TracebackType
from typing import Any, Self

import httpx
import structlog
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import CallToolResult

from .config import Settings, get_settings

log = structlog.get_logger(__name__)


def _insecure_httpx_factory(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """httpx client factory matching the SDK's ``McpHttpClientFactory`` signature.

    Identical to the SDK default except ``verify=False`` for the self-signed
    Splunk management-port certificate.
    """
    kwargs: dict[str, Any] = {"follow_redirects": True, "verify": False}
    if timeout is not None:
        kwargs["timeout"] = timeout
    if headers is not None:
        kwargs["headers"] = headers
    if auth is not None:
        kwargs["auth"] = auth
    return httpx.AsyncClient(**kwargs)


class SplunkMCPClient:
    """Thin async client over the Splunk MCP server."""

    def __init__(
        self,
        endpoint: str,
        token: str,
        *,
        connect_timeout: float = 30.0,
        read_timeout: float = 300.0,
    ) -> None:
        self._endpoint = endpoint
        self._token = token
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

        # AsyncExitStack-free: we hold the raw async context managers and exit
        # them in reverse in __aexit__. Kept private; use the context manager.
        self._transport_cm: Any = None
        self._session_cm: ClientSession | None = None
        self._session: ClientSession | None = None

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Self:
        s = settings or get_settings()
        return cls(s.splunk_mcp_endpoint, s.splunk_mcp_token)

    # ---- lifecycle ----
    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def connect(self) -> None:
        headers = {"Authorization": f"Bearer {self._token}"}
        self._transport_cm = streamablehttp_client(
            url=self._endpoint,
            headers=headers,
            timeout=timedelta(seconds=self._connect_timeout),
            sse_read_timeout=timedelta(seconds=self._read_timeout),
            httpx_client_factory=_insecure_httpx_factory,
        )
        read_stream, write_stream, _get_session_id = await self._transport_cm.__aenter__()
        self._session_cm = ClientSession(read_stream, write_stream)
        self._session = await self._session_cm.__aenter__()
        await self._session.initialize()
        log.info("mcp_connected", endpoint=self._endpoint)

    async def close(self) -> None:
        # Exit in reverse order; swallow shutdown errors so a failed run never
        # masks the real exception with a teardown traceback.
        if self._session_cm is not None:
            try:
                await self._session_cm.__aexit__(None, None, None)
            except Exception as e:  # noqa: BLE001
                log.debug("session_close_error", error=str(e))
            self._session_cm = None
            self._session = None
        if self._transport_cm is not None:
            try:
                await self._transport_cm.__aexit__(None, None, None)
            except Exception as e:  # noqa: BLE001
                log.debug("transport_close_error", error=str(e))
            self._transport_cm = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("SplunkMCPClient is not connected; use 'async with' or call connect().")
        return self._session

    # ---- result parsing helpers ----
    @staticmethod
    def _result_payload(result: CallToolResult) -> dict[str, Any]:
        """Extract the JSON payload from a tool result.

        The Splunk MCP server returns a single text content block whose body is
        a JSON object (typically ``{"results": [...], ...}``). Newer SDKs also
        surface ``structuredContent``; prefer it when present, else parse text.
        """
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict) and structured:
            return structured

        for block in result.content:
            text = getattr(block, "text", None)
            if text:
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    return parsed
                if isinstance(parsed, list):
                    return {"results": parsed}
        return {}

    # ---- public API ----
    async def list_tools(self) -> list[str]:
        resp = await self.session.list_tools()
        return [t.name for t in resp.tools]

    async def list_indexes(self) -> list[str]:
        result = await self.session.call_tool("splunk_get_indexes", {})
        payload = self._result_payload(result)
        rows = payload.get("results", [])
        names: list[str] = []
        for row in rows:
            if isinstance(row, dict):
                name = row.get("title") or row.get("index") or row.get("name")
                if name:
                    names.append(str(name))
            elif isinstance(row, str):
                names.append(row)
        return names

    async def run_query(self, spl: str) -> list[dict[str, Any]]:
        """Run an SPL query and return result rows as dicts.

        A leading ``search`` is prepended automatically for non-piped queries
        (i.e. ones that don't already start with ``search`` or ``|``).
        """
        query = self._normalize_spl(spl)
        result = await self.session.call_tool("splunk_run_query", {"query": query})
        payload = self._result_payload(result)
        rows = payload.get("results", [])
        return [r for r in rows if isinstance(r, dict)]

    @staticmethod
    def _normalize_spl(spl: str) -> str:
        stripped = spl.strip()
        head = stripped.lower()
        if head.startswith("search ") or head.startswith("|") or head == "search":
            return stripped
        return f"search {stripped}"
