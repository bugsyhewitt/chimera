"""Write-back path for CHIMERA orchestrator decisions.

The Splunk MCP server is READ-ONLY (no write/ingest tool), so decisions are
indexed into ``idx_deception`` via the Splunk REST *simple receiver* endpoint::

    POST https://<host>:<mgmt_port>/services/receivers/simple
        ?index=idx_deception
        &sourcetype=chimera:decision
        &source=chimera:orchestrator

with HTTP basic auth (admin / password from ``.env``) over self-signed TLS
(``verify=False``). The request body is the raw event; we send compact JSON
text so the event indexes with KV fields auto-extracted (``src_ip`` etc.).

This is the **Tier-1 placeholder** write path. The real SPRT verdict logic
(P09) reuses :meth:`DeceptionWriter.write_decision` to emit richer decisions.

Timeout rationale: a single conservative ``connect+write`` timeout (10s) — the
simple receiver is a synchronous indexing call on the local mgmt port and
should return in well under a second; 10s tolerates a slow TLS handshake
without hanging the poll loop.
"""

from __future__ import annotations

import json
from types import TracebackType
from typing import Any, Self

import httpx
import structlog

from .config import Settings, get_settings

log = structlog.get_logger(__name__)

# Fixed metadata for every decision event. ``sourcetype`` is what the readback
# search / tests key on; keep it stable.
SOURCETYPE = "chimera:decision"
SOURCE = "chimera:orchestrator"
DECEPTION_INDEX = "idx_deception"


class DeceptionWriter:
    """Indexes decision events into ``idx_deception`` via the REST receiver."""

    def __init__(
        self,
        host: str,
        mgmt_port: int,
        username: str,
        password: str,
        *,
        index: str = DECEPTION_INDEX,
        timeout: float = 10.0,
    ) -> None:
        self._base = f"https://{host}:{mgmt_port}/services/receivers/simple"
        self._auth = httpx.BasicAuth(username, password)
        self._index = index
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Self:
        s = settings or get_settings()
        return cls(
            s.splunk_host,
            s.splunk_mgmt_port,
            s.splunk_admin_user,
            s.splunk_admin_password,
        )

    # ---- lifecycle ----
    async def __aenter__(self) -> Self:
        self._ensure_client()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(verify=False, timeout=self._timeout)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception as e:  # noqa: BLE001 — teardown must never mask
                log.debug("writer_close_error", error=str(e))
            self._client = None

    # ---- public API ----
    async def write_decision(self, event: dict[str, Any]) -> None:
        """Index a single decision event into ``idx_deception``.

        ``event`` is sent as compact JSON text as the raw event body. Failures
        are logged (not raised) so a transient write error never kills the poll
        loop; the caller can re-emit on the next observation.
        """
        client = self._ensure_client()
        params = {
            "index": self._index,
            "sourcetype": SOURCETYPE,
            "source": SOURCE,
        }
        body = json.dumps(event, separators=(",", ":"))
        try:
            resp = await client.post(
                self._base,
                params=params,
                auth=self._auth,
                content=body.encode("utf-8"),
            )
            resp.raise_for_status()
        except Exception as e:  # noqa: BLE001 — keep the loop alive
            log.warning(
                "deception_write_failed",
                src_ip=event.get("src_ip"),
                error=str(e),
            )
            return
        log.info(
            "deception_write_ok",
            src_ip=event.get("src_ip"),
            decision=event.get("decision"),
        )
