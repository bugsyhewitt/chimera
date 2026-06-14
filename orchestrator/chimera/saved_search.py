"""P13: persist a generated SPL detection as a real Splunk saved search.

The Splunk MCP server is **read-only** (no write/ingest tool), so — just like
:class:`chimera.deception_writer.DeceptionWriter` posts events via the REST
simple receiver — this module creates the durable detection artifact via the
Splunk REST *saved-searches* endpoint::

    POST https://<host>:<mgmt>/servicesNS/nobody/chimera/saved/searches
        name=chimera_detection_<slug>
        search=<generated_spl>
        description=<auto from session>
        is_scheduled=0
        disabled=0

with HTTP basic auth (admin / password from ``.env``) over self-signed TLS
(``verify=False``). Creating a saved search this way does **not** require a
Splunkd restart — it is hot-applied.

Idempotency: a re-run for the same session would 409 (the entity already
exists). We handle that by POSTing an *update* to the per-entity URL
``.../saved/searches/<name>`` (which omits ``name`` and just updates the
``search``/``description``). So the finalize path is safe to run more than once.

This is the MCP-can't-write workaround and the **P13 payoff**: the agent emits a
durable Splunk object (a saved detection) plus an action, not merely a summary.
"""

from __future__ import annotations

import re
from types import TracebackType
from typing import Any, Self

import httpx
import structlog

from .config import Settings, get_settings

log = structlog.get_logger(__name__)

# The saved search is created in the ``chimera`` app, owned by ``nobody`` so it
# is a shared (app-level) object rather than a per-user private one.
SAVED_SEARCH_APP = "chimera"
SAVED_SEARCH_OWNER = "nobody"

# Real index/sourcetype the honeypot evidence lands in (CLAUDE.md: idx_honeypot
# Cowrie JSON). Used as the last-resort fallback detection if the model's SPL is
# unusable.
_FALLBACK_SPL = (
    "index=idx_honeypot sourcetype=cowrie:json "
    'eventid IN ("cowrie.login.success","cowrie.command.input",'
    '"cowrie.session.file_download") '
    "| stats count values(input) as commands by src_ip session "
    "| where count > 1"
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")
# A fenced ```spl ... ``` block, if the SPL arrived wrapped in markdown.
_FENCE_RE = re.compile(r"```(?:spl|splunk)?\s*\n(.*?)\n```", re.IGNORECASE | re.DOTALL)


def slugify(value: str) -> str:
    """Lower-case, collapse non-alphanumerics to ``_``, trim — for the name."""
    s = _SLUG_RE.sub("_", str(value).strip().lower()).strip("_")
    return s or "unknown"


def detection_name(*, session: str | None = None, src_ip: str | None = None) -> str:
    """Stable saved-search name ``chimera_detection_<session-or-srcip-slug>``."""
    selector = session or src_ip or "unknown"
    return f"chimera_detection_{slugify(selector)}"


def normalize_spl(spl: str | None) -> str:
    """Make a generated SPL string usable as a saved-search ``search`` value.

    * Unwrap a single ```spl fenced block if present.
    * Collapse newlines/indentation into a single-line search (Splunk accepts
      multi-line but a one-liner is the most portable as a saved search).
    * Fall back to a sane real-index detection if the model emitted nothing
      usable (empty, or no ``index=`` / pipe-stage — i.e. not a search).
    """
    text = (spl or "").strip()
    m = _FENCE_RE.search(text)
    if m:
        text = m.group(1).strip()
    # Join continuation lines into one logical search.
    one_line = " ".join(part.strip() for part in text.splitlines() if part.strip())
    one_line = re.sub(r"\s+", " ", one_line).strip()

    looks_like_search = ("index=" in one_line.lower()) or one_line.lstrip().startswith(
        "|"
    )
    if not one_line or not looks_like_search:
        return _FALLBACK_SPL
    return one_line


class SavedSearchWriter:
    """Creates/updates Splunk saved searches via the REST API (verify=False)."""

    def __init__(
        self,
        host: str,
        mgmt_port: int,
        username: str,
        password: str,
        *,
        app: str = SAVED_SEARCH_APP,
        owner: str = SAVED_SEARCH_OWNER,
        timeout: float = 15.0,
    ) -> None:
        self._base = (
            f"https://{host}:{mgmt_port}/servicesNS/{owner}/{app}/saved/searches"
        )
        self._auth = httpx.BasicAuth(username, password)
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
                log.debug("saved_search_close_error", error=str(e))
            self._client = None

    # ---- public API ----
    async def create_detection(
        self,
        spl: str,
        *,
        session: str | None = None,
        src_ip: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Create (or idempotently update) the saved search for this detection.

        Returns a small status dict ``{name, created|updated|failed, status}``.
        Never raises into the caller — the finalize path must not die on a REST
        hiccup; the failure is logged and surfaced in the returned dict.
        """
        client = self._ensure_client()
        name = detection_name(session=session, src_ip=src_ip)
        search = normalize_spl(spl)
        if description is None:
            sel = session or src_ip or "unknown"
            description = (
                f"CHIMERA auto-generated detection for session {sel} "
                "(Foundation-Sec-8B engagement report)."
            )

        create_data = {
            "name": name,
            "search": search,
            "description": description,
            "is_scheduled": "0",
            "disabled": "0",
        }
        try:
            resp = await client.post(
                self._base,
                data=create_data,
                auth=self._auth,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception as e:  # noqa: BLE001 — keep finalize alive
            log.warning("saved_search_create_error", name=name, error=str(e))
            return {"name": name, "result": "failed", "status": None}

        if resp.status_code in (200, 201):
            log.info("saved_search_created", name=name, status=resp.status_code)
            return {"name": name, "result": "created", "status": resp.status_code}

        if resp.status_code == 409:
            # Already exists — update in place via the per-entity endpoint (the
            # update POST must NOT include ``name``).
            return await self._update_detection(name, search, description)

        log.warning(
            "saved_search_create_unexpected",
            name=name,
            status=resp.status_code,
            body=resp.text[:300],
        )
        return {"name": name, "result": "failed", "status": resp.status_code}

    async def _update_detection(
        self, name: str, search: str, description: str
    ) -> dict[str, Any]:
        """POST an update to ``.../saved/searches/<name>`` (idempotent path)."""
        client = self._ensure_client()
        url = f"{self._base}/{name}"
        update_data = {
            "search": search,
            "description": description,
            "is_scheduled": "0",
            "disabled": "0",
        }
        try:
            resp = await client.post(
                url,
                data=update_data,
                auth=self._auth,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception as e:  # noqa: BLE001
            log.warning("saved_search_update_error", name=name, error=str(e))
            return {"name": name, "result": "failed", "status": None}

        if resp.status_code in (200, 201):
            log.info("saved_search_updated", name=name, status=resp.status_code)
            return {"name": name, "result": "updated", "status": resp.status_code}

        log.warning(
            "saved_search_update_unexpected",
            name=name,
            status=resp.status_code,
            body=resp.text[:300],
        )
        return {"name": name, "result": "failed", "status": resp.status_code}
