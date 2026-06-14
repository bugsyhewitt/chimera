"""Unit tests for the P13 saved-search write path (mocked httpx).

No live Splunk: we stub ``SavedSearchWriter``'s httpx client with a fake that
records the POSTs and returns canned status codes, so we can assert:

  * a fresh create POSTs to ``.../saved/searches`` with the right form params
    (name, search, description, is_scheduled=0, disabled=0);
  * a 409 (already exists) triggers an idempotent update POST to
    ``.../saved/searches/<name>`` that omits ``name``;
  * the name slug and SPL normalization helpers behave.
"""

from __future__ import annotations

import pytest

from chimera import saved_search
from chimera.saved_search import (
    SavedSearchWriter,
    detection_name,
    normalize_spl,
    slugify,
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def test_slugify() -> None:
    assert slugify("d0bb649bffb7") == "d0bb649bffb7"
    assert slugify("172.30.0.1") == "172_30_0_1"
    assert slugify("  Weird/Name!! ") == "weird_name"
    assert slugify("") == "unknown"


def test_detection_name_prefers_session() -> None:
    assert detection_name(session="abc123", src_ip="1.2.3.4") == "chimera_detection_abc123"
    assert detection_name(src_ip="172.30.0.1") == "chimera_detection_172_30_0_1"


def test_normalize_spl_unwraps_fence_and_one_lines() -> None:
    spl = "```spl\nindex=idx_honeypot sourcetype=cowrie:json\n| stats count by src_ip\n```"
    out = normalize_spl(spl)
    assert out.startswith("index=idx_honeypot")
    assert "\n" not in out
    assert "| stats count by src_ip" in out


def test_normalize_spl_falls_back_when_unusable() -> None:
    # No index= and not a pipe-lead => not a search => fallback.
    out = normalize_spl("the model wrote prose, no actual search here")
    assert "index=idx_honeypot sourcetype=cowrie:json" in out
    assert normalize_spl(None).startswith("index=idx_honeypot sourcetype=cowrie:json")
    assert normalize_spl("").startswith("index=idx_honeypot")


def test_normalize_spl_accepts_pipe_lead() -> None:
    out = normalize_spl("| tstats count where index=idx_honeypot by src_ip")
    assert out.startswith("| tstats")


# ---------------------------------------------------------------------------
# Mocked httpx client
# ---------------------------------------------------------------------------
class _FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _FakeHttpx:
    """Records POSTs; returns queued responses in order."""

    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = responses
        self.posts: list[dict] = []

    async def post(self, url, *, data=None, auth=None, headers=None):  # noqa: ANN001
        self.posts.append({"url": url, "data": data, "headers": headers})
        return self._responses.pop(0)

    async def aclose(self) -> None:
        pass


def _writer_with(responses: list[_FakeResponse]) -> tuple[SavedSearchWriter, _FakeHttpx]:
    w = SavedSearchWriter("h", 8089, "admin", "pw")
    fake = _FakeHttpx(responses)
    w._client = fake  # type: ignore[assignment]
    return w, fake


@pytest.mark.asyncio
async def test_create_detection_fresh_create() -> None:
    w, fake = _writer_with([_FakeResponse(201)])
    res = await w.create_detection(
        "index=idx_honeypot sourcetype=cowrie:json | stats count by src_ip",
        session="abc123",
        src_ip="172.30.0.1",
    )
    assert res["result"] == "created"
    assert res["name"] == "chimera_detection_abc123"
    assert len(fake.posts) == 1
    post = fake.posts[0]
    assert post["url"].endswith("/servicesNS/nobody/chimera/saved/searches")
    data = post["data"]
    assert data["name"] == "chimera_detection_abc123"
    assert data["is_scheduled"] == "0"
    assert data["disabled"] == "0"
    assert "index=idx_honeypot" in data["search"]
    assert data["description"]


@pytest.mark.asyncio
async def test_create_detection_409_updates_idempotently() -> None:
    # First POST (create) 409s; second POST (update) succeeds.
    w, fake = _writer_with([_FakeResponse(409, "already exists"), _FakeResponse(200)])
    res = await w.create_detection(
        "index=idx_honeypot sourcetype=cowrie:json | stats count by src_ip",
        session="dupe123",
    )
    assert res["result"] == "updated"
    assert res["name"] == "chimera_detection_dupe123"
    assert len(fake.posts) == 2
    # Update POST hits the per-entity URL and omits ``name``.
    update = fake.posts[1]
    assert update["url"].endswith("/saved/searches/chimera_detection_dupe123")
    assert "name" not in update["data"]
    assert update["data"]["is_scheduled"] == "0"


@pytest.mark.asyncio
async def test_create_detection_unexpected_status_is_failed_not_raised() -> None:
    w, fake = _writer_with([_FakeResponse(500, "boom")])
    res = await w.create_detection("index=idx_honeypot | stats count", session="x")
    assert res["result"] == "failed"
    assert res["status"] == 500


@pytest.mark.asyncio
async def test_create_detection_network_error_is_failed_not_raised() -> None:
    w = SavedSearchWriter("h", 8089, "admin", "pw")

    class _Boom:
        async def post(self, *a, **k):  # noqa: ANN002, ANN003
            raise RuntimeError("connection refused")

        async def aclose(self) -> None:
            pass

    w._client = _Boom()  # type: ignore[assignment]
    res = await w.create_detection("index=idx_honeypot | stats count", session="x")
    assert res["result"] == "failed"
    assert res["status"] is None


def test_fallback_spl_uses_real_index() -> None:
    # Guard the documented real index/sourcetype in the module fallback.
    assert "idx_honeypot" in saved_search._FALLBACK_SPL
    assert "cowrie:json" in saved_search._FALLBACK_SPL
