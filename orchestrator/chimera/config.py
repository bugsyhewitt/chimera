"""Configuration for the CHIMERA orchestrator.

Loads settings from the repo-root ``.env`` (``/home/hi/chimera/.env``) using
``pydantic-settings``. The ``.env`` path is resolved relative to this file so
it works regardless of the current working directory.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# This file lives at <repo>/orchestrator/chimera/config.py, so the repo root
# (where .env lives) is three parents up. Resolve absolutely so cwd is irrelevant.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_ENV_FILE = _REPO_ROOT / ".env"


class Settings(BaseSettings):
    """Strongly-typed view of the CHIMERA environment.

    Field names map case-insensitively to the upper-case keys in ``.env``
    (pydantic-settings lower-cases env var names by default).
    """

    # ---- Splunk MCP server ----
    splunk_mcp_endpoint: str
    splunk_mcp_token: str

    # ---- Splunk core (handy for diagnostics / direct REST if ever needed) ----
    splunk_host: str = "192.168.1.12"
    splunk_mgmt_port: int = 8089
    splunk_admin_user: str = "admin"
    splunk_admin_password: str = ""

    # ---- Ollama / Foundation-Sec-8B ----
    ollama_base_url: str = "http://localhost:11434"
    foundation_sec_model: str = "FenkoHQ/Foundation-Sec-8B"

    # ---- Router / deception gateway (P11) ----
    # "simulate" (default, what runs on this workstation): record a would-route
    # decision to idx_deception, touch no host networking. "enforce": maintain
    # nftables sets and DNAT hostile sources to honeypots (real deployments only).
    router_mode: str = "simulate"

    # ---- Session-end / write-back (P13) ----
    # A honeypot session is considered ended after this many seconds with no new
    # events (the other end condition is a terminal Cowrie event). Default 300s;
    # set low (e.g. 1) for demos/tests to finalize promptly.
    session_idle_seconds: float = 300.0

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # .env has extra keys (SPLUNK_WEB_PORT, etc.)
    )


def get_settings() -> Settings:
    """Return a freshly-loaded :class:`Settings` instance."""
    return Settings()  # type: ignore[call-arg]  # values come from .env
