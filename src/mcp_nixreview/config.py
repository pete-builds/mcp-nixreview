"""Validated, env-driven configuration for mcp-nixreview.

Loads values from environment variables (and a ``.env`` file when present),
validates types/ranges. No secrets are required: the CISA KEV feed is keyless.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# CISA Known Exploited Vulnerabilities catalog (keyless, ~1300 entries).
DEFAULT_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class Settings(BaseSettings):
    """Runtime configuration for the MCP nixreview server."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------
    data_dir: str = Field(
        default="/data",
        description="Directory for the audit ledger, review store, and KEV cache.",
    )

    # ------------------------------------------------------------------
    # CISA KEV feed
    # ------------------------------------------------------------------
    kev_url: str = Field(default=DEFAULT_KEV_URL)
    kev_ttl_hours: float = Field(
        default=24.0,
        ge=0.0,
        le=720.0,
        description="How long a cached KEV snapshot is considered fresh.",
    )
    kev_fetch_timeout_seconds: float = Field(default=30.0, ge=1.0, le=120.0)

    # ------------------------------------------------------------------
    # Timestamps
    # ------------------------------------------------------------------
    timezone: str = Field(
        default="America/New_York",
        description="IANA tz used for human-readable ISO 8601 ledger timestamps.",
    )

    # ------------------------------------------------------------------
    # MCP server settings
    # ------------------------------------------------------------------
    mcp_host: str = Field(default="0.0.0.0")  # noqa: S104 (container binds all ifaces by design)
    mcp_port: int = Field(default=3722, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(default="INFO")
    log_format: Literal["json", "text"] = Field(default="json")

    def safe_repr(self) -> dict[str, object]:
        """Return a dict suitable for logging at startup (no secrets to redact)."""
        return {
            "data_dir": self.data_dir,
            "kev_url": self.kev_url,
            "kev_ttl_hours": self.kev_ttl_hours,
            "timezone": self.timezone,
            "mcp_host": self.mcp_host,
            "mcp_port": self.mcp_port,
            "log_level": self.log_level,
            "log_format": self.log_format,
        }


def load_settings() -> Settings:
    """Build a Settings instance from the environment. Raises on invalid config."""
    return Settings()
