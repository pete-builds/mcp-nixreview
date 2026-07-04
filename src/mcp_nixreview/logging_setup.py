"""Structured logging configuration for mcp-nixreview.

JSON formatter for production (one record per line). Plain text fallback for
local dev. Sensitive keys are scrubbed from any ``extra`` dicts passed through,
and noisy HTTP-client loggers are silenced so URLs / headers never reach INFO.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {"password", "token", "authorization", "api_key", "apikey", "secret"}
)

_RESERVED_LOGRECORD_FIELDS: frozenset[str] = frozenset(
    {
        "args", "asctime", "created", "exc_info", "exc_text", "filename",
        "funcName", "levelname", "levelno", "lineno", "message", "module",
        "msecs", "msg", "name", "pathname", "process", "processName",
        "relativeCreated", "stack_info", "thread", "threadName", "taskName",
    }
)


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if k.lower() in _SENSITIVE_KEYS else _scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    """Serialise each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        extras = {
            key: _scrub(value)
            for key, value in record.__dict__.items()
            if key not in _RESERVED_LOGRECORD_FIELDS and not key.startswith("_")
        }
        if extras:
            payload["extra"] = extras
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure the root logger. Idempotent — safe to call multiple times."""
    root = logging.getLogger()
    root.setLevel(level.upper())
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
    root.addHandler(handler)

    # Never let HTTP clients log full URLs (which can carry query params) at INFO.
    for noisy in ("urllib3", "requests", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
