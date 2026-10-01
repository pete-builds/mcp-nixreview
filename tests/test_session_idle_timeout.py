"""Streamable-http sessions must expire when idle.

FastMCP 4 passes ``session_idle_timeout=None`` to the SDK session manager
explicitly, overriding the SDK's 1800s default. Nothing errors and nothing
logs: the manager just never reaps an abandoned session.
``apply_session_idle_timeout`` restores the timeout through FastMCP 4's own
setting, and these tests read it back from the live session manager.

If the control test starts failing, FastMCP has fixed this upstream: delete
``apply_session_idle_timeout`` and this file together.
"""

from __future__ import annotations

import asyncio

import fastmcp
import pytest

from mcp_nixreview import server
from mcp_nixreview.config import Settings


def _manager_timeout(tmp_path) -> float | None:
    app = server.build_server(Settings(data_dir=str(tmp_path))).http_app(
        transport="streamable-http"
    )

    async def read() -> float | None:
        async with app.router.lifespan_context(app):
            (route,) = [r for r in app.routes if getattr(r, "path", None) == "/mcp"]
            return route.endpoint.session_manager.session_idle_timeout

    return asyncio.run(read())


@pytest.fixture
def unset(monkeypatch):
    monkeypatch.setattr(fastmcp.settings, "http_session_idle_timeout", None)


def test_sessions_get_the_default_idle_timeout(unset, tmp_path):
    assert server.apply_session_idle_timeout() == 1800
    assert _manager_timeout(tmp_path) == 1800


def test_explicit_fastmcp_setting_wins(unset, monkeypatch, tmp_path):
    monkeypatch.setattr(fastmcp.settings, "http_session_idle_timeout", 600.0)
    assert server.apply_session_idle_timeout() == 600
    assert _manager_timeout(tmp_path) == 600


def test_control_without_the_fix_sessions_never_expire(unset, tmp_path):
    """Positive control: proves the assertions above can fail."""
    assert _manager_timeout(tmp_path) is None


def test_main_applies_it_before_serving(unset, monkeypatch, tmp_path):
    """The entry point, not just the helper: a dropped call in main() fails here."""
    seen = {}

    def fake_run(self, **kwargs):
        seen["timeout"] = fastmcp.settings.http_session_idle_timeout

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr(fastmcp.FastMCP, "run", fake_run)
    server.main()
    assert seen == {"timeout": 1800}
