"""Every tool declares what it does, and where it reaches to do it.

Nothing in an MCP manifest distinguishes `approve` from `list_reviews` unless
the tool says so. On this server that distinction is the whole point: approve
writes a human decision into an append-only ledger whose entire purpose is to
be cited later as evidence of what was authorised.

Two claims here are load-bearing and both are asserted rather than assumed:

* Nothing is destructive. This server never applies a change and has no delete
  path. That is a deliberate design property, and declaring it is what lets a
  client treat the servers that DO have one differently.
* openWorldHint varies per tool. Six of the eight only touch files under
  data_dir. Marking everything open-world would be the easy uniform answer and
  would misdescribe most of the surface.
"""

from __future__ import annotations

import pytest

from mcp_nixreview.config import Settings
from mcp_nixreview.server import build_server

LOCAL = {
    "list_reviews", "get_audit_log", "verify_ledger",
    "review_diff", "request_approval", "approve",
}
REMOTE = {"attest_closure", "refresh_kev_cache"}
WRITES = {"review_diff", "request_approval", "approve", "attest_closure",
          "refresh_kev_cache"}


@pytest.fixture
def tools(tmp_path):
    """The live manifest, not the source. What a client would receive."""
    mcp = build_server(Settings(data_dir=str(tmp_path)))
    import asyncio

    return {tool.name: tool for tool in asyncio.run(mcp.list_tools())}


def test_every_tool_is_annotated(tools):
    assert [name for name, t in tools.items() if t.annotations is None] == []


def test_the_expected_eight_are_present(tools):
    """Guards the guard: an empty server would pass everything below."""
    assert set(tools) == LOCAL | REMOTE


def test_nothing_is_destructive(tools):
    """This server never applies a change and has no delete path."""
    assert [n for n, t in tools.items() if t.annotations.destructiveHint] == []


def test_writes_are_never_marked_read_only(tools):
    mislabelled = [n for n in WRITES if tools[n].annotations.readOnlyHint]
    assert mislabelled == []


def test_local_tools_do_not_claim_an_open_world(tools):
    wrong = [n for n in LOCAL if tools[n].annotations.openWorldHint is not False]
    assert wrong == []


def test_the_two_outward_tools_do(tools):
    """attest_closure shells out to vulnix and consults KEV; refresh fetches it."""
    wrong = [n for n in REMOTE if tools[n].annotations.openWorldHint is not True]
    assert wrong == []


def test_recording_a_decision_is_not_idempotent(tools):
    """Every call appends another audit record, and that is the point.

    The ledger's value comes from being a faithful account of what happened,
    including a decision made twice. An idempotent hint would suggest the
    second call was a no-op, which is exactly what the ledger must not imply.
    """
    for name in ("review_diff", "request_approval", "approve", "attest_closure"):
        assert tools[name].annotations.idempotentHint is False, name


def test_refreshing_the_cache_is_idempotent(tools):
    """The other direction: repeating it converges on the same cache.

    Marking it non-idempotent alongside the ledger writers would be a false
    alarm, and hints that cry wolf get ignored.
    """
    assert tools["refresh_kev_cache"].annotations.idempotentHint is True
