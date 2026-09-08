"""One grade order for the writer and the replayer.

The server graded attestations ``HIGH/MED/LOW`` while the ledger replay
ranked ``NONE/LOW/MEDIUM/HIGH/CRITICAL``. ``MED`` was unknown to the replay
and ranked lowest, so the most ordinary flow (a clean review, then a closure
attestation with any non-KEV CVE) left ``reviews.json`` saying ``MED`` and
the replay saying ``NONE``, and ``verify_ledger`` reported tampering on an
untouched ledger. A check that cries wolf on legitimate data gets ignored.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_nixreview.clients.kev import KevCache
from mcp_nixreview.config import Settings
from mcp_nixreview.grades import grade_outranks, grade_rank
from mcp_nixreview.server import build_server
from mcp_nixreview.store import Store


def test_the_writers_med_and_the_replayers_medium_are_the_same_rank():
    assert grade_rank("MED") == grade_rank("MEDIUM")
    assert grade_rank("NONE") < grade_rank("LOW") < grade_rank("MED")
    assert grade_rank("MED") < grade_rank("HIGH") < grade_rank("CRITICAL")


def test_unknown_grades_rank_lowest_and_never_escalate():
    assert grade_rank("UNKNOWN") == grade_rank("NONE") == 0
    assert grade_rank("garbage") == 0
    assert grade_outranks("garbage", "NONE") is False
    assert grade_outranks("MED", "LOW") is True
    assert grade_outranks("MED", "MEDIUM") is False


async def _call(mcp, name: str, args: dict) -> dict:
    raw = await mcp.call_tool(name, args)
    content = getattr(raw, "content", raw)
    text = content[0].text if hasattr(content[0], "text") else content[0]["text"]
    return json.loads(text)


@pytest.mark.asyncio
async def test_a_cve_only_attestation_does_not_make_verify_ledger_cry_wolf(tmp_path: Path):
    """Drive the real tools: clean review, attest a closure with CVEs that are
    not in KEV, then verify. The ledger is untouched, so verify must pass."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    # A fresh, empty KEV cache so attest_closure never reaches the network and
    # no CVE matches: the grade must land on MED by the server's own rule.
    kev_path = data_dir / "kev_cache.json"
    kev_path.write_text(json.dumps({
        "cached_at": datetime.now(UTC).isoformat(),
        "source": "test",
        "catalog_version": "test",
        "count": 0,
        "entries": {},
    }))
    vulnix = tmp_path / "vulnix.json"
    vulnix.write_text(json.dumps([
        {"name": "openssl-3.0.1", "pname": "openssl", "version": "3.0.1",
         "affected_by": ["CVE-2022-0778"]},
    ]))

    store = Store(data_dir)
    kev = KevCache("http://kev.test/feed.json", kev_path)
    mcp = build_server(Settings(data_dir=str(data_dir)), store=store, kev=kev)

    reviewed = await _call(mcp, "review_diff", {
        "config_ref": "+  services.nginx.enable = true;\n", "ref_type": "text",
    })
    assert "error" not in reviewed, reviewed
    review_id = reviewed["data"]["review_id"]
    assert reviewed["data"]["overall_grade"] == "NONE"

    attested = await _call(mcp, "attest_closure", {
        "drv_or_path": str(vulnix), "review_id": review_id,
    })
    assert "error" not in attested, attested
    assert attested["data"]["grade"] == "MED"
    assert attested["data"]["kev_match_count"] == 0

    verified = await _call(mcp, "verify_ledger", {})
    assert "error" not in verified, verified
    assert verified["data"]["state"]["ok"] is True, verified["data"]
    assert verified["data"]["ok"] is True, verified["data"]["reason"]
    assert store.get_review(review_id)["overall_grade"] == "MED"
