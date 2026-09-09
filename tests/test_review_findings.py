"""Findings 3 and 5 of the 2026-09-08 review.

3. With CVEs present and no KEV catalog at all (fetch failed, no cache), the
   attestation used to grade ``MED`` with ``kev_match_count: 0``, the same
   shape as "checked, none known-exploited". It now grades ``UNKNOWN``,
   says ``kev_checked: false``, and carries a ``degraded`` reason. A stale
   cache fallback is marked too.

5. ``review_diff`` in its default mode sniffed any short string with a path
   separator and, if it named an existing file, opened it and echoed matching
   lines back. Only ``ref_type="file_path"`` opens a file now, and only under
   ``review_root``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_nixreview.clients.kev import KevCache
from mcp_nixreview.config import Settings
from mcp_nixreview.server import build_server
from mcp_nixreview.store import Store

# A port nothing listens on, so ensure_fresh fails fast instead of reaching CISA.
DEAD_KEV_URL = "http://127.0.0.1:9/feed.json"


async def _call(mcp, name: str, args: dict) -> dict:
    raw = await mcp.call_tool(name, args)
    content = getattr(raw, "content", raw)
    text = content[0].text if hasattr(content[0], "text") else content[0]["text"]
    return json.loads(text)


def _vulnix_with_one_cve(tmp_path: Path) -> Path:
    vulnix = tmp_path / "vulnix.json"
    vulnix.write_text(
        json.dumps(
            [
                {
                    "name": "openssl-3.0.1",
                    "pname": "openssl",
                    "version": "3.0.1",
                    "affected_by": ["CVE-2022-0778"],
                }
            ]
        )
    )
    return vulnix


def _kev_cache(path: Path, *, cached_at: datetime, entries: dict | None = None) -> None:
    path.write_text(
        json.dumps(
            {
                "cached_at": cached_at.isoformat(),
                "source": "test",
                "catalog_version": "test",
                "count": len(entries or {}),
                "entries": entries or {},
            }
        )
    )


def _server(
    tmp_path: Path,
    *,
    kev_cache_present: bool,
    cache_age: timedelta | None = None,
    **settings,
):
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    kev_path = data_dir / "kev_cache.json"
    if kev_cache_present:
        _kev_cache(kev_path, cached_at=datetime.now(UTC) - (cache_age or timedelta(0)))
    store = Store(data_dir)
    kev = KevCache(DEAD_KEV_URL, kev_path, timeout=1.0)
    mcp = build_server(Settings(data_dir=str(data_dir), **settings), store=store, kev=kev)
    return mcp, store


# ---------------------------------------------------------------------------
# Finding 3
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kev_unreachable_with_no_cache_grades_unknown_not_med(tmp_path: Path):
    mcp, _ = _server(tmp_path, kev_cache_present=False)
    vulnix = _vulnix_with_one_cve(tmp_path)

    out = await _call(mcp, "attest_closure", {"drv_or_path": str(vulnix)})

    data = out["data"]
    assert data["kev_feed"]["available"] is False
    assert data["kev_checked"] is False
    assert data["grade"] == "UNKNOWN"
    assert "unchecked" in data["degraded"]["reason"]
    assert data["kev_match_count"] == 0  # still zero, but now labelled unchecked


@pytest.mark.asyncio
async def test_kev_fresh_cache_still_grades_med_and_is_not_degraded(tmp_path: Path):
    """Control: the same closure with a catalog present keeps the old answer."""
    mcp, _ = _server(tmp_path, kev_cache_present=True)
    vulnix = _vulnix_with_one_cve(tmp_path)

    out = await _call(mcp, "attest_closure", {"drv_or_path": str(vulnix)})

    data = out["data"]
    assert data["kev_checked"] is True
    assert data["grade"] == "MED"
    assert data["kev_feed"]["stale"] is False
    assert "degraded" not in data


@pytest.mark.asyncio
async def test_kev_stale_cache_fallback_is_marked(tmp_path: Path):
    mcp, _ = _server(tmp_path, kev_cache_present=True, cache_age=timedelta(days=30))
    vulnix = _vulnix_with_one_cve(tmp_path)

    out = await _call(mcp, "attest_closure", {"drv_or_path": str(vulnix)})

    data = out["data"]
    assert data["kev_checked"] is True
    assert data["kev_feed"]["stale"] is True
    assert data["grade"] == "MED"
    assert "stale" in data["degraded"]["reason"]


@pytest.mark.asyncio
async def test_unchecked_attestation_is_recorded_on_the_review(tmp_path: Path):
    mcp, store = _server(tmp_path, kev_cache_present=False)
    vulnix = _vulnix_with_one_cve(tmp_path)
    reviewed = await _call(
        mcp, "review_diff", {"config_ref": "+  services.nginx.enable = true;\n", "ref_type": "text"}
    )
    review_id = reviewed["data"]["review_id"]

    await _call(mcp, "attest_closure", {"drv_or_path": str(vulnix), "review_id": review_id})

    attestation = store.get_review(review_id)["attestation"]
    assert attestation["kev_checked"] is False
    assert attestation["grade"] == "UNKNOWN"
    assert "unchecked" in attestation["degraded"]["reason"]


# ---------------------------------------------------------------------------
# Finding 5
# ---------------------------------------------------------------------------

RISKY_LINE = 'services.postgresql.settings.listen_addresses = "0.0.0.0";'


@pytest.mark.asyncio
async def test_auto_mode_never_opens_a_file(tmp_path: Path):
    """A string that names an existing file is graded as text, not read."""
    outside = tmp_path / "sibling-app.nix"
    outside.write_text(RISKY_LINE + "\n")
    mcp, _ = _server(tmp_path, kev_cache_present=True, review_root=str(tmp_path / "review"))

    out = await _call(mcp, "review_diff", {"config_ref": str(outside)})

    assert "error" not in out, out
    assert out["data"]["findings"] == []
    assert "0.0.0.0" not in json.dumps(out)


@pytest.mark.asyncio
async def test_file_path_outside_review_root_is_refused_without_echo(tmp_path: Path):
    outside = tmp_path / "sibling-app.nix"
    outside.write_text(RISKY_LINE + "\n")
    review_root = tmp_path / "review"
    review_root.mkdir()
    mcp, _ = _server(tmp_path, kev_cache_present=True, review_root=str(review_root))

    out = await _call(mcp, "review_diff", {"config_ref": str(outside), "ref_type": "file_path"})

    assert out["code"] == "INVALID_INPUT"
    assert "review_root" in out["error"]
    assert "0.0.0.0" not in json.dumps(out)


@pytest.mark.asyncio
async def test_file_path_traversal_out_of_review_root_is_refused(tmp_path: Path):
    outside = tmp_path / "sibling-app.nix"
    outside.write_text(RISKY_LINE + "\n")
    review_root = tmp_path / "review"
    review_root.mkdir()
    mcp, _ = _server(tmp_path, kev_cache_present=True, review_root=str(review_root))

    out = await _call(
        mcp, "review_diff", {"config_ref": "../sibling-app.nix", "ref_type": "file_path"}
    )

    assert out["code"] == "INVALID_INPUT"
    assert "0.0.0.0" not in json.dumps(out)


@pytest.mark.asyncio
async def test_file_path_inside_review_root_is_graded(tmp_path: Path):
    review_root = tmp_path / "review"
    review_root.mkdir()
    (review_root / "configuration.nix").write_text(RISKY_LINE + "\n")
    mcp, _ = _server(tmp_path, kev_cache_present=True, review_root=str(review_root))

    absolute = await _call(
        mcp,
        "review_diff",
        {"config_ref": str(review_root / "configuration.nix"), "ref_type": "file_path"},
    )
    relative = await _call(
        mcp, "review_diff", {"config_ref": "configuration.nix", "ref_type": "file_path"}
    )

    for out in (absolute, relative):
        assert "error" not in out, out
        assert out["data"]["findings"], out
        assert any("0.0.0.0" in f["snippet"] for f in out["data"]["findings"])


@pytest.mark.asyncio
async def test_file_path_missing_inside_review_root_is_not_found(tmp_path: Path):
    review_root = tmp_path / "review"
    review_root.mkdir()
    mcp, _ = _server(tmp_path, kev_cache_present=True, review_root=str(review_root))

    out = await _call(mcp, "review_diff", {"config_ref": "nope.nix", "ref_type": "file_path"})

    assert out["code"] == "NOT_FOUND"
