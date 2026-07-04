"""Vulnix wrapper: JSON parsing + graceful degradation contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_nixreview.review.vulnix import attest


@pytest.fixture
def vulnix_json(tmp_path: Path) -> str:
    payload = [
        {"name": "apache-log4j-2.14.1", "pname": "apache-log4j", "version": "2.14.1",
         "affected_by": ["CVE-2021-44228", "CVE-2021-45046"]},
        {"name": "openssl-3.0.1", "pname": "openssl", "version": "3.0.1",
         "affected_by": ["CVE-2022-0778"]},
    ]
    p = tmp_path / "vulnix.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


async def test_parses_vulnix_json(vulnix_json: str):
    result = await attest(vulnix_json)
    assert result.available is True
    assert result.source == "json-file"
    assert "CVE-2021-44228" in result.cve_ids
    assert len(result.cve_ids) == 3


async def test_missing_json_degrades(tmp_path: Path):
    result = await attest(str(tmp_path / "does-not-exist.json"))
    assert result.available is False
    assert result.cve_ids == []
    assert result.degraded_reason


async def test_no_vulnix_binary_degrades_on_store_path():
    # A non-.json path with vulnix absent must degrade, never fabricate CVEs.
    result = await attest("/nix/store/fake-closure")
    assert result.available is False
    assert result.cve_ids == []
    assert "vulnix" in (result.degraded_reason or "").lower()
