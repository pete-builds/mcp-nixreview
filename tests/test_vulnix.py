"""Vulnix wrapper: JSON parsing + graceful degradation contract."""

from __future__ import annotations

import json
import os
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


class TestFailedScanIsNotACleanScan:
    """A crashed scanner used to be indistinguishable from a clean closure.

    The exit code was never read, and empty stdout was coerced to "[]", so a
    db-locked or misconfigured vulnix returned available=True with zero CVEs --
    a response byte-identical to a genuinely clean scan, graded LOW.
    """

    @staticmethod
    def _fake_vulnix(tmp_path, script: str) -> str:
        binp = tmp_path / "vulnix"
        binp.write_text(script)
        binp.chmod(0o755)
        return str(tmp_path)

    @pytest.mark.asyncio
    async def test_nonzero_exit_with_no_output_is_degraded(self, tmp_path, monkeypatch) -> None:
        d = self._fake_vulnix(
            tmp_path, '#!/bin/sh\necho "ERROR: db locked" >&2\nexit 1\n'
        )
        monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
        closure = tmp_path / "closure"
        closure.mkdir()
        result = await attest(str(closure))
        assert result.available is False
        assert result.degraded_reason
        assert "exited 1" in result.degraded_reason

    @pytest.mark.asyncio
    async def test_exit_2_with_findings_still_succeeds(self, tmp_path, monkeypatch) -> None:
        """vulnix uses exit 2 for 'found vulnerabilities'. That must keep working."""
        d = self._fake_vulnix(
            tmp_path,
            '#!/bin/sh\necho \'[{"name":"openssl","affected_by":["CVE-2022-0778"]}]\'\nexit 2\n',
        )
        monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
        closure = tmp_path / "closure"
        closure.mkdir()
        result = await attest(str(closure))
        assert result.available is True
        assert "CVE-2022-0778" in result.cve_ids

    @pytest.mark.asyncio
    async def test_clean_scan_still_reports_clean(self, tmp_path, monkeypatch) -> None:
        d = self._fake_vulnix(tmp_path, "#!/bin/sh\necho '[]'\nexit 0\n")
        monkeypatch.setenv("PATH", f"{d}:{os.environ['PATH']}")
        closure = tmp_path / "closure"
        closure.mkdir()
        result = await attest(str(closure))
        assert result.available is True
        assert result.cve_ids == []
