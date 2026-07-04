"""Closure CVE attestation: wrap vulnix (or its JSON output) + join to CISA KEV.

vulnix (https://github.com/nix-community/vulnix) scans a Nix store closure for
packages whose name/version match NVD CVE entries. It is the engine here, not a
competitor. Its authors state its NVD name-matching is "a coarse heuristic...
too simplistic"; the attestation inherits that limitation and says so.

This module runs vulnix if the binary is on PATH, OR parses a pre-generated
``vulnix --json`` output file (so the tool is testable without a NixOS host).
When neither is available it degrades honestly: ``vulnix_available: false`` and
zero CVEs, never fabricated data.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path

logger = logging.getLogger("mcp_nixreview.vulnix")

VULNIX_CAVEAT = (
    "vulnix matches Nix package names to NVD products via a coarse heuristic "
    "(its authors call it 'too simplistic'). Missing and spurious matches are "
    "both possible. This is one leg of an advisory review, not a guarantee."
)


class VulnixResult:
    def __init__(
        self,
        *,
        available: bool,
        cve_ids: list[str],
        items: list[dict],
        degraded_reason: str | None = None,
        source: str = "",
    ):
        self.available = available
        self.cve_ids = cve_ids
        self.items = items
        self.degraded_reason = degraded_reason
        self.source = source


def _parse_vulnix_json(raw: object) -> tuple[list[str], list[dict]]:
    """Parse a vulnix --json payload into (unique CVE IDs, per-package items).

    vulnix emits a JSON list of objects; each affected package carries an
    ``affected_by`` list of CVE IDs plus name/pname/version. We parse
    defensively so a schema tweak degrades to fewer fields, not a crash.
    """
    cve_ids: set[str] = set()
    items: list[dict] = []
    if isinstance(raw, list):
        records: list = raw
    elif isinstance(raw, dict):
        records = raw.get("packages", [])
    else:
        records = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        affected = rec.get("affected_by") or rec.get("cves") or []
        if isinstance(affected, str):
            affected = [affected]
        pkg_cves = [c for c in affected if isinstance(c, str) and c.upper().startswith("CVE-")]
        for c in pkg_cves:
            cve_ids.add(c.upper())
        items.append(
            {
                "package": rec.get("name") or rec.get("pname") or "unknown",
                "version": rec.get("version"),
                "cves": sorted({c.upper() for c in pkg_cves}),
            }
        )
    return sorted(cve_ids), items


async def attest(path: str) -> VulnixResult:
    """Produce a CVE list for a closure path or a vulnix JSON file.

    - If ``path`` ends in ``.json`` and exists, parse it as vulnix output.
    - Else if ``vulnix`` is on PATH, run ``vulnix --json <path>``.
    - Else degrade: available=False, no CVEs, a reason string.
    """
    p = Path(path)

    if path.endswith(".json") and p.exists():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            return VulnixResult(
                available=False, cve_ids=[], items=[],
                degraded_reason=f"could not read vulnix JSON at {path}: {exc}",
                source="json-file",
            )
        cve_ids, items = _parse_vulnix_json(raw)
        return VulnixResult(available=True, cve_ids=cve_ids, items=items, source="json-file")

    if shutil.which("vulnix") is None:
        return VulnixResult(
            available=False, cve_ids=[], items=[],
            degraded_reason=(
                "vulnix is not installed on this host (this MCP runs on a "
                "non-NixOS box). Point attest_closure at a NixOS host's vulnix "
                "output, or pass a pre-generated 'vulnix --json' file path."
            ),
            source="unavailable",
        )

    if not p.exists():
        return VulnixResult(
            available=False, cve_ids=[], items=[],
            degraded_reason=f"closure path does not exist: {path}",
            source="vulnix",
        )

    try:
        proc = await asyncio.create_subprocess_exec(
            "vulnix", "--json", path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
    except OSError as exc:
        return VulnixResult(
            available=False, cve_ids=[], items=[],
            degraded_reason=f"failed to execute vulnix: {exc}", source="vulnix",
        )

    # vulnix exits non-zero (2) when it finds vulnerabilities; that's expected.
    try:
        raw = json.loads(stdout.decode("utf-8") or "[]")
    except json.JSONDecodeError:
        return VulnixResult(
            available=False, cve_ids=[], items=[],
            degraded_reason=(
                "vulnix produced no parseable JSON "
                f"(stderr: {stderr.decode('utf-8', 'replace')[:300]})"
            ),
            source="vulnix",
        )
    cve_ids, items = _parse_vulnix_json(raw)
    return VulnixResult(available=True, cve_ids=cve_ids, items=items, source="vulnix")
