"""CISA Known Exploited Vulnerabilities (KEV) catalog client + local cache.

The KEV catalog is a free, keyless JSON feed (~1300 entries). We fetch it over
httpx and cache it to ``<data_dir>/kev_cache.json`` with a fetch timestamp so
attestation can run against a recent snapshot without hammering the feed.

Honest failure: some fetchers are bot-blocked by cisa.gov. If a live fetch
fails we do NOT fabricate data. We fall back to the last cached snapshot (and
report its age), or report that no cache exists. We never invent CVE/KEV rows.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx

logger = logging.getLogger("mcp_nixreview.kev")


class KevError(Exception):
    """Raised when the KEV feed cannot be fetched AND no cache exists."""

    def __init__(self, message: str, code: str = "UPSTREAM_DOWN"):
        super().__init__(message)
        self.code = code


class KevCache:
    """Fetches, caches, and queries the CISA KEV catalog."""

    def __init__(self, url: str, cache_path: str | os.PathLike[str], timeout: float = 30.0):
        self.url = url
        self.cache_path = Path(cache_path)
        self.timeout = timeout

    # -- cache I/O ----------------------------------------------------------

    def _read_cache(self) -> dict | None:
        if not self.cache_path.exists():
            return None
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("kev: cache unreadable", extra={"error": str(exc)})
            return None

    def _write_cache(self, payload: dict) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(self.cache_path)

    def cache_age_hours(self) -> float | None:
        cache = self._read_cache()
        if not cache or "cached_at" not in cache:
            return None
        try:
            cached_at = datetime.fromisoformat(cache["cached_at"])
        except ValueError:
            return None
        return (datetime.now(UTC) - cached_at).total_seconds() / 3600.0

    # -- fetch --------------------------------------------------------------

    async def fetch_and_cache(self) -> dict:
        """Fetch the live KEV feed and overwrite the cache. Raises KevError on failure."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    self.url,
                    headers={"User-Agent": "mcp-nixreview/0.1 (+https://github.com/pete-builds/mcp-nixreview)"},
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            raise KevError(
                f"CISA KEV feed returned HTTP {exc.response.status_code} "
                "(the feed bot-blocks some clients).",
                code="UPSTREAM_DOWN",
            ) from exc
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise KevError(f"CISA KEV feed fetch failed: {exc}", code="UPSTREAM_DOWN") from exc

        entries = {
            v["cveID"]: {
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "vulnerability_name": v.get("vulnerabilityName"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "known_ransomware": v.get("knownRansomwareCampaignUse"),
            }
            for v in data.get("vulnerabilities", [])
            if v.get("cveID")
        }
        payload = {
            "cached_at": datetime.now(UTC).isoformat(),
            "source": self.url,
            "catalog_version": data.get("catalogVersion"),
            "count": len(entries),
            "entries": entries,
        }
        self._write_cache(payload)
        logger.info("kev: cached %d entries", len(entries))
        return payload

    async def ensure_fresh(self, ttl_hours: float) -> dict:
        """Return a cache dict, refreshing if stale/missing.

        If a live refresh fails but a cache exists, return the stale cache with
        a ``stale`` marker. Only raises KevError when there is no cache at all.
        """
        age = self.cache_age_hours()
        if age is not None and age <= ttl_hours:
            cache = self._read_cache()
            if cache is not None:
                cache["stale"] = False
                return cache
        try:
            return await self.fetch_and_cache()
        except KevError:
            cache = self._read_cache()
            if cache is not None:
                logger.warning("kev: live refresh failed, using stale cache")
                cache["stale"] = True
                return cache
            raise

    def status(self) -> dict:
        cache = self._read_cache()
        if not cache:
            return {"available": False, "cached_at": None, "entry_count": 0}
        return {
            "available": True,
            "cached_at": cache.get("cached_at"),
            "entry_count": cache.get("count", len(cache.get("entries", {}))),
            "source": cache.get("source"),
            "age_hours": self.cache_age_hours(),
        }

    def lookup(self, cve_ids: list[str]) -> list[dict]:
        """Return KEV entries for any of the given CVE IDs. Empty list if no cache."""
        cache = self._read_cache()
        if not cache:
            return []
        entries = cache.get("entries", {})
        return [entries[cid] for cid in cve_ids if cid in entries]
