"""mcp-nixreview — advisory NixOS change-review + CVE/KEV attestation gate.

Seven tools, Streamable HTTP (FastMCP). ADVISORY, NOT AUTHORITATIVE: this
server reviews a curated set of security-relevant NixOS options and joins a
coarse CVE scan to CISA KEV. It NEVER applies a change; it records a human
decision and writes an append-only audit ledger.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from mcp_nixreview import ADVISORY_NOTICE, __version__
from mcp_nixreview.clients.kev import KevCache, KevError
from mcp_nixreview.config import Settings, load_settings
from mcp_nixreview.logging_setup import configure_logging
from mcp_nixreview.review import diff as diffmod
from mcp_nixreview.review import vulnix as vulnixmod
from mcp_nixreview.store import Store

logger = logging.getLogger("mcp_nixreview.server")

_MAX_INLINE_CONFIG_BYTES = 512 * 1024  # 512 KiB guard on inline config text


def _ok(data: Any) -> str:
    return json.dumps({"data": data}, default=str, indent=2)


def _err(message: str, code: str, **details: Any) -> str:
    payload: dict[str, Any] = {"error": message, "code": code}
    if details:
        payload["details"] = details
    return json.dumps(payload, default=str)


def _grade_rank(grade: str) -> int:
    return {"HIGH": 3, "MED": 2, "LOW": 1}.get(grade, 0)


def build_server(
    settings: Settings,
    *,
    store: Store | None = None,
    kev: KevCache | None = None,
) -> FastMCP:
    store = store or Store(settings.data_dir, timezone=settings.timezone)
    kev = kev or KevCache(
        settings.kev_url,
        Path(settings.data_dir) / "kev_cache.json",
        timeout=settings.kev_fetch_timeout_seconds,
    )

    mcp = FastMCP("nixreview")

    # ------------------------------------------------------------------
    # 1. review_diff
    # ------------------------------------------------------------------
    @mcp.tool()
    async def review_diff(config_ref: str, ref_type: str = "auto") -> str:
        """Grade a proposed NixOS config change for security-relevant deltas.

        Extracts a curated, high-signal set of option changes and grades each
        HIGH/MED/LOW: opened firewall ports, SSH root/password login, wheel
        (sudo) membership and passwordless-sudo, fail2ban toggles, and services
        bound to 0.0.0.0. Deterministic; no network, no NixOS host required.
        Creates a review record and writes an audit-ledger entry.

        ADVISORY, NOT AUTHORITATIVE. It pattern-matches known-risky options and
        WILL miss risks in custom modules, raw systemd units, or indirect
        exposure. A clean result means "nothing known-risky matched," not "safe."

        Args:
            config_ref: The change to review. Either literal text (a unified
                diff OR a raw configuration.nix snippet), or a filesystem path
                to such a file when ref_type="file_path".
            ref_type: "auto" (default; treats a short existing path as a file,
                otherwise as literal text), "text", or "file_path".

        Returns:
            Success: {"data": {"review_id", "created_at", "input_kind",
                "findings": [{"category","option","change","snippet","grade",
                "rationale"}], "summary": {"high","med","low"},
                "overall_grade", "advisory_notice"}}.
            Failure: {"error","code","details"} with code in
            {INVALID_INPUT, NOT_FOUND, INTERNAL}.

        Example:
            review_diff("+  services.openssh.settings.PermitRootLogin = \\"yes\\";")
        """
        try:
            text = config_ref
            resolved_from = "text"
            looks_like_path = (
                ref_type == "file_path"
                or (ref_type == "auto" and "\n" not in config_ref
                    and len(config_ref) < 4096 and os.path.sep in config_ref)
            )
            if looks_like_path:
                p = Path(config_ref)
                if not p.exists():
                    if ref_type == "file_path":
                        return _err(f"file not found: {config_ref}", "NOT_FOUND", path=config_ref)
                else:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    resolved_from = "file_path"

            if not text.strip():
                return _err("config_ref is empty", "INVALID_INPUT")
            if len(text.encode("utf-8")) > _MAX_INLINE_CONFIG_BYTES:
                return _err(
                    "config text exceeds 512 KiB; pass a file path or trim the diff",
                    "INVALID_INPUT",
                )

            graded = diffmod.grade_diff(text)
            findings = graded["findings"]
            overall = "NONE"
            for f in findings:
                if _grade_rank(f["grade"]) > _grade_rank(overall):
                    overall = f["grade"]

            review_id = store.new_review_id()
            created_at = store.now_iso()
            review = {
                "review_id": review_id,
                "created_at": created_at,
                "status": "reviewed",
                "input_kind": graded["input_kind"],
                "resolved_from": resolved_from,
                "findings": findings,
                "summary": graded["summary"],
                "overall_grade": overall,
                "attestation": None,
                "decision": None,
            }
            store.upsert_review(review)
            store.append_audit(
                {
                    "event": "reviewed",
                    "review_id": review_id,
                    "overall_grade": overall,
                    "summary": graded["summary"],
                    "finding_count": len(findings),
                }
            )
            return _ok(
                {
                    "review_id": review_id,
                    "created_at": created_at,
                    "input_kind": graded["input_kind"],
                    "findings": findings,
                    "summary": graded["summary"],
                    "overall_grade": overall,
                    "advisory_notice": ADVISORY_NOTICE,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("review_diff failed")
            return _err(f"unexpected error: {exc}", "INTERNAL")

    # ------------------------------------------------------------------
    # 2. attest_closure
    # ------------------------------------------------------------------
    @mcp.tool()
    async def attest_closure(drv_or_path: str, review_id: str = "") -> str:
        """Attest a built NixOS closure against CVEs + the CISA KEV catalog.

        Runs vulnix on the closure (or parses a pre-generated 'vulnix --json'
        file), then joins the CVE IDs against the cached CISA KEV feed. Any KEV
        match escalates the attestation grade to HIGH. If vulnix is unavailable
        (this MCP runs on a non-NixOS host), it degrades honestly: no CVEs are
        fabricated and ``degraded`` explains why.

        ADVISORY. The CVE leg inherits vulnix's self-described "coarse"
        name-matching; missing and spurious matches are both possible.

        Args:
            drv_or_path: A Nix store path / .drv to scan with vulnix, OR a path
                ending in .json holding pre-generated 'vulnix --json' output
                (useful for testing without a NixOS host).
            review_id: Optional. If given, attach the attestation to that review
                and write a ledger entry.

        Returns:
            Success: {"data": {"review_id"?, "attested_at", "vulnix_available",
                "source", "cve_count", "cve_ids", "kev_matches":
                [{"cve_id","vendor","product","known_ransomware","date_added"}],
                "grade", "kev_feed": {...}, "degraded"?: {"reason"},
                "vulnix_caveat", "advisory_notice"}}.
            Failure: {"error","code","details"} with code in
            {UPSTREAM_DOWN, NOT_FOUND, INTERNAL}.

        Example:
            attest_closure("/nix/store/....json", review_id="nixrev-...")
        """
        try:
            result = await vulnixmod.attest(drv_or_path)

            kev_matches: list[dict] = []
            kev_feed: dict = kev.status()
            if result.cve_ids:
                try:
                    await kev.ensure_fresh(settings.kev_ttl_hours)
                    kev_feed = kev.status()
                except KevError as exc:
                    kev_feed = {"available": False, "error": str(exc)}
                kev_matches = kev.lookup(result.cve_ids)

            if not result.available:
                grade = "UNKNOWN"
            elif kev_matches:
                grade = "HIGH"
            elif result.cve_ids:
                grade = "MED"
            else:
                grade = "LOW"

            attested_at = store.now_iso()
            payload: dict[str, Any] = {
                "attested_at": attested_at,
                "vulnix_available": result.available,
                "source": result.source,
                "cve_count": len(result.cve_ids),
                "cve_ids": result.cve_ids,
                "packages": result.items,
                "kev_matches": kev_matches,
                "kev_match_count": len(kev_matches),
                "grade": grade,
                "kev_feed": kev_feed,
                "vulnix_caveat": vulnixmod.VULNIX_CAVEAT,
                "advisory_notice": ADVISORY_NOTICE,
            }
            if result.degraded_reason:
                payload["degraded"] = {"reason": result.degraded_reason}

            if review_id:
                review = store.get_review(review_id)
                if review is None:
                    return _err(f"review not found: {review_id}", "NOT_FOUND", review_id=review_id)
                review["attestation"] = {
                    "attested_at": attested_at,
                    "vulnix_available": result.available,
                    "cve_count": len(result.cve_ids),
                    "kev_match_count": len(kev_matches),
                    "grade": grade,
                }
                # Escalate the review's overall grade if a KEV hit outranks it.
                if _grade_rank(grade) > _grade_rank(review.get("overall_grade", "NONE")):
                    review["overall_grade"] = grade
                store.upsert_review(review)
                store.append_audit(
                    {
                        "event": "attested",
                        "review_id": review_id,
                        "vulnix_available": result.available,
                        "cve_count": len(result.cve_ids),
                        "kev_match_count": len(kev_matches),
                        "grade": grade,
                    }
                )
                payload["review_id"] = review_id

            return _ok(payload)
        except Exception as exc:  # noqa: BLE001
            logger.exception("attest_closure failed")
            return _err(f"unexpected error: {exc}", "INTERNAL")

    # ------------------------------------------------------------------
    # 3. request_approval
    # ------------------------------------------------------------------
    @mcp.tool()
    async def request_approval(review_id: str) -> str:
        """Mark a reviewed change as pending human approval.

        Transitions a review to ``pending_approval`` and writes a ledger entry.
        Does not apply anything. Call ``approve`` next to record the human
        decision.

        Args:
            review_id: The id returned by review_diff.

        Returns:
            Success: {"data": {"review_id","status","requested_at",
                "overall_grade","advisory_notice"}}.
            Failure: {"error","code"} with NOT_FOUND if the review is unknown.

        Example:
            request_approval("nixrev-20260704T101500-ab12cd")
        """
        try:
            review = store.get_review(review_id)
            if review is None:
                return _err(f"review not found: {review_id}", "NOT_FOUND", review_id=review_id)
            requested_at = store.now_iso()
            review["status"] = "pending_approval"
            review["requested_at"] = requested_at
            store.upsert_review(review)
            store.append_audit({"event": "approval_requested", "review_id": review_id})
            return _ok(
                {
                    "review_id": review_id,
                    "status": "pending_approval",
                    "requested_at": requested_at,
                    "overall_grade": review.get("overall_grade"),
                    "advisory_notice": ADVISORY_NOTICE,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("request_approval failed")
            return _err(f"unexpected error: {exc}", "INTERNAL")

    # ------------------------------------------------------------------
    # 4. approve
    # ------------------------------------------------------------------
    @mcp.tool()
    async def approve(
        review_id: str, approver: str = "", decision: str = "approve", note: str = ""
    ) -> str:
        """Record a human decision on a review. NEVER applies the change.

        This tool only records the decision in the review state and the
        append-only ledger. Applying the approved change (e.g. handing it to an
        ops layer / nixos-rebuild) is out of scope for this MVP.

        Args:
            review_id: The id returned by review_diff.
            approver: Free-form identifier of the human deciding (optional).
            decision: "approve" (default) or "reject".
            note: Optional free-form justification recorded in the ledger.

        Returns:
            Success: {"data": {"review_id","decision","approver","decided_at",
                "resulting_generation": null, "note", "advisory_notice"}}.
            Failure: {"error","code"} with NOT_FOUND or INVALID_INPUT.

        Example:
            approve("nixrev-20260704T101500-ab12cd", approver="pete",
                    decision="approve", note="reviewed the opened port")
        """
        try:
            decision = decision.strip().lower()
            if decision not in {"approve", "reject"}:
                return _err("decision must be 'approve' or 'reject'", "INVALID_INPUT",
                            decision=decision)
            review = store.get_review(review_id)
            if review is None:
                return _err(f"review not found: {review_id}", "NOT_FOUND", review_id=review_id)
            decided_at = store.now_iso()
            decision_record = {
                "decision": decision,
                "approver": approver or "unspecified",
                "decided_at": decided_at,
                "note": note,
                "resulting_generation": None,  # this tool never applies changes
            }
            review["decision"] = decision_record
            review["status"] = "approved" if decision == "approve" else "rejected"
            store.upsert_review(review)
            store.append_audit(
                {
                    "event": "decided",
                    "review_id": review_id,
                    "decision": decision,
                    "approver": approver or "unspecified",
                    "note": note,
                }
            )
            return _ok(
                {
                    "review_id": review_id,
                    **decision_record,
                    "advisory_notice": ADVISORY_NOTICE,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("approve failed")
            return _err(f"unexpected error: {exc}", "INTERNAL")

    # ------------------------------------------------------------------
    # 5. list_reviews
    # ------------------------------------------------------------------
    @mcp.tool()
    async def list_reviews(status: str = "", limit: int = 20) -> str:
        """List reviews, most recent first.

        Args:
            status: Optional filter: "reviewed", "pending_approval",
                "approved", or "rejected". Empty returns all.
            limit: Max reviews to return (default 20).

        Returns:
            Success: {"data": {"count", "reviews": [{"review_id","created_at",
                "status","overall_grade","summary"}]}}. Read-only, idempotent.

        Example:
            list_reviews(status="pending_approval", limit=10)
        """
        try:
            reviews = store.list_reviews(status=status.strip(), limit=limit)
            slim = [
                {
                    "review_id": r["review_id"],
                    "created_at": r.get("created_at"),
                    "status": r.get("status"),
                    "overall_grade": r.get("overall_grade"),
                    "summary": r.get("summary"),
                    "has_attestation": r.get("attestation") is not None,
                }
                for r in reviews
            ]
            return _ok({"count": len(slim), "reviews": slim})
        except Exception as exc:  # noqa: BLE001
            logger.exception("list_reviews failed")
            return _err(f"unexpected error: {exc}", "INTERNAL")

    # ------------------------------------------------------------------
    # 6. get_audit_log
    # ------------------------------------------------------------------
    @mcp.tool()
    async def get_audit_log(review_id: str = "", limit: int = 50) -> str:
        """Read the append-only audit ledger (audit.jsonl).

        Every review, attestation, approval request, and decision appends one
        immutable line here. Read-only, idempotent.

        Args:
            review_id: Optional. Filter to a single review's events.
            limit: Max entries to return, most recent last (default 50).

        Returns:
            Success: {"data": {"count", "entries": [{"ts","event","review_id",
                ...}]}}.

        Example:
            get_audit_log(review_id="nixrev-20260704T101500-ab12cd")
        """
        try:
            entries = store.read_audit(review_id=review_id.strip(), limit=limit)
            return _ok({"count": len(entries), "entries": entries})
        except Exception as exc:  # noqa: BLE001
            logger.exception("get_audit_log failed")
            return _err(f"unexpected error: {exc}", "INTERNAL")

    # ------------------------------------------------------------------
    # 7. refresh_kev_cache
    # ------------------------------------------------------------------
    @mcp.tool()
    async def refresh_kev_cache() -> str:
        """Fetch the live CISA KEV catalog and refresh the local cache.

        Proves the KEV leg works independently of a NixOS host. Fetches the
        keyless CISA feed over HTTPS and caches it. On fetch failure (the feed
        bot-blocks some clients) it reports the error honestly and does NOT
        fabricate data.

        Args: none.

        Returns:
            Success: {"data": {"refreshed": true, "cached_at", "entry_count",
                "source", "catalog_version"}}.
            Failure: {"error","code","details"} with UPSTREAM_DOWN if the feed
            could not be fetched and no usable cache exists.

        Example:
            refresh_kev_cache()
        """
        try:
            payload = await kev.fetch_and_cache()
            return _ok(
                {
                    "refreshed": True,
                    "cached_at": payload["cached_at"],
                    "entry_count": payload["count"],
                    "source": payload["source"],
                    "catalog_version": payload.get("catalog_version"),
                }
            )
        except KevError as exc:
            status = kev.status()
            return _err(
                str(exc),
                exc.code,
                existing_cache=status,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("refresh_kev_cache failed")
            return _err(f"unexpected error: {exc}", "INTERNAL")

    return mcp


def main() -> None:
    settings = load_settings()
    configure_logging(level=settings.log_level, fmt=settings.log_format)
    logger.info(
        "mcp-nixreview starting",
        extra={"version": __version__, "config": settings.safe_repr()},
    )
    server = build_server(settings)
    server.run(
        transport="streamable-http",
        host=settings.mcp_host,
        port=settings.mcp_port,
    )


if __name__ == "__main__":
    main()
