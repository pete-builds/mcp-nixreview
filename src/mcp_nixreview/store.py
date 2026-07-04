"""Persistence: append-only, hash-chained audit ledger + queryable review state.

Two files under ``data_dir``:

- ``audit.jsonl`` — append-only, one JSON line per event, **hash-chained** so
  the ledger is tamper-EVIDENT (not tamper-proof). Each record carries a
  ``prev_hash`` (the previous record's ``record_hash``, or 64 zeros for the
  genesis record) and a ``record_hash`` = sha256 over the record's content plus
  ``prev_hash``. Any edit, deletion, or reordering breaks the chain, which
  ``verify_chain()`` detects. A local process with write access can still
  rewrite the file, but it cannot do so *undetectably* without recomputing every
  downstream hash — and it still cannot forge a record that matches an
  externally recorded head hash.
- ``reviews.json`` — current state of each review, keyed by ``review_id``
  (rewritten on update, so ``list_reviews`` is cheap). The ledger is the
  source of truth for history; this file is a materialised view.

Secrets are never written to either file — only config text the user supplied,
grades, CVE/KEV metadata, and human decisions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

logger = logging.getLogger("mcp_nixreview.store")


class Store:
    def __init__(self, data_dir: str | os.PathLike[str], timezone: str = "America/New_York"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.data_dir / "audit.jsonl"
        self.reviews_path = self.data_dir / "reviews.json"
        try:
            self._tz = ZoneInfo(timezone)
        except Exception:  # pragma: no cover - falls back to UTC if tzdata missing
            self._tz = ZoneInfo("UTC")

    def now_iso(self) -> str:
        return datetime.now(self._tz).isoformat(timespec="seconds")

    def new_review_id(self) -> str:
        stamp = datetime.now(self._tz).strftime("%Y%m%dT%H%M%S")
        return f"nixrev-{stamp}-{uuid.uuid4().hex[:6]}"

    # -- reviews (materialised state) --------------------------------------

    def _load_reviews(self) -> dict[str, dict]:
        if not self.reviews_path.exists():
            return {}
        try:
            return json.loads(self.reviews_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_reviews(self, reviews: dict[str, dict]) -> None:
        tmp = self.reviews_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(reviews, indent=2), encoding="utf-8")
        tmp.replace(self.reviews_path)

    def get_review(self, review_id: str) -> dict | None:
        return self._load_reviews().get(review_id)

    def upsert_review(self, review: dict) -> None:
        reviews = self._load_reviews()
        reviews[review["review_id"]] = review
        self._save_reviews(reviews)

    def list_reviews(self, status: str = "", limit: int = 20) -> list[dict]:
        reviews = list(self._load_reviews().values())
        if status:
            reviews = [r for r in reviews if r.get("status") == status]
        reviews.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return reviews[: max(0, limit)]

    # -- audit ledger (append-only, hash-chained) --------------------------

    GENESIS_HASH = "0" * 64

    @staticmethod
    def _record_hash(content: dict, prev_hash: str) -> str:
        """sha256 over the canonical content plus prev_hash.

        ``content`` is the record WITHOUT its own ``record_hash`` field. Keys are
        sorted so the digest is stable regardless of dict insertion order.
        """
        payload = json.dumps(
            {"content": content, "prev_hash": prev_hash},
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _last_hash(self) -> str:
        """Return the record_hash of the last ledger line, or GENESIS if empty."""
        if not self.audit_path.exists():
            return self.GENESIS_HASH
        last = self.GENESIS_HASH
        with self.audit_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last = rec.get("record_hash", last)
        return last

    def append_audit(self, event: dict) -> None:
        prev_hash = self._last_hash()
        content = {"ts": self.now_iso(), **event}
        record = {**content, "prev_hash": prev_hash}
        record["record_hash"] = self._record_hash(content, prev_hash)
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    def read_audit(self, review_id: str = "", limit: int = 50) -> list[dict]:
        if not self.audit_path.exists():
            return []
        entries: list[dict] = []
        with self.audit_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if review_id and rec.get("review_id") != review_id:
                    continue
                entries.append(rec)
        return entries[-max(0, limit):]

    def verify_chain(self) -> dict:
        """Verify the audit ledger's hash chain end-to-end.

        Recomputes each record's hash from its content + the previous record's
        hash and checks the linkage. Detects edits, deletions, reordering, and a
        broken genesis link.

        Returns a dict:
            {"ok": bool, "entries": int, "head_hash": str,
             "broken_at": int|None, "reason": str|None}
        ``broken_at`` is the 1-based line number of the first bad record.
        Legacy records written before hash-chaining (no ``record_hash``) are
        reported as ``ok: false`` with reason "unchained legacy record".
        """
        if not self.audit_path.exists():
            return {"ok": True, "entries": 0, "head_hash": self.GENESIS_HASH,
                    "broken_at": None, "reason": None}
        prev = self.GENESIS_HASH
        count = 0
        with self.audit_path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                count += 1
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return {"ok": False, "entries": count, "head_hash": prev,
                            "broken_at": lineno, "reason": "malformed JSON line"}
                if "record_hash" not in rec or "prev_hash" not in rec:
                    return {"ok": False, "entries": count, "head_hash": prev,
                            "broken_at": lineno,
                            "reason": "unchained legacy record (no hash fields)"}
                content = {k: v for k, v in rec.items()
                           if k not in ("record_hash", "prev_hash")}
                if rec["prev_hash"] != prev:
                    return {"ok": False, "entries": count, "head_hash": prev,
                            "broken_at": lineno, "reason": "prev_hash does not link"}
                expected = self._record_hash(content, rec["prev_hash"])
                if rec["record_hash"] != expected:
                    return {"ok": False, "entries": count, "head_hash": prev,
                            "broken_at": lineno,
                            "reason": "record_hash mismatch (content altered)"}
                prev = rec["record_hash"]
        return {"ok": True, "entries": count, "head_hash": prev,
                "broken_at": None, "reason": None}
