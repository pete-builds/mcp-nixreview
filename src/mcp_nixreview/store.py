"""Persistence: append-only audit ledger + queryable review state.

Two files under ``data_dir``:

- ``audit.jsonl`` — append-only, one JSON line per event (immutable history).
  Every review action writes a line here and it is never rewritten.
- ``reviews.json`` — current state of each review, keyed by ``review_id``
  (rewritten on update, so ``list_reviews`` is cheap). The ledger is the
  source of truth for history; this file is a materialised view.

Secrets are never written to either file — only config text the user supplied,
grades, CVE/KEV metadata, and human decisions.
"""

from __future__ import annotations

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

    # -- audit ledger (append-only) ----------------------------------------

    def append_audit(self, event: dict) -> None:
        record = {"ts": self.now_iso(), **event}
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
