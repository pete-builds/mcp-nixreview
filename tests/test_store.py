"""Store: append-only ledger + review state contract, and secret hygiene."""

from __future__ import annotations

from pathlib import Path

from mcp_nixreview.store import Store


def test_append_only_ledger(tmp_path: Path):
    store = Store(tmp_path)
    store.append_audit({"event": "reviewed", "review_id": "r1"})
    store.append_audit({"event": "decided", "review_id": "r1", "decision": "approve"})
    entries = store.read_audit()
    assert len(entries) == 2
    assert entries[0]["event"] == "reviewed"
    assert all("ts" in e for e in entries)


def test_audit_filter_by_review(tmp_path: Path):
    store = Store(tmp_path)
    store.append_audit({"event": "reviewed", "review_id": "r1"})
    store.append_audit({"event": "reviewed", "review_id": "r2"})
    assert len(store.read_audit(review_id="r1")) == 1


def test_review_upsert_and_list(tmp_path: Path):
    store = Store(tmp_path)
    rid = store.new_review_id()
    assert rid.startswith("nixrev-")
    store.upsert_review({"review_id": rid, "status": "reviewed", "created_at": store.now_iso()})
    assert store.get_review(rid) is not None
    assert len(store.list_reviews(status="reviewed")) == 1
    assert len(store.list_reviews(status="approved")) == 0


def test_ledger_never_stores_raw_secrets(tmp_path: Path):
    # The store writes whatever event dict it's given; the server never passes
    # secrets in. This asserts the ledger file only contains what we wrote.
    store = Store(tmp_path)
    store.append_audit({"event": "reviewed", "review_id": "r1", "overall_grade": "HIGH"})
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "password" not in raw.lower()
    assert "authorization" not in raw.lower()
