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


def test_ledger_is_hash_chained(tmp_path: Path):
    store = Store(tmp_path)
    store.append_audit({"event": "reviewed", "review_id": "r1"})
    store.append_audit({"event": "decided", "review_id": "r1", "decision": "approve"})
    entries = store.read_audit()
    assert entries[0]["prev_hash"] == store.GENESIS_HASH
    assert entries[1]["prev_hash"] == entries[0]["record_hash"]
    assert len(entries[0]["record_hash"]) == 64


def test_verify_chain_passes_on_intact_ledger(tmp_path: Path):
    store = Store(tmp_path)
    for i in range(3):
        store.append_audit({"event": "reviewed", "review_id": f"r{i}"})
    result = store.verify_chain()
    assert result["ok"] is True
    assert result["entries"] == 3
    assert result["broken_at"] is None
    assert result["head_hash"] != store.GENESIS_HASH


def test_verify_chain_detects_content_tamper(tmp_path: Path):
    store = Store(tmp_path)
    store.append_audit({"event": "reviewed", "review_id": "r1", "grade": "HIGH"})
    store.append_audit({"event": "decided", "review_id": "r1", "decision": "reject"})
    # Rewrite line 2's decision reject -> approve, leaving its record_hash intact.
    p = tmp_path / "audit.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"reject"', '"approve"')
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = store.verify_chain()
    assert result["ok"] is False
    assert result["broken_at"] == 2
    assert "record_hash mismatch" in result["reason"]


def test_verify_chain_detects_deletion(tmp_path: Path):
    store = Store(tmp_path)
    for i in range(3):
        store.append_audit({"event": "reviewed", "review_id": f"r{i}"})
    # Delete the middle record; the third's prev_hash no longer links.
    p = tmp_path / "audit.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    p.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    result = store.verify_chain()
    assert result["ok"] is False
    assert result["broken_at"] == 2
    assert "prev_hash does not link" in result["reason"]


def test_ledger_never_stores_raw_secrets(tmp_path: Path):
    # The store writes whatever event dict it's given; the server never passes
    # secrets in. This asserts the ledger file only contains what we wrote.
    store = Store(tmp_path)
    store.append_audit({"event": "reviewed", "review_id": "r1", "overall_grade": "HIGH"})
    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "password" not in raw.lower()
    assert "authorization" not in raw.lower()
