"""What the ledger can and cannot prove, pinned.

This server exists to prove what was approved. Its verify tool used to claim a
local writer "can still alter the file, but not without breaking the chain this
check detects". Two reviewers disproved that by flipping a rejection into an
approval by a named human and getting a clean verdict.

These tests pin both halves of the correction: the forgery still succeeds when
nothing anchors the chain (and the tool now says so instead of claiming
otherwise), and it fails once something does.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mcp_nixreview.store import Store

KEY = "a-key-that-does-not-live-in-data-dir"


def _reject(store: Store, review_id: str = "r1") -> None:
    """A HIGH-grade change that a named human rejected. The thing worth forging."""
    store.upsert_review({
        "review_id": review_id,
        "status": "rejected",
        "overall_grade": "HIGH",
        "decision": {"decision": "reject", "approver": "pete", "note": "opens root ssh"},
    })
    store.append_audit({"event": "reviewed", "review_id": review_id,
                        "overall_grade": "HIGH", "finding_count": 1})
    store.append_audit({"event": "decided", "review_id": review_id,
                        "decision": "reject", "approver": "pete",
                        "note": "opens root ssh"})


def _forge_ledger(data_dir: Path) -> None:
    """Rewrite history and recompute every hash, using only the public recipe.

    Deliberately does not call any of the server's own append code -- this is
    what an outside writer with access to the directory can do, and what the
    second reviewer did from the README alone.
    """
    path = data_dir / "audit.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for rec in records:
        if rec.get("event") == "decided":
            rec["decision"] = "approve"
    prev = Store.GENESIS_HASH
    out = []
    for rec in records:
        content = {k: v for k, v in rec.items() if k not in ("record_hash", "prev_hash")}
        rec["prev_hash"] = prev
        rec["record_hash"] = Store._record_hash(content, prev)
        prev = rec["record_hash"]
        out.append(json.dumps(rec))
    path.write_text("\n".join(out) + "\n")
    # ...and rewrite the sidecar that is supposed to catch exactly this.
    (data_dir / "audit.head.json").write_text(
        json.dumps({"head_hash": prev, "entries": len(out)})
    )


def _forge_state(store: Store, review_id: str = "r1") -> None:
    store.upsert_review({
        "review_id": review_id,
        "status": "approved",
        "overall_grade": "HIGH",
        "decision": {"decision": "approve", "approver": "pete", "note": "opens root ssh"},
    })


# --- 7a: the chain alone cannot detect a forgery -------------------------


def test_unanchored_forgery_still_verifies_and_the_tool_says_so(tmp_path: Path):
    """The honest result. The check passes; the caveat is what carries the truth.

    Pretending otherwise is the bug being fixed, so this asserts the forgery
    goes undetected AND that the result no longer claims tamper-evidence.
    """
    store = Store(tmp_path)
    _reject(store)
    _forge_ledger(tmp_path)
    _forge_state(store)

    result = store.verify_chain()
    assert result["anchor"] == "none"
    # The chain itself is clean -- that is precisely the problem.
    assert result["broken_at"] is None
    assert "forgery" in result["anchor_note"]
    assert "unkeyed" in result["anchor_note"]


def test_a_signed_head_defeats_the_forgery(tmp_path: Path):
    """A writer who can reach the volume cannot produce a sidecar that verifies."""
    store = Store(tmp_path, ledger_key=KEY)
    _reject(store)
    assert store.verify_chain()["anchor"] == "hmac"

    _forge_ledger(tmp_path)
    _forge_state(store)

    result = store.verify_chain()
    assert result["ok"] is False
    assert "MAC" in result["reason"]


def test_a_tampered_sidecar_count_is_caught_by_the_mac(tmp_path: Path):
    """The MAC covers entries as well as head_hash, so neither moves alone."""
    store = Store(tmp_path, ledger_key=KEY)
    _reject(store)
    head = json.loads((tmp_path / "audit.head.json").read_text())
    head["entries"] = 99
    (tmp_path / "audit.head.json").write_text(json.dumps(head))

    assert store.verify_chain()["ok"] is False


def test_expected_head_catches_what_an_in_container_attacker_cannot(tmp_path: Path):
    """The strongest check: the operator's own record, from outside.

    An attacker with code execution here can read the signing key, so the HMAC
    is not the last word. A head hash written down elsewhere is.
    """
    store = Store(tmp_path)
    _reject(store)
    genuine_head = store.verify_chain()["head_hash"]

    _forge_ledger(tmp_path)
    _forge_state(store)

    result = store.verify_chain(expected_head=genuine_head)
    assert result["ok"] is False
    assert result["anchor"] == "none"
    assert "expected head" in result["reason"]

    # And it does not cry wolf on an untampered ledger.
    clean = Store(tmp_path / "clean")
    _reject(clean)
    good = clean.verify_chain()["head_hash"]
    assert clean.verify_chain(expected_head=good)["ok"] is True
    assert clean.verify_chain(expected_head=good)["anchor"] == "expected_head"


def test_a_signing_key_with_an_unsigned_sidecar_fails_rather_than_guessing(tmp_path: Path):
    """Cannot be told apart from a sidecar swapped by a writer without the key."""
    unsigned = Store(tmp_path)
    _reject(unsigned)

    signed = Store(tmp_path, ledger_key=KEY)
    result = signed.verify_chain()
    assert result["ok"] is False
    assert "no MAC" in result["reason"]

    # One legitimate append signs the head, and it recovers.
    signed.upsert_review({"review_id": "r2", "status": "reviewed",
                          "overall_grade": "LOW", "decision": None})
    signed.append_audit({"event": "reviewed", "review_id": "r2",
                         "overall_grade": "LOW"})
    assert signed.verify_chain()["ok"] is True


# --- 7b: the check must cover the file every tool actually reads ---------


def test_editing_the_unprotected_state_file_is_caught(tmp_path: Path):
    """One word in reviews.json used to flip a rejection for every reader.

    The ledger is untouched here: this is the forgery that needs no hashing at
    all, against the file the verify tool never opened.
    """
    store = Store(tmp_path)
    _reject(store)
    assert store.verify_chain()["ok"] is True

    _forge_state(store)

    result = store.verify_chain()
    assert result["ok"] is False
    assert result["state"]["ok"] is False
    fields = {m["field"] for m in result["state"]["mismatches"]}
    assert {"status", "decision"} <= fields
    assert "reviews.json disagrees" in result["reason"]


def test_deleting_a_review_from_the_state_file_is_caught(tmp_path: Path):
    """Destruction of state is as invisible to consumers as forgery of it."""
    store = Store(tmp_path)
    _reject(store)
    store.reviews_path.write_text("{}")

    result = store.verify_chain()
    assert result["ok"] is False
    assert result["state"]["mismatches"][0]["stored"] == "missing"


def test_reconciliation_names_what_it_cannot_check(tmp_path: Path):
    """A clean result must not be read as full coverage.

    The findings list exists ONLY in reviews.json and is not in the ledger at
    all, so replay cannot vouch for it even in principle.
    """
    store = Store(tmp_path)
    _reject(store)
    assert "findings" in store.verify_chain()["state"]["unverifiable"]


def test_an_attestation_escalating_the_grade_is_not_a_mismatch(tmp_path: Path):
    """Replay has to model the escalate-only rule or it reports false positives."""
    store = Store(tmp_path)
    store.upsert_review({"review_id": "r1", "status": "reviewed",
                         "overall_grade": "CRITICAL", "decision": None})
    store.append_audit({"event": "reviewed", "review_id": "r1", "overall_grade": "LOW"})
    store.append_audit({"event": "attested", "review_id": "r1", "grade": "CRITICAL",
                        "vulnix_available": True, "cve_count": 3, "kev_match_count": 1})

    assert store.verify_chain()["state"]["ok"] is True


def test_an_attestation_never_lowers_the_replayed_grade(tmp_path: Path):
    """The escalate-only rule runs both ways, or it hides a downgrade."""
    store = Store(tmp_path)
    store.upsert_review({"review_id": "r1", "status": "reviewed",
                         "overall_grade": "HIGH", "decision": None})
    store.append_audit({"event": "reviewed", "review_id": "r1", "overall_grade": "HIGH"})
    store.append_audit({"event": "attested", "review_id": "r1", "grade": "LOW",
                        "vulnix_available": True, "cve_count": 0, "kev_match_count": 0})

    assert store.verify_chain()["state"]["ok"] is True


def test_replay_reads_the_whole_ledger_not_a_page(tmp_path: Path):
    """read_audit() defaults to the last 50 entries; replay must not inherit that.

    An old review, long past the window, would otherwise be reported as present
    in reviews.json and absent from the ledger on every busy deployment.
    """
    store = Store(tmp_path)
    for i in range(80):
        store.upsert_review({"review_id": f"r{i}", "status": "reviewed",
                             "overall_grade": None, "decision": None})
        store.append_audit({"event": "reviewed", "review_id": f"r{i}"})

    result = store.verify_chain()
    assert result["state"]["checked"] == 80
    assert result["state"]["ok"] is True


# --- the state file's own write path -------------------------------------


def test_concurrent_upserts_do_not_lose_reviews(tmp_path: Path):
    """Without a lock, two upserts read the same map and the last rename wins.

    The ledger has had an advisory lock since the chain was found forking under
    concurrency. The file every tool reads to answer "is this approved?" did
    not, so a review could vanish while the ledger stayed provably intact --
    which reconciliation now reports, and which this prevents.
    """
    store = Store(tmp_path)
    N = 40

    def write(i: int) -> None:
        store.upsert_review({"review_id": f"r{i}", "status": "reviewed",
                             "overall_grade": None, "decision": None})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(N)))

    assert len(store.list_reviews(limit=N * 2)) == N
