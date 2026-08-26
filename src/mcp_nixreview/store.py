"""Persistence: append-only, hash-chained audit ledger + queryable review state.

Three files under ``data_dir``:

- ``audit.jsonl`` — append-only, one JSON line per event, **hash-chained** so
  the ledger is tamper-EVIDENT (not tamper-proof). Each record carries a
  ``prev_hash`` (the previous record's ``record_hash``, or 64 zeros for the
  genesis record) and a ``record_hash`` = sha256 over the record's content plus
  ``prev_hash``. Any edit, deletion, or reordering breaks the chain, which
  ``verify_chain()`` detects.
- ``audit.head.json`` — trusted head sidecar recording ``{head_hash, entries}``
  after each successful append, plus a ``head_mac`` when a signing key is
  configured. ``verify_chain()`` compares the walked ledger against this
  sidecar so suffix deletion or wholesale truncation is caught even when the
  surviving lines still link cleanly.
- ``reviews.json`` — current state of each review, keyed by ``review_id``
  (rewritten on update, so ``list_reviews`` is cheap). The ledger is the
  source of truth for history; this file is a materialised view, and
  ``verify_chain()`` now checks that it still agrees with the ledger.

**What the chain alone does and does not prove.** The record hash is an
unkeyed SHA-256 whose recipe is published in the README, and the sidecar that
is supposed to catch a rewrite sits in the same directory as the ledger it
polices, with the same permissions. So the chain on its own detects an
*accidental* corruption and a *careless* edit, and does not detect a
deliberate forgery: anyone who can write both files can edit a past entry,
recompute every hash after it, rewrite the sidecar, and get a clean verdict.
Two reviewers did exactly that, flipping a rejection into an approval by a
named human, one of them reimplementing the recipe from the README without
using any of this code.

Two things close that gap, and both are opt-in because both need somewhere to
keep a secret that this process does not choose:

- ``ledger_key`` (from the environment, never from ``data_dir``) makes the
  sidecar carry an HMAC. A writer who can reach the volume but not the
  server's environment can no longer produce a sidecar that verifies. This
  does NOT defend against code execution inside this container, which can read
  the key; the case it covers is a shared or bind-mounted volume, a backup, or
  a sibling container.
- ``verify_chain(expected_head=...)`` compares against a head hash the
  operator recorded somewhere else entirely. Nothing inside this container can
  defeat that, which makes it the stronger of the two. The README already
  promised this and there was no way to pass one in.

With neither configured, ``verify_chain`` reports ``anchor: "none"`` and says
in its own reason field that the result does not distinguish an authentic
ledger from a well-made forgery. That is the honest reading and it is stated
rather than left to be inferred.

Secrets are never written to either file — only config text the user supplied,
grades, CVE/KEV metadata, and human decisions.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

logger = logging.getLogger("mcp_nixreview.store")

#: Grade ordering, lowest first. Kept here rather than imported from the
#: server so replay does not depend on the module that writes the events.
_GRADE_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _grade_outranks(candidate: str | None, current: str | None) -> bool:
    """True when ``candidate`` is a strictly higher grade than ``current``.

    An unknown grade string ranks lowest, so a record carrying something this
    version does not recognise can never silently escalate a replay.
    """
    def rank(value: str | None) -> int:
        try:
            return _GRADE_ORDER.index(value or "NONE")
        except ValueError:
            return 0

    return rank(candidate) > rank(current)


class Store:
    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        timezone: str = "America/New_York",
        ledger_key: str = "",
    ):
        self.data_dir = Path(data_dir)
        # Held in memory only. Writing it under data_dir would put the secret
        # in the directory it is meant to protect, which is the exact mistake
        # the plain sidecar already makes.
        self._ledger_key = ledger_key.encode("utf-8") if ledger_key else b""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.data_dir / "audit.jsonl"
        self.head_path = self.data_dir / "audit.head.json"
        self.reviews_path = self.data_dir / "reviews.json"
        self.reviews_lock_path = self.data_dir / "reviews.lock"
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
        # A per-writer temp name. The old fixed "reviews.json.tmp" meant two
        # concurrent writers shared one scratch file: the first rename moved it
        # away and the second raised FileNotFoundError, losing that update
        # entirely. Caught by the concurrency test once verify_chain started
        # reconciling this file against the ledger.
        tmp = self.reviews_path.with_name(
            f"reviews.{os.getpid()}.{uuid.uuid4().hex[:8]}.json.tmp"
        )
        try:
            tmp.write_text(json.dumps(reviews, indent=2), encoding="utf-8")
            tmp.replace(self.reviews_path)
        finally:
            tmp.unlink(missing_ok=True)

    def get_review(self, review_id: str) -> dict | None:
        return self._load_reviews().get(review_id)

    def upsert_review(self, review: dict) -> None:
        """Insert or replace one review, serialised against other writers.

        The whole read-modify-write is held under an advisory lock, for the
        same reason append_audit is: without it two concurrent upserts both
        read the old map, and whichever renames last erases the other's review
        completely. The ledger got this treatment; the file every tool actually
        reads to answer "is this approved?" did not.

        The lock is a separate file rather than reviews.json itself, because
        the atomic rename replaces that inode -- a lock held on it would be a
        lock on a file that no longer exists.
        """
        with self.reviews_lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                reviews = self._load_reviews()
                reviews[review["review_id"]] = review
                self._save_reviews(reviews)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def list_reviews(self, status: str = "", limit: int = 20) -> list[dict]:
        reviews = list(self._load_reviews().values())
        if status:
            reviews = [r for r in reviews if r.get("status") == status]
        reviews.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return reviews[: max(0, limit)]

    # -- audit ledger (append-only, hash-chained) --------------------------

    GENESIS_HASH = "0" * 64

    #: read_audit() slices to the last N entries; replay needs all of them.
    ALL_ENTRIES = 10**9

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

    @property
    def signing_enabled(self) -> bool:
        return bool(self._ledger_key)

    def _head_mac(self, head_hash: str, entries: int) -> str:
        """HMAC-SHA256 over the sidecar's two fields. Empty when unkeyed.

        Both fields are covered, so an attacker cannot keep a valid MAC while
        changing only the count. Separators are fixed rather than relying on
        json defaults, since the MAC's input must never depend on a formatting
        choice somewhere else in the file.
        """
        if not self._ledger_key:
            return ""
        payload = f"{head_hash}:{entries}".encode()
        return hmac.new(self._ledger_key, payload, hashlib.sha256).hexdigest()

    def _load_trusted_head(self) -> dict:
        empty = {"head_hash": self.GENESIS_HASH, "entries": 0, "head_mac": ""}
        if not self.head_path.exists():
            return empty
        try:
            data = json.loads(self.head_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return empty
        return {
            "head_hash": data.get("head_hash", self.GENESIS_HASH),
            "entries": data.get("entries", 0),
            "head_mac": data.get("head_mac", ""),
        }

    def _save_trusted_head(self, head_hash: str, entries: int) -> None:
        payload: dict = {"head_hash": head_hash, "entries": entries}
        mac = self._head_mac(head_hash, entries)
        if mac:
            payload["head_mac"] = mac
        tmp = self.head_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(self.head_path)

    def append_audit(self, event: dict) -> None:
        # Serialize the full read-hash-then-append with an advisory POSIX file
        # lock on the ledger itself. Concurrent workers on the same host block
        # here so prev_hash stays monotonic and the chain never forks.
        self.audit_path.touch(exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                trusted = self._load_trusted_head()
                prev_hash = self._last_hash()
                content = {"ts": self.now_iso(), **event}
                record = {**content, "prev_hash": prev_hash}
                record["record_hash"] = self._record_hash(content, prev_hash)
                fh.write(json.dumps(record, default=str) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
                self._save_trusted_head(record["record_hash"], trusted["entries"] + 1)
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

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

    # -- reconciliation: does reviews.json still match the ledger? ---------

    #: Fields of a review that the ledger actually carries, so a disagreement
    #: is provable. Anything else in reviews.json is unverifiable by replay,
    #: which is reported rather than quietly treated as agreement.
    REPLAYABLE_FIELDS = ("status", "overall_grade", "decision", "approver")

    def replay_reviews(self) -> dict[str, dict]:
        """Rebuild what reviews.json should say, from ledger events alone.

        This is deliberately a separate reconstruction rather than a diff
        against the live file: the point is to derive the answer from the
        protected artifact and then see whether the unprotected one agrees.

        Only the fields the ledger records are reconstructed. The findings
        list, notably, exists ONLY in reviews.json -- it is not in the ledger
        at all -- so the ledger cannot serve as the source of truth for it even
        in principle, whatever the code's comments used to claim.
        """
        state: dict[str, dict] = {}
        # The whole ledger, not a page of it: a replay that silently used
        # the default 50-entry window would call an old, unrepresented review
        # a mismatch.
        for rec in self.read_audit(limit=self.ALL_ENTRIES):
            review_id = rec.get("review_id")
            if not review_id:
                continue
            entry = state.setdefault(
                review_id,
                {"status": None, "overall_grade": None, "decision": None,
                 "approver": None},
            )
            event = rec.get("event")
            if event == "reviewed":
                entry["status"] = "reviewed"
                entry["overall_grade"] = rec.get("overall_grade")
            elif event == "attested":
                # An attestation only ever escalates the grade; it never
                # lowers one, so a lower value here is not a disagreement.
                grade = rec.get("grade")
                if grade and _grade_outranks(grade, entry["overall_grade"]):
                    entry["overall_grade"] = grade
            elif event == "approval_requested":
                entry["status"] = "pending_approval"
            elif event == "decided":
                decision = rec.get("decision")
                entry["decision"] = decision
                entry["approver"] = rec.get("approver")
                entry["status"] = "approved" if decision == "approve" else "rejected"
        return state

    def reconcile_reviews(self) -> dict:
        """Compare reviews.json against the ledger replay.

        Returns ``{"ok", "checked", "mismatches", "unverifiable"}``.

        ``mismatches`` are provable disagreements: a review whose stored status,
        grade, decision, or approver differs from what the ledger says, or which
        appears in one file and not the other. ``unverifiable`` names fields the
        ledger cannot speak to, so a reader knows the limit of this check rather
        than reading a clean result as full coverage.
        """
        stored = self._load_reviews()
        replayed = self.replay_reviews()
        mismatches: list[dict] = []

        for review_id in sorted(set(stored) | set(replayed)):
            if review_id not in stored:
                mismatches.append({
                    "review_id": review_id,
                    "field": "*",
                    "ledger": "present",
                    "stored": "missing",
                })
                continue
            if review_id not in replayed:
                mismatches.append({
                    "review_id": review_id,
                    "field": "*",
                    "ledger": "missing",
                    "stored": "present",
                })
                continue
            live = stored[review_id]
            expected = replayed[review_id]
            decision_record = live.get("decision") or {}
            actual = {
                "status": live.get("status"),
                "overall_grade": live.get("overall_grade"),
                "decision": decision_record.get("decision"),
                "approver": decision_record.get("approver"),
            }
            for field in self.REPLAYABLE_FIELDS:
                # A field the ledger never set is not evidence of anything.
                if expected[field] is None and actual[field] is None:
                    continue
                if expected[field] != actual[field]:
                    mismatches.append({
                        "review_id": review_id,
                        "field": field,
                        "ledger": expected[field],
                        "stored": actual[field],
                    })

        return {
            "ok": not mismatches,
            "checked": len(set(stored) | set(replayed)),
            "mismatches": mismatches,
            "unverifiable": ["findings", "summary_text", "attestation_detail"],
        }

    def verify_chain(self, expected_head: str = "") -> dict:
        """Verify the audit ledger, its sidecar, and the state file that reads it.

        Three separate checks, reported separately because they fail for
        different reasons and mean different things:

        1. **The chain.** Recomputes each record's hash from its content plus
           the previous record's hash and checks the linkage. Detects edits,
           reordering, mid-chain deletions, and a broken genesis link. Then
           cross-checks the walked result against the sidecar, so suffix
           deletion or wholesale truncation -- which leave the surviving prefix
           internally consistent -- is caught too.

        2. **The anchor**, reported in ``anchor``: what, if anything, makes
           this more than a self-consistency check. ``"expected_head"`` when
           the caller supplied a head hash from outside this container and it
           matched (the strongest, since nothing in here can defeat it),
           ``"hmac"`` when a signing key was configured and the sidecar's MAC
           verified, ``"none"`` when neither. With ``"none"``, ``reason``
           says outright that the result does not distinguish an authentic
           ledger from a well-made forgery -- because the hash is unkeyed, the
           recipe is in the README, and the sidecar lives beside the file it
           polices.

        3. **The state file**, reported in ``state``. The chain protects
           audit.jsonl; every tool that answers "is this approved?" reads
           reviews.json, which nothing protected and nothing reconciled. One
           edited word there flipped a rejection to an approval for every
           reader while this method returned a byte-identical clean result.
           It now replays the ledger and reports disagreements, along with the
           fields replay cannot speak to.

        ``ok`` is the conjunction of all three, so a caller who reads only that
        field is not told a forged or contradicted ledger is healthy.

        Returns a dict:
            {"ok", "entries", "head_hash", "broken_at", "reason",
             "anchor", "state"}
        ``broken_at`` is the 1-based line number of the first bad record, or
        ``None`` when the failure is not a per-record one.
        Legacy records written before hash-chaining (no ``record_hash``) are
        reported as ``ok: false`` with reason "unchained legacy record".
        """
        result = self._walk_chain()
        anchor, anchor_note = self._check_anchor(result, expected_head)
        state = self.reconcile_reviews()

        # `reason` stays what it always was: why this FAILED, null when it did
        # not. Being unanchored is a caveat on a passing result, not a failure,
        # so it goes in its own field rather than putting prose in `reason`
        # beside `ok: true` and breaking every caller that tests for null.
        reasons = [result["reason"]] if result["reason"] else []
        if anchor == "broken":
            reasons.append(anchor_note or "anchor check failed")
        if not state["ok"]:
            count = len(state["mismatches"])
            first = state["mismatches"][0]
            reasons.append(
                f"reviews.json disagrees with the ledger in {count} place(s); "
                f"first: {first['review_id']} {first['field']} is "
                f"{first['stored']!r}, ledger says {first['ledger']!r}"
            )

        result["ok"] = result["ok"] and anchor != "broken" and state["ok"]
        result["anchor"] = "none" if anchor == "broken" else anchor
        result["anchor_note"] = anchor_note if anchor == "none" else None
        result["state"] = state
        result["reason"] = "; ".join(reasons) if reasons else None
        return result

    def _check_anchor(self, result: dict, expected_head: str) -> tuple[str, str | None]:
        """Decide what, if anything, makes the chain result more than self-consistent.

        An operator-supplied ``expected_head`` wins over the HMAC when both are
        available: it was recorded outside this container, so unlike the key it
        cannot be read by whatever is running in here.
        """
        trusted = self._load_trusted_head()

        if expected_head:
            if expected_head.strip().lower() != result["head_hash"].lower():
                return "broken", (
                    f"expected head {expected_head.strip()[:12]} but ledger "
                    f"head is {result['head_hash'][:12]}"
                )
            return "expected_head", None

        if self.signing_enabled:
            stored_mac = trusted.get("head_mac", "")
            if not stored_mac:
                return "broken", (
                    "a signing key is configured but the head sidecar carries no "
                    "MAC. Either it predates the key, or it was replaced by a "
                    "writer without it. The next appended event signs the head; "
                    "until then this cannot be told apart from a rewrite, so it "
                    "fails rather than guessing"
                )
            expected_mac = self._head_mac(trusted["head_hash"], trusted["entries"])
            if not hmac.compare_digest(stored_mac, expected_mac):
                return "broken", "head sidecar MAC does not verify against the signing key"
            return "hmac", None

        return "none", (
            "unanchored: the record hash is unkeyed, its recipe is public, and "
            "the head sidecar sits in the same directory as the ledger it "
            "polices. This result therefore does not distinguish an authentic "
            "ledger from a well-made forgery. Set a signing key, or pass "
            "expected_head recorded outside this container"
        )

    def _walk_chain(self) -> dict:
        """Walk the ledger and cross-check the sidecar. Chain integrity only."""
        trusted = self._load_trusted_head()
        if not self.audit_path.exists():
            if trusted["entries"] > 0 or trusted["head_hash"] != self.GENESIS_HASH:
                return {"ok": False, "entries": 0, "head_hash": self.GENESIS_HASH,
                        "broken_at": None,
                        "reason": f"ledger missing; trusted head expects "
                                  f"{trusted['entries']} entries"}
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
        if trusted["head_hash"] != prev or trusted["entries"] != count:
            return {"ok": False, "entries": count, "head_hash": prev,
                    "broken_at": None,
                    "reason": (f"head mismatch: trusted "
                               f"{trusted['head_hash'][:12]}/{trusted['entries']} "
                               f"vs ledger {prev[:12]}/{count}")}
        return {"ok": True, "entries": count, "head_hash": prev,
                "broken_at": None, "reason": None}
