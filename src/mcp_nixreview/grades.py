"""The one grade order every module ranks by.

The server writes grades (``review_diff`` produces ``HIGH/MED/LOW/NONE``,
``attest_closure`` adds ``UNKNOWN``) and the store replays them to check that
``reviews.json`` still agrees with the ledger. Until 2026-09-08 each side had
its own table, and they disagreed on one word: the server said ``MED``, the
replay knew only ``MEDIUM``. Replay ranked ``MED`` as unknown, never
escalated to it, and ``verify_ledger`` reported that the state file disagreed
with the ledger after the most ordinary flow there is. Both tables now live
here, and ``MED`` and ``MEDIUM`` are the same rank so either spelling in an
old ledger replays correctly.
"""

from __future__ import annotations

#: Rank per grade, lowest first. Two spellings of medium on purpose; see above.
#: ``UNKNOWN`` (vulnix unavailable) and anything unrecognised rank with
#: ``NONE`` so a record this version does not understand can never escalate.
GRADE_RANK: dict[str, int] = {
    "NONE": 0,
    "UNKNOWN": 0,
    "LOW": 1,
    "MED": 2,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def grade_rank(grade: str | None) -> int:
    """Numeric rank of ``grade``; unknown or missing grades rank lowest."""
    return GRADE_RANK.get((grade or "NONE").upper(), 0)


def grade_outranks(candidate: str | None, current: str | None) -> bool:
    """True when ``candidate`` is a strictly higher grade than ``current``."""
    return grade_rank(candidate) > grade_rank(current)


__all__ = ["GRADE_RANK", "grade_outranks", "grade_rank"]
