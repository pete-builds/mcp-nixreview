"""Operator CLI: adopt an unsigned ledger under the configured signing key.

    python -m mcp_nixreview.adopt --expected-head <sha256>
    python -m mcp_nixreview.adopt --force

Run once, inside the container (or with the same ``NIXREVIEW_*`` environment),
after adding ``ledger_key`` to a deployment whose ledger predates it. The
server will not do this on its own: signing whatever head is on disk as a side
effect of the next review was the laundering path a forged ledger used to
take. Record the head hash from a ``verify_ledger`` result you trust BEFORE
setting the key, and pass it here. ``--force`` adopts without that check and
is recorded as such in the log line.
"""

from __future__ import annotations

import argparse
import json
import sys

from mcp_nixreview.config import Settings
from mcp_nixreview.store import LedgerIntegrityError, Store


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--expected-head", default="",
                       help="head hash recorded from a trusted verify_ledger result")
    group.add_argument("--force", action="store_true",
                       help="adopt whatever is on disk without an expected head")
    args = parser.parse_args(argv)

    settings = Settings()
    store = Store(settings.data_dir, timezone=settings.timezone, ledger_key=settings.ledger_key)
    try:
        outcome = store.adopt_unsigned_ledger(expected_head=args.expected_head, force=args.force)
    except LedgerIntegrityError as exc:
        print(json.dumps({"adopted": False, "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(outcome))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
