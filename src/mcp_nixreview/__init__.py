"""mcp-nixreview: advisory NixOS change-review + CVE/KEV attestation gate.

An MCP server (FastMCP, Streamable HTTP) that sits between an agent's proposed
NixOS configuration change and the human who applies it. It grades the
security-relevant option deltas in a diff, attests the resulting closure
against a cached CISA KEV feed, gates on a human decision, and writes an
append-only, hash-chained (tamper-evident) audit ledger.

ADVISORY, NOT AUTHORITATIVE. See README for the honest caveats.
"""

__version__ = "0.1.0"

# Short, always-present banner for every success response. The long-form
# ADVISORY_NOTICE below carries the full caveats.
ADVISORY_SHORT = (
    "ADVISORY only, not authoritative. A human must review; "
    "this tool never applies changes."
)

ADVISORY_NOTICE = (
    "ADVISORY, NOT AUTHORITATIVE. This review covers a curated, high-signal "
    "set of NixOS options and a coarse CVE/KEV heuristic; it can miss risks "
    "hidden in custom modules, raw systemd units, or indirect exposure. Do "
    "not treat a clean result as proof of safety. A human must review and "
    "approve. This tool never applies a change."
)
