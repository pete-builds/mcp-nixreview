# mcp-nixreview

[![CI](https://github.com/pete-builds/mcp-nixreview/actions/workflows/ci.yml/badge.svg)](https://github.com/pete-builds/mcp-nixreview/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A safety gate for agent-proposed NixOS configuration changes.**

`mcp-nixreview` is an [MCP](https://modelcontextprotocol.io/) server (FastMCP, Streamable HTTP) that sits between an AI agent's proposed change to a NixOS config and the human who applies it. When an agent proposes a change, this server:

1. **Grades the security-relevant option deltas** in the diff (HIGH / MED / LOW): opened firewall ports, loosened SSH login, new `wheel`/sudo membership, passwordless sudo, disabled `fail2ban`, services bound to `0.0.0.0`.
2. **Attests the resulting closure** for known vulnerabilities by wrapping [`vulnix`](https://github.com/nix-community/vulnix) and joining the CVE IDs against a cached [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog. Any KEV match escalates to HIGH.
3. **Gates on a human decision** and writes an **append-only, hash-chained audit ledger** of every change, grade, KEV hit, and decision. Anchor it before treating it as proof of what was approved: see [the audit ledger](#the-audit-ledger-and-what-the-chain-actually-proves).

Its novel primitive is a **semantic, security-aware risk grade of a NixOS option delta, fused with a CVE/KEV attestation of the closure it would build**, behind a human gate with a verifiable ledger.

---

## Try it in 60 seconds

Given this proposed change:

```nix
+  services.openssh.settings.PermitRootLogin = "yes";
+  networking.firewall.allowedTCPPorts = [ 22 5432 ];
+  security.sudo.wheelNeedsPassword = false;
```

`review_diff` returns (real output, no network or NixOS host needed):

```json
{
  "overall_grade": "HIGH",
  "summary": { "high": 3, "med": 0, "low": 0 },
  "findings": [
    { "grade": "HIGH", "category": "ssh",      "rationale": "Enables direct root login over SSH." },
    { "grade": "HIGH", "category": "firewall", "rationale": "Opens sensitive service port(s) [22, 5432] to the firewall." },
    { "grade": "HIGH", "category": "sudo",     "rationale": "Grants passwordless sudo to the wheel group." }
  ],
  "advisory": "ADVISORY only, not authoritative. A human must review; this tool never applies changes."
}
```

---

## ⚠️ Advisory, not authoritative

**Read this before you rely on it.** `mcp-nixreview` is a decision aid, not a security guarantee. A security tool that silently misses things is worse than none, because it breeds false confidence, so this one states its limits loudly:

- **The diff review is a curated pattern-matcher, not a Nix evaluator.** It matches a known, high-signal set of options with regexes. It does **not** evaluate the NixOS module system, so it will miss risks expressed through custom modules, `let` bindings, imported files, string interpolation, indirect exposure, or raw `systemd` units. **A clean result means "nothing known-risky matched," never "this change is safe."**
- **The CVE leg inherits `vulnix`'s limits.** `vulnix` itself states its NVD name-matching is *"a coarse heuristic... too simplistic and needs to be improved."* Both missing and spurious matches are possible. The KEV join is only as good as that input.
- **It never applies a change.** It records a human decision. Applying the approved change (handing it to an ops layer / `nixos-rebuild`) is deliberately out of scope.

Every tool response carries an `advisory` banner (and the review tools a longer `advisory_notice`). Treat the output as one input to a human review, not a verdict.

### MVP limitations, at a glance

| Area | Current state | Implication |
|------|---------------|-------------|
| Diff analysis | Regex pattern-matcher over a curated option set | Misses custom modules, raw systemd units, indirect exposure. False negatives are expected. |
| Nix evaluation | None (no module-system evaluation) | Grades text, not evaluated config. |
| CVE scanning | Wraps `vulnix` (coarse NVD name-matching) | Missing/spurious CVE matches both possible. |
| KEV feed | Cached CISA catalog; reports stale/failed fetch | Attestation is only as fresh as the last successful fetch. |
| Authentication | **None** on the MCP endpoint | Must be run behind trusted access (see below). |
| Audit ledger | Local file, append-only, hash-chained | Unanchored by default, and that is weaker than "tamper-evident" sounds: see below. Anchor it with `LEDGER_KEY` or `expected_head`. |
| Review state | `reviews.json`, plain JSON, no chain | This is the file every tool reads to answer "is this approved?". `verify_ledger()` reconciles it against a ledger replay. |
| Apply | Never applies changes | Hand-off to an ops layer is out of scope. |

### Network exposure

This server has **no authentication** and binds `0.0.0.0` by default (convenient for LAN/Tailscale use, matching the usual homelab MCP pattern). **Run it locally or behind trusted access (LAN, Tailscale, a reverse proxy with auth). Do not expose it unauthenticated on an untrusted network or the internet.**

---

## Why this exists

NixOS rollback makes an agent's changes *reversible*, which is often mistaken for *safe*. Rollback covers **availability**, not **security**. A change can rebuild cleanly, stay applied, and roll back perfectly while still opening SSH to the world, granting passwordless sudo, or pulling a KEV-listed package into the closure. **Reversible is not reviewable, and not accountable.** `mcp-nixreview` adds the review-and-attest layer between *propose* and *apply*.

It composes with, rather than competes with, the read-only query MCPs (e.g. [`utensils/mcp-nixos`](https://github.com/utensils/mcp-nixos), which gives an agent accurate package/option knowledge) and Nixpkgs PR-review tooling (e.g. [`nixpkgs-review`](https://github.com/Mic92/nixpkgs-review)): those answer different questions. This is the safety gate that runs *before* an agent-proposed apply.

---

## Tools

| Tool | What it does |
|------|--------------|
| `review_diff(config_ref, ref_type="auto")` | Grade a diff or raw config for security-relevant option changes. Creates a review, writes a ledger entry. No network, no NixOS host needed. |
| `attest_closure(drv_or_path, review_id="")` | Run `vulnix` on a closure (or parse a `vulnix --json` file) and join CVEs to the cached CISA KEV feed. Degrades honestly if `vulnix` is absent. |
| `request_approval(review_id)` | Transition a review to `pending_approval`. |
| `approve(review_id, approver="", decision="approve", note="")` | Record a human decision. **Never applies the change.** |
| `list_reviews(status="", limit=20)` | List reviews, most recent first. |
| `get_audit_log(review_id="", limit=50)` | Read the append-only, hash-chained `audit.jsonl` ledger. |
| `verify_ledger()` | Verify the ledger's hash chain end-to-end; detects any edit, deletion, or reordering. |
| `refresh_kev_cache()` | Fetch the live CISA KEV catalog and refresh the local cache. |

Every tool returns a JSON string using a standard contract: success is `{"data": ...}` (always including a short `advisory` banner), failure is `{"error", "code", "details"}` with `code` from a fixed enum (`INVALID_INPUT`, `NOT_FOUND`, `UPSTREAM_DOWN`, `INTERNAL`, ...).

### What `review_diff` detects

| Category | Option(s) | Example grade |
|----------|-----------|---------------|
| Firewall | `networking.firewall.allowedTCP/UDPPorts`, `allowed*PortRanges` | MED (ordinary port), HIGH (sensitive service port or a range) |
| SSH | `services.openssh.settings.PermitRootLogin`, `PasswordAuthentication` | HIGH (`PermitRootLogin="yes"`, `PasswordAuthentication=true`) |
| Sudo | `users.users.*.extraGroups` containing `"wheel"`, `security.sudo.wheelNeedsPassword` | MED (new sudoer), HIGH (passwordless sudo) |
| fail2ban | `services.fail2ban.enable` | MED (disabled/removed) |
| Exposure | any setting binding a service to `0.0.0.0` | MED |

The grading policy lives in [`src/mcp_nixreview/review/diff.py`](src/mcp_nixreview/review/diff.py) and is pinned by tests.

### The audit ledger, and what the chain actually proves

Each `audit.jsonl` line carries a `prev_hash` and a `record_hash` (sha256 over the record's content plus the previous record's hash). `verify_ledger()` recomputes the whole chain and flags the first record that was edited, deleted, or reordered.

**On its own, that does not detect a deliberate forgery, and this section used to say it did.** Two reviewers demonstrated the gap by flipping a rejection into an approval by a named human and getting a clean verdict; one rebuilt the forgery from the recipe in this README without using any of the server's code. The reasons are structural: the hash is unkeyed and its recipe is public, and `audit.head.json`, the sidecar meant to catch a rewrite, sits in the same directory as the ledger it polices with the same permissions. So anyone who can write those two files can edit a past entry, recompute every hash after it, rewrite the sidecar, and pass.

The counterargument is that such an attacker could simply delete the ledger, and deleting both files also passes. True, and not equivalent. A wiped ledger reports zero entries, and nobody reads an empty approval log as "nothing ever happened" -- they start an incident. A forged ledger reports a complete, plausible history in which a dangerous change was approved by a specific person. **Destruction announces itself. Forgery manufactures evidence.**

`verify_ledger()` now reports this in `anchor`, which is the field to read before believing the rest:

| `anchor` | Meaning |
|---|---|
| `"none"` | The chain is self-consistent and nothing more. `anchor_note` says so in words. This is the default. |
| `"hmac"` | `LEDGER_KEY` is set and the sidecar's HMAC verified. Stops a writer who can reach the volume but not this process's environment: a shared or bind-mounted volume, a backup, a sibling container. It does **not** stop code execution inside this container, which can read the key. |
| `"expected_head"` | You passed `verify_ledger(expected_head=...)` with a head hash recorded somewhere else entirely, and it matched. The strongest of the three, because nothing running in this container can defeat it. |

Set `LEDGER_KEY` in the environment. Never in a file under `data_dir` -- that would put the secret in the directory it exists to protect, which is the mistake the plain sidecar already makes.

### The chain protects the history; `reviews.json` is what tools read

Approval state lives in `reviews.json`, ordinary JSON with no chain. Every tool answering "is this approved?" reads that file, not the ledger. Editing one word in it used to flip a rejection to an approval for every consumer while `verify_ledger()` returned a byte-identical clean result, because it never opened the file.

It now replays the ledger and reports disagreements in `state`, covering `status`, `overall_grade`, `decision`, and `approver`, in both directions: a review present in one file and missing from the other is a mismatch too, since deleting a review from the state file hides it from every consumer just as effectively.

`state.unverifiable` names what replay cannot check. The findings list exists **only** in `reviews.json` and is not in the ledger at all, so the ledger cannot be the source of truth for it even in principle. A clean `state.ok` is not full coverage and does not claim to be.

---

## Quick start

### Run with Docker (recommended)

```bash
cp .env.example .env          # no secrets required; the CISA KEV feed is keyless
docker compose up -d --build
```

The server listens on Streamable HTTP at `http://<host>:3722/mcp`. A named volume (`nixreview-data`) holds the audit ledger, review state, and KEV cache. See the network-exposure note above before binding it anywhere untrusted.

### Register with an MCP client

```bash
# Claude Code (Streamable HTTP)
claude mcp add nixreview --transport http --scope user --url http://<host>:3722/mcp
```

### Try it

```
review_diff  -> grade a proposed change (paste a diff or a config snippet)
refresh_kev_cache  -> pull the live CISA KEV catalog into the cache
attest_closure("/path/to/vulnix-output.json", review_id="nixrev-...")
request_approval(review_id) ; approve(review_id, approver="you")
get_audit_log(review_id) ; verify_ledger()
```

Sample inputs are in [`samples/`](samples/): a NixOS diff and a `vulnix --json` fixture (the latter includes Log4Shell, `CVE-2021-44228`, so you can see a KEV escalation without a live closure).

---

## Attestation without a NixOS host

`vulnix` runs on NixOS / Nix. This server runs anywhere, so `attest_closure` supports three modes:

1. **Live closure** — if `vulnix` is on `PATH`, it runs `vulnix --json <path>`.
2. **Pre-generated output** — pass a path ending in `.json` holding `vulnix --json` output. Useful for CI, or for pointing this server at a NixOS host that produced the file.
3. **Degraded** — if `vulnix` is absent and the path is not a `.json` file, it returns `vulnix_available: false` with a reason and **zero fabricated CVEs**.

The CISA KEV join works in all three modes as long as the cache has been populated (`refresh_kev_cache`).

---

## Roadmap (Phase 2)

None of the below is implemented yet. This tool deliberately does one job well; these are directions, not commitments.

**Composition, not competition.** `mcp-nixreview` is one stage in a pipeline, not a replacement for the tools around it:

```
agent writes config              →  mcp-nixreview reviews          →  human approves  →  apply layer
(optionally grounded by             (security meaning + CVE/KEV,                          (e.g. vespo92/mcp-nixos-ops,
 utensils/mcp-nixos for              graded, gated, ledgered)                              rebuild-switch over SSH)
 accurate package/option data)
```

- **Hand-off to an apply layer after approval.** `mcp-nixreview` never applies changes and never will. A Phase-2 integration would, on approval, hand the reviewed change to an apply-capable ops layer such as [`vespo92/mcp-nixos-ops`](https://github.com/vespo92/mcp-nixos-ops). It composes with that tool rather than competing with it: this one *reviews*, that one *applies*.
- **Evaluated-config grounding (reduces the disclosed false-negative weakness).** The biggest known limitation is that `review_diff` matches diff *text* with regexes and does not evaluate the NixOS module system. A Phase-2 upgrade would move it toward reading *evaluated* nixpkgs/option values, borrowing the grounding *technique* (not the code) from the [`utensils/mcp-nixos`](https://github.com/utensils/mcp-nixos) world, so risks hidden in custom modules or indirect option resolution are caught. This must be **designed against a live NixOS host first**, so it is intentionally deferred until then.
- `detect_drift(host)` — compare a running generation's closure to the declared one (accountability for a declarative fleet).
- `render_review(review_id)` — a PR-comment-style rendered review.
- Signed attestations; `sops-nix` secret-exposure checks; multi-host rollups.

---

## Development

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -q
```

## License

[MIT](LICENSE).

## Acknowledgements

Wraps [`nix-community/vulnix`](https://github.com/nix-community/vulnix) for closure CVE scanning and uses the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Built on [FastMCP](https://github.com/jlowin/fastmcp).
