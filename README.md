# mcp-nixreview

**An advisory security-review + attestation gate that sits between an agent's proposed NixOS config change and the human who applies it.**

`mcp-nixreview` is an [MCP](https://modelcontextprotocol.io/) server (FastMCP, Streamable HTTP). When an AI agent proposes a change to a NixOS configuration, this server:

1. **Grades the security-relevant option deltas** in the diff (HIGH / MED / LOW): opened firewall ports, loosened SSH login, new `wheel`/sudo membership, passwordless sudo, disabled `fail2ban`, services bound to `0.0.0.0`.
2. **Attests the resulting closure** by wrapping [`vulnix`](https://github.com/nix-community/vulnix) and joining the CVE IDs against a cached [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) feed. Any KEV match escalates to HIGH.
3. **Gates on a human decision** and writes an **append-only audit ledger** (`audit.jsonl`) of every change, grade, KEV hit, and decision.

Its novel primitive is a **semantic, security-aware risk grade of a NixOS option delta, fused with a CVE/KEV attestation of the closure it would build**, behind a human gate with a durable ledger.

---

## ⚠️ Advisory, not authoritative

**Read this before you rely on it.** `mcp-nixreview` is a decision aid, not a security guarantee. A security tool that silently misses things is worse than none, because it breeds false confidence, so this one states its limits loudly:

- **The diff review is a curated pattern-matcher, not a Nix evaluator.** It matches a known, high-signal set of options. It does **not** evaluate the NixOS module system, so it will miss risks expressed through custom modules, `let` bindings, imported files, string interpolation, indirect exposure, or raw `systemd` units. **A clean result means "nothing known-risky matched," never "this change is safe."**
- **The CVE leg inherits `vulnix`'s limits.** `vulnix` itself states its NVD name-matching is *"a coarse heuristic... too simplistic and needs to be improved."* Both missing and spurious matches are possible. The KEV join is only as good as that input.
- **It never applies a change.** It records a human decision. Applying the approved change (handing it to an ops layer / `nixos-rebuild`) is deliberately out of scope.

Every tool response carries an `advisory_notice` field restating this. Treat the output as one input to a human review, not a verdict.

---

## Why this exists

NixOS rollback makes an agent's changes *reversible*, which is often mistaken for *safe*. Rollback covers **availability**, not **security**. A change can rebuild cleanly, stay applied, and roll back perfectly while still opening SSH to the world, granting passwordless sudo, or pulling a KEV-listed package into the closure. **Reversible is not reviewable, and not accountable.** `mcp-nixreview` adds the review-and-attest layer between *propose* and *apply*.

It composes with, rather than competes with, the read-only query MCPs and the apply-capable ops MCPs in the ecosystem: this is the reviewer that runs *before* an apply.

---

## Tools

| Tool | What it does |
|------|--------------|
| `review_diff(config_ref, ref_type="auto")` | Grade a diff or raw config for security-relevant option changes. Creates a review, writes a ledger entry. No network, no NixOS host needed. |
| `attest_closure(drv_or_path, review_id="")` | Run `vulnix` on a closure (or parse a `vulnix --json` file) and join CVEs to the cached CISA KEV feed. Degrades honestly if `vulnix` is absent. |
| `request_approval(review_id)` | Transition a review to `pending_approval`. |
| `approve(review_id, approver="", decision="approve", note="")` | Record a human decision. **Never applies the change.** |
| `list_reviews(status="", limit=20)` | List reviews, most recent first. |
| `get_audit_log(review_id="", limit=50)` | Read the append-only `audit.jsonl` ledger. |
| `refresh_kev_cache()` | Fetch the live CISA KEV catalog and refresh the local cache. |

Every tool returns a JSON string using a standard contract: success is `{"data": ...}`, failure is `{"error", "code", "details"}` with `code` from a fixed enum (`INVALID_INPUT`, `NOT_FOUND`, `UPSTREAM_DOWN`, `INTERNAL`, ...).

### What `review_diff` detects

| Category | Option(s) | Example grade |
|----------|-----------|---------------|
| Firewall | `networking.firewall.allowedTCP/UDPPorts`, `allowed*PortRanges` | MED (ordinary port), HIGH (sensitive service port or a range) |
| SSH | `services.openssh.settings.PermitRootLogin`, `PasswordAuthentication` | HIGH (`PermitRootLogin="yes"`, `PasswordAuthentication=true`) |
| Sudo | `users.users.*.extraGroups` containing `"wheel"`, `security.sudo.wheelNeedsPassword` | MED (new sudoer), HIGH (passwordless sudo) |
| fail2ban | `services.fail2ban.enable` | MED (disabled/removed) |
| Exposure | any setting binding a service to `0.0.0.0` | MED |

The grading policy lives in [`src/mcp_nixreview/review/diff.py`](src/mcp_nixreview/review/diff.py) and is pinned by tests.

---

## Quick start

### Run with Docker (recommended)

```bash
cp .env.example .env          # no secrets required; the CISA KEV feed is keyless
docker compose up -d --build
```

The server listens on Streamable HTTP at `http://<host>:3722/mcp`. A named volume (`nixreview-data`) holds the audit ledger, review state, and KEV cache.

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
get_audit_log(review_id)
```

Sample inputs are in [`samples/`](samples/): a NixOS diff and a `vulnix --json` fixture (the latter includes Log4Shell, `CVE-2021-44228`, so you can see a KEV escalation without a live closure).

---

## Attestation without a NixOS host

`vulnix` runs on NixOS / Nix. This server runs anywhere (it is stateless apart from its data volume), so `attest_closure` supports three modes:

1. **Live closure** — if `vulnix` is on `PATH`, it runs `vulnix --json <path>`.
2. **Pre-generated output** — pass a path ending in `.json` holding `vulnix --json` output. Useful for CI, or for pointing this server at a NixOS host that produced the file.
3. **Degraded** — if `vulnix` is absent and the path is not a `.json` file, it returns `vulnix_available: false` with a reason and **zero fabricated CVEs**.

The CISA KEV join works in all three modes as long as the cache has been populated (`refresh_kev_cache`).

---

## Roadmap (Phase 2)

- `detect_drift(host)` — compare a running generation's closure to the declared one (accountability for a declarative fleet).
- `render_review(review_id)` — a PR-comment-style rendered review.
- Optional hand-off to an apply-capable ops layer after approval.
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
