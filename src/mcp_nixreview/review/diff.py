"""Deterministic security grading of NixOS configuration deltas.

This module extracts a *curated, high-signal* set of security-relevant option
changes from either a unified diff or a raw ``configuration.nix``-style text and
assigns each a HIGH / MED / LOW grade per a small, explicit policy.

It is deliberately advisory and incomplete. It pattern-matches a known list of
options; it does NOT evaluate the Nix module system, so risks expressed through
custom modules, ``let`` bindings, imported files, string interpolation, or raw
systemd units will be missed. Treat a clean result as "nothing matched the
known-risky patterns," never as "this change is safe."

No network I/O, no NixOS host required.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

Grade = str  # "HIGH" | "MED" | "LOW"

# Service ports whose exposure is high-consequence (remote admin / databases).
_SENSITIVE_PORTS: frozenset[int] = frozenset(
    {22, 23, 445, 1433, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017}
)


@dataclass
class Finding:
    category: str
    option: str
    change: str  # "added" | "removed"
    snippet: str
    grade: Grade
    rationale: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class _Line:
    sign: str  # "+" | "-" | " "
    text: str


def _is_unified_diff(text: str) -> bool:
    if re.search(r"^diff --git ", text, re.M):
        return True
    if re.search(r"^@@ ", text, re.M):
        return True
    has_add = re.search(r"^\+(?!\+\+ )", text, re.M) is not None
    has_del = re.search(r"^-(?!-- )", text, re.M) is not None
    has_hdr = re.search(r"^(\+\+\+|---) ", text, re.M) is not None
    return has_add and has_del and has_hdr


def _tokenize(text: str) -> list[_Line]:
    """Normalise input into signed lines.

    For a unified diff, use the +/- markers. For raw config text, treat every
    line as an addition so we grade the *resulting* declared state.
    """
    lines: list[_Line] = []
    if _is_unified_diff(text):
        for raw in text.splitlines():
            if not raw:
                continue
            if raw.startswith(("+++ ", "--- ", "@@", "diff ", "index ")):
                continue
            if raw[0] == "+":
                lines.append(_Line("+", raw[1:]))
            elif raw[0] == "-":
                lines.append(_Line("-", raw[1:]))
            else:
                lines.append(_Line(" ", raw[1:] if raw[0] == " " else raw))
    else:
        for raw in text.splitlines():
            if raw.strip():
                lines.append(_Line("+", raw))
    return lines


# --- individual detectors ---------------------------------------------------


def _ports_from(text: str) -> list[int]:
    ports: list[int] = []
    for m in re.finditer(r"\b(\d{1,5})\b", text):
        val = int(m.group(1))
        if 0 < val <= 65535:
            ports.append(val)
    return ports


def _detect_firewall(ln: _Line) -> Finding | None:
    t = ln.text
    if "networking.firewall.allowedTCPPortRanges" in t or "allowedTCPPortRanges" in t or (
        "allowedUDPPortRanges" in t
    ):
        if ln.sign == "+" and re.search(r"\d", t):
            return Finding(
                category="firewall",
                option="networking.firewall.allowed*PortRanges",
                change="added",
                snippet=t.strip(),
                grade="HIGH",
                rationale="Opens a RANGE of firewall ports; broad exposure surface.",
            )
        return None
    if re.search(r"allowed(TCP|UDP)Ports\b", t):
        ports = _ports_from(re.sub(r"allowed(TCP|UDP)Ports", "", t))
        if ln.sign == "+" and ports:
            sensitive = sorted(p for p in ports if p in _SENSITIVE_PORTS)
            grade = "HIGH" if sensitive else "MED"
            why = (
                f"Opens sensitive service port(s) {sensitive} to the firewall."
                if sensitive
                else f"Opens firewall port(s) {sorted(set(ports))}."
            )
            return Finding(
                category="firewall",
                option="networking.firewall.allowedTCP/UDPPorts",
                change="added",
                snippet=t.strip(),
                grade=grade,
                rationale=why,
            )
    return None


def _detect_ssh(ln: _Line) -> Finding | None:
    t = ln.text
    if "PermitRootLogin" in t:
        val = _rhs(t)
        if ln.sign == "+" and val in {"yes", '"yes"'}:
            return Finding(
                "ssh", "services.openssh.settings.PermitRootLogin", "added", t.strip(),
                "HIGH", "Enables direct root login over SSH.",
            )
        if ln.sign == "-" and val in {"no", '"no"', "prohibit-password", '"prohibit-password"'}:
            return Finding(
                "ssh", "services.openssh.settings.PermitRootLogin", "removed", t.strip(),
                "MED", "Removes a root-login restriction; SSH may fall back to a looser default.",
            )
        if ln.sign == "+" and val in {"prohibit-password", '"prohibit-password"', "no", '"no"',
                                      "without-password", '"without-password"'}:
            return Finding(
                "ssh", "services.openssh.settings.PermitRootLogin", "added", t.strip(),
                "LOW", "Hardens root login (informational).",
            )
    if "PasswordAuthentication" in t:
        val = _rhs(t)
        if ln.sign == "+" and val == "true":
            return Finding(
                "ssh", "services.openssh.settings.PasswordAuthentication", "added", t.strip(),
                "HIGH", "Enables SSH password authentication (brute-force surface).",
            )
        if ln.sign == "-" and val == "false":
            return Finding(
                "ssh", "services.openssh.settings.PasswordAuthentication", "removed", t.strip(),
                "HIGH", "Removes the key-only SSH restriction.",
            )
        if ln.sign == "+" and val == "false":
            return Finding(
                "ssh", "services.openssh.settings.PasswordAuthentication", "added", t.strip(),
                "LOW", "Enforces key-only SSH (informational).",
            )
    return None


def _detect_sudo(ln: _Line) -> Finding | None:
    t = ln.text
    if "extraGroups" in t and "wheel" in t and ln.sign == "+":
        return Finding(
            "sudo", "users.users.*.extraGroups", "added", t.strip(),
            "MED", 'Grants a user the "wheel" group (sudo access).',
        )
    if "wheelNeedsPassword" in t:
        val = _rhs(t)
        if ln.sign == "+" and val == "false":
            return Finding(
                "sudo", "security.sudo.wheelNeedsPassword", "added", t.strip(),
                "HIGH", "Grants passwordless sudo to the wheel group.",
            )
    return None


def _detect_fail2ban(ln: _Line) -> Finding | None:
    t = ln.text
    if "fail2ban.enable" in t:
        val = _rhs(t)
        if ln.sign == "+" and val == "false":
            return Finding(
                "fail2ban", "services.fail2ban.enable", "added", t.strip(),
                "MED", "Disables fail2ban (removes brute-force protection).",
            )
        if ln.sign == "-" and val == "true":
            return Finding(
                "fail2ban", "services.fail2ban.enable", "removed", t.strip(),
                "MED", "Removes the line that enabled fail2ban.",
            )
    return None


def _detect_bind_all(ln: _Line) -> Finding | None:
    t = ln.text
    if ln.sign == "+" and "0.0.0.0" in t and re.search(  # noqa: S104 (detecting, not binding)
        r"(address|host|bind|listen|interface)", t, re.I
    ):
        return Finding(
            "exposure", "service bind address", "added", t.strip(),
            "MED", "Binds a service to 0.0.0.0 (all interfaces / potentially WAN).",
        )
    return None


_DETECTORS = (
    _detect_firewall,
    _detect_ssh,
    _detect_sudo,
    _detect_fail2ban,
    _detect_bind_all,
)


def _rhs(text: str) -> str:
    """Extract the right-hand side of a ``key = value;`` assignment, trimmed."""
    m = re.search(r"=\s*([^;]+)", text)
    if not m:
        return ""
    return m.group(1).strip().strip(";").strip()


def grade_diff(config_text: str) -> dict:
    """Grade a config/diff text for security-relevant NixOS option changes.

    Returns a dict with ``findings`` (list of Finding dicts), ``summary``
    (counts per grade), and ``input_kind`` ("diff" or "config").
    """
    kind = "diff" if _is_unified_diff(config_text) else "config"
    findings: list[Finding] = []
    for ln in _tokenize(config_text):
        if ln.sign == " ":
            continue
        for detector in _DETECTORS:
            found = detector(ln)
            if found is not None:
                findings.append(found)
    summary = {
        "high": sum(1 for f in findings if f.grade == "HIGH"),
        "med": sum(1 for f in findings if f.grade == "MED"),
        "low": sum(1 for f in findings if f.grade == "LOW"),
    }
    return {
        "input_kind": kind,
        "findings": [f.to_dict() for f in findings],
        "summary": summary,
    }
