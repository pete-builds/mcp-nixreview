"""Diff-grading contract tests. Pin the security policy as code."""

from __future__ import annotations

from mcp_nixreview.review.diff import grade_diff

SAMPLE_DIFF = """diff --git a/configuration.nix b/configuration.nix
--- a/configuration.nix
+++ b/configuration.nix
@@ -10,10 +10,13 @@
-  networking.firewall.allowedTCPPorts = [ 80 443 ];
+  networking.firewall.allowedTCPPorts = [ 80 443 22 5432 ];
-  services.openssh.settings.PermitRootLogin = "no";
+  services.openssh.settings.PermitRootLogin = "yes";
+  services.openssh.settings.PasswordAuthentication = true;
+    extraGroups = [ "docker" "wheel" ];
+  security.sudo.wheelNeedsPassword = false;
+  services.fail2ban.enable = false;
+  services.postgresql.settings.listen_addresses = "0.0.0.0";
"""


def _categories(result: dict) -> set[str]:
    return {f["category"] for f in result["findings"]}


def test_grade_diff_returns_contract_shape():
    result = grade_diff(SAMPLE_DIFF)
    assert set(result.keys()) == {"input_kind", "findings", "summary"}
    assert result["input_kind"] == "diff"
    assert set(result["summary"].keys()) == {"high", "med", "low"}
    for f in result["findings"]:
        assert set(f.keys()) == {
            "category", "option", "change", "snippet", "grade", "rationale"
        }
        assert f["grade"] in {"HIGH", "MED", "LOW"}


def test_sample_diff_flags_all_categories():
    result = grade_diff(SAMPLE_DIFF)
    cats = _categories(result)
    assert {"firewall", "ssh", "sudo", "fail2ban", "exposure"} <= cats


def test_root_login_yes_is_high():
    result = grade_diff('+  services.openssh.settings.PermitRootLogin = "yes";')
    assert result["findings"][0]["grade"] == "HIGH"
    assert result["summary"]["high"] == 1


def test_passwordless_sudo_is_high():
    result = grade_diff("+  security.sudo.wheelNeedsPassword = false;")
    assert result["findings"][0]["grade"] == "HIGH"


def test_sensitive_port_is_high():
    result = grade_diff("+  networking.firewall.allowedTCPPorts = [ 5432 ];")
    assert result["findings"][0]["grade"] == "HIGH"


def test_ordinary_port_is_med():
    result = grade_diff("+  networking.firewall.allowedTCPPorts = [ 8080 ];")
    assert result["findings"][0]["grade"] == "MED"


def test_raw_config_treated_as_additions():
    raw = 'services.openssh.settings.PermitRootLogin = "yes";'
    result = grade_diff(raw)
    assert result["input_kind"] == "config"
    assert result["summary"]["high"] == 1


def test_clean_diff_has_no_findings():
    result = grade_diff("+  services.nginx.enable = true;")
    assert result["findings"] == []
    assert result["summary"] == {"high": 0, "med": 0, "low": 0}
