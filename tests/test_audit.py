"""Unit test suite for StellerSight Priv-Audit."""

import unittest
from unittest.mock import patch, mock_open
from privaudit.models import Finding, Severity, AuditReport
from privaudit.checks.sudo import SudoCheck
from privaudit.checks.suid import SuidCheck, GTFOBINS_EXPLOITABLE
from privaudit.checks.ssh import SshCheck
from privaudit.checks.filesystem import FilesystemCheck
from privaudit.reporters import JsonReporter, MarkdownReporter, ConsoleReporter
from privaudit.engine import AuditEngine


class TestSudoCheck(unittest.TestCase):
    """Tests sudo configuration rules and risk detection."""

    def test_detects_nopasswd_all(self):
        sample_sudoers = [
            "root ALL=(ALL:ALL) ALL\n",
            "%admin ALL=(ALL) NOPASSWD: ALL\n"
        ]
        checker = SudoCheck()
        findings = checker._analyze_lines("/etc/sudoers", sample_sudoers)

        nopasswd_findings = [f for f in findings if f.check_id == "PA-SUDO-NOPASSWD-ALL"]
        self.assertEqual(len(nopasswd_findings), 1)
        self.assertEqual(nopasswd_findings[0].severity, Severity.CRITICAL)

    def test_detects_unsafe_ld_preload(self):
        sample_sudoers = [
            'Defaults env_keep += "LD_PRELOAD"\n'
        ]
        checker = SudoCheck()
        findings = checker._analyze_lines("/etc/sudoers", sample_sudoers)

        env_findings = [f for f in findings if f.check_id == "PA-SUDO-ENV"]
        self.assertEqual(len(env_findings), 1)
        self.assertEqual(env_findings[0].severity, Severity.CRITICAL)

    def test_detects_wildcard_commands(self):
        sample_sudoers = [
            "developer ALL=(root) /usr/local/bin/deploy-*\n"
        ]
        checker = SudoCheck()
        findings = checker._analyze_lines("/etc/sudoers", sample_sudoers)

        wildcard_findings = [f for f in findings if f.check_id == "PA-SUDO-WILDCARD"]
        self.assertEqual(len(wildcard_findings), 1)
        self.assertEqual(wildcard_findings[0].severity, Severity.HIGH)


class TestSuidCheck(unittest.TestCase):
    """Tests SUID binary scanning and GTFOBins catalog."""

    def test_gtfobins_catalog_contains_core_exploitable_binaries(self):
        self.assertIn("bash", GTFOBINS_EXPLOITABLE)
        self.assertIn("python", GTFOBINS_EXPLOITABLE)
        self.assertIn("vim", GTFOBINS_EXPLOITABLE)
        self.assertIn("find", GTFOBINS_EXPLOITABLE)
        self.assertIn("cp", GTFOBINS_EXPLOITABLE)


class TestSshCheck(unittest.TestCase):
    """Tests OpenSSH daemon audit rules."""

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n")
    def test_detects_insecure_ssh_directives(self, mock_file, mock_exists):
        mock_exists.return_value = True
        checker = SshCheck(config_path="/etc/ssh/sshd_config", config_dir="/nonexistent", use_sshd=False)
        findings = checker.run()

        ids = [f.check_id for f in findings]
        self.assertIn("PA-SSH-ROOT", ids)
        self.assertIn("PA-SSH-EMPTY-PW", ids)


class TestReporters(unittest.TestCase):
    """Tests JSON, Markdown, and Console report formatters."""

    def setUp(self):
        self.report = AuditReport(
            hostname="test-sec-node",
            os_info="Linux 6.8.0-x86_64",
            duration_seconds=0.45
        )
        self.report.add_finding(Finding(
            check_id="PA-TEST-001",
            title="Test Critical Finding",
            severity=Severity.CRITICAL,
            description="Testing vulnerability description",
            evidence="Mode 0777",
            remediation="chmod 0600",
            compliance_mappings={"CIS_Linux": "1.1"}
        ))

    def test_json_reporter_valid_structure(self):
        json_output = JsonReporter.render(self.report)
        self.assertIn('"hostname": "test-sec-node"', json_output)
        self.assertIn('"CRITICAL": 1', json_output)

    def test_markdown_reporter_structure(self):
        md = MarkdownReporter.render(self.report)
        self.assertIn("# StellerSight Priv-Audit Security Report", md)
        self.assertIn("**Target Host:** `test-sec-node`", md)
        self.assertIn("| **CRITICAL** | 1 |", md)

    def test_console_reporter_renders(self):
        console = ConsoleReporter.render(self.report)
        self.assertIn("StellerSight Priv-Audit", console)
        self.assertIn("CRITICAL: 1", console)


if __name__ == "__main__":
    unittest.main()
