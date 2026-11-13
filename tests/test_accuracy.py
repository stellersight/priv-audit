# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Regression tests for detection accuracy.

Each test reproduces a defect found in the 12 November 2026 audit, so that
the defect cannot return unnoticed.
"""

import os
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from privaudit.checks.capabilities import CapabilitiesCheck
from privaudit.checks.filesystem import FilesystemCheck
from privaudit.checks.ssh import SshCheck
from privaudit.checks.suid import SuidCheck
from privaudit.checks.sudo import SudoCheck
from privaudit.cli import exit_status, EXIT_CLEAN, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_ERROR
from privaudit.models import AuditReport, Finding, Severity


def _fake_stat(mode, uid=0, gid=0):
    return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid, st_gid=gid)


class TestPermissionBits(unittest.TestCase):
    """Permission modes are bit sets, not numbers."""

    def _run_with(self, path, mode, uid=0):
        files = [(path, 0o640, "PA-FS-SHADOW", "Overly Permissive /etc/shadow Permissions", Severity.CRITICAL)]
        with patch("privaudit.checks.filesystem.CRITICAL_SYSTEM_FILES", files), \
                patch("privaudit.checks.filesystem.SENSITIVE_DIRECTORIES", []), \
                patch("privaudit.checks.filesystem.os.path.exists", return_value=True), \
                patch("privaudit.checks.filesystem.os.stat", return_value=_fake_stat(mode, uid)):
            return FilesystemCheck().run()

    def test_world_readable_shadow_is_flagged_although_numerically_smaller(self):
        # 0o604 < 0o640 as integers, but it grants world read.
        findings = self._run_with("/etc/shadow", 0o604)
        self.assertEqual(["PA-FS-SHADOW"], [f.check_id for f in findings])

    def test_policy_compliant_mode_is_clean(self):
        self.assertEqual([], self._run_with("/etc/shadow", 0o640))

    def test_non_root_owner_is_flagged(self):
        findings = self._run_with("/etc/shadow", 0o640, uid=1000)
        self.assertEqual(["PA-FS-SHADOW-OWNER"], [f.check_id for f in findings])


class TestSshEffectiveConfig(unittest.TestCase):
    """The parser follows sshd_config(5), not last-line-wins."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def _write(self, name, text):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def _root_findings(self, main_text):
        main = self._write("sshd_config", main_text)
        checker = SshCheck(config_path=main, use_sshd=False)
        return [f for f in checker.run() if f.check_id == "PA-SSH-ROOT"], checker

    def test_first_value_wins(self):
        findings, _ = self._root_findings("PermitRootLogin yes\nPermitRootLogin no\n")
        self.assertEqual(1, len(findings))
        self.assertIn("yes", findings[0].evidence)

    def test_later_safe_value_does_not_mask_earlier_unsafe_one(self):
        findings, _ = self._root_findings("PermitRootLogin no\nPermitRootLogin yes\n")
        self.assertEqual([], [f for f in findings if f.title.startswith("Insecure")])

    def test_equals_syntax_is_understood(self):
        findings, _ = self._root_findings("PermitRootLogin=yes\n")
        self.assertEqual(["Insecure SSH Configuration: PermitRootLogin"], [f.title for f in findings])

    def test_include_is_processed_in_place(self):
        self._write("sshd_config.d/50-cloud.conf", "PermitRootLogin yes\n")
        findings, _ = self._root_findings(
            f"Include {os.path.join(self.dir, 'sshd_config.d', '*.conf')}\nPermitRootLogin no\n"
        )
        self.assertEqual(1, len(findings))
        self.assertIn("50-cloud.conf", findings[0].evidence)

    def test_match_block_does_not_set_global_value(self):
        findings, _ = self._root_findings("PermitRootLogin no\nMatch User backup\n  PermitRootLogin yes\n")
        self.assertEqual([], findings)

    def test_match_block_is_reported_as_assessment_gap(self):
        main = self._write("sshd_config", "PermitRootLogin no\nMatch User backup\n  PermitRootLogin yes\n")
        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="permitrootlogin no\n", stderr="")
        with patch("privaudit.checks.ssh.shutil.which", return_value="/usr/sbin/sshd"), \
                patch("privaudit.checks.ssh.subprocess.run", return_value=proc):
            checker = SshCheck(config_path=main)
            findings = checker.run()
        gap = [f for f in findings if f.check_id == "PA-SSH-CONDITIONAL"]
        self.assertEqual(1, len(gap))
        self.assertEqual(Severity.INFO, gap[0].severity)
        self.assertTrue(getattr(checker, "incomplete", []))

    def test_parsed_result_is_marked_incomplete(self):
        _, checker = self._root_findings("PermitRootLogin no\n")
        self.assertTrue(getattr(checker, "incomplete", []))

    def test_sshd_output_is_preferred_when_available(self):
        main = self._write("sshd_config", "PermitRootLogin no\n")
        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="permitrootlogin yes\npasswordauthentication no\n", stderr="")
        with patch("privaudit.checks.ssh.shutil.which", return_value="/usr/sbin/sshd"), \
                patch("privaudit.checks.ssh.subprocess.run", return_value=proc):
            checker = SshCheck(config_path=main)
            findings = checker.run()
        self.assertIn("PA-SSH-ROOT", [f.check_id for f in findings])
        self.assertFalse(getattr(checker, "incomplete", []))


class TestSuidBaseline(unittest.TestCase):
    """Packaged SUID binaries in packaged locations are expected."""

    def _scan(self, paths):
        def walk(base, **kwargs):
            files = [p for p in paths if p.startswith(base + "/")]
            for p in files:
                yield os.path.dirname(p), [], [os.path.basename(p)]

        def lstat(path):
            return _fake_stat(0o4755)

        bases = sorted({"/" + p.split("/")[1] if p.count("/") == 2 else "/".join(p.split("/")[:3]) for p in paths})
        with patch("privaudit.checks.suid.os.path.isdir", return_value=True), \
                patch("privaudit.checks.suid.os.walk", side_effect=walk), \
                patch("privaudit.checks.suid.os.lstat", side_effect=lstat), \
                patch("privaudit.checks.suid.os.path.join", side_effect=lambda a, b: a + "/" + b):
            return SuidCheck(search_paths=bases).run()

    def test_stock_sudo_is_not_a_finding(self):
        self.assertEqual([], self._scan(["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/pkexec"]))

    def test_sudo_outside_system_dirs_is_reported(self):
        findings = self._scan(["/usr/local/bin/sudo"])
        self.assertEqual(1, len(findings))

    def test_suid_in_temporary_dir_is_critical(self):
        findings = self._scan(["/tmp/x/helper"])
        self.assertEqual(["PA-SUID-TMP"], [f.check_id for f in findings])
        self.assertEqual(Severity.CRITICAL, findings[0].severity)

    def test_gtfobins_binary_with_suid_is_still_critical(self):
        findings = self._scan(["/usr/bin/find"])
        self.assertEqual(Severity.CRITICAL, findings[0].severity)


class TestCapabilitiesFormats(unittest.TestCase):

    def _run(self, output):
        proc = subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")
        with patch("privaudit.checks.capabilities.shutil.which", return_value="/usr/sbin/getcap"), \
                patch("privaudit.checks.capabilities.os.path.isdir", return_value=True), \
                patch("privaudit.checks.capabilities.subprocess.run", return_value=proc):
            return CapabilitiesCheck(search_paths=["/usr/bin"]).run()

    def test_current_format(self):
        self.assertIn("PA-CAP-CAP_SETUID", [f.check_id for f in self._run("/usr/bin/python3 cap_setuid=ep\n")])

    def test_packaged_newuidmap_is_expected(self):
        # Stock on every RHEL-family host, for rootless containers.
        self.assertEqual([], self._run("/usr/bin/newuidmap cap_setuid=ep\n/usr/bin/ping cap_net_raw=ep\n"))

    def test_expected_name_with_extra_capability_is_reported(self):
        ids = [f.check_id for f in self._run("/usr/bin/newuidmap cap_setuid,cap_sys_admin=ep\n")]
        self.assertIn("PA-CAP-CAP_SYS_ADMIN", ids)

    def test_expected_name_outside_system_dirs_is_reported(self):
        self.assertTrue(self._run("/opt/tools/newuidmap cap_setuid=ep\n"))

    def test_pre_2_41_format(self):
        self.assertIn("PA-CAP-CAP_SETUID", [f.check_id for f in self._run("/usr/bin/python3 = cap_setuid+ep\n")])


class TestSudoersInclusion(unittest.TestCase):

    def test_files_sudo_ignores_are_not_audited(self):
        d = tempfile.mkdtemp()
        for name in ("10-ops", "10-ops.dpkg-old", "20-tmp~"):
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write("deploy ALL=(ALL) NOPASSWD: ALL\n" if name != "10-ops" else "# nothing\n")
        findings = SudoCheck(sudoers_path=os.path.join(d, "missing"), sudoers_dir=d).run()
        self.assertEqual([], findings)


class TestExitStatus(unittest.TestCase):

    def _report(self, severities=(), incomplete=(), errors=()):
        report = AuditReport()
        for sev in severities:
            report.add_finding(Finding("T", "t", sev, "d", "e", "r"))
        report.incomplete.extend(incomplete)
        report.errors.extend(errors)
        return report

    def test_clean(self):
        self.assertEqual(EXIT_CLEAN, exit_status(self._report()))

    def test_low_findings_do_not_fail_default_gate(self):
        self.assertEqual(EXIT_CLEAN, exit_status(self._report([Severity.LOW, Severity.INFO])))

    def test_high_finding_fails(self):
        self.assertEqual(EXIT_FINDINGS, exit_status(self._report([Severity.HIGH])))

    def test_threshold_is_configurable(self):
        self.assertEqual(EXIT_FINDINGS, exit_status(self._report([Severity.LOW]), "low"))

    def test_incomplete_scan_is_never_clean(self):
        self.assertEqual(EXIT_INCOMPLETE, exit_status(self._report(incomplete=["PA-SUDO-001: could not read /etc/sudoers"])))

    def test_findings_outrank_incompleteness(self):
        self.assertEqual(EXIT_FINDINGS, exit_status(self._report([Severity.CRITICAL], incomplete=["x"])))

    def test_internal_error_outranks_everything(self):
        self.assertEqual(EXIT_ERROR, exit_status(self._report([Severity.CRITICAL], errors=["boom"])))



class TestSuitBrokerRule(unittest.TestCase):
    """SUIT for Linux's own sudoers rule is expected, but only while its files are root's."""

    RULE = "/usr/bin/suit-exec, /usr/bin/suit request *, /usr/bin/suit revoke *, /usr/bin/suit status"

    @staticmethod
    def stat_of(uid, mode):
        from types import SimpleNamespace
        return lambda path: SimpleNamespace(st_uid=uid, st_mode=0o100000 | mode)

    def test_root_owned_broker_rule_is_expected(self):
        from privaudit.checks.sudo import is_suit_broker_rule
        self.assertTrue(is_suit_broker_rule(self.RULE, self.stat_of(0, 0o755)))

    def test_writable_broker_is_not_trusted(self):
        from privaudit.checks.sudo import is_suit_broker_rule
        self.assertFalse(is_suit_broker_rule(self.RULE, self.stat_of(0, 0o757)))
        self.assertFalse(is_suit_broker_rule(self.RULE, self.stat_of(1000, 0o755)))

    def test_other_command_in_the_rule_is_still_reported(self):
        from privaudit.checks.sudo import is_suit_broker_rule
        self.assertFalse(is_suit_broker_rule(self.RULE + ", /usr/bin/vim", self.stat_of(0, 0o755)))
        self.assertFalse(is_suit_broker_rule("/usr/local/bin/suit-exec", self.stat_of(0, 0o755)))


if __name__ == "__main__":
    unittest.main()
