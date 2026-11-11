"""Sudo configuration and privilege escalation auditor."""

import os
import re
from typing import List, Tuple
from privaudit.checks.base import BaseCheck
from privaudit.models import Finding, Severity

# Regular expressions detecting dangerous sudo patterns
RE_NOPASSWD = re.compile(r'\bNOPASSWD\s*:\s*([^#\n]+)', re.IGNORECASE)
RE_ALL_COMMANDS = re.compile(r'\bALL\s*=\s*\([^)]*\)\s*(NOPASSWD\s*:\s*)?ALL\b', re.IGNORECASE)
RE_WILDCARD_EXEC = re.compile(r'/\S*\*\S*', re.IGNORECASE)
RE_UNSAFE_ENV = re.compile(r'\b(env_keep|env_file)\b.*\b(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|RUBYLIB|PERL5LIB)\b', re.IGNORECASE)


class SudoCheck(BaseCheck):
    """Inspects /etc/sudoers and /etc/sudoers.d/* for excessive privileges and security misconfigurations."""

    check_id = "PA-SUDO-001"
    name = "Sudo Privilege & Sudoers Configuration Audit"
    description = "Parses sudoers configuration files to discover NOPASSWD rules, wildcard command executions, and unsafe environment passthroughs."

    def __init__(self, sudoers_path: str = "/etc/sudoers", sudoers_dir: str = "/etc/sudoers.d"):
        self.sudoers_path = sudoers_path
        self.sudoers_dir = sudoers_dir

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        files_to_check: List[str] = []

        if os.path.exists(self.sudoers_path):
            files_to_check.append(self.sudoers_path)

        if os.path.isdir(self.sudoers_dir):
            try:
                for entry in os.listdir(self.sudoers_dir):
                    if not entry.startswith(".") and not entry.endswith("~"):
                        full_entry = os.path.join(self.sudoers_dir, entry)
                        if os.path.isfile(full_entry):
                            files_to_check.append(full_entry)
            except (PermissionError, OSError):
                pass

        for file_path in files_to_check:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                findings.extend(self._analyze_lines(file_path, lines))
            except PermissionError:
                findings.append(Finding(
                    check_id="PA-SUDO-PERM",
                    title="Inaccessible Sudoers File (Root Required)",
                    severity=Severity.INFO,
                    description=f"Unable to read '{file_path}' due to permissions. Run audit with root privileges to complete sudo analysis.",
                    evidence=f"Path: {file_path}",
                    remediation="Execute priv-audit as root or via authorized sudo.",
                ))
            except Exception as e:
                continue

        return findings

    def _analyze_lines(self, file_path: str, lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []

        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Check 1: Unsafe environment variable passthrough (e.g. LD_PRELOAD)
            env_match = RE_UNSAFE_ENV.search(line)
            if env_match:
                findings.append(Finding(
                    check_id="PA-SUDO-ENV",
                    title="Unsafe Sudo Environment Variable Passthrough Detected",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Line {lineno} in '{file_path}' preserves dangerous dynamic linker or interpreter "
                        f"environment variables ({env_match.group(2)}). This allows unprivileged users to inject "
                        f"arbitrary shared objects during sudo execution and gain instant root access."
                    ),
                    evidence=f"{file_path}:{lineno} -> {line}",
                    remediation=f"Remove '{env_match.group(2)}' from env_keep or Defaults specifications in sudoers.",
                    references=[
                        "https://cwe.mitre.org/data/definitions/250.html",
                        "https://www.sudo.ws/docs/man/sudoers.man/"
                    ],
                    compliance_mappings={
                        "CIS_Linux": "5.3.4 Ensure sudo commands require authentication and safe environments",
                        "ISO_27001": "A.9.4.2 Secure Log-on Procedures"
                    }
                ))

            # Check 2: Unrestricted NOPASSWD rules
            nopasswd_match = RE_NOPASSWD.search(line)
            if nopasswd_match:
                target_cmds = nopasswd_match.group(1).strip()
                is_all = bool(re.search(r'\bALL\b', target_cmds, re.IGNORECASE))

                if is_all:
                    findings.append(Finding(
                        check_id="PA-SUDO-NOPASSWD-ALL",
                        title="Unrestricted NOPASSWD: ALL Detected in Sudoers",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Line {lineno} in '{file_path}' grants complete, unrestricted root command execution "
                            f"without password authentication (NOPASSWD: ALL). Any compromise of this user account "
                            f"immediately results in full host root compromise."
                        ),
                        evidence=f"{file_path}:{lineno} -> {line}",
                        remediation="Remove NOPASSWD: ALL and require explicit authentication with least-privilege command lists.",
                        references=["https://cwe.mitre.org/data/definitions/250.html"],
                        compliance_mappings={
                            "CIS_Linux": "5.3.7 Ensure sudo requires authentication",
                            "CERT_In": "Requirement for Multi-Factor and Authenticated Root Access"
                        }
                    ))
                else:
                    findings.append(Finding(
                        check_id="PA-SUDO-NOPASSWD-CMD",
                        title=f"Passwordless Sudo Rule (NOPASSWD) Detected: {target_cmds[:40]}",
                        severity=Severity.HIGH,
                        description=(
                            f"Line {lineno} in '{file_path}' allows executing commands without entering a password. "
                            f"Verify that none of the targets are interactive shells or file-writing utilities."
                        ),
                        evidence=f"{file_path}:{lineno} -> {line}",
                        remediation="Ensure target binaries cannot spawn subshells or write arbitrary files, or require password authentication.",
                        references=["https://gtfobins.github.io/"]
                    ))

            # Check 3: Wildcard binary execution
            if RE_WILDCARD_EXEC.search(line) and not line.startswith("Defaults"):
                findings.append(Finding(
                    check_id="PA-SUDO-WILDCARD",
                    title="Wildcard Path Detected in Sudo Rule",
                    severity=Severity.HIGH,
                    description=(
                        f"Line {lineno} in '{file_path}' contains wildcard characters in command paths. "
                        f"Attackers can craft arbitrary binary filenames or pass malformed arguments to bypass restrictions."
                    ),
                    evidence=f"{file_path}:{lineno} -> {line}",
                    remediation="Replace wildcard paths with explicit, fully qualified binary paths.",
                    references=["https://cwe.mitre.org/data/definitions/78.html"]
                ))

        return findings
