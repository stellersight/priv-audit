"""OpenSSH server configuration security auditor."""

import os
import re
from typing import List, Dict, Tuple
from privaudit.checks.base import BaseCheck
from privaudit.models import Finding, Severity

# Directives to check in sshd_config
# (parameter, safe_regex, unsafe_description, severity, check_id, remediation)
SSHD_CHECKS: List[Tuple[str, str, str, Severity, str, str]] = [
    (
        "PermitRootLogin",
        r'^\s*PermitRootLogin\s+(no|prohibit-password)\b',
        "PermitRootLogin is enabled without restriction or set to 'yes'. Direct root authentication exposes the host to credential stuffing and prevents accountability.",
        Severity.HIGH,
        "PA-SSH-ROOT",
        "Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config."
    ),
    (
        "PasswordAuthentication",
        r'^\s*PasswordAuthentication\s+no\b',
        "PasswordAuthentication is enabled ('yes'). Public key authentication is recommended to prevent brute-force attacks.",
        Severity.MEDIUM,
        "PA-SSH-PASSWD",
        "Set 'PasswordAuthentication no' and deploy authorized SSH keys."
    ),
    (
        "PermitEmptyPasswords",
        r'^\s*PermitEmptyPasswords\s+no\b',
        "PermitEmptyPasswords is set to 'yes' or active. Accounts with empty passwords can be logged into over SSH.",
        Severity.CRITICAL,
        "PA-SSH-EMPTY-PW",
        "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config."
    ),
    (
        "X11Forwarding",
        r'^\s*X11Forwarding\s+no\b',
        "X11Forwarding is enabled ('yes'). If compromised, X11 sessions allow keystroke logging and session hijacking.",
        Severity.LOW,
        "PA-SSH-X11",
        "Set 'X11Forwarding no' unless graphical forwarding is explicitly required."
    ),
    (
        "MaxAuthTries",
        r'^\s*MaxAuthTries\s+([1-4])\b',
        "MaxAuthTries is either unset or exceeds 4. This increases susceptibility to brute force authentication.",
        Severity.LOW,
        "PA-SSH-MAXAUTH",
        "Set 'MaxAuthTries 3' or '4' in /etc/ssh/sshd_config."
    ),
]


class SshCheck(BaseCheck):
    """Audits OpenSSH daemon configuration for hardening compliance."""

    check_id = "PA-SSH-001"
    name = "SSH Daemon Security & Access Boundary Audit"
    description = "Inspects /etc/ssh/sshd_config for dangerous configurations such as PermitRootLogin, empty passwords, and weak authentication settings."

    def __init__(self, config_path: str = "/etc/ssh/sshd_config", config_dir: str = "/etc/ssh/sshd_config.d"):
        self.config_path = config_path
        self.config_dir = config_dir

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        files_to_check: List[str] = []

        if os.path.exists(self.config_path):
            files_to_check.append(self.config_path)

        if os.path.isdir(self.config_dir):
            try:
                for entry in sorted(os.listdir(self.config_dir)):
                    if entry.endswith(".conf"):
                        files_to_check.append(os.path.join(self.config_dir, entry))
            except (PermissionError, OSError):
                pass

        if not files_to_check:
            return findings

        # Aggregated active settings (last one takes precedence in sshd, but match blocks apply conditionally)
        all_lines: List[Tuple[str, int, str]] = []  # (file_path, lineno, line)
        for path in files_to_check:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for idx, line in enumerate(f, start=1):
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            all_lines.append((path, idx, stripped))
            except PermissionError:
                findings.append(Finding(
                    check_id="PA-SSH-PERM",
                    title="Inaccessible SSH Daemon Config (Root Required)",
                    severity=Severity.INFO,
                    description=f"Cannot read '{path}' due to permissions. Run as root for SSH daemon auditing.",
                    evidence=f"Path: {path}",
                    remediation="Execute with elevated privileges.",
                ))
            except Exception:
                continue

        # Evaluate directives
        for param, safe_re, desc, sev, cid, remed in SSHD_CHECKS:
            param_lower = param.lower()
            matching_lines = [
                (f, lno, l) for f, lno, l in all_lines
                if l.split()[0].lower() == param_lower
            ]

            if not matching_lines:
                # Parameter omitted, check default risk
                if param == "PermitRootLogin":
                    findings.append(Finding(
                        check_id=cid,
                        title=f"SSH Config Missing Explicit '{param}' Setting",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The directive '{param}' is not explicitly defined in sshd_config. "
                            f"Depending on OpenSSH distribution version, the default may allow password or key root logins."
                        ),
                        evidence="Directive absent from sshd_config",
                        remediation=remed,
                        compliance_mappings={
                            "CIS_Linux": "5.2.10 Ensure SSH PermitRootLogin is disabled",
                            "ISO_27001": "A.9.4.2 Secure Log-on Procedures"
                        }
                    ))
                continue

            last_file, last_lno, last_line = matching_lines[-1]
            if not re.search(safe_re, last_line, re.IGNORECASE):
                findings.append(Finding(
                    check_id=cid,
                    title=f"Insecure SSH Configuration: {param}",
                    severity=sev,
                    description=f"{desc} Current directive: '{last_line}'.",
                    evidence=f"{last_file}:{last_lno} -> {last_line}",
                    remediation=remed,
                    compliance_mappings={
                        "CIS_Linux": f"5.2 SSH Server Hardening ({param})",
                        "CERT_In": "Secure Remote Administration Baseline"
                    }
                ))

        return findings
