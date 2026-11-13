# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""OpenSSH server configuration security auditor."""

import glob
import os
import re
import shutil
import subprocess
from typing import List, Dict, Optional, Tuple
from privaudit.checks.base import BaseCheck
from privaudit.models import Finding, Severity

# Directives to check in sshd_config
# (parameter, safe_regex, unsafe_description, severity, check_id, remediation)
SSHD_CHECKS: List[Tuple[str, str, str, Severity, str, str]] = [
    (
        "PermitRootLogin",
        r'^\s*PermitRootLogin\s+(no|prohibit-password|without-password|forced-commands-only)\b',
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
    description = "Inspects the effective OpenSSH daemon configuration for dangerous settings such as PermitRootLogin, empty passwords, and weak authentication."

    def __init__(self, config_path: str = "/etc/ssh/sshd_config", config_dir: str = "/etc/ssh/sshd_config.d", use_sshd: bool = True):
        self.config_path = config_path
        # Kept for compatibility. Drop-in files are read only where the main
        # configuration Includes them, which is what sshd itself does.
        self.config_dir = config_dir
        self.use_sshd = use_sshd

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        if not os.path.exists(self.config_path):
            return findings

        self._saw_match = False
        effective = self._effective_from_sshd() if self.use_sshd else None
        if effective is not None:
            source = "sshd -T"
            # sshd -T without -C reports the global configuration only. Parse
            # the text as well, solely to learn whether Match blocks exist.
            self._parse_file(self.config_path, {}, [], depth=0)
        else:
            effective = {}
            if not self._parse_file(self.config_path, effective, findings, depth=0):
                return findings
            source = "parsed configuration text"
            self.mark_incomplete(
                "sshd -T was unavailable, so the effective configuration was derived by "
                "parsing. Match blocks and compiled-in defaults are not evaluated."
            )

        if self._saw_match:
            # An assessment gap, not a vulnerability: the conditional policy
            # may be stricter or weaker than the global one, and nothing here
            # has evaluated it.
            findings.append(Finding(
                check_id="PA-SSH-CONDITIONAL",
                title="Conditional SSH Configuration Not Evaluated",
                severity=Severity.INFO,
                description=(
                    "The configuration contains Match blocks. Settings inside them apply only to matching "
                    "connections and were not evaluated, so the results below describe the global policy only."
                ),
                evidence=f"Match block present in {self.config_path} or a file it includes",
                remediation="Review each Match block, or evaluate representative connections with: sshd -T -C user=<user>,host=<host>,addr=<addr>",
            ))
            self.mark_incomplete("Match blocks exist and connection-specific settings were not evaluated")

        for param, safe_re, desc, sev, cid, remed in SSHD_CHECKS:
            entry = effective.get(param.lower())

            if entry is None:
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

            value, origin = entry
            normalized = f"{param} {value}"
            if not re.search(safe_re, normalized, re.IGNORECASE):
                findings.append(Finding(
                    check_id=cid,
                    title=f"Insecure SSH Configuration: {param}",
                    severity=sev,
                    description=f"{desc} Effective value: '{value}' (from {source}).",
                    evidence=f"{origin} -> {normalized}",
                    remediation=remed,
                    compliance_mappings={
                        "CIS_Linux": f"5.2 SSH Server Hardening ({param})",
                        "CERT_In": "Secure Remote Administration Baseline"
                    }
                ))

        return findings

    def _effective_from_sshd(self) -> Optional[Dict[str, Tuple[str, str]]]:
        """Asks sshd for its effective configuration.

        sshd -T prints every keyword with the value sshd will actually use,
        after Include processing, first-value precedence and compiled-in
        defaults. It needs root to read the host keys, so an unprivileged run
        falls back to parsing.
        """
        sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
        if not sshd:
            return None
        try:
            proc = subprocess.run(
                [sshd, "-T", "-f", self.config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0 or not proc.stdout.strip():
            return None

        effective: Dict[str, Tuple[str, str]] = {}
        for line in proc.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].lower() not in effective:
                effective[parts[0].lower()] = (parts[1], "sshd -T")
        return effective

    def _parse_file(self, path: str, effective: Dict[str, Tuple[str, str]], findings: List[Finding], depth: int) -> bool:
        """Applies one configuration file to the effective settings.

        Follows sshd_config(5): for each keyword the first value obtained is
        used, Include is processed in place with globs expanded in lexical
        order, and keywords may be written "Key value" or "Key=value". Lines
        after a Match keyword are conditional and do not set global values.

        Returns:
            False when the file could not be read.
        """
        if depth > 16:
            self.mark_incomplete(f"Include nesting too deep at {path}")
            return True

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except PermissionError:
            findings.append(Finding(
                check_id="PA-SSH-PERM",
                title="Inaccessible SSH Daemon Config (Root Required)",
                severity=Severity.INFO,
                description=f"Cannot read '{path}' due to permissions. Run as root for SSH daemon auditing.",
                evidence=f"Path: {path}",
                remediation="Execute with elevated privileges.",
            ))
            self.mark_incomplete(f"could not read {path}")
            return False
        except OSError as e:
            self.mark_incomplete(f"could not read {path}: {e}")
            return False

        in_match = False
        for lineno, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue

            m = re.match(r'^([A-Za-z0-9]+)\s*(?:=\s*|\s+)(.*)$', stripped)
            if not m:
                continue
            keyword, value = m.group(1).lower(), m.group(2).strip()

            if keyword == "match":
                in_match = True
                self._saw_match = True
                continue
            if in_match:
                continue

            if keyword == "include":
                for pattern in value.split():
                    if not os.path.isabs(pattern):
                        pattern = os.path.join(os.path.dirname(self.config_path), pattern)
                    for included in sorted(glob.glob(pattern)):
                        self._parse_file(included, effective, findings, depth + 1)
                continue

            if keyword not in effective:
                effective[keyword] = (value.split("#", 1)[0].strip(), f"{path}:{lineno}")

        return True
