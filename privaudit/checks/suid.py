"""SUID and SGID binary auditing module with GTFOBins exploit detection."""

import os
import stat
from typing import List, Set, Dict
from privaudit.checks.base import BaseCheck
from privaudit.models import Finding, Severity

# Binaries that can be weaponized for privilege escalation via GTFOBins if SUID is set
GTFOBINS_EXPLOITABLE: Dict[str, str] = {
    "bash": "Direct root shell via 'bash -p'",
    "sh": "Direct root shell via 'sh -p'",
    "zsh": "Direct root shell via 'zsh'",
    "python": "Arbitrary code execution and root shell via pty.spawn",
    "python3": "Arbitrary code execution and root shell via pty.spawn",
    "python2": "Arbitrary code execution and root shell via pty.spawn",
    "perl": "Arbitrary code execution and root shell via exec()",
    "ruby": "Arbitrary code execution and root shell via exec()",
    "php": "Arbitrary code execution via php -r 'pcntl_exec()'",
    "find": "Arbitrary command execution via -exec /bin/sh -p \\; -quit",
    "vim": "Shell breakout via ':!/bin/sh'",
    "vi": "Shell breakout via ':!/bin/sh'",
    "nano": "Command execution via spelling check or external command hooks",
    "cp": "Arbitrary file overwrite (e.g. overwriting /etc/passwd or /etc/sudoers)",
    "mv": "Arbitrary file overwrite (e.g. replacing system binaries)",
    "tar": "Arbitrary command execution via checkpoint actions",
    "zip": "Command execution via unzip -T --unzip-command",
    "nmap": "Command execution or interactive shell breakout",
    "awk": "Command execution via system('/bin/sh')",
    "gawk": "Command execution via system('/bin/sh')",
    "sed": "Arbitrary file reading or writing",
    "less": "Shell breakout via '!/bin/sh'",
    "more": "Shell breakout via '!/bin/sh'",
    "man": "Shell breakout via pager execution",
    "env": "Direct binary execution with inherited SUID privileges",
    "pkexec": "Polkit execution engine (target of CVE-2021-4034 PwnKit)",
    "doas": "Alternative sudo utility with configuration escalation potential",
    "sudo": "Privilege elevation binary",
    "strace": "Tracing child process with root capabilities",
    "tcpdump": "Command execution via post-rotate script hook (-z)",
    "wget": "Arbitrary file overwrite or credential harvesting",
    "curl": "Arbitrary file write to critical system paths",
    "tee": "Arbitrary file append to /etc/passwd or /etc/sudoers",
    "dd": "Raw block device and system file overwrite",
    "base64": "Sensitive file read (e.g. /etc/shadow)",
    "cat": "Sensitive file read (e.g. /etc/shadow)",
}

# Standard common Linux system SUID binaries typically expected on distributions
STANDARD_SUID_BINARIES: Set[str] = {
    "passwd", "chfn", "chsh", "newgrp", "gpasswd", "mount", "umount", "su",
    "ping", "traceroute6", "ssh-keysign", "fusermount", "fusermount3"
}


class SuidCheck(BaseCheck):
    """Scans system search paths for SUID/SGID binaries and flags GTFOBins escalation vectors."""

    check_id = "PA-SUID-001"
    name = "SUID / SGID Binary Security Audit"
    description = "Discovers SUID/SGID binaries and detects known GTFOBins privilege escalation vectors."

    def __init__(self, search_paths: List[str] = None):
        self.search_paths = search_paths or [
            "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
            "/usr/local/sbin", "/opt", "/tmp", "/var/tmp", "/dev/shm"
        ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        discovered_suid: List[str] = []

        for base_path in self.search_paths:
            if not os.path.isdir(base_path):
                continue

            try:
                for root, _, files in os.walk(base_path, followlinks=False):
                    for file_name in files:
                        full_path = os.path.join(root, file_name)
                        try:
                            # Use lstat to not follow symlinks
                            file_stat = os.lstat(full_path)
                            mode = file_stat.st_mode

                            if stat.S_ISREG(mode):
                                is_suid = bool(mode & stat.S_ISUID)
                                is_sgid = bool(mode & stat.S_ISGID)

                                if is_suid or is_sgid:
                                    discovered_suid.append(full_path)
                                    binary_name = os.path.basename(full_path).lower()

                                    # Check for high-risk GTFOBins exploitability
                                    if binary_name in GTFOBINS_EXPLOITABLE:
                                        exploit_desc = GTFOBINS_EXPLOITABLE[binary_name]
                                        findings.append(Finding(
                                            check_id="PA-SUID-001",
                                            title=f"Exploitable SUID/SGID Binary: {binary_name}",
                                            severity=Severity.CRITICAL if is_suid else Severity.HIGH,
                                            description=(
                                                f"Binary '{full_path}' has SUID/SGID bits set and is known in GTFOBins "
                                                f"to allow immediate privilege escalation: {exploit_desc}."
                                            ),
                                            evidence=f"Path: {full_path}, Octal Mode: {oct(stat.S_IMODE(mode))}",
                                            remediation=f"Remove SUID/SGID permissions using: chmod u-s,g-s '{full_path}'",
                                            references=[
                                                f"https://gtfobins.github.io/gtfobins/{binary_name}/",
                                                "https://cwe.mitre.org/data/definitions/250.html"
                                            ],
                                            compliance_mappings={
                                                "CIS_Linux": "1.1.20 Ensure no unprivileged users can execute SUID/SGID",
                                                "ISO_27001": "A.9.4.4 Use of Privileged Utility Programs",
                                                "CERT_In": "System Integrity and Least Privilege Configuration"
                                            }
                                        ))
                                    elif binary_name not in STANDARD_SUID_BINARIES:
                                        # Non-standard SUID binary found
                                        findings.append(Finding(
                                            check_id="PA-SUID-002",
                                            title=f"Non-Standard SUID/SGID Binary Discovered: {binary_name}",
                                            severity=Severity.MEDIUM,
                                            description=(
                                                f"Binary '{full_path}' carries SUID/SGID privileges but is not part "
                                                f"of the standard distribution baseline."
                                            ),
                                            evidence=f"Path: {full_path}, Octal Mode: {oct(stat.S_IMODE(mode))}",
                                            remediation=f"Review whether elevated privileges are required, or remove via: chmod u-s '{full_path}'",
                                            references=["https://cwe.mitre.org/data/definitions/250.html"],
                                            compliance_mappings={
                                                "CIS_Linux": "1.1.20 Audit SUID/SGID binaries",
                                                "ISO_27001": "A.9.2.3 Management of Privileged Access Rights"
                                            }
                                        ))
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

        return findings
