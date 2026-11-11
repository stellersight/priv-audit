"""Linux file capabilities security auditor."""

import os
import shutil
import subprocess
from typing import List, Dict, Set, Tuple
from privaudit.checks.base import BaseCheck
from privaudit.models import Finding, Severity

# Dangerous capabilities that provide immediate or near-immediate privilege escalation paths
DANGEROUS_CAPS: Dict[str, Tuple[Severity, str]] = {
    "cap_setuid": (Severity.CRITICAL, "Allows setting arbitrary process UID (instant root escalation)"),
    "cap_setgid": (Severity.HIGH, "Allows setting arbitrary process GID"),
    "cap_sys_admin": (Severity.CRITICAL, "Vast administrative capabilities including mounting, namespace manipulation, and bpf execution"),
    "cap_dac_override": (Severity.CRITICAL, "Bypasses all read, write, and execute permission checks on any file on the system"),
    "cap_dac_read_search": (Severity.HIGH, "Bypasses all file read and directory search permission checks (can read /etc/shadow)"),
    "cap_sys_ptrace": (Severity.CRITICAL, "Allows tracing and injecting code into arbitrary processes running as root"),
    "cap_net_raw": (Severity.MEDIUM, "Allows raw packet sniffing and network spoofing"),
    "cap_net_admin": (Severity.HIGH, "Allows modifying firewall rules, routing tables, and network interfaces"),
    "cap_chown": (Severity.HIGH, "Allows arbitrary change of file ownership"),
    "cap_fowner": (Severity.HIGH, "Bypasses permission checks on operations that normally require the file system UID to match"),
    "cap_sys_module": (Severity.CRITICAL, "Allows loading and unloading arbitrary kernel modules"),
}


class CapabilitiesCheck(BaseCheck):
    """Scans Linux filesystem for binaries with dangerous Linux capabilities (cap_setuid, cap_sys_admin, etc.)."""

    check_id = "PA-CAP-001"
    name = "Linux File Capabilities Security Audit"
    description = "Discovers binaries with extended file capabilities and flags capabilities with high privilege escalation potential."

    def __init__(self, search_paths: List[str] = None):
        self.search_paths = search_paths or ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/opt"]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        getcap_bin = shutil.which("getcap")

        if not getcap_bin:
            return findings

        # Run getcap recursively across candidate paths
        for path in self.search_paths:
            if not os.path.isdir(path):
                continue

            try:
                proc = subprocess.run(
                    [getcap_bin, "-r", path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15
                )

                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    # Format: /usr/bin/ping cap_net_raw+ep
                    parts = line.split()
                    if len(parts) >= 2:
                        file_path = parts[0]
                        caps_str = parts[1].lower()

                        for cap_name, (sev, danger_desc) in DANGEROUS_CAPS.items():
                            if cap_name in caps_str:
                                findings.append(Finding(
                                    check_id=f"PA-CAP-{cap_name.upper()}",
                                    title=f"Dangerous File Capability Assigned: {os.path.basename(file_path)} [{cap_name}]",
                                    severity=sev,
                                    description=(
                                        f"Binary '{file_path}' has capability '{cap_name}' assigned ({caps_str}). "
                                        f"{danger_desc}."
                                    ),
                                    evidence=f"getcap output: {line}",
                                    remediation=f"Remove capability using: setcap -r '{file_path}'",
                                    references=[
                                        "https://man7.org/linux/man-pages/man7/capabilities.7.html",
                                        "https://gtfobins.github.io/"
                                    ],
                                    compliance_mappings={
                                        "CIS_Linux": "1.1.21 Audit Linux extended file capabilities",
                                        "ISO_27001": "A.9.4.4 Use of Privileged Utility Programs"
                                    }
                                ))
            except (subprocess.TimeoutExpired, PermissionError, OSError):
                continue

        return findings
