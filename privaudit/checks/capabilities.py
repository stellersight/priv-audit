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


# File capabilities that distributions ship on purpose. newuidmap and
# newgidmap carry cap_setuid/cap_setgid on every RHEL-family host so that
# rootless containers can map ID ranges; ping carries cap_net_raw instead of
# being SUID. In a system directory, with exactly these capabilities or a
# subset, they are expected and not reported.
EXPECTED_CAPABILITIES: Dict[str, Set[str]] = {
    "newuidmap": {"cap_setuid"},
    "newgidmap": {"cap_setgid"},
    "ping": {"cap_net_raw"},
    "ping6": {"cap_net_raw"},
    "arping": {"cap_net_raw"},
    "clockdiff": {"cap_net_raw"},
    "mtr-packet": {"cap_net_raw"},
    "dumpcap": {"cap_net_raw", "cap_net_admin"},
    "gst-ptp-helper": {"cap_net_bind_service", "cap_net_admin"},
}
SYSTEM_BINARY_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/")


def _granted_caps(caps_str: str) -> Set[str]:
    """Extracts capability names from getcap output such as 'cap_net_raw,cap_net_admin=ep'."""
    names: Set[str] = set()
    for clause in caps_str.replace(" ", ",").split(","):
        for token in clause.replace("+", "=").split("=")[:1]:
            if token.startswith("cap_"):
                names.add(token)
    return names


class CapabilitiesCheck(BaseCheck):
    """Scans Linux filesystem for binaries with dangerous Linux capabilities (cap_setuid, cap_sys_admin, etc.)."""

    check_id = "PA-CAP-001"
    name = "Linux File Capabilities Security Audit"
    description = "Discovers binaries with extended file capabilities and flags capabilities with high privilege escalation potential."

    def __init__(self, search_paths: List[str] = None):
        self.search_paths = search_paths or ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/opt"]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        seen_real: Set[str] = set()
        getcap_bin = shutil.which("getcap")

        if not getcap_bin:
            self.mark_incomplete("getcap is not installed, so file capabilities were not inspected")
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

                if proc.returncode != 0 or proc.stderr.strip():
                    detail = proc.stderr.strip().splitlines()[0] if proc.stderr.strip() else f"exit status {proc.returncode}"
                    self.mark_incomplete(f"getcap reported an error under {path}: {detail}")

                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    # Current libcap prints "/usr/bin/ping cap_net_raw=ep";
                    # releases before 2.41 print "/usr/bin/ping = cap_net_raw+ep".
                    parts = line.split()
                    if len(parts) >= 2:
                        file_path = parts[0]
                        real = os.path.realpath(file_path)
                        if real in seen_real:
                            continue
                        seen_real.add(real)
                        caps_str = " ".join(p for p in parts[1:] if p != "=").lower()

                        expected = EXPECTED_CAPABILITIES.get(os.path.basename(file_path))
                        if (expected is not None and file_path.startswith(SYSTEM_BINARY_DIRS)
                                and _granted_caps(caps_str) <= expected):
                            continue

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
            except (subprocess.TimeoutExpired, PermissionError, OSError) as e:
                self.mark_incomplete(f"getcap failed on {path}: {e}")
                continue

        return findings
