# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Filesystem permissions and critical path security auditor."""

import os
import stat
from typing import List, Dict, Tuple
from privaudit.checks.base import BaseCheck
from privaudit.models import Finding, Severity

# Critical system files with expected permissions
# (path, expected_max_mode, check_id, title, severity)
CRITICAL_SYSTEM_FILES: List[Tuple[str, int, str, str, Severity]] = [
    ("/etc/passwd", 0o644, "PA-FS-PASSWD", "Overly Permissive /etc/passwd Permissions", Severity.CRITICAL),
    ("/etc/shadow", 0o640, "PA-FS-SHADOW", "Overly Permissive /etc/shadow Permissions", Severity.CRITICAL),
    ("/etc/gshadow", 0o640, "PA-FS-GSHADOW", "Overly Permissive /etc/gshadow Permissions", Severity.CRITICAL),
    ("/etc/group", 0o644, "PA-FS-GROUP", "Overly Permissive /etc/group Permissions", Severity.HIGH),
    ("/etc/sudoers", 0o440, "PA-FS-SUDOERS", "Overly Permissive /etc/sudoers Permissions", Severity.CRITICAL),
    ("/etc/crontab", 0o600, "PA-FS-CRONTAB", "Overly Permissive /etc/crontab Permissions", Severity.HIGH),
    ("/etc/hosts.equiv", 0o600, "PA-FS-HOSTS-EQUIV", "Insecure /etc/hosts.equiv Permissions", Severity.HIGH),
]

# Sensitive directories that should never be world-writable
SENSITIVE_DIRECTORIES: List[Tuple[str, str, Severity]] = [
    ("/etc/cron.d", "Cron Drop-in Directory", Severity.CRITICAL),
    ("/etc/cron.daily", "Cron Daily Directory", Severity.CRITICAL),
    ("/etc/cron.hourly", "Cron Hourly Directory", Severity.CRITICAL),
    ("/etc/cron.weekly", "Cron Weekly Directory", Severity.CRITICAL),
    ("/etc/cron.monthly", "Cron Monthly Directory", Severity.CRITICAL),
    ("/etc/systemd/system", "Systemd System Units Directory", Severity.CRITICAL),
    ("/usr/lib/systemd/system", "Systemd Vendor Units Directory", Severity.HIGH),
    ("/etc/profile.d", "Global Shell Profile Directory", Severity.CRITICAL),
]


class FilesystemCheck(BaseCheck):
    """Audits critical Linux configuration files and directories for unsafe write and read permissions."""

    check_id = "PA-FS-001"
    name = "Critical Filesystem Permissions Audit"
    description = "Checks permissions on vital system files (/etc/passwd, /etc/shadow, /etc/sudoers) and verifies sensitive directories are not world-writable."

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # Audit critical files
        for file_path, max_mode, cid, title, sev in CRITICAL_SYSTEM_FILES:
            if not os.path.exists(file_path):
                continue

            try:
                st = os.stat(file_path)
                mode = stat.S_IMODE(st.st_mode)

                # World-writable check
                is_world_writable = bool(mode & stat.S_IWOTH)
                # Permission bits are a set, not a number: 0o604 is smaller
                # than 0o640 yet grants world read. Any bit outside the policy
                # mask is an excess, whatever a numeric comparison says.
                excess_bits = mode & ~max_mode & 0o7777

                if is_world_writable:
                    findings.append(Finding(
                        check_id=cid,
                        title=f"CRITICAL: {title} (World-Writable!)",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The critical system file '{file_path}' has world-writable permissions ({oct(mode)}). "
                            f"Any unprivileged user or process can modify this file to inject accounts, alter hashes, "
                            f"or gain instantaneous root compromise."
                        ),
                        evidence=f"Path: {file_path}, Mode: {oct(mode)}, Owner UID: {st.st_uid}, GID: {st.st_gid}",
                        remediation=f"Restore secure ownership and permissions: chmod {oct(max_mode)[2:]} '{file_path}' && chown root:root '{file_path}'",
                        references=["https://cwe.mitre.org/data/definitions/732.html"],
                        compliance_mappings={
                            "CIS_Linux": "6.1.2 Ensure permissions on sensitive system files are configured",
                            "ISO_27001": "A.9.4.1 Information Access Restriction"
                        }
                    ))
                elif excess_bits:
                    findings.append(Finding(
                        check_id=cid,
                        title=title,
                        severity=sev,
                        description=(
                            f"File '{file_path}' permissions ({oct(mode)}) grant bits outside the recommended "
                            f"maximum mode ({oct(max_mode)}): {oct(excess_bits)}."
                        ),
                        evidence=f"Current Mode: {oct(mode)}, Recommended: {oct(max_mode)}, Excess bits: {oct(excess_bits)}",
                        remediation=f"Harden permissions: chmod {oct(max_mode)[2:]} '{file_path}'",
                        references=["https://cwe.mitre.org/data/definitions/732.html"]
                    ))

                # Every file in this list is root-administered. A non-root
                # owner can rewrite it whatever the mode bits say.
                if st.st_uid != 0:
                    findings.append(Finding(
                        check_id=f"{cid}-OWNER",
                        title=f"Critical File Not Owned by root: {file_path}",
                        severity=sev,
                        description=(
                            f"'{file_path}' is owned by UID {st.st_uid}. Its owner can change its contents "
                            f"and permissions without any further privilege."
                        ),
                        evidence=f"Path: {file_path}, Owner UID: {st.st_uid}, GID: {st.st_gid}",
                        remediation=f"chown root '{file_path}'",
                        references=["https://cwe.mitre.org/data/definitions/732.html"]
                    ))
            except (PermissionError, OSError) as e:
                self.mark_incomplete(f"could not stat {file_path}: {e}")
                continue

        # Audit sensitive directories for world-writable permissions
        for dir_path, dir_name, sev in SENSITIVE_DIRECTORIES:
            if not os.path.isdir(dir_path):
                continue

            try:
                st = os.stat(dir_path)
                mode = stat.S_IMODE(st.st_mode)

                if mode & stat.S_IWOTH:
                    findings.append(Finding(
                        check_id="PA-FS-DIR-WRITABLE",
                        title=f"World-Writable Critical Directory: {dir_name} ({dir_path})",
                        severity=sev,
                        description=(
                            f"The directory '{dir_path}' is world-writable ({oct(mode)}). Any unprivileged user "
                            f"can place scripts or systemd service units here that execute automatically as root."
                        ),
                        evidence=f"Directory: {dir_path}, Mode: {oct(mode)}",
                        remediation=f"Remove world-write permissions: chmod o-w '{dir_path}'",
                        references=["https://cwe.mitre.org/data/definitions/732.html"],
                        compliance_mappings={
                            "CIS_Linux": "1.1.18 Ensure no world-writable directories exist in system paths",
                            "CERT_In": "Persistence and Execution Boundary Controls"
                        }
                    ))
            except (PermissionError, OSError):
                continue

        return findings
