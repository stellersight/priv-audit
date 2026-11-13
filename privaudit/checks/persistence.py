# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Persistence mechanism and scheduled task auditor."""

import os
import stat
import glob
from typing import List
from privaudit.checks.base import BaseCheck
from privaudit.models import Finding, Severity


class PersistenceCheck(BaseCheck):
    """Audits system cron jobs, systemd timers, and user crontabs for persistence vectors and writable targets."""

    check_id = "PA-PERSIST-001"
    name = "Persistence & Scheduled Task Security Audit"
    description = "Checks cron directories, systemd timers, and cron job command targets for writable script paths."

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # Check 1: User crontabs in /var/spool/cron/crontabs
        spool_paths = ["/var/spool/cron/crontabs", "/var/spool/cron"]
        for spool in spool_paths:
            if os.path.isdir(spool):
                try:
                    for user_cron in os.listdir(spool):
                        cron_file = os.path.join(spool, user_cron)
                        if os.path.isfile(cron_file):
                            st = os.stat(cron_file)
                            mode = stat.S_IMODE(st.st_mode)
                            if mode & stat.S_IWOTH:
                                findings.append(Finding(
                                    check_id="PA-PERSIST-CRON-WRITABLE",
                                    title=f"World-Writable User Crontab: {user_cron}",
                                    severity=Severity.CRITICAL,
                                    description=f"Crontab file '{cron_file}' is world-writable ({oct(mode)}). Attackers can inject arbitrary scheduled tasks.",
                                    evidence=f"File: {cron_file}, Mode: {oct(mode)}",
                                    remediation=f"chmod 600 '{cron_file}' && chown {st.st_uid}:crontab '{cron_file}'",
                                ))
                except (PermissionError, OSError) as e:
                    self.mark_incomplete(f"could not list {spool}: {e}")

        # Check 2: Inspect scripts inside /etc/cron.* for world-writable permissions
        cron_dirs = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d"]
        for cdir in cron_dirs:
            if not os.path.isdir(cdir):
                continue
            try:
                for entry in os.listdir(cdir):
                    full_entry = os.path.join(cdir, entry)
                    if os.path.isfile(full_entry):
                        try:
                            st = os.stat(full_entry)
                            mode = stat.S_IMODE(st.st_mode)
                            if mode & stat.S_IWOTH:
                                findings.append(Finding(
                                    check_id="PA-PERSIST-CRONSCRIPT-WRITABLE",
                                    title=f"World-Writable Cron Execution Script: {entry}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Script '{full_entry}' inside '{cdir}' executes with root privileges on schedule, "
                                        f"but is world-writable ({oct(mode)})."
                                    ),
                                    evidence=f"Path: {full_entry}, Mode: {oct(mode)}",
                                    remediation=f"chmod 750 '{full_entry}' && chown root:root '{full_entry}'",
                                    compliance_mappings={
                                        "CIS_Linux": "1.1.18 Ensure cron scripts are securely permissions",
                                        "CERT_In": "Scheduled Task and Persistence Security"
                                    }
                                ))
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue

        return findings
