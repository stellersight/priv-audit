# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Audit engine orchestrating check execution and report generation."""

import platform
import socket
import time
from typing import List, Optional
from privaudit.checks import ALL_CHECKS
from privaudit.models import AuditReport, Finding, Severity


class AuditEngine:
    """Coordinates the execution of security checks and builds a structured AuditReport."""

    def __init__(self, checks: Optional[List] = None):
        self.check_classes = checks or ALL_CHECKS

    def run(self) -> AuditReport:
        start_time = time.time()
        report = AuditReport(
            timestamp=start_time,
            hostname=socket.gethostname(),
            os_info=f"{platform.system()} {platform.release()} ({platform.machine()})",
        )

        for check_cls in self.check_classes:
            try:
                checker = check_cls()
                findings = checker.run()
                for finding in findings:
                    report.add_finding(finding)
                report.incomplete.extend(getattr(checker, "incomplete", []))
            except Exception as e:
                report.errors.append(f"{getattr(check_cls, 'check_id', check_cls.__name__)}: {e}")
                # Catch unexpected check exceptions to ensure audit resiliency
                report.add_finding(Finding(
                    check_id="PA-ENGINE-ERR",
                    title=f"Check Execution Error: {getattr(check_cls, 'name', 'Unknown')}",
                    severity=Severity.INFO,
                    description=f"Encountered unexpected error during check execution: {str(e)}",
                    evidence=str(e),
                    remediation="Check system environment permissions or report to StellerSight engineering.",
                ))

        report.duration_seconds = time.time() - start_time
        return report
