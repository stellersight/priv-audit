# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Data models for Priv-Audit findings and audit results."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional
import time


class Severity(str, Enum):
    """Vulnerability and risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents an individual security finding."""
    check_id: str
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)
    compliance_mappings: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class AuditReport:
    """Comprehensive container for all findings from an audit run."""
    timestamp: float = field(default_factory=time.time)
    hostname: str = ""
    os_info: str = ""
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    # Checks that could not inspect everything they cover, with the reason.
    # A scan with entries here must never be read as clean.
    incomplete: List[str] = field(default_factory=list)
    # Checks that failed with an unexpected error.
    errors: List[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def summary(self) -> Dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "os_info": self.os_info,
            "duration_seconds": round(self.duration_seconds, 3),
            "summary": self.summary,
            "complete": not self.incomplete and not self.errors,
            "incomplete": list(self.incomplete),
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.findings],
        }
