# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Report renderers for Priv-Audit results (Console ANSI, JSON, and Markdown)."""

import json
from typing import TextIO
from privaudit.models import AuditReport, Severity

# ANSI color codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[31m"
COLOR_YELLOW = "\033[33m"
COLOR_BLUE = "\033[34m"
COLOR_CYAN = "\033[36m"
COLOR_BOLD = "\033[1m"
COLOR_GREEN = "\033[32m"
COLOR_MAGENTA = "\033[35m"

SEVERITY_COLORS = {
    Severity.CRITICAL: f"{COLOR_BOLD}{COLOR_RED}",
    Severity.HIGH: COLOR_RED,
    Severity.MEDIUM: COLOR_YELLOW,
    Severity.LOW: COLOR_BLUE,
    Severity.INFO: COLOR_CYAN,
}


class ConsoleReporter:
    """Renders formatted, colorized findings to standard output."""

    @staticmethod
    def render(report: AuditReport, show_remediation: bool = True) -> str:
        lines = []
        lines.append(f"{COLOR_BOLD}======================================================================{COLOR_RESET}")
        lines.append(f"{COLOR_BOLD}{COLOR_CYAN}  StellerSight Priv-Audit  --  Linux Privilege & Hardening Auditor{COLOR_RESET}")
        lines.append(f"  Host: {report.hostname} | OS: {report.os_info}")
        lines.append(f"{COLOR_BOLD}======================================================================{COLOR_RESET}\n")

        if not report.findings:
            lines.append(f"{COLOR_GREEN}{COLOR_BOLD}[+] No privilege escalation vectors or security misconfigurations discovered.{COLOR_RESET}\n")
        else:
            for idx, finding in enumerate(report.findings, start=1):
                color = SEVERITY_COLORS.get(finding.severity, COLOR_RESET)
                lines.append(f"{color}[{finding.severity.value}]{COLOR_RESET} #{idx} {COLOR_BOLD}{finding.title}{COLOR_RESET}")
                lines.append(f"    Check ID:    {finding.check_id}")
                lines.append(f"    Description: {finding.description}")
                lines.append(f"    Evidence:    {finding.evidence}")
                if show_remediation and finding.remediation:
                    lines.append(f"    Remediation: {COLOR_GREEN}{finding.remediation}{COLOR_RESET}")
                if finding.compliance_mappings:
                    mappings = ", ".join([f"{k}: {v}" for k, v in finding.compliance_mappings.items()])
                    lines.append(f"    Compliance:  {COLOR_MAGENTA}{mappings}{COLOR_RESET}")
                lines.append("")

        # Summary box
        summary = report.summary
        lines.append(f"{COLOR_BOLD}-------------------------- Audit Summary ---------------------------{COLOR_RESET}")
        lines.append(
            f"  {COLOR_RED}CRITICAL: {summary['CRITICAL']}{COLOR_RESET} | "
            f"{COLOR_RED}HIGH: {summary['HIGH']}{COLOR_RESET} | "
            f"{COLOR_YELLOW}MEDIUM: {summary['MEDIUM']}{COLOR_RESET} | "
            f"{COLOR_BLUE}LOW: {summary['LOW']}{COLOR_RESET} | "
            f"{COLOR_CYAN}INFO: {summary['INFO']}{COLOR_RESET} | "
            f"Total: {len(report.findings)} | "
            f"Duration: {report.duration_seconds:.2f}s"
        )
        lines.append(f"{COLOR_BOLD}--------------------------------------------------------------------{COLOR_RESET}")

        if report.errors or report.incomplete:
            lines.append(f"{COLOR_YELLOW}{COLOR_BOLD}  SCAN INCOMPLETE: the absence of a finding is not evidence of a clean host.{COLOR_RESET}")
            for item in report.errors:
                lines.append(f"    error: {item}")
            for item in report.incomplete:
                lines.append(f"    not inspected: {item}")

        return "\n".join(lines)


class JsonReporter:
    """Serializes AuditReport to clean JSON for SIEM/fleet ingestion."""

    @staticmethod
    def render(report: AuditReport, indent: int = 2) -> str:
        return json.dumps(report.to_dict(), indent=indent)


class MarkdownReporter:
    """Renders a complete markdown report suitable for GitHub or compliance documentation."""

    @staticmethod
    def render(report: AuditReport) -> str:
        md = []
        md.append(f"# StellerSight Priv-Audit Security Report\n")
        md.append(f"- **Target Host:** `{report.hostname}`")
        md.append(f"- **Operating System:** `{report.os_info}`")
        md.append(f"- **Audit Duration:** `{report.duration_seconds:.2f} seconds`")
        md.append(f"- **Total Discovered Findings:** `{len(report.findings)}`\n")

        summary = report.summary
        md.append("## Executive Summary\n")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        for sev in Severity:
            md.append(f"| **{sev.value}** | {summary[sev.value]} |")
        md.append("\n---\n")

        if report.errors or report.incomplete:
            md.append("## Scan Completeness\n")
            md.append("**Incomplete.** The absence of a finding below is not evidence of a clean host.\n")
            for item in report.errors:
                md.append(f"- Error: {item}")
            for item in report.incomplete:
                md.append(f"- Not inspected: {item}")
            md.append("\n---\n")

        md.append("## Detailed Findings\n")
        if not report.findings:
            md.append("*No security findings discovered.*\n")
        else:
            for idx, f in enumerate(report.findings, start=1):
                md.append(f"### {idx}. [{f.severity.value}] {f.title}\n")
                md.append(f"- **Check ID:** `{f.check_id}`")
                md.append(f"- **Description:** {f.description}")
                md.append(f"- **Evidence:** `{f.evidence}`")
                if f.remediation:
                    md.append(f"- **Remediation:** `{f.remediation}`")
                if f.compliance_mappings:
                    md.append(f"- **Compliance Mappings:**")
                    for k, v in f.compliance_mappings.items():
                        md.append(f"  - **{k}:** {v}")
                md.append("\n---\n")

        return "\n".join(md)
