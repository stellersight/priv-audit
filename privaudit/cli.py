"""Command-line interface for StellerSight Priv-Audit."""

import argparse
import sys
from privaudit import __version__
from privaudit.engine import AuditEngine
from privaudit.reporters import ConsoleReporter, JsonReporter, MarkdownReporter
from privaudit.models import Severity


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="priv-audit",
        description="StellerSight Priv-Audit: Zero-dependency Linux privilege boundary and host hardening auditor.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in machine-readable JSON format."
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Output results in formatted Markdown."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Write report output to specified file path."
    )
    parser.add_argument(
        "--exit-code",
        action="store_true",
        help=(
            "Return a status for CI gates: 0 no findings at or above --fail-on, "
            "1 findings at or above --fail-on, 2 scan incomplete (for example "
            "files unreadable without root), 3 a check failed unexpectedly."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Lowest severity that counts as a failure for --exit-code (default: high).",
    )

    args = parser.parse_args()

    engine = AuditEngine()
    report = engine.run()

    # Determine output format
    if args.json:
        output_text = JsonReporter.render(report)
    elif args.markdown:
        output_text = MarkdownReporter.render(report)
    else:
        output_text = ConsoleReporter.render(report)

    # Write or print
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_text)
        print(f"[+] Priv-Audit report saved to: {args.output}")
    else:
        print(output_text)

    if args.exit_code:
        return exit_status(report, args.fail_on)

    return 0


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2
EXIT_ERROR = 3


def exit_status(report, fail_on: str = "high") -> int:
    """Map a report to a CI exit status.

    An internal error outranks everything, because nothing else in the report
    can then be trusted. Findings outrank an incomplete scan, since they are
    real whatever else was missed. An incomplete scan is never reported as
    clean.
    """
    if report.errors:
        return EXIT_ERROR

    threshold = SEVERITY_ORDER.index(Severity(fail_on.upper()))
    failing = {sev.value for sev in SEVERITY_ORDER[: threshold + 1]}
    if any(f.severity.value in failing for f in report.findings):
        return EXIT_FINDINGS

    if report.incomplete:
        return EXIT_INCOMPLETE

    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
