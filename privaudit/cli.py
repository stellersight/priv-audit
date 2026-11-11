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
        help="Exit with non-zero return code (1) if CRITICAL or HIGH findings exist (ideal for CI/CD gates)."
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

    # Return exit code if requested
    if args.exit_code:
        summary = report.summary
        if summary.get(Severity.CRITICAL.value, 0) > 0 or summary.get(Severity.HIGH.value, 0) > 0:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
