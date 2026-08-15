"""Command-line entrypoint.

    python -m sentinel.cli scan http://localhost/dvwa --mock
    python -m sentinel.cli scan http://localhost/dvwa           # uses live ZAP/Nmap if present
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import ScopeError, Settings
from .orchestrator import run_scan


def _build_settings(args) -> Settings:
    settings = Settings()
    if args.mock:
        settings.mock = True
    if args.allow_any:
        settings.allow_any_target = True
    if args.model:
        settings.claude_model = args.model
    if args.reports_dir:
        settings.reports_dir = args.reports_dir
    return settings


def _print_summary(state: dict) -> None:
    confirmed = [f for f in state.get("confirmed_findings", []) if not f.get("false_positive")]
    print("\n=== Scan log ===")
    for line in state.get("log", []):
        print("  " + line)

    print("\n=== Confirmed findings ===")
    if not confirmed:
        print("  (none)")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for f in sorted(confirmed, key=lambda x: order.get(x.get("severity", "low"), 5)):
        print(
            f"  [{f.get('severity', '?').upper():13}] {f.get('category', ''):9} "
            f"{f.get('name', '')}  -> {f.get('endpoint', '')}"
        )

    print("\n=== Output ===")
    print(f"  Markdown: {state.get('report_path', '(none)')}")
    if state.get("pdf_path"):
        print(f"  PDF:      {state['pdf_path']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel", description="AI multi-agent penetration-testing engine"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a full scan against a target")
    scan.add_argument("target", help="Target URL (e.g. http://localhost/dvwa)")
    scan.add_argument("--mock", action="store_true", help="Use bundled sample scan data")
    scan.add_argument(
        "--allow-any", action="store_true", help="Permit non-local targets you own"
    )
    scan.add_argument("--model", help="Override Claude model id")
    scan.add_argument("--reports-dir", help="Directory for report output")
    scan.add_argument("--json", action="store_true", help="Print final state as JSON")

    args = parser.parse_args(argv)

    if args.command == "scan":
        settings = _build_settings(args)
        try:
            state = run_scan(args.target, settings)
        except ScopeError as exc:
            print(f"ERROR (out of scope): {exc}", file=sys.stderr)
            return 2
        if args.json:
            printable = {k: v for k, v in state.items() if k != "report_markdown"}
            print(json.dumps(printable, indent=2, default=str))
        else:
            _print_summary(state)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
