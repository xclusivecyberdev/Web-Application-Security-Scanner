"""Command line interface for the web application security scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from .profiles import load_profile
from .scanner import WebAppScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web application vulnerability scanner",
    )
    parser.add_argument("url", help="Base URL of the application to scan")
    parser.add_argument(
        "--profile",
        default="basic",
        help="Scan profile name or JSON file (default: basic)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path to write the report (Markdown or JSON determined by extension)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        help="Explicitly set the report format",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    profile = load_profile(args.profile)

    scanner = WebAppScanner(args.url, profile)
    report = scanner.scan()

    if args.format:
        report_format = args.format
    elif args.output and args.output.suffix.lower() == ".json":
        report_format = "json"
    else:
        report_format = "markdown"

    if report_format == "json":
        output_data = json.dumps(report.to_dict(), indent=2)
    else:
        output_data = report.to_markdown()

    if args.output:
        args.output.write_text(output_data)
        print(f"Report written to {args.output}")
    else:
        print(output_data)

    return 0 if report.is_clean() else 1


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
