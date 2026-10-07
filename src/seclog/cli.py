"""Command-line interface: ``seclog analyze`` and ``seclog rules``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.table import Table

from seclog import __version__
from seclog.analyzer import analyze
from seclog.detectors import WEB_SIGNATURES, Thresholds
from seclog.models import Severity
from seclog.parsers import LogFormat, load_logs
from seclog.reports import render_terminal, write_csv, write_html, write_json

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

RULES: list[tuple[str, str, str]] = [
    ("SSH-BRUTE-FORCE", "high", "Many failed SSH logins from one IP within a time window"),
    (
        "SSH-LOGIN-AFTER-BRUTE-FORCE",
        "critical",
        "Successful SSH login from an IP that was brute-forcing",
    ),
    ("SSH-USER-ENUMERATION", "medium", "One IP trying many non-existent usernames"),
    ("SSH-DISTRIBUTED-ATTACK", "medium", "One account attacked from many different IPs"),
    ("SSH-ROOT-LOGIN", "medium", "Direct root login over SSH"),
    (
        "WEB-LOGIN-BRUTE-FORCE",
        "high",
        "Burst of POSTs to login endpoints (wp-login.php, /login, ...)",
    ),
    ("WEB-404-SCAN", "medium/high", "Burst of 404 responses from one IP (content discovery)"),
    ("WEB-SCANNER-UA", "medium", "User-Agent of a known scanner (sqlmap, Nikto, Nuclei, ...)"),
    *[(s.rule_id, s.severity.value, s.title) for s in WEB_SIGNATURES],
]


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seclog",
        description=(
            "Analyse Linux auth logs (sshd) and Apache/Nginx access logs for brute-force "
            "attacks, scanners and injection attempts."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyse one or more log files")
    run.add_argument("files", nargs="+", type=Path, help="log files (.log, .txt or .gz)")
    run.add_argument(
        "-f",
        "--format",
        choices=[f.value for f in LogFormat],
        default=LogFormat.AUTO.value,
        help="log format (default: detect per file)",
    )
    run.add_argument(
        "--year", type=int, help="year for syslog timestamps without one (default: current year)"
    )
    run.add_argument("--json", type=Path, metavar="PATH", help="write a JSON report")
    run.add_argument("--csv", type=Path, metavar="PATH", help="write findings as CSV")
    run.add_argument("--html", type=Path, metavar="PATH", help="write a standalone HTML report")
    run.add_argument(
        "--min-severity",
        type=_severity,
        default=Severity.LOW,
        metavar="LEVEL",
        help="hide findings below LEVEL: info, low, medium, high, critical (default: low)",
    )
    run.add_argument(
        "--fail-on",
        type=_severity,
        metavar="LEVEL",
        help="exit with status 1 if any finding is at or above LEVEL (useful in cron/CI)",
    )
    run.add_argument("--top", type=_positive_int, default=15, help="rows per table (default: 15)")
    run.add_argument("-q", "--quiet", action="store_true", help="do not print the terminal report")
    run.add_argument("--no-color", action="store_true", help="disable colours")

    t = run.add_argument_group("detection thresholds")
    d = Thresholds()
    t.add_argument(
        "--ssh-failures",
        type=_positive_int,
        default=d.ssh_failures,
        help=f"failed SSH logins per window (default: {d.ssh_failures})",
    )
    t.add_argument(
        "--ssh-window",
        type=_positive_int,
        default=d.ssh_window_minutes,
        metavar="MINUTES",
        help=f"SSH window (default: {d.ssh_window_minutes})",
    )
    t.add_argument(
        "--user-enum",
        type=_positive_int,
        default=d.user_enum_distinct,
        help=f"distinct invalid users per IP (default: {d.user_enum_distinct})",
    )
    t.add_argument(
        "--scan-404s",
        type=_positive_int,
        default=d.scan_404s,
        help=f"404 responses per window (default: {d.scan_404s})",
    )
    t.add_argument(
        "--scan-window",
        type=_positive_int,
        default=d.scan_window_minutes,
        metavar="MINUTES",
        help=f"404 window (default: {d.scan_window_minutes})",
    )
    t.add_argument(
        "--login-attempts",
        type=_positive_int,
        default=d.web_login_attempts,
        help=f"web login POSTs per window (default: {d.web_login_attempts})",
    )
    t.add_argument(
        "--login-window",
        type=_positive_int,
        default=d.web_login_window_minutes,
        metavar="MINUTES",
        help=f"web login window (default: {d.web_login_window_minutes})",
    )

    sub.add_parser("rules", help="list the detection rules")
    return parser


def _print_rules(console: Console) -> None:
    table = Table(title="Detection rules", title_justify="left")
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("Description")
    for rule_id, severity, description in RULES:
        table.add_row(rule_id, severity, description)
    console.print(table)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(no_color=getattr(args, "no_color", False), highlight=False)
    err = Console(stderr=True, highlight=False)

    if args.command == "rules":
        _print_rules(console)
        return EXIT_OK

    thresholds = Thresholds(
        ssh_failures=args.ssh_failures,
        ssh_window_minutes=args.ssh_window,
        user_enum_distinct=args.user_enum,
        scan_404s=args.scan_404s,
        scan_window_minutes=args.scan_window,
        web_login_attempts=args.login_attempts,
        web_login_window_minutes=args.login_window,
    )
    try:
        logs = load_logs(args.files, fmt=LogFormat(args.format), year=args.year)
    except (FileNotFoundError, ValueError, OSError) as exc:
        err.print(f"[bold red]error:[/bold red] {exc}")
        return EXIT_ERROR

    report = analyze(
        logs.auth,
        logs.access,
        stats=logs.stats,
        thresholds=thresholds,
        min_severity=args.min_severity,
    )

    if not args.quiet:
        render_terminal(report, console, top=args.top)

    written: list[Path] = []
    try:
        if args.json:
            written.append(write_json(report, args.json))
        if args.csv:
            written.append(write_csv(report, args.csv))
        if args.html:
            written.append(write_html(report, args.html))
    except OSError as exc:
        err.print(f"[bold red]error:[/bold red] could not write report: {exc}")
        return EXIT_ERROR
    for path in written:
        err.print(f"[green]Report written:[/green] {path}")

    highest = report.highest_severity
    if args.fail_on is not None and highest is not None and highest >= args.fail_on:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
