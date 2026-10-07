"""Log readers with automatic format detection and transparent gzip support."""

from __future__ import annotations

import gzip
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from itertools import islice
from pathlib import Path

from seclog.models import AccessEvent, AuthEvent, ParseStats
from seclog.parsers.access import ACCESS_LINE, parse_access_line, parse_access_lines
from seclog.parsers.auth import parse_auth_line, parse_auth_lines

__all__ = [
    "LogFormat",
    "ParsedLogs",
    "detect_format",
    "load_logs",
    "parse_access_line",
    "parse_access_lines",
    "parse_auth_line",
    "parse_auth_lines",
    "read_lines",
]


class LogFormat(Enum):
    AUTO = "auto"
    AUTH = "auth"
    ACCESS = "access"


@dataclass(slots=True)
class ParsedLogs:
    auth: list[AuthEvent] = field(default_factory=list)
    access: list[AccessEvent] = field(default_factory=list)
    stats: ParseStats = field(default_factory=ParseStats)


def read_lines(path: Path) -> list[str]:
    """Read a text or ``.gz`` log file, replacing undecodable bytes."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def detect_format(lines: Iterable[str], sample_size: int = 50) -> LogFormat | None:
    """Guess whether ``lines`` come from an auth log or an access log."""
    auth_votes = access_votes = 0
    for line in islice((ln for ln in lines if ln.strip()), sample_size):
        if ACCESS_LINE.match(line):
            access_votes += 1
        elif " sshd" in line or "sshd[" in line:
            auth_votes += 1
    if access_votes == 0 and auth_votes == 0:
        return None
    return LogFormat.ACCESS if access_votes >= auth_votes else LogFormat.AUTH


def load_logs(
    paths: Iterable[Path], *, fmt: LogFormat = LogFormat.AUTO, year: int | None = None
) -> ParsedLogs:
    """Parse every file in ``paths`` and collect events plus statistics.

    Raises ``FileNotFoundError`` for missing files and ``ValueError`` when the
    format of a file cannot be detected.
    """
    result = ParsedLogs()
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"log file not found: {path}")
        lines = read_lines(path)
        result.stats.files.append(str(path))
        result.stats.total_lines += len(lines)
        file_format = fmt if fmt is not LogFormat.AUTO else detect_format(lines)
        if file_format is None:
            raise ValueError(f"could not detect the log format of {path}; use --format")
        if file_format is LogFormat.AUTH:
            events = list(parse_auth_lines(lines, year=year, source=path.name))
            result.auth.extend(events)
            result.stats.auth_events += len(events)
            parsed = len(events)
        else:
            access = list(parse_access_lines(lines, source=path.name))
            result.access.extend(access)
            result.stats.access_events += len(access)
            parsed = len(access)
        result.stats.skipped_lines += sum(1 for ln in lines if ln.strip()) - parsed
    return result
