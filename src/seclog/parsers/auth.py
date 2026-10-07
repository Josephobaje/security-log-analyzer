"""Parser for sshd entries in Linux authentication logs.

Supports the classic syslog prefix (``Oct  7 08:12:01 host sshd[123]: ...``) used by
Debian/Ubuntu ``/var/log/auth.log`` and RHEL ``/var/log/secure``, and the RFC 3339
prefix written by modern rsyslog/journald exports
(``2026-10-07T08:12:01.123456+01:00 host sshd[123]: ...``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from seclog.models import AuthEvent, AuthEventType

_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
_MESSAGES: list[tuple[AuthEventType, re.Pattern[str]]] = [
    (
        AuthEventType.FAILED_PASSWORD,
        re.compile(
            r"^Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for "
            r"(?:invalid user )?(?P<user>.*?) from " + _IP + r" port (?P<port>\d+)"
        ),
    ),
    (
        AuthEventType.ACCEPTED,
        re.compile(
            r"^Accepted (?P<method>\S+) for (?P<user>\S+) from " + _IP + r" port (?P<port>\d+)"
        ),
    ),
    (
        AuthEventType.INVALID_USER,
        re.compile(r"^Invalid user (?P<user>.*?) from " + _IP + r"(?: port (?P<port>\d+))?\s*$"),
    ),
    (
        AuthEventType.MAX_ATTEMPTS,
        re.compile(
            r"^error: maximum authentication attempts exceeded for (?:invalid user )?"
            r"(?P<user>.*?) from " + _IP + r" port (?P<port>\d+)"
        ),
    ),
    (
        AuthEventType.NO_IDENTIFICATION,
        re.compile(
            r"^Did not receive identification string from " + _IP + r"(?: port (?P<port>\d+))?"
        ),
    ),
    (
        AuthEventType.DISCONNECT_PREAUTH,
        re.compile(
            r"^(?:Connection closed|Disconnected from) (?:by )?(?:authenticating |invalid )?"
            r"(?:user (?P<user>\S+) )?" + _IP + r" port (?P<port>\d+) \[preauth\]"
        ),
    ),
]

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _parse_timestamp(match: re.Match[str], year: int) -> datetime | None:
    groups = match.groupdict()
    if groups.get("ts"):
        ts = groups["ts"].replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(ts)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.astimezone()
    month = _MONTHS.get(groups["month"])
    if month is None:
        return None
    try:
        naive = datetime.strptime(
            f"{year}-{month:02d}-{int(groups['day']):02d} {groups['time']}", "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None
    # Classic syslog has no zone; it is written in the server's local time.
    return naive.astimezone()


def parse_auth_line(
    line: str, *, year: int | None = None, source: str = "", line_no: int = 0
) -> AuthEvent | None:
    """Parse one auth log line. Returns ``None`` for lines that are not sshd security events."""
    line = line.rstrip("\r\n")
    prefix = _ISO_PREFIX.match(line) or _SYSLOG_PREFIX.match(line)
    if prefix is None or not prefix.group("proc").startswith("sshd"):
        return None
    message = prefix.group("msg")
    for event_type, pattern in _MESSAGES:
        m = pattern.match(message)
        if m is None:
            continue
        timestamp = _parse_timestamp(prefix, year or datetime.now().year)
        if timestamp is None:
            return None
        fields = m.groupdict()
        port = fields.get("port")
        return AuthEvent(
            timestamp=timestamp,
            host=prefix.group("host"),
            event=event_type,
            ip=fields["ip"],
            user=fields.get("user") or None,
            port=int(port) if port else None,
            method=fields.get("method"),
            source=source,
            line_no=line_no,
            raw=line,
        )
    return None


def parse_auth_lines(
    lines: Iterable[str], *, year: int | None = None, source: str = ""
) -> Iterator[AuthEvent]:
    """Yield every recognised sshd event from ``lines``."""
    for number, line in enumerate(lines, start=1):
        event = parse_auth_line(line, year=year, source=source, line_no=number)
        if event is not None:
            yield event
