"""Parser for Apache and Nginx access logs in Common or Combined Log Format."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime

from seclog.models import AccessEvent

ACCESS_LINE = re.compile(
    r"^(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referrer>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?'
)
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_access_line(line: str, *, source: str = "", line_no: int = 0) -> AccessEvent | None:
    """Parse one access log line, or return ``None`` if it is not in a supported format."""
    line = line.rstrip("\r\n")
    m = ACCESS_LINE.match(line)
    if m is None:
        return None
    try:
        timestamp = datetime.strptime(m.group("time"), _TIME_FORMAT)
    except ValueError:
        return None

    request = m.group("request")
    parts = request.split(" ")
    if len(parts) >= 3:
        method, path, protocol = parts[0], " ".join(parts[1:-1]), parts[-1]
    elif len(parts) == 2:
        method, path, protocol = parts[0], parts[1], ""
    else:
        # Garbage such as "-" or raw TLS bytes sent to a plain-HTTP port.
        method, path, protocol = "-", request, ""

    size = m.group("size")
    return AccessEvent(
        timestamp=timestamp,
        ip=m.group("ip"),
        method=method,
        path=path,
        protocol=protocol,
        status=int(m.group("status")),
        size=0 if size == "-" else int(size),
        referrer="" if m.group("referrer") in (None, "-") else m.group("referrer"),
        user_agent="" if m.group("agent") in (None, "-") else m.group("agent"),
        source=source,
        line_no=line_no,
        raw=line,
    )


def parse_access_lines(lines: Iterable[str], *, source: str = "") -> Iterator[AccessEvent]:
    """Yield every parseable request from ``lines``."""
    for number, line in enumerate(lines, start=1):
        event = parse_access_line(line, source=source, line_no=number)
        if event is not None:
            yield event
