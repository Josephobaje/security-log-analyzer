from __future__ import annotations

import gzip
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from seclog.models import AuthEventType
from seclog.parsers import (
    LogFormat,
    detect_format,
    load_logs,
    parse_access_line,
    parse_auth_line,
)

# --------------------------------------------------------------------------- auth


@pytest.mark.parametrize(
    ("line", "event", "user", "ip", "port"),
    [
        (
            "Oct  5 02:14:05 web01 sshd[4676]: Failed password for root from 203.0.113.45 "
            "port 62892 ssh2",
            AuthEventType.FAILED_PASSWORD,
            "root",
            "203.0.113.45",
            62892,
        ),
        (
            "Oct  5 02:14:05 web01 sshd[4676]: Failed password for invalid user admin from "
            "203.0.113.45 port 1022 ssh2",
            AuthEventType.FAILED_PASSWORD,
            "admin",
            "203.0.113.45",
            1022,
        ),
        (
            "Oct 15 08:00:00 web01 sshd[1]: Accepted publickey for deploy from 198.51.100.10 "
            "port 51022 ssh2: ED25519 SHA256:abc",
            AuthEventType.ACCEPTED,
            "deploy",
            "198.51.100.10",
            51022,
        ),
        (
            "Oct  5 05:03:00 web01 sshd[9]: Invalid user oracle from 203.0.113.77 port 4444",
            AuthEventType.INVALID_USER,
            "oracle",
            "203.0.113.77",
            4444,
        ),
        (
            "Oct  5 05:03:00 web01 sshd[9]: Invalid user  from 203.0.113.77 port 4444",
            AuthEventType.INVALID_USER,
            None,
            "203.0.113.77",
            4444,
        ),
        (
            "Oct  5 02:20:00 web01 sshd[9]: error: maximum authentication attempts exceeded for "
            "root from 203.0.113.45 port 41234 ssh2 [preauth]",
            AuthEventType.MAX_ATTEMPTS,
            "root",
            "203.0.113.45",
            41234,
        ),
        (
            "Oct  5 11:00:00 web01 sshd[9]: Did not receive identification string from "
            "192.0.2.200 port 61000",
            AuthEventType.NO_IDENTIFICATION,
            None,
            "192.0.2.200",
            61000,
        ),
        (
            "Oct  5 11:05:00 web01 sshd[9]: Connection closed by authenticating user root "
            "192.0.2.200 port 61002 [preauth]",
            AuthEventType.DISCONNECT_PREAUTH,
            "root",
            "192.0.2.200",
            61002,
        ),
        (
            "Oct  5 11:05:00 web01 sshd[9]: Failed password for root from 2001:db8::7 port 22 ssh2",
            AuthEventType.FAILED_PASSWORD,
            "root",
            "2001:db8::7",
            22,
        ),
    ],
)
def test_parse_auth_line_variants(
    line: str, event: AuthEventType, user: str | None, ip: str, port: int
) -> None:
    parsed = parse_auth_line(line, year=2026)
    assert parsed is not None
    assert parsed.event is event
    assert parsed.user == user
    assert parsed.ip == ip
    assert parsed.port == port
    assert parsed.host == "web01"


def test_syslog_timestamp_uses_given_year_and_local_zone() -> None:
    line = "Feb 29 23:59:58 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    parsed = parse_auth_line(line, year=2028)
    assert parsed is not None
    assert parsed.timestamp.replace(tzinfo=None) == datetime(2028, 2, 29, 23, 59, 58)
    assert parsed.timestamp.tzinfo is not None


def test_invalid_syslog_date_is_skipped() -> None:
    line = "Feb 30 10:00:00 h sshd[1]: Failed password for root from 192.0.2.1 port 22 ssh2"
    assert parse_auth_line(line, year=2026) is None


def test_iso_timestamp_keeps_offset() -> None:
    line = (
        "2026-10-07T08:12:01.123456+01:00 web01 sshd[77]: Failed password for root from "
        "192.0.2.9 port 2222 ssh2"
    )
    parsed = parse_auth_line(line)
    assert parsed is not None
    assert parsed.timestamp == datetime(
        2026, 10, 7, 8, 12, 1, 123456, tzinfo=timezone(timedelta(hours=1))
    )


@pytest.mark.parametrize(
    "line",
    [
        "Oct  5 00:07:05 web01 CRON[1]: pam_unix(cron:session): session opened for user root",
        "Oct  5 00:07:05 web01 sudo[1]: deploy : TTY=pts/0 ; COMMAND=/usr/bin/ls",
        "Oct  5 00:07:05 web01 sshd[1]: Server listening on 0.0.0.0 port 22.",
        "garbage",
        "",
    ],
)
def test_irrelevant_auth_lines_are_ignored(line: str) -> None:
    assert parse_auth_line(line, year=2026) is None


# --------------------------------------------------------------------------- access


def test_parse_combined_log_format() -> None:
    line = (
        '198.51.100.7 - frank [06/Oct/2026:08:05:00 +0100] "GET /products.php?id=1 HTTP/1.1" '
        '200 11203 "https://example.com/" "Mozilla/5.0 (X11)"'
    )
    e = parse_access_line(line)
    assert e is not None
    assert (e.ip, e.method, e.path, e.protocol) == (
        "198.51.100.7",
        "GET",
        "/products.php?id=1",
        "HTTP/1.1",
    )
    assert (e.status, e.size) == (200, 11203)
    assert e.referrer == "https://example.com/"
    assert e.user_agent == "Mozilla/5.0 (X11)"
    assert e.timestamp.utcoffset() == timedelta(hours=1)


def test_parse_common_log_format_and_dash_size() -> None:
    e = parse_access_line('2001:db8::1 - - [06/Oct/2026:08:05:00 +0000] "HEAD / HTTP/1.0" 304 -')
    assert e is not None
    assert e.ip == "2001:db8::1"
    assert e.size == 0
    assert e.user_agent == ""


def test_parse_garbage_request_line() -> None:
    line = '203.0.113.250 - - [06/Oct/2026:12:00:00 +0100] "\\x16\\x03\\x01" 400 157 "-" "-"'
    e = parse_access_line(line)
    assert e is not None
    assert e.method == "-"
    assert e.status == 400


def test_escaped_quotes_inside_user_agent() -> None:
    line = (
        '192.0.2.1 - - [06/Oct/2026:12:00:00 +0100] "GET / HTTP/1.1" 200 1 "-" '
        '"evil \\"agent\\" v1"'
    )
    e = parse_access_line(line)
    assert e is not None
    assert "agent" in e.user_agent


@pytest.mark.parametrize(
    "line",
    [
        "not a log line",
        '1.2.3.4 - - [99/Foo/2026:12:00:00 +0100] "GET / HTTP/1.1" 200 1',
        "Oct  5 02:14:05 web01 sshd[4676]: Failed password for root from 1.2.3.4 port 1 ssh2",
    ],
)
def test_unparseable_access_lines(line: str) -> None:
    assert parse_access_line(line) is None


# --------------------------------------------------------------------------- loading


def test_detect_format(samples: Path) -> None:
    auth = (samples / "auth.log").read_text().splitlines()
    access = (samples / "access.log").read_text().splitlines()
    assert detect_format(auth) is LogFormat.AUTH
    assert detect_format(access) is LogFormat.ACCESS
    assert detect_format(["hello", "world"]) is None


def test_load_logs_reads_gzip_and_counts(tmp_path: Path, samples: Path) -> None:
    gz = tmp_path / "access.log.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write((samples / "access.log").read_text())
    logs = load_logs([samples / "auth.log", gz], year=2026)
    assert logs.stats.auth_events == len(logs.auth) > 50
    assert logs.stats.access_events == len(logs.access) > 300
    assert logs.stats.files == [str(samples / "auth.log"), str(gz)]


def test_load_logs_errors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_logs([tmp_path / "missing.log"])
    unknown = tmp_path / "notes.txt"
    unknown.write_text("just some text\n")
    with pytest.raises(ValueError, match="could not detect"):
        load_logs([unknown])
    # An explicit format bypasses detection.
    assert load_logs([unknown], fmt=LogFormat.AUTH).stats.skipped_lines == 1
