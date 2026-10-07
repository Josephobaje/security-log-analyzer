from __future__ import annotations

from pathlib import Path

import pytest

from seclog.analyzer import analyze, network_label, threat_score
from seclog.models import Finding, Severity
from seclog.parsers import load_logs


@pytest.fixture
def sample_report(samples: Path):  # type: ignore[no-untyped-def]
    logs = load_logs(sorted(samples.glob("*.log")), year=2026)
    return analyze(logs.auth, logs.access, stats=logs.stats)


def test_samples_trigger_every_rule_family(sample_report) -> None:  # type: ignore[no-untyped-def]
    found = {f.rule_id for f in sample_report.findings}
    expected = {
        "SSH-BRUTE-FORCE",
        "SSH-LOGIN-AFTER-BRUTE-FORCE",
        "SSH-USER-ENUMERATION",
        "SSH-DISTRIBUTED-ATTACK",
        "SSH-ROOT-LOGIN",
        "WEB-LOGIN-BRUTE-FORCE",
        "WEB-404-SCAN",
        "WEB-SCANNER-UA",
        "WEB-SQLI",
        "WEB-XSS",
        "WEB-PATH-TRAVERSAL",
        "WEB-COMMAND-INJECTION",
        "WEB-SENSITIVE-FILE",
        "WEB-LOG4SHELL",
        "WEB-SHELLSHOCK",
    }
    assert expected <= found


def test_findings_sorted_by_severity(sample_report) -> None:  # type: ignore[no-untyped-def]
    ranks = [f.severity.rank for f in sample_report.findings]
    assert ranks == sorted(ranks, reverse=True)
    assert sample_report.highest_severity is Severity.CRITICAL


def test_legitimate_visitors_are_not_suspicious(sample_report) -> None:  # type: ignore[no-untyped-def]
    flagged = {s.ip for s in sample_report.suspicious_ips}
    # Normal visitors in the samples use 198.51.100.11-59.
    assert not any(
        ip.startswith("198.51.100.") and 11 <= int(ip.rsplit(".", 1)[1]) <= 59 for ip in flagged
    )
    top = sample_report.suspicious_ips[0]
    assert top.ip == "192.0.2.150"
    assert top.severity is Severity.CRITICAL
    assert top.network == "documentation"


def test_min_severity_filters(samples: Path) -> None:
    logs = load_logs([samples / "auth.log"], year=2026)
    report = analyze(logs.auth, logs.access, min_severity=Severity.HIGH)
    assert report.findings
    assert all(f.severity >= Severity.HIGH for f in report.findings)


def test_summaries(sample_report) -> None:  # type: ignore[no-untyped-def]
    auth = sample_report.auth_summary
    web = sample_report.web_summary
    assert auth["successful_logins"] == 7
    assert auth["top_targeted_users"][0][0] in {"root", "admin"}
    assert web["requests"] == sample_report.stats.access_events
    assert "404" in web["status_codes"]


def test_empty_input_gives_clean_report() -> None:
    report = analyze([], [])
    assert report.findings == []
    assert report.suspicious_ips == []
    assert report.highest_severity is None
    assert report.severity_counts["critical"] == 0


def test_threat_score() -> None:
    def f(sev: Severity, count: int = 1) -> Finding:
        return Finding("R", "t", sev, "c", "d", ip="192.0.2.1", count=count)

    assert threat_score([]) == 0
    assert threat_score([f(Severity.MEDIUM)]) == 30
    assert threat_score([f(Severity.HIGH, 40)]) == 59
    assert threat_score([f(Severity.CRITICAL), f(Severity.HIGH), f(Severity.HIGH)]) == 90
    assert threat_score([f(Severity.CRITICAL, 1000)] * 10) == 100


@pytest.mark.parametrize(
    ("ip", "label"),
    [
        ("8.8.8.8", "public"),
        ("10.0.0.5", "private"),
        ("192.168.1.10", "private"),
        ("127.0.0.1", "loopback"),
        ("203.0.113.9", "documentation"),
        ("2001:db8::1", "documentation"),
        ("not-an-ip", "invalid"),
    ],
)
def test_network_label(ip: str, label: str) -> None:
    assert network_label(ip) == label
