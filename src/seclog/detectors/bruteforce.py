"""SSH and web login brute-force detection."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import timedelta

from seclog.detectors.config import Thresholds
from seclog.detectors.windows import busiest_window
from seclog.models import AccessEvent, AuthEvent, AuthEventType, Finding, Severity

WEB_LOGIN_PATHS = (
    "/wp-login.php",
    "/xmlrpc.php",
    "/login",
    "/user/login",
    "/admin/login",
    "/administrator/index.php",
    "/auth/login",
    "/signin",
)


def _top(counter: Counter[str], n: int = 5) -> str:
    return ", ".join(f"{name} ({count})" for name, count in counter.most_common(n))


def detect_ssh_attacks(events: Iterable[AuthEvent], thresholds: Thresholds) -> list[Finding]:
    """Detect SSH brute force, user enumeration, distributed attacks and risky logins."""
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    failures_by_user: dict[str, set[str]] = defaultdict(set)
    for event in events:
        by_ip[event.ip].append(event)
        if event.is_failure and event.user:
            failures_by_user[event.user].add(event.ip)

    findings: list[Finding] = []
    window = timedelta(minutes=thresholds.ssh_window_minutes)

    for ip, ip_events in sorted(by_ip.items()):
        ip_events.sort(key=lambda e: e.timestamp)
        failures = [e for e in ip_events if e.is_failure]
        accepted = [e for e in ip_events if e.event is AuthEventType.ACCEPTED]
        users = Counter(e.user for e in failures if e.user)
        burst = busiest_window([e.timestamp for e in failures], window)
        is_bruteforce = burst is not None and burst.count >= thresholds.ssh_failures

        if is_bruteforce and burst is not None:
            findings.append(
                Finding(
                    rule_id="SSH-BRUTE-FORCE",
                    title="SSH brute-force attack",
                    severity=Severity.HIGH,
                    category="brute-force",
                    description=(
                        f"{len(failures)} failed SSH logins from {ip}, peaking at {burst.count} "
                        f"within {thresholds.ssh_window_minutes} minutes."
                    ),
                    ip=ip,
                    count=len(failures),
                    first_seen=failures[0].timestamp,
                    last_seen=failures[-1].timestamp,
                    evidence=[
                        f"Targeted users: {_top(users)}",
                        f"Peak window: {burst.start:%Y-%m-%d %H:%M:%S} to {burst.end:%H:%M:%S}",
                    ],
                )
            )

        if failures and accepted:
            after = [a for a in accepted if a.timestamp >= failures[0].timestamp]
            if after and (is_bruteforce or len(failures) >= thresholds.ssh_failures):
                success = after[0]
                findings.append(
                    Finding(
                        rule_id="SSH-LOGIN-AFTER-BRUTE-FORCE",
                        title="Successful SSH login after repeated failures",
                        severity=Severity.CRITICAL,
                        category="compromise",
                        description=(
                            f"{ip} logged in as '{success.user}' via {success.method} after "
                            f"{len(failures)} failed attempts. Treat the account as compromised "
                            "until proven otherwise."
                        ),
                        ip=ip,
                        count=len(after),
                        first_seen=success.timestamp,
                        last_seen=after[-1].timestamp,
                        evidence=[success.raw or f"Accepted {success.method} for {success.user}"],
                    )
                )

        invalid_users = {
            e.user
            for e in ip_events
            if e.user
            and (
                e.event is AuthEventType.INVALID_USER
                or (e.event is AuthEventType.FAILED_PASSWORD and "invalid user" in e.raw)
            )
        }
        if len(invalid_users) >= thresholds.user_enum_distinct:
            findings.append(
                Finding(
                    rule_id="SSH-USER-ENUMERATION",
                    title="SSH username enumeration",
                    severity=Severity.MEDIUM,
                    category="reconnaissance",
                    description=(
                        f"{ip} tried {len(invalid_users)} usernames that do not exist on the host."
                    ),
                    ip=ip,
                    count=len(invalid_users),
                    first_seen=ip_events[0].timestamp,
                    last_seen=ip_events[-1].timestamp,
                    evidence=[f"Usernames: {', '.join(sorted(invalid_users)[:12])}"],
                )
            )

        root_logins = [a for a in accepted if a.user == "root"]
        if root_logins:
            findings.append(
                Finding(
                    rule_id="SSH-ROOT-LOGIN",
                    title="Direct root login over SSH",
                    severity=Severity.MEDIUM,
                    category="policy",
                    description=(
                        f"root logged in directly from {ip}. Consider PermitRootLogin no and "
                        "key-only authentication."
                    ),
                    ip=ip,
                    count=len(root_logins),
                    first_seen=root_logins[0].timestamp,
                    last_seen=root_logins[-1].timestamp,
                    evidence=[root_logins[0].raw] if root_logins[0].raw else [],
                )
            )

    for user, ips in sorted(failures_by_user.items()):
        if len(ips) >= thresholds.distributed_ips:
            findings.append(
                Finding(
                    rule_id="SSH-DISTRIBUTED-ATTACK",
                    title="Distributed attack on one account",
                    severity=Severity.MEDIUM,
                    category="brute-force",
                    description=(
                        f"Account '{user}' had failed logins from {len(ips)} different "
                        "IP addresses."
                    ),
                    ip=None,
                    count=len(ips),
                    evidence=[f"Source IPs: {', '.join(sorted(ips)[:10])}"],
                )
            )
    return findings


def _is_login_path(path: str) -> bool:
    clean = path.split("?", 1)[0].lower().rstrip("/") or "/"
    return any(clean == p or clean.endswith(p) for p in WEB_LOGIN_PATHS)


def detect_web_login_bruteforce(
    events: Iterable[AccessEvent], thresholds: Thresholds
) -> list[Finding]:
    """Detect bursts of POST requests to well-known login endpoints from one IP."""
    attempts: dict[str, list[AccessEvent]] = defaultdict(list)
    for event in events:
        if event.method.upper() == "POST" and _is_login_path(event.path):
            attempts[event.ip].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=thresholds.web_login_window_minutes)
    for ip, items in sorted(attempts.items()):
        burst = busiest_window([e.timestamp for e in items], window)
        if burst is None or burst.count < thresholds.web_login_attempts:
            continue
        items.sort(key=lambda e: e.timestamp)
        paths = Counter(e.path.split("?", 1)[0] for e in items)
        statuses = Counter(str(e.status) for e in items)
        findings.append(
            Finding(
                rule_id="WEB-LOGIN-BRUTE-FORCE",
                title="Web login brute-force attack",
                severity=Severity.HIGH,
                category="brute-force",
                description=(
                    f"{len(items)} login POSTs from {ip}, peaking at {burst.count} within "
                    f"{thresholds.web_login_window_minutes} minutes."
                ),
                ip=ip,
                count=len(items),
                first_seen=items[0].timestamp,
                last_seen=items[-1].timestamp,
                evidence=[f"Endpoints: {_top(paths)}", f"Status codes: {_top(statuses)}"],
            )
        )
    return findings
