"""Run all detectors and assemble a report."""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

from seclog import __version__
from seclog.detectors import (
    Thresholds,
    detect_404_bursts,
    detect_scanner_agents,
    detect_ssh_attacks,
    detect_web_attacks,
    detect_web_login_bruteforce,
)
from seclog.models import AccessEvent, AuthEvent, AuthEventType, Finding, ParseStats, Severity


@dataclass(slots=True)
class SuspiciousIP:
    """Aggregated threat picture for one source address."""

    ip: str
    score: int
    severity: Severity
    findings: int
    categories: list[str]
    rules: list[str]
    auth_failures: int = 0
    requests: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    network: str = "public"

    def to_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "score": self.score,
            "severity": self.severity.value,
            "findings": self.findings,
            "categories": self.categories,
            "rules": self.rules,
            "auth_failures": self.auth_failures,
            "requests": self.requests,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "network": self.network,
        }


@dataclass(slots=True)
class Report:
    """Everything the exporters need."""

    generated_at: datetime
    stats: ParseStats
    findings: list[Finding]
    suspicious_ips: list[SuspiciousIP]
    auth_summary: dict[str, object] = field(default_factory=dict)
    web_summary: dict[str, object] = field(default_factory=dict)
    version: str = __version__

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = Counter(f.severity for f in self.findings)
        return {s.value: counts.get(s, 0) for s in sorted(Severity, reverse=True)}

    @property
    def highest_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict[str, object]:
        return {
            "tool": "security-log-analyzer",
            "version": self.version,
            "generated_at": self.generated_at.isoformat(),
            "input": {
                "files": self.stats.files,
                "total_lines": self.stats.total_lines,
                "auth_events": self.stats.auth_events,
                "access_events": self.stats.access_events,
                "ignored_lines": self.stats.skipped_lines,
            },
            "summary": {
                "findings": len(self.findings),
                "by_severity": self.severity_counts,
                "suspicious_ips": len(self.suspicious_ips),
            },
            "auth": self.auth_summary,
            "web": self.web_summary,
            "findings": [f.to_dict() for f in self.findings],
            "suspicious_ips": [ip.to_dict() for ip in self.suspicious_ips],
        }


_DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def network_label(ip: str) -> str:
    """Classify an address as public, private, loopback, documentation, reserved or invalid."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    # RFC 5737 / RFC 3849 documentation ranges, used by the bundled sample logs.
    if any(addr.version == net.version and addr in net for net in _DOCUMENTATION_NETS):
        return "documentation"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_multicast:
        return "reserved"
    return "public"


_BASE_SCORE = {
    Severity.CRITICAL: 80,
    Severity.HIGH: 55,
    Severity.MEDIUM: 30,
    Severity.LOW: 10,
    Severity.INFO: 0,
}


def _score_to_severity(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 55:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    return Severity.LOW


def threat_score(findings: Sequence[Finding]) -> int:
    """Score 0-100: the worst finding sets the base, breadth and volume add to it.

    * base: 80 critical, 55 high, 30 medium, 10 low
    * +5 for every additional finding (max +15)
    * +1 per 10 matching events (max +15)
    """
    if not findings:
        return 0
    worst = max(f.severity for f in findings)
    breadth = min(15, 5 * (len(findings) - 1))
    volume = min(15, sum(f.count for f in findings) // 10)
    return min(100, _BASE_SCORE[worst] + breadth + volume)


def rank_ips(
    findings: Sequence[Finding],
    auth: Sequence[AuthEvent],
    access: Sequence[AccessEvent],
) -> list[SuspiciousIP]:
    """Score every IP that has at least one finding (0-100, higher is worse)."""
    per_ip: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.ip:
            per_ip[f.ip].append(f)

    failures = Counter(e.ip for e in auth if e.is_failure)
    requests = Counter(e.ip for e in access)
    seen: dict[str, list[datetime]] = defaultdict(list)
    for f in findings:
        if f.ip:
            seen[f.ip].extend(t for t in (f.first_seen, f.last_seen) if t is not None)

    ranked: list[SuspiciousIP] = []
    for ip, items in per_ip.items():
        score = threat_score(items)
        times = sorted(seen[ip])
        ranked.append(
            SuspiciousIP(
                ip=ip,
                score=score,
                severity=_score_to_severity(score),
                findings=len(items),
                categories=sorted({f.category for f in items}),
                rules=sorted({f.rule_id for f in items}),
                auth_failures=failures.get(ip, 0),
                requests=requests.get(ip, 0),
                first_seen=times[0] if times else None,
                last_seen=times[-1] if times else None,
                network=network_label(ip),
            )
        )
    ranked.sort(key=lambda s: (-s.score, -s.findings, s.ip))
    return ranked


def _auth_summary(events: Sequence[AuthEvent]) -> dict[str, object]:
    failures = [e for e in events if e.is_failure]
    accepted = [e for e in events if e.event is AuthEventType.ACCEPTED]
    return {
        "failed_logins": len(failures),
        "successful_logins": len(accepted),
        "unique_failing_ips": len({e.ip for e in failures}),
        "top_targeted_users": Counter(e.user for e in failures if e.user).most_common(10),
        "top_failing_ips": Counter(e.ip for e in failures).most_common(10),
        "successful_logins_by_user": Counter(e.user for e in accepted if e.user).most_common(10),
    }


def _web_summary(events: Sequence[AccessEvent]) -> dict[str, object]:
    status = Counter(e.status for e in events)
    return {
        "requests": len(events),
        "unique_ips": len({e.ip for e in events}),
        "status_codes": {str(k): v for k, v in sorted(status.items())},
        "top_ips": Counter(e.ip for e in events).most_common(10),
        "top_404_paths": Counter(e.path for e in events if e.status == 404).most_common(10),
        "methods": dict(Counter(e.method for e in events).most_common()),
    }


def analyze(
    auth: Sequence[AuthEvent],
    access: Sequence[AccessEvent],
    *,
    stats: ParseStats | None = None,
    thresholds: Thresholds | None = None,
    min_severity: Severity = Severity.INFO,
    now: datetime | None = None,
) -> Report:
    """Run every detector over the parsed events and build a :class:`Report`."""
    limits = thresholds or Thresholds()
    findings: list[Finding] = []
    findings += detect_ssh_attacks(auth, limits)
    findings += detect_web_login_bruteforce(access, limits)
    findings += detect_web_attacks(access)
    findings += detect_404_bursts(access, limits)
    findings += detect_scanner_agents(access)

    findings = [f for f in findings if f.severity >= min_severity]
    findings.sort(key=lambda f: (-f.severity.rank, -f.count, f.ip or "", f.rule_id))

    return Report(
        generated_at=now or datetime.now(timezone.utc).astimezone(),
        stats=stats or ParseStats(auth_events=len(auth), access_events=len(access)),
        findings=findings,
        suspicious_ips=rank_ips(findings, auth, access),
        auth_summary=_auth_summary(auth),
        web_summary=_web_summary(access),
    )
