"""Detection of automated scanners: 404 bursts and known tool user agents."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import timedelta

from seclog.detectors.config import Thresholds
from seclog.detectors.windows import busiest_window
from seclog.models import AccessEvent, Finding, Severity

SCANNER_AGENTS: dict[str, str] = {
    "sqlmap": "sqlmap",
    "nikto": "Nikto",
    "nmap": "Nmap NSE",
    "masscan": "masscan",
    "zgrab": "ZGrab",
    "gobuster": "Gobuster",
    "dirbuster": "DirBuster",
    "dirb": "DIRB",
    "wpscan": "WPScan",
    "nuclei": "Nuclei",
    "acunetix": "Acunetix",
    "nessus": "Nessus",
    "openvas": "OpenVAS",
    "wfuzz": "Wfuzz",
    "fuzz faster u fool": "ffuf",
    "ffuf": "ffuf",
    "hydra": "THC Hydra",
    "whatweb": "WhatWeb",
    "jorgee": "Jorgee",
    "zmeu": "ZmEu",
}
_AGENT_PATTERN = re.compile(
    "|".join(rf"\b{re.escape(k)}\b" for k in sorted(SCANNER_AGENTS, key=len, reverse=True)),
    re.IGNORECASE,
)


def scanner_name(user_agent: str) -> str | None:
    """Return the scanner tool name if ``user_agent`` belongs to a known security tool."""
    m = _AGENT_PATTERN.search(user_agent)
    return SCANNER_AGENTS[m.group(0).lower()] if m else None


def detect_404_bursts(events: Iterable[AccessEvent], thresholds: Thresholds) -> list[Finding]:
    """Flag IPs that produce many 404 responses in a short time (content discovery)."""
    not_found: dict[str, list[AccessEvent]] = defaultdict(list)
    for event in events:
        if event.status == 404:
            not_found[event.ip].append(event)

    findings: list[Finding] = []
    window = timedelta(minutes=thresholds.scan_window_minutes)
    for ip, items in sorted(not_found.items()):
        burst = busiest_window([e.timestamp for e in items], window)
        if burst is None or burst.count < thresholds.scan_404s:
            continue
        items.sort(key=lambda e: e.timestamp)
        severity = Severity.HIGH if burst.count >= thresholds.scan_404s * 3 else Severity.MEDIUM
        sample = [e.path for e in items[:6]]
        findings.append(
            Finding(
                rule_id="WEB-404-SCAN",
                title="404 scanning burst",
                severity=severity,
                category="reconnaissance",
                description=(
                    f"{len(items)} requests from {ip} returned 404, with {burst.count} within "
                    f"{thresholds.scan_window_minutes} minutes: typical of directory brute-forcing."
                ),
                ip=ip,
                count=len(items),
                first_seen=items[0].timestamp,
                last_seen=items[-1].timestamp,
                evidence=[f"Sample paths: {', '.join(sample)}"],
            )
        )
    return findings


def detect_scanner_agents(events: Iterable[AccessEvent]) -> list[Finding]:
    """Flag requests whose User-Agent identifies a known vulnerability scanner."""
    hits: dict[str, list[AccessEvent]] = defaultdict(list)
    tools: dict[str, Counter[str]] = defaultdict(Counter)
    for event in events:
        name = scanner_name(event.user_agent)
        if name:
            hits[event.ip].append(event)
            tools[event.ip][name] += 1

    findings: list[Finding] = []
    for ip, items in sorted(hits.items()):
        items.sort(key=lambda e: e.timestamp)
        names = ", ".join(n for n, _ in tools[ip].most_common())
        findings.append(
            Finding(
                rule_id="WEB-SCANNER-UA",
                title="Known vulnerability scanner",
                severity=Severity.MEDIUM,
                category="reconnaissance",
                description=f"{len(items)} request(s) from {ip} identified as {names}.",
                ip=ip,
                count=len(items),
                first_seen=items[0].timestamp,
                last_seen=items[-1].timestamp,
                evidence=[f"User-Agent: {items[0].user_agent[:120]}"],
            )
        )
    return findings
