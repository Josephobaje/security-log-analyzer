"""Signature-based detection of common web attacks in request lines."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import unquote_plus

from seclog.models import AccessEvent, Finding, Severity


@dataclass(frozen=True, slots=True)
class Signature:
    rule_id: str
    title: str
    category: str
    severity: Severity
    patterns: tuple[re.Pattern[str], ...]
    check_headers: bool = False
    """Also inspect the User-Agent and Referer headers, not only the URL."""


def _compile(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


WEB_SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "WEB-LOG4SHELL",
        "Log4Shell (JNDI injection) attempt",
        "rce",
        Severity.CRITICAL,
        _compile(r"\$\{\s*jndi\s*:", r"\$\{[^}]*\$\{(?:lower|upper|env|::-)"),
        check_headers=True,
    ),
    Signature(
        "WEB-SHELLSHOCK",
        "Shellshock (CVE-2014-6271) attempt",
        "rce",
        Severity.HIGH,
        _compile(r"\(\)\s*\{\s*:?\s*;?\s*\}\s*;"),
        check_headers=True,
    ),
    Signature(
        "WEB-SQLI",
        "SQL injection attempt",
        "injection",
        Severity.HIGH,
        _compile(
            r"\bunion\b(?:\s|/\*.*?\*/|\+)+(?:all\s+)?select\b",
            r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*(?:=|like)\s*['\"]?\w+",
            r"\b(?:or|and)\s+\d+\s*=\s*\d+",
            r"\b(?:sleep|benchmark|pg_sleep)\s*\(",
            r"\bwaitfor\s+delay\b",
            r"\binformation_schema\b",
            r"\b(?:extractvalue|updatexml|load_file)\s*\(",
            r"['\";)]\s*(?:drop|truncate|delete|insert|update)\s+(?:table|from|into|\w+\s+set)\b",
            r"\bselect\b.+\bfrom\b.+\bwhere\b",
            r"'\s*(?:--|#|/\*)",
        ),
    ),
    Signature(
        "WEB-XSS",
        "Cross-site scripting (XSS) attempt",
        "injection",
        Severity.HIGH,
        _compile(
            r"<\s*/?\s*script\b",
            r"\bjavascript\s*:",
            r"<[^>]*\bon(?:error|load|mouseover|focus|click|toggle|begin)\s*=",
            r"<\s*(?:svg|iframe|img|body|object|embed)\b[^>]*>",
            r"\bdocument\.(?:cookie|location|domain)\b",
            r"\b(?:alert|prompt|confirm)\s*\(\s*[\w'\"`]",
        ),
    ),
    Signature(
        "WEB-PATH-TRAVERSAL",
        "Path traversal / local file inclusion attempt",
        "traversal",
        Severity.HIGH,
        _compile(
            r"(?:\.\.[/\\]){1,}",
            r"/etc/(?:passwd|shadow|group|hosts)\b",
            r"\b(?:boot|win)\.ini\b",
            r"/proc/self/(?:environ|cmdline|fd)",
            r"\b(?:php|zip|phar|expect|data)://",
            r"\bfile:///",
        ),
    ),
    Signature(
        "WEB-COMMAND-INJECTION",
        "OS command injection attempt",
        "rce",
        Severity.HIGH,
        _compile(
            r"[;|&]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|powershell)\b",
            r"\$\(\s*(?:cat|id|whoami|uname|wget|curl|echo)\b",
            r"`\s*(?:cat|id|whoami|uname|wget|curl)\b[^`]*`",
            r"\b(?:cmd|exec|command|shell)=[^&]*(?:wget|curl|bash|/bin/)",
        ),
    ),
    Signature(
        "WEB-SENSITIVE-FILE",
        "Probe for sensitive files or admin tools",
        "reconnaissance",
        Severity.MEDIUM,
        _compile(
            r"/\.env(?:\.\w+)?(?:$|\?)",
            r"/\.git(?:/|$)",
            r"/\.(?:aws|ssh|svn|hg|DS_Store|htpasswd|htaccess)\b",
            r"/wp-config\.php(?:\.bak|\.old|\.save|~|\.txt)",
            r"/(?:phpmyadmin|pma|myadmin|adminer)(?:/|\.php|$)",
            r"\.(?:sql|bak|old|swp|backup)(?:$|\?)",
            r"/server-status\b",
            r"/(?:config|configuration|settings)\.(?:json|yml|yaml|ini)(?:$|\?)",
        ),
    ),
)


def _decode(value: str) -> str:
    """URL-decode up to three times to defeat simple double-encoding evasion."""
    for _ in range(3):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def classify_request(event: AccessEvent) -> list[Signature]:
    """Return every signature that matches ``event``."""
    url = _decode(event.path)
    headers = _decode(f"{event.user_agent}\n{event.referrer}")
    matches: list[Signature] = []
    for sig in WEB_SIGNATURES:
        targets = (url, headers) if sig.check_headers else (url,)
        if any(p.search(t) for t in targets for p in sig.patterns):
            matches.append(sig)
    return matches


def detect_web_attacks(events: Iterable[AccessEvent]) -> list[Finding]:
    """Group signature matches into one finding per (IP, rule)."""
    grouped: dict[tuple[str, str], list[AccessEvent]] = defaultdict(list)
    signatures = {sig.rule_id: sig for sig in WEB_SIGNATURES}
    for event in events:
        for sig in classify_request(event):
            grouped[(event.ip, sig.rule_id)].append(event)

    findings: list[Finding] = []
    for (ip, rule_id), hits in sorted(grouped.items()):
        sig = signatures[rule_id]
        hits.sort(key=lambda e: e.timestamp)
        successful = [h for h in hits if 200 <= h.status < 300]
        evidence = [f"{h.method} {h.path} -> {h.status}" for h in hits[:5]]
        if successful and sig.category != "reconnaissance":
            evidence.append(
                f"{len(successful)} matching request(s) returned 2xx: verify they were blocked"
            )
        findings.append(
            Finding(
                rule_id=rule_id,
                title=sig.title,
                severity=sig.severity,
                category=sig.category,
                description=(
                    f"{len(hits)} request(s) from {ip} matched {sig.title.lower()} patterns."
                ),
                ip=ip,
                count=len(hits),
                first_seen=hits[0].timestamp,
                last_seen=hits[-1].timestamp,
                evidence=evidence,
            )
        )
    return findings
