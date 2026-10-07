"""Core data structures shared by parsers, detectors and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import total_ordering


@total_ordering
class Severity(Enum):
    """Finding severity, ordered from least to most serious."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError as exc:
            choices = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from: {choices})") from exc


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AuthEventType(Enum):
    """Kinds of sshd events the auth parser understands."""

    FAILED_PASSWORD = "failed_password"  # noqa: S105 - event name, not a secret
    INVALID_USER = "invalid_user"
    ACCEPTED = "accepted"
    MAX_ATTEMPTS = "max_attempts"
    NO_IDENTIFICATION = "no_identification"
    DISCONNECT_PREAUTH = "disconnect_preauth"


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """One security-relevant sshd line from ``/var/log/auth.log`` or ``/var/log/secure``."""

    timestamp: datetime
    host: str
    event: AuthEventType
    ip: str
    user: str | None = None
    port: int | None = None
    method: str | None = None
    source: str = ""
    line_no: int = 0
    raw: str = ""

    @property
    def is_failure(self) -> bool:
        return self.event in {
            AuthEventType.FAILED_PASSWORD,
            AuthEventType.INVALID_USER,
            AuthEventType.MAX_ATTEMPTS,
        }


@dataclass(frozen=True, slots=True)
class AccessEvent:
    """One request from an Apache or Nginx access log (Common or Combined format)."""

    timestamp: datetime
    ip: str
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referrer: str = ""
    user_agent: str = ""
    source: str = ""
    line_no: int = 0
    raw: str = ""


@dataclass(slots=True)
class Finding:
    """A detected security issue, usually tied to a single source IP."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    ip: str | None = None
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "evidence": list(self.evidence),
        }


@dataclass(slots=True)
class ParseStats:
    """Bookkeeping about what was read from each input."""

    files: list[str] = field(default_factory=list)
    total_lines: int = 0
    auth_events: int = 0
    access_events: int = 0
    skipped_lines: int = 0
