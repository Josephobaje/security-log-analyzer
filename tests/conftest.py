from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from seclog.models import AccessEvent, AuthEvent, AuthEventType

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
WAT = timezone(timedelta(hours=1))
BASE = datetime(2026, 10, 6, 12, 0, 0, tzinfo=WAT)


@pytest.fixture
def samples() -> Path:
    return SAMPLES


def auth_event(
    event: AuthEventType,
    ip: str,
    *,
    user: str | None = "root",
    seconds: int = 0,
    method: str | None = "password",
    raw: str = "",
) -> AuthEvent:
    return AuthEvent(
        timestamp=BASE + timedelta(seconds=seconds),
        host="web01",
        event=event,
        ip=ip,
        user=user,
        port=22,
        method=method,
        raw=raw,
    )


def access_event(
    path: str,
    *,
    ip: str = "203.0.113.5",
    status: int = 200,
    method: str = "GET",
    seconds: int = 0,
    user_agent: str = "Mozilla/5.0",
    referrer: str = "",
) -> AccessEvent:
    return AccessEvent(
        timestamp=BASE + timedelta(seconds=seconds),
        ip=ip,
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        size=100,
        user_agent=user_agent,
        referrer=referrer,
    )
