from __future__ import annotations

import pytest

from seclog.models import AuthEventType, Finding, Severity
from tests.conftest import BASE, auth_event


def test_severity_ordering() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert max([Severity.LOW, Severity.HIGH, Severity.MEDIUM]) is Severity.HIGH
    assert sorted([Severity.HIGH, Severity.INFO]) == [Severity.INFO, Severity.HIGH]


@pytest.mark.parametrize("text", ["high", "HIGH", " High "])
def test_severity_parse(text: str) -> None:
    assert Severity.parse(text) is Severity.HIGH


def test_severity_parse_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("severe")


def test_auth_event_failure_flag() -> None:
    assert auth_event(AuthEventType.FAILED_PASSWORD, "192.0.2.1").is_failure
    assert auth_event(AuthEventType.INVALID_USER, "192.0.2.1").is_failure
    assert not auth_event(AuthEventType.ACCEPTED, "192.0.2.1").is_failure


def test_finding_to_dict_serialises_dates() -> None:
    f = Finding("R", "Title", Severity.LOW, "cat", "desc", ip="1.2.3.4", first_seen=BASE)
    data = f.to_dict()
    assert data["severity"] == "low"
    assert data["first_seen"] == "2026-10-06T12:00:00+01:00"
    assert data["last_seen"] is None
