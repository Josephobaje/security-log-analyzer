"""Tunable detection thresholds."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Thresholds used by the rate-based detectors.

    The defaults are deliberately conservative for a small or medium server and can
    be overridden from the command line.
    """

    ssh_failures: int = 5
    ssh_window_minutes: int = 10
    user_enum_distinct: int = 5
    distributed_ips: int = 5
    scan_404s: int = 15
    scan_window_minutes: int = 5
    web_login_attempts: int = 10
    web_login_window_minutes: int = 5

    def __post_init__(self) -> None:
        for name in self.__slots__:
            if getattr(self, name) < 1:
                raise ValueError(f"threshold {name} must be at least 1")
