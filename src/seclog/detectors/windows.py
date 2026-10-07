"""Sliding-window helpers for rate-based detection."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class Burst:
    """The busiest window found in a series of timestamps."""

    count: int
    start: datetime
    end: datetime


def busiest_window(timestamps: Sequence[datetime], window: timedelta) -> Burst | None:
    """Return the window of length ``window`` containing the most events.

    ``timestamps`` does not need to be sorted. Runs in O(n log n).
    """
    if not timestamps:
        return None
    ordered = sorted(timestamps)
    best = Burst(1, ordered[0], ordered[0])
    left = 0
    for right, current in enumerate(ordered):
        while current - ordered[left] > window:
            left += 1
        size = right - left + 1
        if size > best.count:
            best = Burst(size, ordered[left], current)
    return best
