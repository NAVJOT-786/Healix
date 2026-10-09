"""Healix Scaler — event sources (KEDA-style trigger plugins).

Each Scaler turns an external number into a float the engine can scale on:
    get_metric(trigger) -> float | None
    None means "source unavailable" — the engine fails static (never scales
    on a broken query).
"""

from __future__ import annotations


class Scaler:
    """Base class for all metric sources."""

    type_name = ""

    def get_metric(self, trigger: dict) -> float | None:
        raise NotImplementedError
