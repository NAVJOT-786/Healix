"""Scaler registry — add a new source by writing one module and one line here."""

from __future__ import annotations

from scalers.base import Scaler
from scalers.prometheus_scaler import PrometheusScaler

# type name -> class
REGISTRY: dict[str, type[Scaler]] = {
    "prometheus": PrometheusScaler,
}
REGISTRY: dict[str]

def build_scalers() -> dict[str, Scaler]:
    """One shared instance per source type (clients are cheap, reuse them)."""
    return {name: cls() for name, cls in REGISTRY.items()}


def known_types() -> list[str]:
    return sorted(REGISTRY.keys())
