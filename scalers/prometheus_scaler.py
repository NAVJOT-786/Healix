"""Prometheus scaler — reads any instant PromQL query and returns its value.

Reuses the existing prometheus.PrometheusClient (requests-only, no new deps).
When several series come back their values are summed, so total-based queries
like `sum(rate(...))` or `sum(demo_pending_work)` map directly onto
desired = ceil(total / target_per_pod).
"""

from __future__ import annotations

import logging

from prometheus import PrometheusClient
from scalers.base import Scaler

log = logging.getLogger("scaler.prometheus")


class PrometheusScaler(Scaler):
    type_name = "prometheus"

    def __init__(self, client: PrometheusClient | None = None) -> None:
        self._client = client or PrometheusClient()

    @property
    def available(self) -> bool:
        return self._client.is_available()

    def get_metric(self, trigger: dict) -> float | None:
        query = (trigger.get("query") or "").strip()
        if not query:
            log.warning("Prometheus trigger missing 'query'")
            return None
        # Server unreachable -> None (engine keeps current replicas).
        if not self._client.is_available():
            return None
        try:
            rows = self._client.query(query)
        except Exception as e:
            log.warning("Prometheus query failed: %s", e)
            return None
        if rows is None:
            return None
        if not rows:
            # Query succeeded but matched no series -> metric is genuinely 0.
            return 0.0
        total = 0.0
        for row in rows:
            try:
                total += float(row["value"][1])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
        return total
