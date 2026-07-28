#!/usr/bin/env python3
"""
Prometheus Metrics Fetcher for AI Healing Agent
------------------------------------------------
Fetches CPU, memory, and resource limit metrics from Prometheus
to provide richer context for LLM diagnosis.

Metrics fetched:
  - container_memory_usage_bytes        (current memory usage)
  - container_spec_memory_limit_bytes   (configured memory limit)
  - container_cpu_usage_seconds_total   (CPU usage, rate over 5m)
  - container_spec_cpu_quota/period     (CPU limit, if set)

Gracefully returns empty dict + warning if Prometheus is unreachable
or not configured (PROMETHEUS_URL not set).

Usage:
    from prometheus import PrometheusClient, fetch_pod_metrics

    client = PrometheusClient()
    metrics = fetch_pod_metrics(client, namespace="demo", pod="my-app-xyz")
    print(metrics["memory_human"], metrics["cpu_human"])
"""

import os
import requests
from rich.console import Console

console = Console()

# ── Config ────────────────────────────────────────────────────────────────────

PROMETHEUS_URL         = os.getenv("PROMETHEUS_URL", "").rstrip("/")
PROMETHEUS_TIMEOUT_SEC = int(os.getenv("PROMETHEUS_TIMEOUT_SEC", "5"))

RATE_WINDOW = "5m"


class PrometheusClient:
    """Thin wrapper around Prometheus HTTP API."""

    def __init__(self, url: str = None, timeout: int = None):
        self.url = (url or PROMETHEUS_URL).rstrip("/")
        self.timeout = timeout or PROMETHEUS_TIMEOUT_SEC
        self.enabled = bool(self.url)

    def is_available(self) -> bool:
        if not self.enabled:
            return False
        try:
            resp = requests.get(f"{self.url}/api/v1/status/config", timeout=self.timeout)
            return resp.status_code == 200
        except Exception:
            return False

    def query(self, promql: str) -> list:
        """Execute an instant PromQL query. Returns [] on any failure."""
        if not self.enabled:
            return []
        try:
            resp = requests.get(
                f"{self.url}/api/v1/query",
                params={"query": promql},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            if data.get("status") != "success":
                return []
            return data.get("data", {}).get("result", [])
        except Exception:
            return []


def _bytes_to_human(b: float) -> str:
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(b) < 1024.0:
            return f"{b:.1f}{unit}"
        b /= 1024.0
    return f"{b:.1f}PiB"


def _cores_to_human(c: float) -> str:
    if c < 0.01:
        return f"{c * 1000:.1f}m"
    return f"{c:.2f}"


def fetch_pod_metrics(client: PrometheusClient, namespace: str, pod: str,
                      container: str = None) -> dict:
    """
    Fetch resource metrics for a pod from Prometheus.

    Returns dict with memory_bytes, memory_limit, memory_percent,
    memory_human, cpu_cores, cpu_limit, cpu_percent, cpu_human.
    Returns empty dict if Prometheus not configured or query fails.
    """
    if not client.enabled:
        return {}

    metrics = {
        "memory_bytes": None, "memory_limit": None, "memory_percent": None,
        "memory_human": "unknown",
        "cpu_cores": None, "cpu_limit": None, "cpu_percent": None,
        "cpu_human": "unknown",
    }

    cf = f'namespace="{namespace}", pod="{pod}"'
    if container:
        cf += f', container="{container}"'

    # Memory usage
    for r in client.query(f'container_memory_usage_bytes{{{cf}}}'):
        v = float(r["value"][1])
        metrics["memory_bytes"] = v
        metrics["memory_human"] = _bytes_to_human(v)
        break

    # Memory limit
    for r in client.query(f'container_spec_memory_limit_bytes{{{cf}}}'):
        limit = float(r["value"][1])
        if limit > 0:
            metrics["memory_limit"] = limit
            if metrics["memory_bytes"] is not None:
                metrics["memory_percent"] = round((metrics["memory_bytes"] / limit) * 100, 1)
        break

    # CPU usage (rate over 5min)
    for r in client.query(f'rate(container_cpu_usage_seconds_total{{{cf}}}[{RATE_WINDOW}])'):
        v = float(r["value"][1])
        metrics["cpu_cores"] = v
        metrics["cpu_human"] = _cores_to_human(v)
        break

    # CPU limit (quota / period)
    quota_r = client.query(f'container_spec_cpu_quota{{{cf}}}')
    period_r = client.query(f'container_spec_cpu_period{{{cf}}}')
    if quota_r and period_r:
        quota = float(quota_r[0]["value"][1])
        period = float(period_r[0]["value"][1])
        if quota > 0 and period > 0:
            limit_cores = quota / period
            metrics["cpu_limit"] = limit_cores
            if metrics["cpu_cores"] is not None:
                metrics["cpu_percent"] = round((metrics["cpu_cores"] / limit_cores) * 100, 1)

    return metrics


def format_metrics_for_prompt(metrics: dict) -> str:
    """Format metrics dict into a string for LLM prompt injection."""
    if not metrics:
        return "(no Prometheus metrics available — PROMETHEUS_URL not configured or unreachable)"

    lines = []

    if metrics["memory_bytes"] is not None:
        line = f"Memory usage: {metrics['memory_human']}"
        if metrics["memory_limit"] is not None:
            line += f" / {_bytes_to_human(metrics['memory_limit'])} ({metrics['memory_percent']}% used)"
        else:
            line += " (no memory limit set)"
        lines.append(line)
    else:
        lines.append("Memory usage: unavailable")

    if metrics["cpu_cores"] is not None:
        line = f"CPU usage: {metrics['cpu_human']}"
        if metrics["cpu_limit"] is not None:
            line += f" / {_cores_to_human(metrics['cpu_limit'])} cores ({metrics['cpu_percent']}% used)"
        else:
            line += " (no CPU limit set)"
        lines.append(line)
    else:
        lines.append("CPU usage: unavailable")

    return "\n".join(lines)
