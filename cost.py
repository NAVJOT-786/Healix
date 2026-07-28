#!/usr/bin/env python3
"""
Cost estimation for healing reports.
Calculates estimated compute cost impact of restarts, memory changes, and downtime.
"""

from __future__ import annotations

import logging
from config import COST_PER_GB_HOUR, COST_PER_CPU_HOUR

log = logging.getLogger("cost")


def estimate_restart_cost(
    restart_count: int,
    memory_limit_str: str = "256Mi",
    cpu_limit_str: str = "0.5",
) -> str:
    """Estimate wasted compute from repeated restarts."""
    memory_bytes = _parse_memory_to_bytes(memory_limit_str)
    memory_gb = memory_bytes / (1024 ** 3)
    try:
        cpu_cores = float(cpu_limit_str.replace("m", "")) / 1000 if "m" in cpu_limit_str else float(cpu_limit_str)
    except (ValueError, TypeError):
        cpu_cores = 0.5

    # Each restart wastes ~10s of allocated resources
    wasted_seconds = restart_count * 10
    wasted_hours = wasted_seconds / 3600

    memory_cost = memory_gb * wasted_hours * COST_PER_GB_HOUR
    cpu_cost = cpu_cores * wasted_hours * COST_PER_CPU_HOUR
    total = memory_cost + cpu_cost

    if total < 0.001:
        return f"~$0 (negligible — {restart_count} restarts × ~10s each)"
    return f"~${total:.4f} ({restart_count} restarts × ~10s of {memory_limit_str} + {cpu_limit_str} CPU)"


def estimate_memory_increase_cost(
    old_limit_str: str,
    new_limit_str: str,
    hours_running: float = 24.0,
) -> str:
    """Estimate additional hourly cost from increasing memory limit."""
    old_bytes = _parse_memory_to_bytes(old_limit_str)
    new_bytes = _parse_memory_to_bytes(new_limit_str)
    delta_gb = (new_bytes - old_bytes) / (1024 ** 3)

    if delta_gb <= 0:
        return "No additional cost (limit decreased or unchanged)"

    hourly_cost = delta_gb * COST_PER_GB_HOUR
    daily_cost = hourly_cost * 24

    return (
        f"+${hourly_cost:.6f}/hour (+${daily_cost:.4f}/day) "
        f"for {old_limit_str} -> {new_limit_str} "
        f"({delta_gb:.3f} GB additional)"
    )


def estimate_bounce_downtime(
    replicas: int,
    avg_restart_seconds: float = 15.0,
) -> str:
    """Estimate impact of bouncing a deployment."""
    total_downtime = replicas * avg_restart_seconds
    return (
        f"~{total_downtime:.0f}s total pod downtime across {replicas} replica(s) "
        f"(~{avg_restart_seconds:.0f}s per pod restart)"
    )


def format_cost_summary(
    action: str,
    params: dict,
    restart_count: int = 0,
    original_state: dict | None = None,
) -> str:
    """Generate a cost summary string for email reports."""
    parts: list[str] = []

    if restart_count > 0:
        mem = params.get("memory_limit", "256Mi")
        cpu = params.get("cpu_limit", "0.5")
        parts.append(f"Restart waste: {estimate_restart_cost(restart_count, mem, cpu)}")

    if action == "increase_memory_limit":
        new_mem = params.get("memory_limit", "512Mi")
        old_mem = (original_state or {}).get("original_memory_limit", "256Mi")
        parts.append(f"Memory cost change: {estimate_memory_increase_cost(old_mem, new_mem)}")

    elif action == "bounce_deployment":
        replicas = int(params.get("replicas", 1))
        parts.append(f"Downtime impact: {estimate_bounce_downtime(replicas)}")

    return "\n".join(parts) if parts else "Cost data not available"


def _parse_memory_to_bytes(value: str) -> int:
    import re
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([a-zA-Z]*)$", s)
    if not m:
        return 256 * 1024 * 1024
    num, unit = float(m.group(1)), m.group(2).lower()
    multipliers = {
        "": 1, "b": 1, "k": 1000, "kb": 1000, "ki": 1024,
        "m": 1000**2, "mb": 1000**2, "mi": 1024**2,
        "g": 1000**3, "gb": 1000**3, "gi": 1024**3,
    }
    return int(num * multipliers.get(unit, 1024**2))
