#!/usr/bin/env python3
"""
Docker engine — client init, container health helpers, action executors.
"""

from __future__ import annotations

import re
import logging
from typing import Any

from config import DRY_RUN, DOCKER_HOST_LABEL, LOG_TAIL_LINES

log = logging.getLogger("docker_engine")

try:
    import docker as docker_sdk
except ImportError:
    docker_sdk = None


# ══════════════════════════════════════════════════════════════════════════════
#  CLIENT INIT
# ══════════════════════════════════════════════════════════════════════════════

def init_docker() -> Any:
    if docker_sdk is None:
        log.error("ENABLE_DOCKER=true but 'docker' package not installed. Run: pip install docker")
        return None
    try:
        dc = docker_sdk.from_env()
        dc.ping()
        log.info("Connected to Docker daemon (host: %s)", DOCKER_HOST_LABEL)
        return dc
    except Exception as e:
        log.error("Could not connect to Docker daemon: %s", e)
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  CONTAINER HEALTH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def docker_restart_count(container: Any) -> int:
    return int(container.attrs.get("RestartCount", 0) or 0)


def docker_is_oom_killed(container: Any) -> bool:
    state = container.attrs.get("State", {}) or {}
    return bool(state.get("OOMKilled", False))


def docker_is_crashloop(container: Any) -> bool:
    state = container.attrs.get("State", {}) or {}
    status = state.get("Status", "")
    host_cfg = container.attrs.get("HostConfig", {}) or {}
    restart_policy = (host_cfg.get("RestartPolicy") or {}).get("Name", "")
    if status == "restarting":
        return True
    if status == "exited" and restart_policy in ("on-failure", "always", "unless-stopped"):
        if state.get("ExitCode", 0) != 0 and docker_restart_count(container) > 0:
            return True
    return False


def container_summary(container: Any) -> dict:
    attrs = container.attrs
    state = attrs.get("State", {}) or {}
    cfg = attrs.get("Config", {}) or {}
    host_cfg = attrs.get("HostConfig", {}) or {}
    return {
        "platform": "docker",
        "host": DOCKER_HOST_LABEL,
        "container_id": container.short_id,
        "name": container.name,
        "image": cfg.get("Image", "unknown"),
        "status": state.get("Status", "unknown"),
        "exit_code": state.get("ExitCode"),
        "oom_killed": state.get("OOMKilled", False),
        "restart_count": docker_restart_count(container),
        "restart_policy": (host_cfg.get("RestartPolicy") or {}).get("Name", ""),
        "memory_limit_bytes": host_cfg.get("Memory", 0),
        "created_at": attrs.get("Created", "unknown"),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  ACTION EXECUTORS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_memory_to_bytes(value: str) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([a-zA-Z]*)$", s)
    if not m:
        return 512 * 1024 * 1024
    num, unit = float(m.group(1)), m.group(2).lower()
    multipliers = {
        "": 1, "b": 1, "k": 1000, "kb": 1000, "ki": 1024,
        "m": 1000**2, "mb": 1000**2, "mi": 1024**2,
        "g": 1000**3, "gb": 1000**3, "gi": 1024**3,
    }
    return int(num * multipliers.get(unit, 1024**2))


def execute_action_docker(
    action: str, params: dict, docker_container: Any,
) -> str:
    dry = "[DRY RUN] " if DRY_RUN else ""

    if action == "restart_pod":
        if not DRY_RUN:
            docker_container.restart(timeout=10)
        log.info("%sRestarted container %s", dry, docker_container.name)
        return f"Container {docker_container.name} restarted."

    elif action == "increase_memory_limit":
        new_memory_raw = params.get("memory_limit", "512Mi")
        new_memory_bytes = _parse_memory_to_bytes(new_memory_raw)
        if not DRY_RUN:
            docker_container.update(mem_limit=new_memory_bytes)
        log.info("%sIncreased memory on %s to %s", dry, docker_container.name, new_memory_raw)
        return f"Memory limit for {docker_container.name} increased to {new_memory_raw}."

    elif action == "describe_diagnosis":
        log.info("Diagnosis surfaced: %s", params.get("summary", ""))
        return "Diagnosis surfaced to operator. Manual intervention required."

    elif action in ("scale_deployment", "bounce_deployment"):
        log.warning("Action '%s' unsupported for standalone Docker", action)
        return f"Action '{action}' unsupported outside orchestrator. Manual review needed."

    return f"Unknown action: {action}"
