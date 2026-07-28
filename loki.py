#!/usr/bin/env python3
"""
Loki log fetcher with Docker label auto-detection.
"""

from __future__ import annotations

import time
import logging
import requests
from typing import TYPE_CHECKING

from config import (
    LOKI_URL, LOKI_LOOKBACK_MINUTES, LOKI_QUERY_LIMIT, LOKI_TIMEOUT_SEC,
    LOKI_K8S_LABEL_TEMPLATE, LOKI_DOCKER_LABEL_TEMPLATE,
    DOCKER_LOKI_PROBE_TEMPLATES, LOKI_PROBE_TIMEOUT_SEC,
)

if TYPE_CHECKING:
    from kubernetes import client

log = logging.getLogger("loki")

_docker_loki_template_cache: str | None = None


def fetch_logs_from_loki(
    label_selector: str, timeout: int | None = None,
) -> str:
    if not LOKI_URL:
        return ""
    try:
        end_ns = int(time.time() * 1e9)
        start_ns = end_ns - (LOKI_LOOKBACK_MINUTES * 60 * int(1e9))
        resp = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={
                "query": label_selector,
                "limit": LOKI_QUERY_LIMIT,
                "start": start_ns,
                "end": end_ns,
                "direction": "backward",
            },
            timeout=timeout or LOKI_TIMEOUT_SEC,
        )
        if resp.status_code != 200:
            log.warning("Loki HTTP %d: %s", resp.status_code, resp.text[:150])
            return ""
        streams = resp.json().get("data", {}).get("result", [])
        lines: list[str] = []
        for stream in streams:
            for _ts, line in stream.get("values", []):
                lines.append(line)
        if not lines:
            return ""
        lines.reverse()
        return "\n".join(lines[-LOKI_QUERY_LIMIT:])
    except requests.exceptions.ConnectionError:
        log.warning("Could not reach Loki at %s", LOKI_URL)
        return ""
    except requests.exceptions.Timeout:
        log.warning("Loki timed out after %ds", timeout or LOKI_TIMEOUT_SEC)
        return ""
    except Exception as e:
        log.warning("Loki query failed: %s", e)
        return ""


# ── Docker label auto-detection ───────────────────────────────────────────────

def _probe_docker_loki_templates(host: str, container_name: str) -> str:
    log.info("Probing Loki for Docker labels (host=%s, container=%s)", host, container_name)
    for tmpl in DOCKER_LOKI_PROBE_TEMPLATES:
        selector = tmpl.replace("$host", host).replace("$container", container_name)
        logs = fetch_logs_from_loki(selector, timeout=LOKI_PROBE_TIMEOUT_SEC)
        if logs:
            log.info("Docker Loki label detected: %s", tmpl)
            return tmpl
        log.debug("No logs for: %s", selector)
    log.warning("All Docker Loki probes failed — using native logs")
    return "none"


def _get_docker_loki_template(host: str, container_name: str) -> str:
    global _docker_loki_template_cache
    if LOKI_DOCKER_LABEL_TEMPLATE:
        return LOKI_DOCKER_LABEL_TEMPLATE
    if _docker_loki_template_cache is not None:
        return _docker_loki_template_cache
    _docker_loki_template_cache = _probe_docker_loki_templates(host, container_name)
    return _docker_loki_template_cache


# ── Unified log fetcher ──────────────────────────────────────────────────────

def fetch_pod_logs_k8s_native(
    v1: "client.CoreV1Api", pod: object, tail: int = 50,
) -> str:
    logs: list[str] = []
    for c in (pod.spec.containers or []):
        for previous in (False, True):
            try:
                log_text = v1.read_namespaced_pod_log(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    container=c.name,
                    tail_lines=tail,
                    previous=previous,
                )
                label = f"[{c.name}{'  previous' if previous else ''}]"
                logs.append(f"{label}\n{log_text.strip()}")
            except Exception:
                pass
    return "\n\n".join(logs) if logs else ""


def fetch_container_logs_docker_native(container: object, tail: int = 50) -> str:
    try:
        raw = container.logs(tail=tail, timestamps=True).decode("utf-8", errors="replace")
        return raw.strip()
    except Exception:
        return ""


def fetch_logs_unified(
    target: dict,
    v1: "client.CoreV1Api | None" = None,
    docker_container: object | None = None,
) -> str:
    platform = target["platform"]

    if platform == "k8s":
        selector = (
            LOKI_K8S_LABEL_TEMPLATE
            .replace("$namespace", target["namespace"])
            .replace("$pod", target["name"])
        )
    else:
        template = _get_docker_loki_template(target["host"], target["name"])
        if template == "none":
            selector = ""
        else:
            selector = template.replace("$host", target["host"]).replace("$container", target["name"])

    logs = ""
    if selector:
        logs = fetch_logs_from_loki(selector)
    if logs:
        log.info("Logs sourced from Loki (%s)", selector)
        return logs

    if selector:
        log.info("Loki returned nothing for %s — falling back to native logs", selector)
    else:
        log.info("Loki Docker labels not available — using native logs")

    if platform == "k8s" and v1 is not None:
        logs = fetch_pod_logs_k8s_native(v1, target["_raw_pod"])
    elif platform == "docker" and docker_container is not None:
        logs = fetch_container_logs_docker_native(docker_container)

    return logs if logs else "(no logs available from Loki or native source)"
