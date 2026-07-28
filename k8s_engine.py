#!/usr/bin/env python3
"""
Kubernetes engine — client init, pod health helpers, deployment helpers,
action executors (with multi-container support), and event-driven watcher.
"""

from __future__ import annotations

import re
import time
import logging
import threading
from typing import Any

from kubernetes import client, config, watch

from config import (
    DRY_RUN, MAX_RESTARTS, LOG_TAIL_LINES, WATCH_ALL_NAMESPACES,
    WATCH_NAMESPACES, WATCH_EVENTS_ENABLED, WATCH_EVENTS_DEBOUNCE_SEC,
)

log = logging.getLogger("k8s_engine")


# ══════════════════════════════════════════════════════════════════════════════
#  CLIENT INIT
# ══════════════════════════════════════════════════════════════════════════════

def init_k8s() -> tuple[client.CoreV1Api | None, client.AppsV1Api | None]:
    try:
        config.load_incluster_config()
        log.info("Using in-cluster kubeconfig")
    except config.ConfigException:
        try:
            config.load_kube_config()
            log.info("Using local kubeconfig")
        except Exception as e:
            log.error("Could not load kubeconfig: %s", e)
            return None, None

    v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()

    try:
        v1.list_namespace(_request_timeout=5)
        log.info("K8s API connectivity verified")
    except Exception as e:
        log.warning("K8s API unreachable: %s — K8s monitoring disabled this cycle", e)
        return None, None

    return v1, apps_v1


# ══════════════════════════════════════════════════════════════════════════════
#  POD HEALTH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_pod_restart_count(pod: client.V1Pod) -> int:
    cs = pod.status.container_statuses or []
    return sum(c.restart_count for c in cs)


def is_crashloop(pod: client.V1Pod) -> bool:
    cs = pod.status.container_statuses or []
    for c in cs:
        if c.state and c.state.waiting:
            reason = c.state.waiting.reason or ""
            if "CrashLoopBackOff" in reason or "Error" in reason:
                return True
    return False


def is_oom_killed(pod: client.V1Pod) -> bool:
    cs = pod.status.container_statuses or []
    for c in cs:
        if c.last_state and c.last_state.terminated:
            if c.last_state.terminated.reason == "OOMKilled":
                return True
    return False


def get_oom_container(pod: client.V1Pod) -> str:
    """Return the name of the container that was OOMKilled."""
    cs = pod.status.container_statuses or []
    for c in cs:
        if c.last_state and c.last_state.terminated:
            if c.last_state.terminated.reason == "OOMKilled":
                return c.name
    return ""


def get_container_names(pod: client.V1Pod) -> list[str]:
    return [c.name for c in (pod.spec.containers or [])]


def pod_summary(pod: client.V1Pod) -> dict:
    cs = pod.status.container_statuses or []
    containers = []
    for c in cs:
        state_str, reason = "unknown", ""
        if c.state:
            if c.state.running:
                state_str = "running"
            elif c.state.waiting:
                state_str = "waiting"
                reason = c.state.waiting.reason or ""
            elif c.state.terminated:
                state_str = "terminated"
                reason = c.state.terminated.reason or ""
        containers.append({
            "name": c.name,
            "ready": c.ready,
            "restart_count": c.restart_count,
            "state": state_str,
            "reason": reason,
            "image": c.image,
        })
    return {
        "platform": "k8s",
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "phase": pod.status.phase,
        "containers": containers,
        "node": pod.spec.node_name,
        "created_at": (
            pod.metadata.creation_timestamp.isoformat()
            if pod.metadata.creation_timestamp
            else "unknown"
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  DEPLOYMENT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def derive_deployment_from_pod(
    v1: client.CoreV1Api,
    apps_v1: client.AppsV1Api,
    namespace: str,
    pod_name: str,
) -> str:
    """Derive deployment name from pod owner references: Pod -> ReplicaSet -> Deployment."""
    try:
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        for owner in (pod.metadata.owner_references or []):
            if owner.kind == "ReplicaSet":
                rs = apps_v1.read_namespaced_replica_set(
                    name=owner.name, namespace=namespace,
                )
                for rs_owner in (rs.metadata.owner_references or []):
                    if rs_owner.kind == "Deployment":
                        return rs_owner.name
    except Exception as e:
        log.debug("derive_deployment_from_pod failed for %s/%s: %s", namespace, pod_name, e)
    return ""


def get_deployment_resource_limits(
    apps_v1: client.AppsV1Api, namespace: str, deployment_name: str,
) -> dict:
    """Fetch current resource limits from a deployment for prompt context."""
    try:
        dep = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
        containers = dep.spec.template.spec.containers or []
        limits: dict[str, dict] = {}
        for c in containers:
            res = c.resources
            if res and res.limits:
                limits[c.name] = {}
                if res.limits.get("memory"):
                    limits[c.name]["memory_limit"] = str(res.limits["memory"])
                if res.limits.get("cpu"):
                    limits[c.name]["cpu_limit"] = str(res.limits["cpu"])
        return limits
    except Exception as e:
        log.debug("get_deployment_resource_limits failed: %s", e)
        return {}


def validate_container_in_deployment(
    apps_v1: client.AppsV1Api, namespace: str, deployment_name: str, container_name: str,
) -> bool:
    """Check if the container name exists in the deployment spec."""
    try:
        dep = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
        containers = dep.spec.template.spec.containers or []
        return any(c.name == container_name for c in containers)
    except Exception:
        return False


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


def execute_action_k8s(
    action: str, params: dict, v1: client.CoreV1Api, apps_v1: client.AppsV1Api,
) -> str:
    dry = "[DRY RUN] " if DRY_RUN else ""
    ns = params.get("namespace", "default")

    if action == "restart_pod":
        pod_name = params["pod_name"]
        if not DRY_RUN:
            v1.delete_namespaced_pod(name=pod_name, namespace=ns)
        log.info("%sDeleted pod %s in %s", dry, pod_name, ns)
        return f"Pod {pod_name} deleted and will be recreated by the Deployment."

    elif action == "scale_deployment":
        dep = params.get("deployment", "")
        reps = int(params.get("replicas", 1))
        if not dep:
            dep = derive_deployment_from_pod(v1, apps_v1, ns, params.get("pod_name", ""))
        if not dep:
            return "Cannot determine deployment name — manual intervention required."
        if not DRY_RUN:
            apps_v1.patch_namespaced_deployment_scale(
                name=dep, namespace=ns, body={"spec": {"replicas": reps}},
            )
        log.info("%sScaled %s/%s -> %d replicas", dry, dep, ns, reps)
        return f"Deployment {dep} scaled to {reps} replicas."

    elif action == "bounce_deployment":
        dep = params.get("deployment", "")
        orig = int(params.get("replicas", 1))
        if not dep:
            dep = derive_deployment_from_pod(v1, apps_v1, ns, params.get("pod_name", ""))
        if not dep:
            return "Cannot determine deployment name — manual intervention required."
        if not DRY_RUN:
            apps_v1.patch_namespaced_deployment_scale(
                name=dep, namespace=ns, body={"spec": {"replicas": 0}},
            )
            time.sleep(3)
            apps_v1.patch_namespaced_deployment_scale(
                name=dep, namespace=ns, body={"spec": {"replicas": orig}},
            )
        log.info("%sBounced %s/%s (0 -> %d)", dry, dep, ns, orig)
        return f"Deployment {dep} bounced: scaled to 0 then back to {orig}."

    elif action == "increase_memory_limit":
        dep = params.get("deployment", "")
        container = params.get("container", dep)
        new_memory = params.get("memory_limit", "512Mi")
        if not dep:
            dep = derive_deployment_from_pod(v1, apps_v1, ns, params.get("pod_name", ""))
        if not dep:
            return "Cannot determine deployment name — manual intervention required."

        # Multi-container: validate container name exists
        if container and not validate_container_in_deployment(
            apps_v1, ns, dep, container,
        ):
            # Fall back to first container
            try:
                dep_obj = apps_v1.read_namespaced_deployment(name=dep, namespace=ns)
                first = (dep_obj.spec.template.spec.containers or [None])[0]
                if first:
                    log.warning("Container '%s' not in deployment, using '%s'", container, first.name)
                    container = first.name
            except Exception:
                pass

        patch = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": container,
                            "resources": {"limits": {"memory": new_memory}},
                        }]
                    }
                }
            }
        }
        if not DRY_RUN:
            apps_v1.patch_namespaced_deployment(name=dep, namespace=ns, body=patch)
        log.info("%sIncreased memory to %s on %s/%s", dry, new_memory, dep, ns)
        return f"Memory limit for {container} in {dep} increased to {new_memory}."

    elif action == "describe_diagnosis":
        log.info("Diagnosis surfaced: %s", params.get("summary", ""))
        return "Diagnosis surfaced to operator. Manual intervention required."

    return f"Unknown action: {action}"


# ══════════════════════════════════════════════════════════════════════════════
#  EVENT-DRIVEN WATCHER (Feature 3)
# ══════════════════════════════════════════════════════════════════════════════

class K8sEventWatcher:
    """
    Background thread that watches K8s pod events for instant reaction.
    Populates a shared pending_heals set that the main loop reads.
    """

    def __init__(
        self,
        v1: client.CoreV1Api,
        pending_heals: set[str],
        lock: threading.Lock,
    ):
        self.v1 = v1
        self.pending_heals = pending_heals
        self.lock = lock
        self._stop = threading.Event()
        self._debounce: dict[str, float] = {}
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not WATCH_EVENTS_ENABLED:
            log.info("Event-driven watcher disabled (WATCH_EVENTS_ENABLED=false)")
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="k8s-event-watcher")
        self._thread.start()
        log.info("Event-driven watcher started (debounce=%ds)", WATCH_EVENTS_DEBOUNCE_SEC)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _get_namespaces(self) -> list[str]:
        if WATCH_ALL_NAMESPACES:
            try:
                return [ns.metadata.name for ns in self.v1.list_namespace().items]
            except Exception:
                return ["default"]
        return list(WATCH_NAMESPACES)

    def _run(self) -> None:
        while not self._stop.is_set():
            for ns in self._get_namespaces():
                if self._stop.is_set():
                    break
                try:
                    w = watch.Watch()
                    for event in w.stream(
                        self.v1.list_namespaced_event,
                        namespace=ns,
                        timeout_seconds=30,
                    ):
                        if self._stop.is_set():
                            w.stop()
                            break
                        self._handle_event(event, ns)
                except Exception as e:
                    log.debug("Watch stream error in %s: %s", ns, e)
                    time.sleep(5)

    def _handle_event(self, event: dict, ns: str) -> None:
        obj = event.get("object")
        if not obj:
            return
        if obj.type != "Warning":
            return
        reason = obj.reason or ""
        pod_name = obj.involved_object.name if obj.involved_object else ""
        if not pod_name:
            return

        # Only trigger on meaningful warning reasons
        trigger_reasons = {
            "OOMKilling", "BackOff", "CrashLoopBackOff",
            "Failed", "Unhealthy", "CreateContainerConfigError",
        }
        if reason not in trigger_reasons:
            return

        uid = f"k8s/{ns}/{pod_name}"
        now = time.time()

        # Debounce
        last = self._debounce.get(uid, 0)
        if now - last < WATCH_EVENTS_DEBOUNCE_SEC:
            return
        self._debounce[uid] = now

        log.info("Event-driven trigger: %s in %s (reason=%s)", pod_name, ns, reason)
        with self.lock:
            self.pending_heals.add(uid)
