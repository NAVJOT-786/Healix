#!/usr/bin/env python3
"""
Post-heal verification and automatic rollback.
After executing a heal action, waits and checks if the pod recovered.
If still crashing, rolls back the change and escalates.
"""

from __future__ import annotations

import time
import logging
from typing import Any

from config import HEAL_VERIFY_ENABLED, HEAL_VERIFY_DELAY_SEC, DRY_RUN
from k8s_engine import (
    derive_deployment_from_pod, get_pod_restart_count,
    is_crashloop, is_oom_killed,
)

log = logging.getLogger("rollback")


def verify_and_maybe_rollback_k8s(
    action: str,
    params: dict,
    v1: Any,
    apps_v1: Any,
    original_state: dict,
) -> tuple[bool, str]:
    """
    After a heal action, wait and verify pod health.
    Returns (success: bool, message: str).

    original_state should contain:
        - original_memory_limit: str (e.g. "128Mi") — for memory rollback
        - original_replicas: int — for scale/bounce rollback
        - deployment: str — deployment name
    """
    if not HEAL_VERIFY_ENABLED:
        return True, "Verification disabled — assuming success"
    if action not in ("increase_memory_limit", "bounce_deployment", "scale_deployment"):
        return True, "Verification not applicable for this action"
    if DRY_RUN:
        return True, "Dry run — no verification needed"

    dep = params.get("deployment", "")
    ns = params.get("namespace", "default")
    pod_name = params.get("pod_name", "")

    if not dep:
        dep = derive_deployment_from_pod(v1, apps_v1, ns, pod_name)
    if not dep:
        return True, "Cannot determine deployment — skipping verification"

    log.info("Waiting %ds to verify heal on %s/%s ...", HEAL_VERIFY_DELAY_SEC, dep, ns)
    time.sleep(HEAL_VERIFY_DELAY_SEC)

    # Check pod status after wait
    try:
        pods = v1.list_namespaced_pod(
            namespace=ns,
            label_selector=f"app={dep}" if dep else "",
        )
        # Fallback: find pod by deployment owner ref
        if not pods.items and pod_name:
            pods = v1.list_namespaced_pod(namespace=ns)
            matching = []
            for p in pods.items:
                for owner in (p.metadata.owner_references or []):
                    if owner.kind == "ReplicaSet":
                        try:
                            rs = apps_v1.read_namespaced_replica_set(
                                name=owner.name, namespace=ns,
                            )
                            for rs_owner in (rs.metadata.owner_references or []):
                                if rs_owner.kind == "Deployment" and rs_owner.name == dep:
                                    matching.append(p)
                        except Exception:
                            pass
            pods.items = matching

        if not pods.items:
            log.warning("No pods found for deployment %s after verification delay", dep)
            return True, "No pods found — cannot verify"

        # Check the most recent pod
        latest_pod = max(
            pods.items,
            key=lambda p: p.metadata.creation_timestamp or p.metadata.name,
        )

        restarts = get_pod_restart_count(latest_pod)
        crashloop = is_crashloop(latest_pod)
        oom = is_oom_killed(latest_pod)
        phase = latest_pod.status.phase or "Unknown"

        if crashloop or oom:
            log.warning(
                "Pod %s still unhealthy after heal (restarts=%d, crashloop=%s, oom=%s)",
                latest_pod.metadata.name, restarts, crashloop, oom,
            )
            # Rollback
            rollback_msg = _rollback_k8s(action, params, v1, apps_v1, ns, dep, original_state)
            return False, (
                f"Pod still unhealthy after {HEAL_VERIFY_DELAY_SEC}s. "
                f"Rollback applied: {rollback_msg}"
            )

        log.info("Pod %s recovered (phase=%s, restarts=%d)", latest_pod.metadata.name, phase, restarts)
        return True, f"Pod recovered (phase={phase})"

    except Exception as e:
        log.error("Verification failed: %s", e)
        return True, f"Verification error: {e} — manual check recommended"


def _rollback_k8s(
    action: str,
    params: dict,
    v1: Any,
    apps_v1: Any,
    ns: str,
    dep: str,
    original_state: dict,
) -> str:
    """Execute rollback for the given action."""
    try:
        if action == "increase_memory_limit":
            orig_mem = original_state.get("original_memory_limit", "128Mi")
            container = params.get("container", dep)
            patch = {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": container,
                                "resources": {"limits": {"memory": orig_mem}},
                            }]
                        }
                    }
                }
            }
            apps_v1.patch_namespaced_deployment(name=dep, namespace=ns, body=patch)
            msg = f"Memory rolled back to {orig_mem}"
            log.info("Rolled back memory on %s/%s to %s", dep, ns, orig_mem)
            return msg

        elif action in ("bounce_deployment", "scale_deployment"):
            orig_replicas = original_state.get("original_replicas", 1)
            apps_v1.patch_namespaced_deployment_scale(
                name=dep, namespace=ns,
                body={"spec": {"replicas": orig_replicas}},
            )
            msg = f"Replicas rolled back to {orig_replicas}"
            log.info("Rolled back %s/%s to %d replicas", dep, ns, orig_replicas)
            return msg

    except Exception as e:
        log.error("Rollback failed: %s", e)
        return f"Rollback failed: {e}"

    return "No rollback needed"
