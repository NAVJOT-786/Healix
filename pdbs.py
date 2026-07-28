#!/usr/bin/env python3
"""
Pod Disruption Budget (PDB) awareness — checks if a healing action
would violate a PDB before executing it.
"""

from __future__ import annotations

import logging
from typing import Any

from kubernetes import client

log = logging.getLogger("pdbs")


class PDBViolationError(Exception):
    """Raised when an action would violate a Pod Disruption Budget."""
    pass


def check_pdb_before_bounce(
    apps_v1: client.AppsV1Api,
    namespace: str,
    deployment_name: str,
) -> str | None:
    """
    Check if bouncing (scale to 0 then back) would violate any PDB.

    Returns:
        None if safe to proceed.
        Error message string if action would violate PDB.
    """
    try:
        pdbs = apps_v1.list_namespaced_pod_disruption_budget(namespace=namespace)
    except Exception as e:
        log.debug("Could not list PDBs in %s: %s", namespace, e)
        return None  # Can't check — proceed with caution

    if not pdbs.items:
        return None

    # Get deployment's pod selector labels
    try:
        dep = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
        selector = dep.spec.selector
        if not selector or not selector.match_labels:
            return None
        dep_labels = selector.match_labels
    except Exception as e:
        log.debug("Could not read deployment %s/%s: %s", namespace, deployment_name, e)
        return None

    for pdb in pdbs.items:
        if pdb.spec.selector and pdb.spec.selector.match_labels:
            pdb_labels = pdb.spec.selector.match_labels
            # Check if PDB selectors overlap with deployment selectors
            if all(dep_labels.get(k) == v for k, v in pdb_labels.items()):
                # PDB matches this deployment — check constraints
                min_available = pdb.spec.min_available
                max_unavailable = pdb.spec.max_unavailable

                # Get current healthy pod count
                pods = client.CoreV1Api().list_namespaced_pod(
                    namespace=namespace,
                    label_selector=",".join(f"{k}={v}" for k, v in dep_labels.items()),
                )
                total = len(pods.items)
                ready = sum(
                    1 for p in pods.items
                    if p.status.phase == "Running"
                    and all(
                        c.ready for c in (p.status.container_statuses or [])
                    )
                )

                if min_available is not None:
                    min_avail = int(min_available) if isinstance(min_available, int) else int(str(min_available).replace("%", ""))
                    if "%" in str(min_available):
                        min_avail = max(1, int(total * min_avail / 100))
                    if ready - total <= min_avail:
                        return (
                            f"PDB '{pdb.metadata.name}' requires minAvailable={min_avail} "
                            f"but bounce would reduce ready pods from {ready} to 0 "
                            f"(total={total}). Action blocked."
                        )

                if max_unavailable is not None:
                    max_unavail = int(max_unavailable) if isinstance(max_unavailable, int) else int(str(max_unavailable).replace("%", ""))
                    if "%" in str(max_unavailable):
                        max_unavail = max(1, int(total * max_unavail / 100))
                    if total - max_unavail < 1:
                        return (
                            f"PDB '{pdb.metadata.name}' allows maxUnavailable={max_unavail} "
                            f"but bounce would reduce ready pods from {ready} to 0 "
                            f"(total={total}). Action blocked."
                        )

    return None


def check_pdb_before_scale(
    apps_v1: client.AppsV1Api,
    namespace: str,
    deployment_name: str,
    target_replicas: int,
) -> str | None:
    """
    Check if scaling to target_replicas would violate any PDB.

    Returns:
        None if safe, error message if violation.
    """
    try:
        pdbs = apps_v1.list_namespaced_pod_disruption_budget(namespace=namespace)
    except Exception:
        return None

    if not pdbs.items:
        return None

    try:
        dep = apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
        selector = dep.spec.selector
        if not selector or not selector.match_labels:
            return None
        dep_labels = selector.match_labels
        current_replicas = dep.spec.replicas or 1
    except Exception:
        return None

    # Only check if scaling down
    if target_replicas >= current_replicas:
        return None

    for pdb in pdbs.items:
        if pdb.spec.selector and pdb.spec.selector.match_labels:
            pdb_labels = pdb.spec.selector.match_labels
            if all(dep_labels.get(k) == v for k, v in pdb_labels.items()):
                min_available = pdb.spec.min_available
                if min_available is not None:
                    total = current_replicas
                    min_avail = int(min_available) if isinstance(min_available, int) else int(str(min_available).replace("%", ""))
                    if "%" in str(min_available):
                        min_avail = max(1, int(total * min_avail / 100))
                    if target_replicas < min_avail:
                        return (
                            f"PDB '{pdb.metadata.name}' requires minAvailable={min_avail} "
                            f"but target replicas={target_replicas}. Action blocked."
                        )

    return None
