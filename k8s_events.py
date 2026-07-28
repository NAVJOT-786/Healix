#!/usr/bin/env python3
"""
K8s Events Fetcher for AI Healing Agent
-----------------------------------------
Queries Kubernetes Warning events for a given pod to provide
richer diagnosis context. Catches things pod status doesn't show:
  - FailedScheduling (node Affinity/PDB issues)
  - BackOff / ImagePullBackOff (image issues)
  - UnmountVolume / FailedMount (storage issues)
  - OOMKilling (confirmed by kubelet)
  - ExceededGracePeriod / Deadline (liveness/readiness probe failures)

Usage:
    from k8s_events import fetch_warning_events
    events_str = fetch_warning_events(v1, namespace="demo", pod="my-app-xyz")
"""

from datetime import datetime, timezone, timedelta
from kubernetes import client
from rich.console import Console

console = Console()

# Warning event reasons that are useful for diagnosis
RELEVANT_REASONS = {
    "FailedScheduling",
    "BackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "ImageInspectError",
    "Failed",
    "Unhealthy",
    "FailedMount",
    "FailedDetachVolume",
    "UnmountVolume",
    "VolumeMountFailed",
    "OOMKilling",
    "ExceededGracePeriod",
    "DeadlineExceeded",
    "Killing",
    "NetworkNotReady",
    "Rebooted",
    "NodeNotReady",
    "ContainerGCFailed",
    "FreeDiskSpaceFailed",
    "ReplicaSetCreateFailed",
    "ScalingReplicaSet",
    "CreateContainerConfigError",
    "CreateContainerError",
    "RunContainerError",
    "StartContainerError",
    "PreStartHookError",
    "PostStartHookError",
}


def fetch_warning_events(v1: client.CoreV1Api, namespace: str, pod: str,
                         lookback_minutes: int = 10) -> str:
    """
    Fetch Warning events for a specific pod.

    Args:
        v1: Kubernetes CoreV1Api client
        namespace: Pod namespace
        pod: Pod name
        lookback_minutes: How far back to look (default: 10min)

    Returns:
        Formatted string of relevant warning events, or empty string.
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        events = v1.list_namespaced_event(
            namespace=namespace,
            field_selector=f"involvedObject.name={pod},type=Warning",
        )

        relevant = []
        for ev in events.items:
            if ev.reason not in RELEVANT_REASONS:
                continue
            # Filter by time if last_timestamp is available
            if ev.last_timestamp:
                ev_time = ev.last_timestamp.replace(tzinfo=timezone.utc) if ev.last_timestamp.tzinfo is None else ev.last_timestamp
                if ev_time < cutoff:
                    continue
            elif ev.event_time:
                ev_time = ev.event_time.replace(tzinfo=timezone.utc) if ev.event_timestamp.tzinfo is None else ev.event_time
                if ev_time < cutoff:
                    continue

            age = ""
            ts = ev.last_timestamp or ev.event_time
            if ts:
                age_seconds = (datetime.now(timezone.utc) - ts.replace(tzinfo=timezone.utc)).total_seconds()
                if age_seconds < 60:
                    age = f"{int(age_seconds)}s ago"
                elif age_seconds < 3600:
                    age = f"{int(age_seconds / 60)}m ago"
                else:
                    age = f"{int(age_seconds / 3600)}h ago"

            relevant.append({
                "reason": ev.reason,
                "message": (ev.message or "")[:200],
                "count": ev.count or 1,
                "age": age,
            })

        if not relevant:
            return ""

        lines = []
        for ev in relevant[-10:]:  # Last 10 events max
            count_str = f" (x{ev['count']})" if ev["count"] > 1 else ""
            age_str = f" [{ev['age']}]" if ev["age"] else ""
            lines.append(f"- {ev['reason']}{count_str}{age_str}: {ev['message']}")

        return "\n".join(lines)

    except Exception as e:
        console.print(f"  [yellow]⚠ Could not fetch K8s events for {pod}: {e}[/yellow]")
        return ""


def fetch_all_warning_events(v1: client.CoreV1Api, namespace: str,
                              lookback_minutes: int = 10) -> str:
    """
    Fetch all Warning events in a namespace (not filtered by pod).
    Useful for detecting cluster-wide issues.
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        events = v1.list_namespaced_event(
            namespace=namespace,
            field_selector="type=Warning",
        )

        relevant = []
        for ev in events.items:
            if ev.reason not in RELEVANT_REASONS:
                continue
            if ev.last_timestamp:
                ev_time = ev.last_timestamp.replace(tzinfo=timezone.utc) if ev.last_timestamp.tzinfo is None else ev.last_timestamp
                if ev_time < cutoff:
                    continue

            relevant.append({
                "reason": ev.reason,
                "message": (ev.message or "")[:150],
                "pod": ev.involved_object.name if ev.involved_object else "unknown",
                "count": ev.count or 1,
            })

        if not relevant:
            return ""

        lines = []
        for ev in relevant[-15:]:
            count_str = f" (x{ev['count']})" if ev["count"] > 1 else ""
            lines.append(f"- [{ev['pod']}] {ev['reason']}{count_str}: {ev['message']}")

        return f"Namespace-level Warning events ({len(relevant)} total):\n" + "\n".join(lines)

    except Exception as e:
        console.print(f"  [yellow]⚠ Could not fetch namespace events for {namespace}: {e}[/yellow]")
        return ""
