#!/usr/bin/env python3
"""
K8s + Docker AI Healing Agent — v9 (Modular Multi-Provider Edition)
-------------------------------------------------------------------
Thin orchestrator that wires together all modules:
  config, providers, prompts, loki, k8s_engine, docker_engine,
  pdbs, rollback, cost, notifications, observability,
  prometheus, k8s_events
"""

from __future__ import annotations

import os
import sys
import time
import json
import signal
import logging
import threading
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

import google.generativeai as genai

# ── Module imports ────────────────────────────────────────────────────────────

import config
from providers import build_provider_registry, call_provider_chain, warmup_ollama
from prompts import build_full_prompt
from k8s_engine import (
    init_k8s, get_pod_restart_count, is_crashloop, is_oom_killed,
    get_oom_container, get_container_names, pod_summary,
    derive_deployment_from_pod, get_deployment_resource_limits,
    execute_action_k8s, K8sEventWatcher,
)
from docker_engine import (
    init_docker, docker_restart_count, docker_is_oom_killed,
    docker_is_crashloop, container_summary, execute_action_docker,
)
from loki import fetch_logs_unified
from pdbs import check_pdb_before_bounce, check_pdb_before_scale
from rollback import verify_and_maybe_rollback_k8s
from cost import format_cost_summary
from notifications import (
    send_dev_email, send_resolution_email, send_infra_report_email,
    send_self_heal_email, send_rollback_email, notify_n8n,
    send_approval_email, send_approval_executed_email, send_approval_rejected_email,
)
from observability import (
    setup_logging, start_health_server, heartbeat, metrics, diagnosis_store,
    service_status, set_approval_store, get_approval_store,
    set_storage, set_circuit_breaker,
)
from prometheus import PrometheusClient, fetch_pod_metrics, format_metrics_for_prompt
from k8s_events import fetch_warning_events

log = logging.getLogger("agent")
console = Console()


# ══════════════════════════════════════════════════════════════════════════════
#  SELF-HEAL DETECTION
# ══════════════════════════════════════════════════════════════════════════════

SELF_HEAL_MARKER = os.getenv("AGENT_MARKER_DIR", "/tmp") + "/.ai-healer-self-healed"


def _check_and_notify_self_heal() -> None:
    if not os.path.exists(SELF_HEAL_MARKER):
        return
    try:
        with open(SELF_HEAL_MARKER, "r") as f:
            restarted_at = f.read().strip()
        os.remove(SELF_HEAL_MARKER)
    except Exception:
        return
    log.info("Self-heal detected — agent was restarted by watchdog at %s", restarted_at)
    send_self_heal_email(restarted_at)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN HEAL FUNCTION (v9)
# ══════════════════════════════════════════════════════════════════════════════

def heal_with_diagnosis(
    target: dict,
    logs: str,
    gemini_model,
    issue_type: str,
    v1=None,
    apps_v1=None,
    docker_container=None,
    prom_client=None,
    provider_registry=None,
    circuit_breaker=None,
    target_id=None,
) -> None:
    platform = target["platform"]
    summary_data = target["summary_data"]
    restarts = target["restarts"]
    location = target["location"]
    heal_start = time.time()

    # ── Fetch Prometheus metrics (K8s pods only) ────────────────────
    metrics_str = ""
    if prom_client and prom_client.enabled and platform == "k8s":
        log.info("Fetching Prometheus metrics for %s ...", target["name"])
        pod_metrics = fetch_pod_metrics(prom_client, target["namespace"], target["name"])
        metrics_str = format_metrics_for_prompt(pod_metrics)
        if pod_metrics:
            log.info("Metrics: %s", metrics_str.replace("\n", " | "))

    # ── Fetch K8s Warning events ────────────────────────────────────
    events_str = ""
    if v1 and platform == "k8s":
        log.info("Fetching K8s Warning events for %s ...", target["name"])
        events_str = fetch_warning_events(v1, target["namespace"], target["name"])
        if events_str:
            log.info("Events: %d warning event(s)", len(events_str.splitlines()))

    # ── Multi-container support: get container names + resource limits ──
    container_names: list[str] | None = None
    resource_limits: dict | None = None
    if platform == "k8s" and v1 and apps_v1:
        pod = target.get("_raw_pod")
        if pod:
            container_names = get_container_names(pod)
            # Auto-detect OOM container
            oom_container = get_oom_container(pod)
            if oom_container and not target.get("oom_container"):
                target["oom_container"] = oom_container

            # Get deployment resource limits for prompt context
            dep = target.get("deployment") or derive_deployment_from_pod(
                v1, apps_v1, target["namespace"], target["name"],
            )
            if dep:
                resource_limits = get_deployment_resource_limits(
                    apps_v1, target["namespace"], dep,
                )
                target["deployment"] = dep

    # ── Build the enhanced prompt ───────────────────────────────────
    prompt = build_full_prompt(
        platform=platform,
        summary_data=summary_data,
        restarts=restarts,
        logs=logs,
        metrics_str=metrics_str,
        events_str=events_str,
        container_names=container_names,
        resource_limits=resource_limits,
    )

    # ── Multi-provider chain iteration ──────────────────────────────
    llm_start = time.time()
    raw, used_model = call_provider_chain(prompt, provider_registry, gemini_model)
    llm_latency = time.time() - llm_start

    metrics.record_llm_call(used_model, llm_latency, raw is not None)

    if raw is None:
        log.error("All providers failed — skipping diagnosis for this cycle")
        return

    log.info("Response: %s", raw[:300])

    # ── Parse and validate ──────────────────────────────────────────
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.error("Could not parse model JSON: %s", e)
        log.debug("Raw output: %s", raw)
        return

    # Validate required fields
    action = data.get("action", "describe_diagnosis")
    params = data.get("params", {})
    is_dev_issue = data.get("is_developer_issue", False)

    allowed_actions = {
        "restart_pod", "scale_deployment", "bounce_deployment",
        "increase_memory_limit", "describe_diagnosis",
    }
    if action not in allowed_actions:
        log.warning("Invalid action '%s' — falling back to describe_diagnosis", action)
        action = "describe_diagnosis"

    if not isinstance(is_dev_issue, bool):
        is_dev_issue = bool(is_dev_issue)

    # Ensure deployment is set for K8s
    if platform == "k8s" and not params.get("deployment"):
        params["deployment"] = target.get("deployment", "")

    # Ensure OOM container is used if available
    if platform == "k8s" and not params.get("container"):
        oom_c = target.get("oom_container", "")
        if oom_c:
            params["container"] = oom_c

    # Set namespace and pod_name from target
    if platform == "k8s":
        params.setdefault("namespace", target["namespace"])
        params.setdefault("pod_name", target["name"])

    log.info(
        "Action: %s | dev_issue: %s | model: %s | reason: %s",
        action, is_dev_issue, used_model, params.get("reason", ""),
    )

    # ── PDB check before bounce/scale ───────────────────────────────
    if action in ("bounce_deployment", "scale_deployment") and platform == "k8s" and apps_v1:
        dep = params.get("deployment", "")
        if not dep:
            dep = derive_deployment_from_pod(
                v1, apps_v1, params.get("namespace", "default"),
                params.get("pod_name", ""),
            )
        if dep:
            if action == "bounce_deployment":
                pdb_err = check_pdb_before_bounce(apps_v1, params.get("namespace", "default"), dep)
            else:
                pdb_err = check_pdb_before_scale(
                    apps_v1, params.get("namespace", "default"), dep,
                    int(params.get("replicas", 1)),
                )
            if pdb_err:
                log.warning("PDB violation blocked: %s", pdb_err)
                metrics.record_pdb_block()
                # Override action to describe_diagnosis
                action = "describe_diagnosis"
                params["summary"] = f"PDB violation: {pdb_err}"
                params["root_cause"] = pdb_err
                params["recommendation"] = "Manual intervention required — PDB prevents automated action."

    # ── Save original state for rollback ────────────────────────────
    original_state: dict = {}
    if platform == "k8s" and action in ("increase_memory_limit", "bounce_deployment", "scale_deployment"):
        dep = params.get("deployment", "")
        if dep and apps_v1:
            try:
                dep_obj = apps_v1.read_namespaced_deployment(
                    name=dep, namespace=params.get("namespace", "default"),
                )
                original_state["original_replicas"] = dep_obj.spec.replicas or 1
                containers = dep_obj.spec.template.spec.containers or []
                for c in containers:
                    if c.name == params.get("container", dep):
                        if c.resources and c.resources.limits:
                            original_state["original_memory_limit"] = str(
                                c.resources.limits.get("memory", "128Mi"),
                            )
                        break
            except Exception:
                original_state["original_memory_limit"] = "128Mi"
                original_state["original_replicas"] = 1

    # ── Approval gate ─────────────────────────────────────────────
    if config.APPROVAL_MODE and action != "describe_diagnosis":
        store = get_approval_store()
        approval_id = store.create(
            target=target,
            action=action,
            params=params,
            platform=platform,
            location=location,
            issue_type=issue_type,
            restarts=restarts,
            logs=logs,
            used_model=used_model,
            cost_data=format_cost_summary(action=action, params=params, restart_count=restarts, original_state=original_state),
            is_developer_issue=is_dev_issue,
        )
        log.info("Approval required — pausing heal for %s (id: %s)", target["name"], approval_id)
        send_approval_email(
            approval_id, target["name"], location, params, issue_type,
            platform, restarts,
            format_cost_summary(action=action, params=params, restart_count=restarts, original_state=original_state),
            logs,
        )
        notify_n8n({
            "route": "needs_approval",
            "approval_id": approval_id,
            "platform": platform,
            "location": location,
            "target_name": target["name"],
            "issue_type": issue_type,
            "is_developer_issue": is_dev_issue,
            "action": action,
            "summary": params.get("summary", ""),
            "root_cause": params.get("root_cause", ""),
            "recommendation": params.get("recommendation", ""),
            "diagnosed_by": used_model,
            "restart_count": restarts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        diag_status = "OOMKilled" if target.get("oom_container") else issue_type
        diagnosis_store.record(
            platform=platform,
            name=target["name"],
            namespace=target.get("namespace", ""),
            location=location,
            deployment=target.get("deployment", ""),
            status=diag_status,
            restarts=restarts,
            action=action,
            route="needs_approval",
            is_developer_issue=is_dev_issue,
            llm_model=used_model,
            llm_latency=round(llm_latency, 2),
            summary=params.get("summary", ""),
            root_cause=params.get("root_cause", ""),
            recommendation=params.get("recommendation", ""),
            logs=logs[:2000] if logs else "",
            action_result=f"[APPROVAL PENDING] id={approval_id}",
            cost_data=format_cost_summary(action=action, params=params, restart_count=restarts, original_state=original_state),
            success=True,
        )
        return

    # ── Execute action ──────────────────────────────────────────────
    if config.REPORT_ONLY:
        action_result = (
            f"[REPORT ONLY] No action executed. Model recommended: '{action}' "
            f"- {params.get('reason', 'no reason given')}."
        )
        log.info("[REPORT ONLY] %s", action_result)
    else:
        if platform == "k8s":
            action_result = execute_action_k8s(action, params, v1, apps_v1)
        else:
            action_result = execute_action_docker(action, params, docker_container)
        log.info("Result: %s", action_result)

    # ── Post-heal verification + rollback ───────────────────────────
    rolled_back = False
    if (
        not config.REPORT_ONLY
        and platform == "k8s"
        and action in ("increase_memory_limit", "bounce_deployment", "scale_deployment")
        and apps_v1
    ):
        success, verify_msg = verify_and_maybe_rollback_k8s(
            action, params, v1, apps_v1, original_state,
        )
        if not success:
            rolled_back = True
            metrics.record_rollback()
            log.warning("Heal failed — rollback applied: %s", verify_msg)
            send_rollback_email(
                target["name"], location, action, verify_msg,
                params.get("root_cause", "See logs"), logs, platform,
            )
            notify_n8n({
                "route": "rollback",
                "platform": platform,
                "location": location,
                "target_name": target["name"],
                "action": action,
                "rollback_msg": verify_msg,
                "root_cause": params.get("root_cause", ""),
                "diagnosed_by": used_model,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return

    # ── Cost estimation ─────────────────────────────────────────────
    cost_data = format_cost_summary(
        action=action,
        params=params,
        restart_count=restarts,
        original_state=original_state,
    )

    # ── Determine route ─────────────────────────────────────────────
    if config.REPORT_ONLY:
        route = "dev_issue" if is_dev_issue else "needs_escalation"
    elif is_dev_issue and action == "describe_diagnosis":
        route = "dev_issue"
    elif not is_dev_issue and action != "describe_diagnosis":
        route = "auto_healed"
    else:
        route = "auto_healed" if action != "describe_diagnosis" else "needs_escalation"

    log.info("Route: %s", route.upper())

    # ── Record metrics ──────────────────────────────────────────────
    heal_latency = time.time() - heal_start
    metrics.record_heal(action, platform, route, heal_latency)

    # ── Record in circuit breaker ───────────────────────────────────
    if circuit_breaker and target_id:
        circuit_breaker.record_heal(target_id, action, success=not rolled_back)

    # ── Record diagnosis for dashboard ──────────────────────────────
    diag_status = issue_type
    if target.get("oom_container"):
        diag_status = "OOMKilled"
    diagnosis_store.record(
        platform=platform,
        name=target["name"],
        namespace=target.get("namespace", ""),
        location=location,
        deployment=target.get("deployment", ""),
        status=diag_status,
        restarts=restarts,
        action=action,
        route=route,
        is_developer_issue=is_dev_issue,
        llm_model=used_model,
        llm_latency=round(llm_latency, 2),
        summary=params.get("summary", ""),
        root_cause=params.get("root_cause", ""),
        recommendation=params.get("recommendation", ""),
        logs=logs[:2000] if logs else "",
        action_result=action_result if not config.REPORT_ONLY else "[REPORT ONLY]",
        cost_data=cost_data,
        success=not rolled_back,
    )

    # ── Send notifications ──────────────────────────────────────────
    if route == "dev_issue":
        log.info("Developer issue — notifying dev team")
        send_dev_email(
            target["name"], location, params.get("summary", "Failure"),
            params.get("root_cause", "See logs"),
            params.get("recommendation", "Check application code and config"),
            logs, action_result, platform, cost_data,
        )
    elif route == "auto_healed":
        log.info("Infra auto-heal applied — sending resolution email")
        send_resolution_email(
            target["name"], location, params.get("summary", "Was auto-healed"),
            params.get("root_cause", "See logs"), action_result,
            params.get("recommendation", "Monitor for recurrence"),
            logs, issue_type, platform, cost_data,
        )
    elif route == "needs_escalation" and config.REPORT_ONLY:
        log.info("Infra issue — sending report email")
        send_infra_report_email(
            target["name"], location, params.get("summary", "Issue detected"),
            params.get("root_cause", "See logs"), action_result,
            params.get("recommendation", "Review and apply manually"),
            logs, issue_type, platform, cost_data,
        )
    else:
        log.info("Could not auto-heal — escalating via n8n")

    notify_n8n({
        "route": route,
        "platform": platform,
        "location": location,
        "target_name": target["name"],
        "issue_type": issue_type,
        "is_developer_issue": is_dev_issue,
        "action": action,
        "action_result": action_result,
        "summary": params.get("summary", ""),
        "root_cause": params.get("root_cause", ""),
        "recommendation": params.get("recommendation", ""),
        "reason": params.get("reason", ""),
        "diagnosed_by": used_model,
        "restart_count": restarts,
        "cost_data": cost_data,
        "logs_snippet": logs[-800:],
        "dry_run": config.DRY_RUN,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ══════════════════════════════════════════════════════════════════════════════
#  K8S WATCH PASS
# ══════════════════════════════════════════════════════════════════════════════

def k8s_watch_pass(
    v1, apps_v1, gemini_model, healed_pods, table, prom_client,
    provider_registry, pending_heals=None, circuit_breaker=None,
    storage=None,
) -> None:
    ns_list = []
    try:
        ns_list = (
            [ns.metadata.name for ns in v1.list_namespace().items]
            if config.WATCH_ALL_NAMESPACES
            else config.WATCH_NAMESPACES
        )
    except Exception as e:
        log.error("Cannot list namespaces: %s", e)
        return
    alive_k8s: set[str] = set()
    for ns in ns_list:
        try:
            pods = v1.list_namespaced_pod(namespace=ns.strip()).items
        except Exception as e:
            log.error("Cannot list pods in %s: %s", ns, e)
            continue

        for pod in pods:
            alive_k8s.add(f"k8s/{pod.metadata.namespace}/{pod.metadata.name}")
            restarts = get_pod_restart_count(pod)
            crashloop = is_crashloop(pod)
            oom = is_oom_killed(pod)
            uid = f"k8s/{pod.metadata.namespace}/{pod.metadata.name}"

            if crashloop:
                status_txt, issue_type = "[red]CrashLoopBackOff[/red]", "CrashLoopBackOff"
            elif oom:
                status_txt, issue_type = "[magenta]OOMKilled[/magenta]", "OOMKilled"
            elif pod.status.phase == "Running":
                status_txt, issue_type = "[green]Running[/green]", "None"
            else:
                status_txt = f"[yellow]{pod.status.phase or 'Unknown'}[/yellow]"
                issue_type = pod.status.phase or "Unknown"

            table.add_row(
                "k8s", pod.metadata.namespace, pod.metadata.name,
                pod.status.phase or "Unknown", str(restarts), status_txt,
            )

            needs_heal = (crashloop or oom) and restarts >= config.MAX_RESTARTS
            triggered = uid in (pending_heals or set())

            if (needs_heal or triggered) and uid not in healed_pods:
                # ── Circuit breaker check ──────────────────────────────
                if circuit_breaker:
                    allowed, reason = circuit_breaker.can_heal(uid)
                    if not allowed:
                        log.warning("Skipping %s — %s", uid, reason)
                        console.print(f"  [yellow]Skipped (circuit open): {reason}[/yellow]")
                        continue
                # ──────────────────────────────────────────────────────
                console.print(
                    f"\n[bold red]Unhealthy pod:[/bold red] {uid}  "
                    f"(restarts={restarts}, oom={oom}, crashloop={crashloop})"
                )
                dep = derive_deployment_from_pod(
                    v1, apps_v1, pod.metadata.namespace, pod.metadata.name,
                )
                target = {
                    "platform": "k8s",
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "deployment": dep,
                    "location": f"{pod.metadata.namespace} (node: {pod.spec.node_name or 'unknown'})",
                    "summary_data": pod_summary(pod),
                    "restarts": restarts,
                    "_raw_pod": pod,
                }
                logs = fetch_logs_unified(target, v1=v1)
                heal_with_diagnosis(
                    target, logs, gemini_model, issue_type,
                    v1=v1, apps_v1=apps_v1, prom_client=prom_client,
                    provider_registry=provider_registry,
                    circuit_breaker=circuit_breaker,
                    target_id=uid,
                )
                healed_pods.add(uid)
                if pending_heals and uid in pending_heals:
                    pending_heals.discard(uid)
                log.info("Healing complete for %s", uid)

    # ── Mark stale K8s diagnoses as deleted ─────────────────────
    diagnosis_store.mark_deleted_by_resource(alive_k8s, platform="k8s")
    if storage:
        try:
            storage.mark_stale_diagnoses(alive_k8s, platform="k8s")
        except Exception as e:
            log.warning("Failed to mark stale K8s diagnoses: %s", e)

    # ── Mark stale K8s approvals as deleted ────────────────────
    approval_store = get_approval_store()
    if approval_store:
        try:
            approval_store.mark_deleted_by_resource(alive_k8s, platform="k8s")
        except Exception as e:
            log.warning("Failed to mark stale K8s approvals: %s", e)
    if storage:
        try:
            storage.mark_stale_approvals(alive_k8s, platform="k8s")
        except Exception as e:
            log.warning("Failed to mark stale K8s approvals in DB: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
#  DOCKER WATCH PASS
# ══════════════════════════════════════════════════════════════════════════════

def docker_watch_pass(
    dc, gemini_model, healed_containers, table, provider_registry,
    circuit_breaker=None, storage=None,
) -> None:
    try:
        containers = dc.containers.list(all=True)
    except Exception as e:
        log.error("Cannot list Docker containers: %s", e)
        return

    for c in containers:
        try:
            c.reload()
        except Exception:
            continue

        restarts = docker_restart_count(c)
        crashloop = docker_is_crashloop(c)
        oom = docker_is_oom_killed(c)
        status = c.attrs.get("State", {}).get("Status", "unknown")
        uid = f"docker/{config.DOCKER_HOST_LABEL}/{c.name}"

        if crashloop:
            status_txt, issue_type = "[red]RestartLoop[/red]", "RestartLoop"
        elif oom:
            status_txt, issue_type = "[magenta]OOMKilled[/magenta]", "OOMKilled"
        elif status == "running":
            status_txt, issue_type = "[green]Running[/green]", "None"
        else:
            status_txt, issue_type = f"[yellow]{status}[/yellow]", status

        table.add_row(
            "docker", config.DOCKER_HOST_LABEL, c.name, status,
            str(restarts), status_txt,
        )

        needs_heal = (crashloop or oom) and restarts >= config.MAX_RESTARTS
        if needs_heal and uid not in healed_containers:
            # ── Circuit breaker check ──────────────────────────────
            if circuit_breaker:
                allowed, reason = circuit_breaker.can_heal(uid)
                if not allowed:
                    log.warning("Skipping %s — %s", uid, reason)
                    console.print(f"  [yellow]Skipped (circuit open): {reason}[/yellow]")
                    continue
            # ──────────────────────────────────────────────────────
            console.print(
                f"\n[bold red]Unhealthy container:[/bold red] {uid}  "
                f"(restarts={restarts}, oom={oom}, crashloop={crashloop})"
            )
            target = {
                "platform": "docker",
                "name": c.name,
                "host": config.DOCKER_HOST_LABEL,
                "location": config.DOCKER_HOST_LABEL,
                "summary_data": container_summary(c),
                "restarts": restarts,
            }
            logs = fetch_logs_unified(target, docker_container=c)
            heal_with_diagnosis(
                target, logs, gemini_model, issue_type,
                docker_container=c, provider_registry=provider_registry,
                circuit_breaker=circuit_breaker,
                target_id=uid,
            )
            healed_containers.add(uid)
            log.info("Healing complete for %s", uid)

    # ── Mark stale Docker diagnoses as deleted ────────────────────
    alive_docker = set()
    for c in containers:
        alive_docker.add(f"docker/{config.DOCKER_HOST_LABEL}/{c.name}")
    diagnosis_store.mark_deleted_by_resource(alive_docker, platform="docker")
    if storage:
        try:
            storage.mark_stale_diagnoses(alive_docker, platform="docker")
        except Exception as e:
            log.warning("Failed to mark stale Docker diagnoses: %s", e)

    # ── Mark stale Docker approvals as deleted ───────────────────
    approval_store = get_approval_store()
    if approval_store:
        try:
            approval_store.mark_deleted_by_resource(alive_docker, platform="docker")
        except Exception as e:
            log.warning("Failed to mark stale Docker approvals: %s", e)
    if storage:
        try:
            storage.mark_stale_approvals(alive_docker, platform="docker")
        except Exception as e:
            log.warning("Failed to mark stale Docker approvals in DB: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def run() -> None:
    setup_logging(json_mode=False)

    if not config.GEMINI_API_KEY:
        console.print("[red]GEMINI_API_KEY not set.[/red]")
        sys.exit(1)
    if not config.ENABLE_K8S and not config.ENABLE_DOCKER:
        console.print("[red]Both ENABLE_K8S and ENABLE_DOCKER are false — nothing to watch.[/red]")
        sys.exit(1)

    genai.configure(api_key=config.GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel("gemini-2.5-flash")

    _check_and_notify_self_heal()

    v1 = apps_v1 = dc = None
    k8s_init_failed = False
    if config.ENABLE_K8S:
        v1, apps_v1 = init_k8s()
        if v1 is None:
            k8s_init_failed = True
            log.warning("K8s init failed — will retry each cycle")
            service_status.set_platform("k8s", connected=False, detail="API unreachable")
        else:
            service_status.set_platform("k8s", connected=True, detail=f"namespaces={','.join(config.WATCH_NAMESPACES) if not config.WATCH_ALL_NAMESPACES else '*'}")
    if config.ENABLE_DOCKER:
        dc = init_docker()
        if dc is None:
            log.warning("Continuing without Docker monitoring")
            service_status.set_platform("docker", connected=False, detail="socket unreachable")
        else:
            service_status.set_platform("docker", connected=True, detail=f"host={config.DOCKER_HOST_LABEL}")

    prom_client = PrometheusClient()
    if prom_client.enabled:
        if prom_client.is_available():
            console.print(f"[green]✓ Prometheus connected at {prom_client.url}[/green]")
        else:
            console.print(f"[yellow]⚠ Prometheus unreachable at {prom_client.url}[/yellow]")

    provider_registry = build_provider_registry()
    warmup_ollama()

    # Start health server
    start_health_server()

    # ── Database & Circuit Breaker ─────────────────────────────────
    storage = None
    circuit_breaker = None
    if config.DATABASE_URL:
        try:
            from storage import StorageBackend
            storage = StorageBackend(config.DATABASE_URL)
            set_storage(storage)
            console.print("[green]✓[/green] PostgreSQL storage connected")
            if config.CIRCUIT_BREAKER_ENABLED:
                from circuit_breaker import CircuitBreaker
                circuit_breaker = CircuitBreaker(
                    storage=storage,
                    threshold=config.CIRCUIT_BREAKER_THRESHOLD,
                    window_min=config.CIRCUIT_BREAKER_WINDOW_MIN,
                    cooldown_min=config.CIRCUIT_BREAKER_COOLDOWN_MIN,
                )
                set_circuit_breaker(circuit_breaker)
                console.print("[green]✓[/green] Circuit breaker enabled")
        except Exception as e:
            log.error("Database init failed: %s — continuing without persistence", e)
            console.print(f"[red]✗[/red] PostgreSQL connection failed: {e}")

    # ── Approval mode ───────────────────────────────────────────────
    approval_store = None
    if config.APPROVAL_MODE:
        from approval import ApprovalStore, start_approval_executor
        approval_store = ApprovalStore(timeout_hours=config.APPROVAL_TIMEOUT_HOURS)
        set_approval_store(approval_store)
        start_approval_executor(
            store=approval_store,
            execute_fn=execute_action_k8s if config.ENABLE_K8S else execute_action_docker,
            verify_fn=verify_and_maybe_rollback_k8s,
            send_executed_email_fn=send_approval_executed_email,
            send_rejected_email_fn=send_approval_rejected_email,
            notify_n8n_fn=notify_n8n,
            record_metrics_fn=metrics.record_heal,
            record_diagnosis_fn=diagnosis_store.record,
            update_diagnosis_fn=diagnosis_store.update_by_approval_id,
            k8s_context={"v1": v1, "apps_v1": apps_v1} if v1 else None,
            docker_context={"container": dc} if dc else None,
            storage=storage,
            circuit_breaker=circuit_breaker,
        )
        console.print("[green]✓[/green] Approval mode enabled — heals require human approval")
        if config.APPROVAL_DASHBOARD_URL:
            console.print(f"  Dashboard: {config.APPROVAL_DASHBOARD_URL}")

    if config.IMAP_ENABLED and approval_store:
        from email_reader import EmailReplyReader
        reader = EmailReplyReader(
            config.IMAP_HOST, config.IMAP_PORT, config.IMAP_USER, config.IMAP_PASSWORD,
            config.IMAP_POLL_INTERVAL,
        )
        reader.start(approval_store, send_approval_rejected_email)
        console.print("[green]✓[/green] IMAP email reply reader enabled")

    # Start event-driven watcher
    pending_heals: set[str] = set()
    event_lock = threading.Lock()
    event_watcher = None
    if config.ENABLE_K8S and v1 and config.WATCH_EVENTS_ENABLED:
        event_watcher = K8sEventWatcher(v1, pending_heals, event_lock)
        event_watcher.start()

    # Graceful shutdown
    def _shutdown(sig, frame):
        log.info("Received signal %s — shutting down", sig)
        if event_watcher:
            event_watcher.stop()
        sys.exit(0)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # ── Banner ──────────────────────────────────────────────────────
    email_configured = bool(config.SMTP_USER and config.SMTP_PASSWORD)
    n8n_configured = bool(config.N8N_WEBHOOK_URL)
    loki_configured = bool(config.LOKI_URL)
    all_recipients = list({e.strip() for e in config.DEV_EMAILS + config.OPS_EMAILS if e.strip()})

    provider_lines = []
    for pname in config.DIAGNOSIS_PROVIDER_CHAIN:
        p = provider_registry.get(pname)
        if not p:
            continue
        if p["enabled"]:
            provider_lines.append(f"  [green]✓[/green] {pname}: {p['model']}")
        else:
            provider_lines.append(f"  [dim]✗[/dim] {pname}: disabled")
    provider_status = "\n".join(provider_lines)

    console.print(Panel(
        f"K8s monitoring      : [cyan]{'✓ ' + ', '.join(config.WATCH_NAMESPACES) if config.ENABLE_K8S else '✗ disabled'}[/cyan]\n"
        f"Docker monitoring   : [cyan]{'✓ host=' + config.DOCKER_HOST_LABEL if (config.ENABLE_DOCKER and dc) else '✗ disabled'}[/cyan]\n"
        f"Loki log source     : [cyan]{'✓ ' + config.LOKI_URL if loki_configured else '✗ not configured'}[/cyan]\n"
        f"Prometheus metrics  : [cyan]{'✓ ' + prom_client.url if prom_client.enabled else '✗ not configured'}[/cyan]\n"
        f"K8s events context  : [green]enabled[/green]\n"
        f"Event-driven watch  : [green]{'enabled' if config.WATCH_EVENTS_ENABLED else 'disabled'}[/green]\n"
        f"Poll interval       : [cyan]{config.POLL_INTERVAL_SEC}s[/cyan]  |  Heal threshold: [cyan]{config.MAX_RESTARTS} restarts[/cyan]  |  Dry run: [cyan]{config.DRY_RUN}[/cyan]\n"
        f"Mode                : {'[bold yellow]REPORT ONLY[/bold yellow]' if config.REPORT_ONLY else '[bold green]AUTO-HEAL ENABLED[/bold green]'}\n"
        f"Rollback verify     : [cyan]{'enabled (' + str(config.HEAL_VERIFY_DELAY_SEC) + 's delay)' if config.HEAL_VERIFY_ENABLED else 'disabled'}[/cyan]\n"
        f"Circuit breaker     : [cyan]{'enabled (threshold=' + str(config.CIRCUIT_BREAKER_THRESHOLD) + ', cooldown=' + str(config.CIRCUIT_BREAKER_COOLDOWN_MIN) + 'm)' if circuit_breaker else 'disabled'}[/cyan]\n"
        f"Database            : [green]{'PostgreSQL ✓' if storage else '✗ disabled'}[/green]\n"
        f"Cost estimation     : [green]enabled[/green]\n"
        f"\n[bold]LLM Provider Chain:[/bold]\n{provider_status}\n"
        f"Chain order         : [cyan]{', '.join(config.DIAGNOSIS_PROVIDER_CHAIN)}[/cyan]\n"
        f"n8n webhook         : [cyan]{'✓ ' + config.N8N_WEBHOOK_URL if n8n_configured else '✗ Not configured'}[/cyan]\n"
        f"Email alerts        : [cyan]{'✓ ' + ', '.join(all_recipients) if email_configured else '✗ Not configured'}[/cyan]\n"
        f"Health endpoint     : [cyan]:{config.HEALTH_PORT}/health[/cyan]  |  Metrics: [cyan]:{config.HEALTH_PORT}/metrics[/cyan]\n"
        f"\n[bold]Routing logic:[/bold]\n"
        + (
            f"  [red]dev_issue[/red]        -> developer bug, dev email + n8n\n"
            f"  [yellow]needs_escalation[/yellow] -> infra issue, report email (dev+ops) + n8n"
            if config.REPORT_ONLY else
            f"  [red]dev_issue[/red]        -> developer bug, describe_diagnosis, dev email + n8n\n"
            f"  [green]auto_healed[/green]      -> infra fix applied, rollback check, resolution email + n8n\n"
            f"  [yellow]needs_escalation[/yellow] -> agent cannot heal, n8n escalation only\n"
            f"  [orange]rollback[/orange]        -> heal failed, auto-rollback, escalation email + n8n"
        ),
        title="[bold]AI Healing Agent — v9 (Modular Multi-Provider)[/bold]",
        border_style="blue",
    ))

    healed_pods: set[str] = set()
    healed_containers: set[str] = set()

    # ── Main loop ───────────────────────────────────────────────────
    while True:
        heartbeat()

        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Platform")
        table.add_column("Location")
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("Restarts", justify="right")
        table.add_column("Flag")

        if config.ENABLE_K8S:
            if k8s_init_failed:
                v1, apps_v1 = init_k8s()
                if v1 is not None:
                    k8s_init_failed = False
                    log.info("K8s API reconnected — resuming K8s monitoring")
                    service_status.set_platform("k8s", connected=True, detail=f"namespaces={','.join(config.WATCH_NAMESPACES) if not config.WATCH_ALL_NAMESPACES else '*'}")
                else:
                    log.debug("K8s API still unreachable — skipping K8s pass")
                    service_status.set_platform("k8s", connected=False, detail="API unreachable")
            if not k8s_init_failed and v1 is not None:
                try:
                    k8s_watch_pass(
                        v1, apps_v1, gemini_model, healed_pods, table,
                        prom_client, provider_registry, pending_heals,
                        circuit_breaker=circuit_breaker,
                        storage=storage,
                    )
                except Exception as e:
                    log.error("K8s watch pass failed: %s — will retry next cycle", e)
                    v1 = apps_v1 = None
                    k8s_init_failed = True
                    service_status.set_platform("k8s", connected=False, detail=str(e)[:60])

        if config.ENABLE_DOCKER and dc is not None:
            docker_watch_pass(
                dc, gemini_model, healed_containers, table, provider_registry,
                circuit_breaker=circuit_breaker, storage=storage,
            )

        console.print(table)
        console.print(
            f"[dim]Last checked: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}"
            f" — next check in {config.POLL_INTERVAL_SEC}s[/dim]\n"
        )
        time.sleep(config.POLL_INTERVAL_SEC)


if __name__ == "__main__":
    run()
