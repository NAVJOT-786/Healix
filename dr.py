#!/usr/bin/env python3
"""
Cloud Disaster Recovery — manifest backup, disaster detection, approval-gated restore.

Flow:  backup (scheduled/manual) → detect (cluster unreachable) →
       decide (approval flow) → restore (primary or standby) → verify.

Runs only when config.DR_ENABLED is true. All state is module-level and
wired by agent.py via set_storage()/set_labels()/set_reporter().
"""

from __future__ import annotations

import copy
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

import config

log = logging.getLogger("healer.dr")

# ── Module state ─────────────────────────────────────────────────────────────

_lock = threading.Lock()
_storage: Any = None
_reporter: Callable[..., None] | None = None          # service_status.set_platform
_clients: dict[str, tuple[Any, Any]] = {}             # label -> (v1, apps_v1)
_labels: dict[str, str] = {}                          # label -> kube context name
_probe: dict[str, tuple[bool, str]] = {}              # label -> (ok, detail)
_last_backup_epoch: float = 0.0
_fail_streak = 0
_disaster: dict[str, Any] = {"active": False, "cluster": "", "detail": "", "since": ""}
_inited = False

# Restore order: lower index first (dependency order)
RESTORE_ORDER = [
    ("v1", "ServiceAccount"),
    ("v1", "Secret"),
    ("v1", "ConfigMap"),
    ("v1", "PersistentVolumeClaim"),
    ("v1", "Service"),
    ("apps/v1", "Deployment"),
    ("apps/v1", "StatefulSet"),
    ("apps/v1", "DaemonSet"),
    ("batch/v1", "CronJob"),
    ("networking.k8s.io/v1", "Ingress"),
    ("networking.k8s.io/v1", "NetworkPolicy"),
    ("policy/v1", "PodDisruptionBudget"),
    ("autoscaling/v2", "HorizontalPodAutoscaler"),
]

_META_STRIP = {
    "resourceVersion", "uid", "generation", "creationTimestamp",
    "managedFields", "selfLink", "ownerReferences",
}
_ANN_STRIP = {
    "kubectl.kubernetes.io/last-applied-configuration",
    "deployment.kubernetes.io/revision",
}
_SKIP_CONFIGMAPS = {"kube-root-ca.crt"}
_SKIP_SECRET_TYPES = (
    "kubernetes.io/service-account-token",
    "bootstrap.kubernetes.io/token",
)

# (apiVersion, kind) -> (api_slot, create_fn, replace_fn, read_fn)
_KIND_METHODS: dict[tuple[str, str], tuple[str, str, str, str]] = {
    ("v1", "ServiceAccount"): (
        "core", "create_namespaced_service_account",
        "replace_namespaced_service_account", "read_namespaced_service_account"),
    ("v1", "Secret"): (
        "core", "create_namespaced_secret",
        "replace_namespaced_secret", "read_namespaced_secret"),
    ("v1", "ConfigMap"): (
        "core", "create_namespaced_config_map",
        "replace_namespaced_config_map", "read_namespaced_config_map"),
    ("v1", "PersistentVolumeClaim"): (
        "core", "create_namespaced_persistent_volume_claim",
        "replace_namespaced_persistent_volume_claim",
        "read_namespaced_persistent_volume_claim"),
    ("v1", "Service"): (
        "core", "create_namespaced_service",
        "replace_namespaced_service", "read_namespaced_service"),
    ("apps/v1", "Deployment"): (
        "apps", "create_namespaced_deployment",
        "replace_namespaced_deployment", "read_namespaced_deployment"),
    ("apps/v1", "StatefulSet"): (
        "apps", "create_namespaced_stateful_set",
        "replace_namespaced_stateful_set", "read_namespaced_stateful_set"),
    ("apps/v1", "DaemonSet"): (
        "apps", "create_namespaced_daemon_set",
        "replace_namespaced_daemon_set", "read_namespaced_daemon_set"),
    ("batch/v1", "CronJob"): (
        "batch", "create_namespaced_cron_job",
        "replace_namespaced_cron_job", "read_namespaced_cron_job"),
    ("networking.k8s.io/v1", "Ingress"): (
        "net", "create_namespaced_ingress",
        "replace_namespaced_ingress", "read_namespaced_ingress"),
    ("networking.k8s.io/v1", "NetworkPolicy"): (
        "net", "create_namespaced_network_policy",
        "replace_namespaced_network_policy", "read_namespaced_network_policy"),
    ("policy/v1", "PodDisruptionBudget"): (
        "policy", "create_namespaced_pod_disruption_budget",
        "replace_namespaced_pod_disruption_budget",
        "read_namespaced_pod_disruption_budget"),
    ("autoscaling/v2", "HorizontalPodAutoscaler"): (
        "autos", "create_namespaced_horizontal_pod_autoscaler",
        "replace_namespaced_horizontal_pod_autoscaler",
        "read_namespaced_horizontal_pod_autoscaler"),
}


# ── Wiring (called by agent.py) ──────────────────────────────────────────────

def set_storage(storage: Any) -> None:
    global _storage
    _storage = storage


def set_labels(labels: dict[str, str]) -> None:
    global _labels, _inited
    with _lock:
        _labels = dict(labels)
        _inited = False


def set_reporter(fn: Callable[..., None]) -> None:
    global _reporter
    _reporter = fn


def is_enabled() -> bool:
    return config.DR_ENABLED


# ── Cluster clients & probing ────────────────────────────────────────────────

def probe(label: str) -> tuple[bool, str]:
    """Ensure clients for label exist and are reachable; update _probe."""
    ctx = _labels.get(label, "")
    if not ctx and not (label == "primary"):
        _probe[label] = (False, "not configured")
        return False, "not configured"
    if not ctx:
        ctx = "(default)"

    v1, _apps = _clients.get(label, (None, None))
    if v1 is None:
        from k8s_engine import init_k8s
        v1, apps = init_k8s(context=ctx if ctx != "(default)" else "")
        if v1 is None:
            _probe[label] = (False, f"context unreachable ({ctx})")
            return False, f"context unreachable ({ctx})"
        _clients[label] = (v1, apps)
        _probe[label] = (True, f"context={ctx}")
        return True, f"context={ctx}"

    try:
        v1.list_namespace(_request_timeout=5)
        _probe[label] = (True, f"context={ctx}")
        return True, f"context={ctx}"
    except Exception as e:
        _clients[label] = (None, None)  # force re-init next cycle
        _probe[label] = (False, str(e)[:100])
        return False, str(e)[:100]


def get_clients(label: str) -> tuple[Any, Any] | None:
    v1, apps = _clients.get(label, (None, None))
    return (v1, apps) if v1 is not None else None


def _api_slots(v1, apps_v1) -> dict:
    from kubernetes import client as kc
    return {
        "core": v1,
        "apps": apps_v1,
        "batch": kc.BatchV1Api(v1.api_client),
        "net": kc.NetworkingV1Api(v1.api_client),
        "policy": kc.PolicyV1Api(v1.api_client),
        "autos": kc.AutoscalingV2Api(v1.api_client),
    }


# ── Backup ───────────────────────────────────────────────────────────────────

def _sanitize(d: dict) -> dict:
    d.pop("status", None)
    md = d.get("metadata")
    if isinstance(md, dict):
        for k in _META_STRIP:
            md.pop(k, None)
        ann = md.get("annotations")
        if isinstance(ann, dict):
            for k in [k for k in ann if k in _ANN_STRIP]:
                ann.pop(k, None)
            if not ann:
                md.pop("annotations", None)
    tpl = d.get("spec")
    if isinstance(tpl, dict):
        tpl = tpl.get("template")
        if isinstance(tpl, dict):
            tmd = tpl.get("metadata")
            if isinstance(tmd, dict):
                tmd.pop("creationTimestamp", None)
                tmd.pop("annotations", None)
    return d


def _should_skip(obj: dict) -> bool:
    kind = obj.get("kind", "")
    name = (obj.get("metadata") or {}).get("name", "")
    if kind == "ConfigMap" and name in _SKIP_CONFIGMAPS:
        return True
    if kind == "Secret":
        stype = (obj.get("type") or "")
        if any(stype.startswith(p) for p in _SKIP_SECRET_TYPES):
            return True
    if kind == "ServiceAccount" and name == "default":
        return True
    return False


def collect_resources(v1, apps_v1, namespaces: list[str]) -> list[dict]:
    """Serialize all backup-able namespaced resources (sanitized)."""
    out: list[dict] = []
    slots = _api_slots(v1, apps_v1)
    include_secrets = config.DR_BACKUP_SECRETS

    def emit(items, api_v: str, kind: str) -> None:
        for it in items:
            d = v1.api_client.sanitize_for_serialization(it)
            d = _sanitize(d)
            # sanitize_for_serialization drops kind/apiVersion (None on list
            # items) — re-inject so restore can dispatch on them
            d["apiVersion"] = api_v
            d["kind"] = kind
            if not _should_skip(d):
                out.append(d)

    for ns in namespaces:
        collectors = [
            ("v1", "ServiceAccount",
             lambda n: slots["core"].list_namespaced_service_account(n)),
            ("v1", "ConfigMap",
             lambda n: slots["core"].list_namespaced_config_map(n)),
            ("v1", "Service",
             lambda n: slots["core"].list_namespaced_service(n)),
            ("v1", "PersistentVolumeClaim",
             lambda n: slots["core"].list_namespaced_persistent_volume_claim(n)),
            ("apps/v1", "Deployment",
             lambda n: slots["apps"].list_namespaced_deployment(n)),
            ("apps/v1", "StatefulSet",
             lambda n: slots["apps"].list_namespaced_stateful_set(n)),
            ("apps/v1", "DaemonSet",
             lambda n: slots["apps"].list_namespaced_daemon_set(n)),
            ("batch/v1", "CronJob",
             lambda n: slots["batch"].list_namespaced_cron_job(n)),
            ("networking.k8s.io/v1", "Ingress",
             lambda n: slots["net"].list_namespaced_ingress(n)),
            ("networking.k8s.io/v1", "NetworkPolicy",
             lambda n: slots["net"].list_namespaced_network_policy(n)),
            ("policy/v1", "PodDisruptionBudget",
             lambda n: slots["policy"].list_namespaced_pod_disruption_budget(n)),
            ("autoscaling/v2", "HorizontalPodAutoscaler",
             lambda n: slots["autos"].list_namespaced_horizontal_pod_autoscaler(n)),
        ]
        if include_secrets:
            collectors.insert(2, ("v1", "Secret",
                                  lambda n: slots["core"].list_namespaced_secret(n)))

        for api_v, kind, fn in collectors:
            try:
                emit(fn(ns).items, api_v, kind)
            except Exception as e:
                log.warning("DR backup: skipping %s in %s: %s", kind, ns, e)
    return out


def _record_event(action: str, summary: str, *, success: bool = True,
                  status: str = "Resolved", route: str = "auto_healed",
                  name: str = "", namespace: str = "", detail: str = "") -> None:
    """Record DR event: Postgres (reports/audit) + in-memory (live timeline)."""
    rec_name = name or action
    if _storage:
        try:
            _storage.record_diagnosis(
                platform="dr", name=rec_name, namespace=namespace,
                location=_labels.get("primary", ""), deployment="",
                status=status, restarts=0, action=action, route=route,
                is_developer_issue=False, llm_model="", llm_latency=None,
                summary=summary, root_cause=detail, recommendation="",
                logs="", action_result="ok" if success else "failed",
                cost_data="", success=success,
            )
        except Exception as e:
            log.warning("DR: failed to record timeline event: %s", e)
    try:
        # Lazy import: observability imports dr at module load
        from observability import diagnosis_store as _ui_store
        _ui_store.record(
            platform="dr", name=rec_name, namespace=namespace,
            location=_labels.get("primary", ""), deployment="",
            status=status, restarts=0, action=action, route=route,
            is_developer_issue=False, llm_model="", llm_latency=0.0,
            summary=summary, root_cause=detail, recommendation="",
            logs="", action_result="ok" if success else "failed",
            cost_data="", success=success,
        )
    except Exception as e:
        log.warning("DR: failed to record in-memory timeline event: %s", e)


def _record_history(table: str, sql: str, params: tuple) -> None:
    if not _storage:
        return
    try:
        conn = _storage._conn()
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            conn.commit()
        finally:
            _storage._put(conn)
    except Exception as e:
        log.warning("DR history write failed: %s", e)


def backup_manifests(label: str = "primary", created_by: str = "system",
                     notes: str = "") -> dict:
    """Snapshot watched namespaces from cluster `label`. Returns new row."""
    if not config.DR_ENABLED:
        raise RuntimeError("Disaster recovery is disabled")
    if not _storage:
        raise RuntimeError("Database not available")
    v1, apps = get_clients(label) or (None, None)
    if v1 is None:
        ok, detail = probe(label)
        v1, apps = get_clients(label) or (None, None)
        if v1 is None:
            raise RuntimeError(f"Cluster '{label}' not reachable: {detail}")

    namespaces = config.WATCH_NAMESPACES or ["default"]
    started = time.time()
    resources = collect_resources(v1, apps, namespaces)
    payload = {
        "cluster_context": _labels.get(label, label),
        "label": label,
        "namespaces": namespaces,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "resource_count": len(resources),
        "resources": resources,
    }
    blob = json.dumps(payload)
    if len(blob) > config.DR_PAYLOAD_MAX_BYTES:
        raise RuntimeError(
            f"Backup payload {len(blob) // 1024}KB exceeds limit "
            f"{config.DR_PAYLOAD_MAX_BYTES // 1024}KB")

    import uuid as _uuid
    backup_id = _uuid.uuid4().hex[:12]
    row = _storage.record_backup(
        backup_id=backup_id, cluster=label,
        namespaces=",".join(namespaces), resource_count=len(resources),
        payload=blob, byte_size=len(blob), created_by=created_by,
        label=notes,
    )
    global _last_backup_epoch
    _last_backup_epoch = time.time()
    try:
        _storage.prune_backups(config.DR_MAX_BACKUPS)
    except Exception as e:
        log.warning("DR prune failed: %s", e)

    elapsed = time.time() - started
    kb = len(blob) // 1024
    log.info("DR backup %s: %d resources, %dKB, %.1fs (%s)",
             backup_id, len(resources), kb, elapsed, created_by)
    if created_by != "auto":  # auto/startup backups stay quiet in the timeline
        _record_event(
            "backup_manifests",
            f"Cluster snapshot captured: {len(resources)} resources, {kb}KB",
            name=f"snapshot-{backup_id}", namespace=",".join(namespaces),
            detail=f"cluster={_labels.get(label, label)} source={created_by}",
        )
    return row


def _safe_backup(label: str, created_by: str) -> None:
    try:
        backup_manifests(label=label, created_by=created_by)
    except Exception as e:
        log.error("DR auto-backup failed: %s", e)


def maybe_auto_backup() -> None:
    if not config.DR_BACKUP_AUTO or not _storage:
        return
    global _last_backup_epoch, _inited
    if not _inited:
        # Seed timer from the most recent existing backup
        try:
            latest = _storage.latest_backup_at()
            if latest:
                _last_backup_epoch = latest.timestamp()
            _inited = True
            if not latest:
                threading.Thread(
                    target=_safe_backup, args=("primary", "startup"),
                    daemon=True, name="dr-startup-backup").start()
                return
        except Exception as e:
            log.warning("DR: could not seed backup timer: %s", e)
            _inited = True
    if time.time() - _last_backup_epoch < config.DR_BACKUP_INTERVAL_SEC:
        return
    log.info("DR: scheduled backup due (interval %ss)", config.DR_BACKUP_INTERVAL_SEC)
    threading.Thread(
        target=_safe_backup, args=("primary", "auto"),
        daemon=True, name="dr-auto-backup").start()
    _last_backup_epoch = time.time()  # avoid thread pileups


def initial_backup() -> None:
    """Called once at agent startup: guarantees at least one snapshot exists."""
    maybe_auto_backup()


# ── Disaster detection ───────────────────────────────────────────────────────

def _send_email(subject: str, rows_html: str, color: str = "#d9534f",
                badge: str = "DISASTER") -> None:
    try:
        from notifications import send_dr_alert_email
        send_dr_alert_email(subject, rows_html, color, badge)
    except Exception as e:
        log.warning("DR email failed: %s", e)


def _handle_disaster(ok: bool, detail: str) -> None:
    global _fail_streak, _disaster
    if ok:
        if _disaster["active"]:
            since = _disaster.get("since", "")
            _disaster = {"active": False, "cluster": "", "detail": "", "since": ""}
            _record_event(
                "disaster_recovered",
                f"Primary DR cluster reachable again after outage",
                status="Resolved", route="auto_healed",
                name="dr-primary-recovery", detail=f"since={since}",
            )
            _send_email(
                "RECOVERED: DR primary cluster is reachable again",
                f"<tr><td>Recovered at</td><td>{_ts()}</td></tr>"
                f"<tr><td>Was down since</td><td>{since}</td></tr>",
                color="#2ea043", badge="RECOVERED",
            )
            log.info("DR: primary cluster recovered")
        _fail_streak = 0
        return

    _fail_streak += 1
    if _disaster["active"]:
        return  # already alerted; keep state
    if _fail_streak < config.DR_DISASTER_FAIL_CYCLES:
        return

    ctx = _labels.get("primary", "(default)")
    _disaster = {
        "active": True, "cluster": ctx, "detail": detail,
        "since": _ts(),
    }
    last = None
    try:
        rows = _storage.list_backups(limit=1) if _storage else []
        last = rows[0] if rows else None
    except Exception:
        pass
    backup_note = (
        f"latest snapshot {last['created_at']} "
        f"({last['resource_count']} resources) ready for restore"
        if last else "no snapshot available — take a backup now"
    )
    log.error("DR DISASTER: cluster %s unreachable (%s)", ctx, detail)
    _record_event(
        "disaster_detected",
        f"DISASTER: cluster {ctx} unreachable for "
        f"{_fail_streak * config.POLL_INTERVAL_SEC}s — {backup_note}",
        success=False, status="Critical", route="needs_escalation",
        name="dr-primary-down", detail=detail,
    )
    _send_email(
        f"DISASTER: cluster {ctx} unreachable",
        f"<tr><td>Cluster</td><td>{ctx}</td></tr>"
        f"<tr><td>Since</td><td>{_disaster['since']}</td></tr>"
        f"<tr><td>Error</td><td>{detail}</td></tr>"
        f"<tr><td>Restore point</td><td>{backup_note}</td></tr>",
    )
    try:
        from notifications import notify_n8n
        notify_n8n({
            "route": "disaster",
            "cluster": ctx,
            "detail": detail,
            "since": _disaster["since"],
            "restore_point": backup_note,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        log.warning("DR n8n notify failed: %s", e)


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def poll_cycle() -> None:
    """Per agent cycle: probe clusters, disaster state, report, auto-backup."""
    if not config.DR_ENABLED:
        return
    ok, detail = probe("primary")
    _handle_disaster(ok, detail)
    if _reporter:
        _reporter("k8s_dr_primary", ok, detail)
        if _labels.get("standby"):
            s_ok, s_detail = probe("standby")
            _reporter("k8s_dr_standby", s_ok, s_detail)
    maybe_auto_backup()


# ── Restore ──────────────────────────────────────────────────────────────────

def _sort_resources(resources: list[dict]) -> list[dict]:
    def key(r: dict) -> int:
        api = r.get("apiVersion", "")
        kind = r.get("kind", "")
        for i, (want_api, want_kind) in enumerate(RESTORE_ORDER):
            if kind == want_kind and api == want_api:
                return i
        return len(RESTORE_ORDER)
    return sorted(resources, key=key)


def _apply_one(api, create_fn: str, replace_fn: str, read_fn: str,
               body: dict, ns: str) -> str:
    from kubernetes.client import ApiException
    name = body["metadata"]["name"]
    try:
        # create_* methods take (namespace, body) — no name kwarg
        getattr(api, create_fn)(namespace=ns, body=body)
        return "created"
    except ApiException as e:
        if e.status != 409:
            raise
        cur = getattr(api, read_fn)(name=name, namespace=ns)
        cur_dict = api.api_client.sanitize_for_serialization(cur)
        cur_md = cur_dict.get("metadata") or {}
        cur_spec = cur_dict.get("spec") or {}
        new_body = copy.deepcopy(body)
        md = new_body.setdefault("metadata", {})
        # keep identity fields required for replace
        md["resourceVersion"] = cur_md.get("resourceVersion")
        if cur_md.get("uid"):
            md["uid"] = cur_md.get("uid")
        new_spec = new_body.get("spec")
        if isinstance(new_spec, dict) and body.get("kind") == "Service":
            # immutable/allocated fields must carry over on replace
            for f in ("clusterIP", "clusterIPs", "ipFamilies",
                      "ipFamilyPolicy", "internalTrafficPolicy"):
                if f in cur_spec and f not in new_spec:
                    new_spec[f] = cur_spec[f]
            # per-port nodePort allocation
            cur_ports = {p.get("port"): p.get("nodePort")
                         for p in (cur_spec.get("ports") or [])
                         if p.get("nodePort")}
            for p in (new_spec.get("ports") or []):
                if "nodePort" not in p and cur_ports.get(p.get("port")):
                    p["nodePort"] = cur_ports[p["port"]]
        getattr(api, replace_fn)(name=name, namespace=ns, body=new_body)
        return "updated"


def _verify(v1, apps_v1, resources: list[dict], namespaces: list[str]) -> str:
    """Wait for restored workloads to become ready. Returns summary text."""
    workloads = [
        (r["metadata"]["name"], r["metadata"].get("namespace", "default"))
        for r in resources
        if r.get("kind") in ("Deployment", "StatefulSet", "DaemonSet")
        and (r.get("spec") or {}).get("replicas", 1)
    ]
    if not workloads:
        return "no workloads to verify (configs/services only)"

    def check() -> tuple[int, list[str]]:
        ready, not_ready = 0, []
        for kind in ("Deployment", "StatefulSet", "DaemonSet"):
            for r in resources:
                if r.get("kind") != kind:
                    continue
                name = r["metadata"]["name"]
                ns = r["metadata"].get("namespace", "default")
                try:
                    if kind == "Deployment":
                        obj = apps_v1.read_namespaced_deployment(name, ns)
                        rr = obj.status.ready_replicas or 0
                        want = obj.spec.replicas or 1
                    elif kind == "StatefulSet":
                        obj = apps_v1.read_namespaced_stateful_set(name, ns)
                        rr = obj.status.ready_replicas or 0
                        want = obj.spec.replicas or 1
                    else:
                        obj = apps_v1.read_namespaced_daemon_set(name, ns)
                        rr = obj.status.number_ready or 0
                        want = 1
                    if rr >= want:
                        ready += 1
                    else:
                        not_ready.append(f"{kind}/{name} ({rr}/{want})")
                except Exception as e:
                    not_ready.append(f"{kind}/{name} ({e})")
        return ready, not_ready

    deadline = time.time() + config.DR_VERIFY_TIMEOUT_SEC
    ready, not_ready = check()
    while time.time() < deadline and not_ready:
        time.sleep(3)
        ready, not_ready = check()
    total = ready + len(not_ready)
    if not not_ready:
        return f"{ready}/{total} workloads ready ✓"
    return f"{ready}/{total} workloads ready — waiting: {'; '.join(not_ready[:4])}"


def restore_backup(backup_id: str, target: str = "primary") -> str:
    """Apply a stored snapshot to `target` cluster (primary|standby)."""
    if not config.DR_ENABLED:
        return "[ERROR] Disaster recovery is disabled"
    if not _storage:
        return "[ERROR] Database not available"
    row = _storage.get_backup(backup_id)
    if not row:
        return f"[ERROR] Backup {backup_id} not found"

    ok, detail = probe(target)
    clients = get_clients(target)
    if not ok or clients is None:
        return f"[ERROR] Target cluster '{target}' unreachable: {detail}"
    v1, apps_v1 = clients

    payload = json.loads(row["payload"])
    resources = _sort_resources(payload.get("resources", []))
    if not resources:
        return "[ERROR] Backup contains no resources"
    namespaces = [ns for ns in (payload.get("namespaces") or []) if ns]

    slots = _api_slots(v1, apps_v1)
    created = updated = failed = 0
    failures: list[str] = []
    for r in resources:
        api_v = r.get("apiVersion", "")
        kind = r.get("kind", "")
        ns = (r.get("metadata") or {}).get("namespace")
        if not ns:
            continue  # cluster-scoped resources are not backed up
        method = _KIND_METHODS.get((api_v, kind))
        if method:
            slot, create_fn, replace_fn, read_fn = method
        else:
            failed += 1
            failures.append(f"{kind} (unsupported)")
            continue
        try:
            res = _apply_one(slots[slot], create_fn, replace_fn, read_fn, r, ns)
            if res == "created":
                created += 1
            else:
                updated += 1
        except Exception as e:
            failed += 1
            failures.append(f"{kind}/{r['metadata']['name']}: {str(e)[:120]}")

    applied = created + updated
    msg = (f"Restored {applied}/{len(resources)} resources to '{target}' "
           f"({created} created, {updated} replaced)")
    if failed:
        msg += f"; FAILED {failed}: " + "; ".join(failures[:5])

    verify_msg = "restore failed before verification"
    if applied and not failed:
        verify_msg = _verify(v1, apps_v1, resources, namespaces)
    elif applied:
        verify_msg = _verify(v1, apps_v1, resources, namespaces)

    full = f"{msg} — {verify_msg}"
    success = failed == 0 and applied > 0
    _record_event(
        "restore_backup",
        f"Restore to '{target}' cluster: {full}",
        success=success, status="Resolved" if success else "Critical",
        route="auto_healed" if success else "rollback",
        name=f"restore-{backup_id}", namespace=",".join(namespaces),
        detail=f"backup={backup_id} target_context={_labels.get(target, target)}",
    )
    if not _disaster["active"]:
        pass  # normal restore — timeline is enough
    log.info("DR restore %s -> %s: %s", backup_id, target, full)
    return full


def execute_approved(params: dict) -> str:
    """Entry point used by the approval executor (platform='dr')."""
    backup_id = params.get("backup_id", "")
    target = params.get("target", "primary")
    return restore_backup(backup_id, target)


# ── Status (for /dr/status) ─────────────────────────────────────────────────

def get_status() -> dict:
    def cluster_info(label: str) -> dict:
        ctx = _labels.get(label, "")
        ok, detail = _probe.get(label, (False, "not probed yet"))
        return {
            "configured": bool(ctx) or label == "primary",
            "context": ctx or "(default)",
            "connected": ok if label in _probe else False,
            "detail": detail,
        }

    count = 0
    last_at = None
    if _storage:
        try:
            count = _storage.backup_count()
            last = _storage.latest_backup_at()
            last_at = last.isoformat() if last else None
        except Exception:
            pass

    return {
        "enabled": config.DR_ENABLED,
        "primary": cluster_info("primary"),
        "standby": cluster_info("standby"),
        "velero": config.VELERO_ENABLED,
        "mode": ("Manifest snapshots (Velero: future)"
                 if not config.VELERO_ENABLED else "Manifest + Velero snapshots"),
        "auto_backup": {
            "enabled": config.DR_BACKUP_AUTO,
            "interval_sec": config.DR_BACKUP_INTERVAL_SEC,
        },
        "backup_count": count,
        "last_backup_at": last_at,
        "disaster": dict(_disaster),
        "namespaces": config.WATCH_NAMESPACES or ["default"],
        "secrets_included": config.DR_BACKUP_SECRETS,
    }
