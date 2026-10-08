"""Healix Scaler — event-driven, KEDA-style replica scaling.

    external metric -> desired replicas -> guardrails -> execute -> verify -> show

Deliberately does NOT involve the LLM: scaling is deterministic math on a
10-15s poll (same event model KEDA itself uses). Guardrails are non-negotiable:

  * conflict detection — skip Deployments owned by an HPA or KEDA ScaledObject
  * hard caps — minReplicas/maxReplicas/scaleUpStepMax enforced in code
  * never bounce_deployment (it scales to 0 mid-spike)
  * fail static — a broken/unreachable source keeps current replicas
  * cooldown in both directions — no flapping
  * PDB check before every scale-down
  * circuit breaker pauses a rule whose scaling keeps failing
  * per-rule state (NOT the never-resetting heal-tracking structures)

Runs in its own daemon thread (same pattern as K8sEventWatcher) so the 30s
main loop and the approval executor never block it.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import deque
from datetime import datetime, timezone

from config import (
    SCALE_ENABLED, SCALE_POLL_INTERVAL_SEC, SCALE_RULES, SCALE_VERIFY_TIMEOUT_SEC,
    DRY_RUN,
)
from k8s_engine import execute_action_k8s
from pdbs import check_pdb_before_scale
from scalers import build_scalers
from notifications import send_slack, send_approval_email, notify_n8n

log = logging.getLogger("scale_engine")

# ── Engine singleton state ───────────────────────────────────────────────────

_thread: threading.Thread | None = None
_stop = threading.Event()
_storage = None
_approval_store = None
_circuit_breaker = None
_v1 = None
_apps_v1 = None
_scalers: dict = {}
_states: dict[str, "RuleState"] = {}
_events: deque = deque(maxlen=100)


class RuleState:
    """Per-rule mutable state (cooldowns live here, never in heal tracking)."""

    def __init__(self, rule: dict) -> None:
        self.rule = rule
        self.paused = False
        self.state = "init"
        self.last_metric: float | None = None
        self.desired: int | None = None
        self.current: int | None = None
        self.down_since: float | None = None
        self.cooldown_until: float = 0.0
        self.conflict = ""
        self.source_error = False
        self.approval_id: str | None = None
        self.last_action = ""
        self.last_reason = ""
        self.last_eval_at = ""
        self.count_up = 0
        self.count_down = 0
        self.source_errors = 0
        self._alerted_source_down = False
        self._alerted_conflict = False
        self._alerted_pdb = False


def configure(*, storage=None, approval_store=None, circuit_breaker=None,
              v1=None, apps_v1=None) -> None:
    global _storage, _approval_store, _circuit_breaker, _v1, _apps_v1
    _storage = storage
    _approval_store = approval_store
    _circuit_breaker = circuit_breaker
    _v1 = v1
    _apps_v1 = apps_v1


def start() -> bool:
    """Start the scaler thread. Returns True if running."""
    global _thread, _scalers
    if not SCALE_ENABLED:
        log.info("Healix Scaler disabled (SCALE_ENABLED=false)")
        return False
    if not SCALE_RULES:
        log.warning("Healix Scaler enabled but no valid rules in %s", "scale_rules.yaml")
        return False
    if _thread and _thread.is_alive():
        return True
    _scalers = build_scalers()
    _rule_states()  # build states now so /scaling/status is instant
    _stop.clear()
    _thread = threading.Thread(target=_run, daemon=True, name="healix-scaler")
    _thread.start()
    log.info("Healix Scaler started — %d rule(s), poll %ds",
             len(SCALE_RULES), SCALE_POLL_INTERVAL_SEC)
    return True


def stop() -> None:
    _stop.set()


def is_running() -> bool:
    return bool(_thread and _thread.is_alive())


# ── Rule states ──────────────────────────────────────────────────────────────

def _rule_states() -> dict[str, RuleState]:
    for rule in SCALE_RULES:
        name = rule["name"]
        if name not in _states:
            _states[name] = RuleState(rule)
            _states[name].desired = int(rule.get("minReplicas", 1))
    return _states


def pause_rule(name: str) -> bool:
    st = _states.get(name)
    if not st:
        return False
    st.paused = True
    st.state = "paused"
    _push_event(name, "paused", None, None, "paused from dashboard", "manual")
    return True


def resume_rule(name: str) -> bool:
    st = _states.get(name)
    if not st:
        return False
    st.paused = False
    st.state = "steady"
    _push_event(name, "resumed", None, None, "resumed from dashboard", "manual")
    return True


# ── Main loop ────────────────────────────────────────────────────────────────

def _run() -> None:
    states = _rule_states()
    # Poll at the fastest rule interval (never slower than the global default
    # would suggest, never faster than 5s).
    interval = SCALE_POLL_INTERVAL_SEC
    for rule in SCALE_RULES:
        interval = min(interval, max(5, int(rule.get("pollingIntervalSec", SCALE_POLL_INTERVAL_SEC))))
    while not _stop.is_set():
        for name, st in states.items():
            if _stop.is_set():
                break
            try:
                _evaluate(st)
            except Exception as e:
                log.error("Scale rule %s evaluation error: %s", name, e)
                st.state = "error"
                st.last_reason = str(e)[:200]
        _stop.wait(interval)


def _evaluate(st: RuleState) -> None:
    rule = st.rule
    ns, dep = rule["namespace"], rule["deployment"]
    st.last_eval_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if st.paused:
        st.state = "paused"
        return

    # ── 1. Conflict: HPA or KEDA already owns this Deployment ────────────────
    conflict = _find_conflict(ns, dep)
    if conflict:
        if not st._alerted_conflict:
            st._alerted_conflict = True
            _push_event(rule["name"], "conflict", None, None,
                        f"{conflict} already manages {dep}", "guardrail")
        st.conflict = conflict
        st.state = "conflict"
        return
    st.conflict = ""
    st._alerted_conflict = False

    # ── 2. Current replicas (fail static if target missing) ─────────────────
    current = _current_replicas(ns, dep)
    if current is None:
        st.state = "unknown_target"
        return
    st.current = current

    # ── 3. Approval in flight? (wait for human, don't re-evaluate) ──────────
    if st.approval_id:
        _advance_approval(st)
        if st.approval_id:
            st.state = "awaiting_approval"
            return

    # ── 4. Read the metric ──────────────────────────────────────────────────
    desired_full, metric_value, ok = _desired_replicas(rule)
    st.last_metric = metric_value
    if not ok:
        st.source_error = True
        st.source_errors += 1
        st.state = "source_down"
        if not st._alerted_source_down:
            st._alerted_source_down = True
            _alert(rule, "Source down", "#d9534f",
                   [("Rule", rule["name"]), ("Target", dep),
                    ("Detail", "metric query failed — holding at "
                               f"{current} replica(s)")],
                   "scale-source-down")
        return
    st.source_error = False
    st._alerted_source_down = False

    lo, hi = int(rule["minReplicas"]), int(rule["maxReplicas"])
    raw_desired = max(lo, min(hi, int(desired_full)))
    st.desired = raw_desired

    # ── 5. Direction ────────────────────────────────────────────────────────
    if raw_desired > current:
        # Scale UP: immediate, bounded by scaleUpStepMax
        st.down_since = None
        step = max(1, int(rule.get("scaleUpStepMax", 3)))
        desired = min(raw_desired, current + step)
        if desired <= current:
            st.state = "at_max" if raw_desired >= hi else "steady"
            return
        reason = (f"metric {metric_value:g} vs target "
                  f"{_target_of(rule):g}/pod → {raw_desired} wanted")
        _scale_up(st, current, desired, raw_desired, reason)
    elif raw_desired < current:
        # Scale DOWN / to zero: only after cooldownSec of sustained low metric
        now = time.time()
        if st.down_since is None:
            st.down_since = now
        cooldown = int(rule.get("cooldownSec", 300))
        if now - st.down_since < cooldown:
            st.cooldown_until = st.down_since + cooldown
            st.state = "cooldown"
            return
        viol = check_pdb_before_scale(_apps_v1, ns, dep, raw_desired)
        if viol:
            st.state = "pdb_blocked"
            if not st._alerted_pdb:
                st._alerted_pdb = True
                _push_event(rule["name"], "pdb_blocked", current, raw_desired,
                            viol, "guardrail")
            return
        st._alerted_pdb = False
        reason = (f"metric {metric_value:g} below target for {cooldown}s")
        _execute(st, current, raw_desired, rule, reason,
                 direction="down", mode="auto")
        st.down_since = None  # full cooldown before the next down-step
    else:
        st.down_since = None
        if current == 0:
            st.state = "zero"
        elif raw_desired >= hi:
            st.state = "at_max"
        else:
            st.state = "steady"
        st.cooldown_until = 0.0


def _scale_up(st: RuleState, current: int, desired: int, raw_desired: int,
              reason: str) -> None:
    rule = st.rule
    uid = f"k8s/{rule['namespace']}/{rule['deployment']}"

    if _circuit_breaker:
        allowed, why = _circuit_breaker.can_heal(uid)
        if not allowed:
            st.state = "paused"
            st.last_reason = f"circuit breaker: {why}"
            return

    if rule.get("requireApproval") and _approval_store:
        if not st.approval_id:
            st.approval_id = _create_approval(st, current, desired, reason)
            st.state = "awaiting_approval"
            _push_event(rule["name"], "awaiting_approval", current, desired,
                        reason, "approval")
        return

    _execute(st, current, desired, rule, reason, direction="up", mode="auto")


def _execute(st: RuleState, current: int, desired: int, rule: dict,
             reason: str, *, direction: str, mode: str) -> None:
    ns, dep = rule["namespace"], rule["deployment"]
    uid = f"k8s/{ns}/{dep}"
    params = {
        "namespace": ns, "deployment": dep, "replicas": desired,
        "summary": f"Scalable rule '{rule['name']}': {current} -> {desired}",
        "rule": rule["name"],
    }
    st.last_reason = reason
    try:
        result = execute_action_k8s("scale_deployment", params, _v1, _apps_v1)
        if result.startswith("Cannot"):
            raise RuntimeError(result)
    except Exception as e:
        log.error("Scale rule %s: execute failed: %s", rule["name"], e)
        st.state = "error"
        st.last_action = f"{current} -> {desired} FAILED"
        if _circuit_breaker:
            _circuit_breaker.record_heal(uid, "scale_deployment", False)
        _push_event(rule["name"], "failed", current, desired, str(e)[:200], mode)
        _alert(rule, "Scale action failed", "#d9534f",
               [("Rule", rule["name"]), ("Target", dep),
                ("Attempt", f"{current} → {desired}"), ("Error", str(e)[:200])],
               "scale-failed")
        return

    verified = True
    detail = ""
    if not DRY_RUN:
        verified, detail = _verify(ns, dep, desired)

    st.last_action = f"{current} -> {desired}"
    if direction == "up":
        st.count_up += 1
        st.state = "scaling_up" if verified else "unverified"
    else:
        st.count_down += 1
        st.state = "zero" if desired == 0 else ("scaling_down" if verified else "unverified")

    if _circuit_breaker:
        _circuit_breaker.record_heal(uid, "scale_deployment", verified)

    _push_event(rule["name"], direction, current, desired,
                reason + (f" ({detail})" if detail else ""), mode, ok=verified)
    _record_timeline(rule, current, desired, reason, success=verified)

    verb = "scaled up" if direction == "up" else "scaled down"
    color = "#27ae60" if direction == "up" else ("#7d6608" if desired else "#b8860b")
    _alert(rule, f"Healix {verb} {dep}", color,
           [("Rule", rule["name"]), ("Target", f"k8s/{ns}"),
            ("Replicas", f"{current} → {desired}"),
            ("Reason", reason),
            ("Verify", "ok" if verified else (detail or "unverified"))],
           f"scale-{direction}")


# ── Metric → replicas ────────────────────────────────────────────────────────

def _desired_replicas(rule: dict) -> tuple[int, float | None, bool]:
    """KEDA's formula, per trigger: ceil(metric / targetPerPod), highest wins."""
    best = 0
    best_metric: float | None = None
    any_ok = False
    for t in rule.get("triggers", []):
        sc = _scalers.get((t.get("type") or "").strip())
        if not sc:
            continue
        val = sc.get_metric(t)
        if val is None:
            continue
        any_ok = True
        target = _float(t.get("targetPerPod"), 0.0)
        if target <= 0:
            log.warning("Rule %s: targetPerPod must be > 0", rule["name"])
            continue
        activation = _float(t.get("activationThreshold"), 1.0)
        if val >= activation:
            d = math.ceil(val / target)
            if d > best:
                best = d
                best_metric = val
        elif best_metric is None:
            best_metric = val
    return best, best_metric, any_ok


def _target_of(rule: dict) -> float:
    for t in rule.get("triggers", []):
        v = _float(t.get("targetPerPod"), 0.0)
        if v > 0:
            return v
    return 0.0


def _float(v, default: float) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


# ── Kubernetes helpers ───────────────────────────────────────────────────────

def _current_replicas(ns: str, dep: str) -> int | None:
    try:
        s = _apps_v1.read_namespaced_deployment_scale(name=dep, namespace=ns)
        return int(s.spec.replicas or 0)
    except Exception as e:
        log.debug("Cannot read scale for %s/%s: %s", ns, dep, e)
        return None


def _find_conflict(ns: str, dep: str) -> str:
    """HPA/KEDA already managing this Deployment? (two controllers = flapping)."""
    if not _v1:
        return ""
    try:
        from kubernetes import client
        co = client.CustomObjectsApi(api_client=_v1.api_client)
        try:
            hpas = co.list_namespaced_custom_object(
                "autoscaling", "v2", ns, "horizontalpodautoscalers")
            for h in hpas.get("items") or []:
                ref = (h.get("spec") or {}).get("scaleTargetRef") or {}
                if ref.get("kind") == "Deployment" and ref.get("name") == dep:
                    return f"HPA/{h.get('metadata', {}).get('name', '?')}"
        except Exception:
            pass
        try:
            sos = co.list_namespaced_custom_object(
                "keda.sh", "v1alpha1", ns, "scaledobjects")
            for s in sos.get("items") or []:
                ref = (s.get("spec") or {}).get("scaleTargetRef") or {}
                if (ref.get("deploymentName") == dep or ref.get("name") == dep):
                    return f"KEDA/{s.get('metadata', {}).get('name', '?')}"
        except Exception:
            pass  # KEDA CRD not installed — nothing to conflict with
    except Exception as e:
        log.debug("Conflict check failed: %s", e)
    return ""


def _verify(ns: str, dep: str, desired: int) -> tuple[bool, str]:
    """Scaling must actually happen: replicas set, and pods ready (if >0)."""
    deadline = time.time() + SCALE_VERIFY_TIMEOUT_SEC
    last = ""
    while time.time() < deadline:
        try:
            s = _apps_v1.read_namespaced_deployment_scale(name=dep, namespace=ns)
            set_ok = int(s.spec.replicas or 0) == desired
            if desired == 0:
                return set_ok, "" if set_ok else f"replicas not {desired} yet"
            d = _apps_v1.read_namespaced_deployment(name=dep, namespace=ns)
            ready = d.status.ready_replicas or 0
            if set_ok and ready >= desired:
                return True, ""
            last = f"ready {ready}/{desired}"
        except Exception as e:
            last = str(e)[:80]
        time.sleep(2)
    return False, f"verify timeout ({last})"


# ── Approval path ────────────────────────────────────────────────────────────

def _create_approval(st: RuleState, current: int, desired: int,
                     reason: str) -> str:
    rule = st.rule
    ns, dep = rule["namespace"], rule["deployment"]
    params = {
        "namespace": ns, "deployment": dep, "replicas": desired,
        "summary": f"Healix Scaler wants {dep}: {current} → {desired} replicas",
        "root_cause": f"Scaling rule '{rule['name']}': {reason}",
        "recommendation": "Approve to scale out; reject to keep current replicas",
        "reason": "scale rule has requireApproval=true",
        "rule": rule["name"],
    }
    aid = _approval_store.create(
        target={"name": dep, "namespace": ns, "deployment": dep,
                "original_replicas": current},
        action="scale_deployment",
        params=params,
        platform="k8s",
        location=f"k8s/{ns}",
        issue_type="autoscaling",
        restarts=0,
        logs="",
        used_model="healix-scaler",
        cost_data="",
        is_developer_issue=False,
    )
    send_approval_email(aid, dep, f"k8s/{ns}", params, "autoscaling", "k8s",
                        0, "", "")
    notify_n8n({
        "route": "needs_approval",
        "approval_id": aid,
        "platform": "k8s",
        "location": f"k8s/{ns}",
        "target_name": dep,
        "issue_type": "autoscaling",
        "is_developer_issue": False,
        "action": "scale_deployment",
        "summary": params["summary"],
        "root_cause": params["root_cause"],
        "recommendation": params["recommendation"],
        "diagnosed_by": "healix-scaler",
        "restart_count": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    log.info("Scale rule %s — approval %s created (%s→%s)",
             rule["name"], aid, current, desired)
    return aid


def _advance_approval(st: RuleState) -> None:
    """Clear st.approval_id once the approval executor finished with it."""
    req = _approval_store.get(st.approval_id) if _approval_store else None
    if req is None or req.status in ("pending", "approved"):
        if req is None:
            # Store restarted / expired — release the rule.
            _push_event(st.rule["name"], "approval_expired", st.current,
                        st.desired, "approval no longer exists", "approval")
            st.approval_id = None
        return
    status = req.status  # executed | rejected
    _push_event(st.rule["name"], f"approval_{status}", st.current, st.desired,
                f"approval {st.approval_id} {status} by "
                f"{req.approved_by or 'system'}", "approval")
    st.approval_id = None


# ── Events / timeline / notifications ────────────────────────────────────────

def _push_event(rule: str, direction: str, from_r: int | None, to_r: int | None,
                reason: str, mode: str, ok: bool = True) -> None:
    _events.append({
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "rule": rule, "direction": direction,
        "from": from_r, "to": to_r,
        "reason": reason, "mode": mode, "ok": ok,
    })


def _record_timeline(rule: dict, current: int, desired: int, reason: str,
                     *, success: bool) -> None:
    """Dual-write: Postgres (reports) + in-memory store (live Timeline tab)."""
    summary = (f"Scaled {rule['deployment']} {current} → {desired} replicas — "
               f"{reason}")
    if _storage:
        try:
            _storage.record_diagnosis(
                platform="k8s", name=rule["deployment"],
                namespace=rule["namespace"], location=f"k8s/{rule['namespace']}",
                deployment=rule["deployment"], status="Auto-scaled", restarts=0,
                action="scale_deployment", route="scaled",
                is_developer_issue=False, llm_model="healix-scaler",
                llm_latency=None, summary=summary,
                root_cause=f"Scaling rule '{rule['name']}'",
                recommendation="", logs="",
                action_result="ok" if success else "verify failed",
                cost_data="", success=success,
            )
        except Exception as e:
            log.warning("Scaler: failed to record timeline event: %s", e)
    try:
        from observability import diagnosis_store as _ui_store
        _ui_store.record(
            platform="k8s", name=rule["deployment"],
            namespace=rule["namespace"], location=f"k8s/{rule['namespace']}",
            deployment=rule["deployment"], status="Auto-scaled", restarts=0,
            action="scale_deployment", route="scaled",
            is_developer_issue=False, llm_model="healix-scaler",
            llm_latency=0.0, summary=summary,
            root_cause=f"Scaling rule '{rule['name']}'",
            recommendation="", logs="",
            action_result="ok" if success else "verify failed",
            cost_data="", success=success,
        )
    except Exception:
        pass


def _alert(rule: dict, title: str, color: str,
           fields: list[tuple[str, str]], label: str) -> None:
    try:
        send_slack(title, color, fields, label=label, footer="Healix Scaler")
    except Exception as e:
        log.warning("Scaler slack alert failed: %s", e)


# ── Dashboard / metrics interfaces ───────────────────────────────────────────

def get_status() -> dict:
    states = _rule_states()
    rules = []
    for name, st in states.items():
        r = st.rule
        sources = sorted({(t.get("type") or "?") for t in r.get("triggers", [])})
        cooldown_left = 0.0
        if st.cooldown_until:
            cooldown_left = max(0.0, st.cooldown_until - time.time())
        rules.append({
            "name": name,
            "namespace": r["namespace"],
            "deployment": r["deployment"],
            "source": ",".join(sources),
            "metric": st.last_metric,
            "target": _target_of(r),
            "desired": st.desired,
            "actual": st.current,
            "state": st.state,
            "conflict": st.conflict,
            "paused": st.paused,
            "approval_id": st.approval_id,
            "cooldown_left": round(cooldown_left),
            "cooldown_sec": int(r.get("cooldownSec", 300)),
            "poll_sec": int(r.get("pollingIntervalSec", SCALE_POLL_INTERVAL_SEC)),
            "min": int(r.get("minReplicas", 1)),
            "max": int(r.get("maxReplicas", 5)),
            "step_max": int(r.get("scaleUpStepMax", 3)),
            "require_approval": bool(r.get("requireApproval")),
            "last_action": st.last_action,
            "last_reason": st.last_reason,
            "last_eval_at": st.last_eval_at,
            "count_up": st.count_up,
            "count_down": st.count_down,
            "source_errors": st.source_errors,
            "source_error": st.source_error,
        })
    return {
        "enabled": SCALE_ENABLED,
        "engine": "running" if is_running() else "stopped",
        "poll_interval_sec": SCALE_POLL_INTERVAL_SEC,
        "rules": rules,
        "events": list(_events)[::-1][:50],
    }


def prometheus_lines() -> str:
    """healer_scale_* gauges/counters for /metrics/raw (scrapeable by Grafana)."""
    if not SCALE_ENABLED:
        return ""
    out: list[str] = []
    states = _rule_states()

    def gauge(name: str, help_txt: str, fn) -> None:
        out.append(f"# HELP {name} {help_txt}")
        out.append(f"# TYPE {name} gauge")
        for rule_name, st in states.items():
            v = fn(st)
            if v is None:
                continue
            out.append(f'{name}{{rule="{rule_name}"}} {v}')

    gauge("healer_scale_desired_replicas", "Desired replicas from metric math",
          lambda s: s.desired)
    gauge("healer_scale_actual_replicas", "Current replicas on the cluster",
          lambda s: s.current)
    gauge("healer_scale_metric_value", "Latest metric value from the source",
          lambda s: s.last_metric)
    out.append("# HELP healer_scale_events_total Scaling actions by direction")
    out.append("# TYPE healer_scale_events_total counter")
    for rule_name, st in states.items():
        out.append(f'healer_scale_events_total{{rule="{rule_name}",direction="up"}} {st.count_up}')
        out.append(f'healer_scale_events_total{{rule="{rule_name}",direction="down"}} {st.count_down}')
    out.append("# HELP healer_scale_source_errors_total Failed metric reads")
    out.append("# TYPE healer_scale_source_errors_total counter")
    for rule_name, st in states.items():
        out.append(f'healer_scale_source_errors_total{{rule="{rule_name}"}} {st.source_errors}')
    return "\n".join(out) + "\n"
