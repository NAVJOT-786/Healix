#!/usr/bin/env python3
"""
Human-in-the-loop approval flow for the AI healing agent.

When APPROVAL_MODE=true, the agent diagnoses issues but pauses before executing.
Approval can happen via the dashboard or email reply.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("healer.approval")


@dataclass
class ApprovalRequest:
    id: str
    created_at: str
    status: str  # pending | approved | rejected | executed | expired
    target: dict
    action: str
    params: dict
    platform: str
    location: str
    issue_type: str
    restarts: int
    logs: str
    used_model: str
    cost_data: str
    is_developer_issue: bool
    summary: str = ""
    root_cause: str = ""
    recommendation: str = ""
    approved_by: str = ""
    approved_at: str = ""
    rejected_by: str = ""
    action_result: str = ""
    rolled_back: bool = False
    deleted: bool = False


class ApprovalStore:
    def __init__(self, max_size: int = 50, timeout_hours: float = 24.0) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()
        self._max_size = max_size
        self._timeout_hours = timeout_hours

    def create(
        self,
        target: dict,
        action: str,
        params: dict,
        platform: str,
        location: str,
        issue_type: str,
        restarts: int,
        logs: str,
        used_model: str,
        cost_data: str,
        is_developer_issue: bool,
    ) -> str:
        approval_id = uuid.uuid4().hex[:12]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        req = ApprovalRequest(
            id=approval_id,
            created_at=now,
            status="pending",
            target=target,
            action=action,
            params=params,
            platform=platform,
            location=location,
            issue_type=issue_type,
            restarts=restarts,
            logs=logs,
            used_model=used_model,
            cost_data=cost_data,
            is_developer_issue=is_developer_issue,
            summary=params.get("summary", ""),
            root_cause=params.get("root_cause", ""),
            recommendation=params.get("recommendation", ""),
        )
        with self._lock:
            self._requests[approval_id] = req
            if len(self._requests) > self._max_size:
                oldest = min(self._requests, key=lambda k: self._requests[k].created_at)
                del self._requests[oldest]
        log.info("Approval request created: %s for %s", approval_id, target.get("name", "?"))
        return approval_id

    def approve(self, approval_id: str, by: str = "dashboard") -> bool:
        with self._lock:
            req = self._requests.get(approval_id)
            if not req or req.status != "pending":
                return False
            req.status = "approved"
            req.approved_by = by
            req.approved_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        log.info("Approval %s APPROVED by %s", approval_id, by)
        return True

    def reject(self, approval_id: str, by: str = "dashboard") -> bool:
        with self._lock:
            req = self._requests.get(approval_id)
            if not req or req.status != "pending":
                return False
            req.status = "rejected"
            req.rejected_by = by
        log.info("Approval %s REJECTED by %s", approval_id, by)
        return True

    def get(self, approval_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._requests.get(approval_id)

    def get_pending(self) -> list[dict]:
        with self._lock:
            return [self._req_to_dict(r) for r in self._requests.values() if r.status == "pending"]

    def get_all(self) -> list[dict]:
        with self._lock:
            return [self._req_to_dict(r) for r in self._requests.values()]

    def _req_to_dict(self, r: ApprovalRequest) -> dict:
        return {
            "id": r.id,
            "created_at": r.created_at,
            "status": r.status,
            "name": r.target.get("name", ""),
            "namespace": r.target.get("namespace", ""),
            "location": r.location,
            "deployment": r.target.get("deployment", ""),
            "platform": r.platform,
            "issue_type": r.issue_type,
            "restarts": r.restarts,
            "action": r.action,
            "summary": r.summary,
            "root_cause": r.root_cause,
            "recommendation": r.recommendation,
            "used_model": r.used_model,
            "cost_data": r.cost_data,
            "is_developer_issue": r.is_developer_issue,
            "approved_by": r.approved_by,
            "approved_at": r.approved_at,
            "rejected_by": r.rejected_by,
            "action_result": r.action_result,
            "rolled_back": r.rolled_back,
            "deleted": r.deleted,
        }

    def to_dict(self) -> dict:
        return {"requests": self.get_all(), "pending_count": len(self.get_pending())}

    def mark_deleted_by_resource(self, alive_keys: set[str], platform: str | None = None) -> int:
        with self._lock:
            count = 0
            for req in self._requests.values():
                if req.deleted:
                    continue
                if platform and req.platform != platform:
                    continue
                if req.platform == "k8s":
                    key = f"k8s/{req.target.get('namespace', '')}/{req.target.get('name', '')}"
                elif req.platform == "docker":
                    key = f"docker/{req.location}/{req.target.get('name', '')}"
                else:
                    continue
                if key not in alive_keys:
                    req.deleted = True
                    count += 1
            return count


def start_approval_executor(
    store: ApprovalStore,
    execute_fn: Any,
    verify_fn: Any,
    send_executed_email_fn: Any,
    send_rejected_email_fn: Any,
    notify_n8n_fn: Any,
    record_metrics_fn: Any,
    record_diagnosis_fn: Any,
    update_diagnosis_fn: Any,
    k8s_context: dict | None = None,
    docker_context: dict | None = None,
    storage: Any = None,
    circuit_breaker: Any = None,
) -> threading.Thread:
    def _executor_loop() -> None:
        while True:
            try:
                _process_approved(
                    store, execute_fn, verify_fn, send_executed_email_fn,
                    send_rejected_email_fn, notify_n8n_fn, record_metrics_fn,
                    update_diagnosis_fn, k8s_context, docker_context,
                    circuit_breaker,
                )
                _process_rejected(store, notify_n8n_fn, update_diagnosis_fn)
                _expire_old(store)
            except Exception as e:
                log.error("Approval executor error: %s", e)
            time.sleep(5)

    t = threading.Thread(target=_executor_loop, daemon=True, name="approval-executor")
    t.start()
    log.info("Approval executor thread started")
    return t


def _process_approved(
    store, execute_fn, verify_fn, send_executed_email_fn,
    send_rejected_email_fn, notify_n8n_fn, record_metrics_fn,
    update_diagnosis_fn, k8s_context, docker_context, circuit_breaker,
) -> None:
    pending = []
    with store._lock:
        for req in list(store._requests.values()):
            if req.status == "approved":
                pending.append(req)

    for req in pending:
        try:
            platform = req.platform
            action = req.action
            params = dict(req.params)

            # ── Circuit breaker check ─────────────────────────────────
            uid = f"{platform}/{req.target.get('namespace', '')}/{req.target.get('name', '')}"
            if circuit_breaker:
                allowed, reason = circuit_breaker.can_heal(uid)
                if not allowed:
                    log.warning("Circuit breaker blocks approved heal %s: %s", req.id, reason)
                    with store._lock:
                        req.status = "rejected"
                        req.action_result = f"Circuit breaker open: {reason}"
                    update_diagnosis_fn(req.id, route="rejected",
                                        action_result=req.action_result)
                    notify_n8n_fn({
                        "route": "rejected",
                        "approval_id": req.id,
                        "rejected_by": "circuit_breaker",
                        "platform": platform,
                        "location": req.location,
                        "target_name": req.target.get("name", ""),
                        "action": action,
                        "summary": req.summary,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    continue
            # ────────────────────────────────────────────────────────────

            log.info("Executing approved action %s for %s", action, req.target.get("name"))

            if platform == "k8s" and k8s_context:
                action_result = execute_fn(action, params, k8s_context["v1"], k8s_context["apps_v1"])
            elif platform == "docker" and docker_context:
                action_result = execute_fn(action, params, docker_context.get("container"))
            else:
                action_result = f"[ERROR] No context for platform={platform}"

            rolled_back = False
            if (
                platform == "k8s"
                and action in ("increase_memory_limit", "bounce_deployment", "scale_deployment")
                and k8s_context
            ):
                original_state = {
                    "original_memory_limit": req.target.get("original_memory_limit", "128Mi"),
                    "original_replicas": req.target.get("original_replicas", 1),
                    "deployment": req.target.get("deployment", ""),
                }
                success, verify_msg = verify_fn(
                    action, params, k8s_context["v1"], k8s_context["apps_v1"], original_state,
                )
                if not success:
                    rolled_back = True
                    log.warning("Approved heal failed — rollback: %s", verify_msg)
                    action_result = f"Rolled back: {verify_msg}"

            with store._lock:
                req.status = "executed"
                req.action_result = action_result
                req.rolled_back = rolled_back

            send_executed_email_fn(
                req.id, req.target.get("name", ""), req.location,
                action, action_result, req.approved_by, platform,
            )

            route = "rollback" if rolled_back else "auto_healed"
            notify_n8n_fn({
                "route": route,
                "approval_id": req.id,
                "approved_by": req.approved_by,
                "platform": platform,
                "location": req.location,
                "target_name": req.target.get("name", ""),
                "action": action,
                "action_result": action_result,
                "summary": req.summary,
                "root_cause": req.root_cause,
                "recommendation": req.recommendation,
                "diagnosed_by": req.used_model,
                "restart_count": req.restarts,
                "cost_data": req.cost_data,
                "rolled_back": rolled_back,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            record_metrics_fn(action, platform, route, 0)
            update_diagnosis_fn(
                req.id,
                route=route,
                action_result=action_result,
                success=not rolled_back,
            )

            # ── Record in circuit breaker ─────────────────────────────
            if circuit_breaker:
                circuit_breaker.record_heal(uid, action, success=not rolled_back)

            log.info("Approved action executed: %s — result: %s", req.id, action_result)

        except Exception as e:
            log.error("Failed to execute approved action %s: %s", req.id, e)
            with store._lock:
                req.status = "pending"
                req.action_result = f"Execution failed: {e}"


def _process_rejected(store, notify_n8n_fn, update_diagnosis_fn) -> None:
    rejected = []
    with store._lock:
        for req in list(store._requests.values()):
            if req.status == "rejected":
                rejected.append(req)

    for req in rejected:
        try:
            log.info("Processing rejected approval %s for %s", req.id, req.target.get("name"))
            with store._lock:
                req.status = "rejected"

            notify_n8n_fn({
                "route": "rejected",
                "approval_id": req.id,
                "rejected_by": req.rejected_by,
                "platform": req.platform,
                "location": req.location,
                "target_name": req.target.get("name", ""),
                "action": req.action,
                "summary": req.summary,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            update_diagnosis_fn(
                req.id,
                route="rejected",
                action_result=f"Rejected by {req.rejected_by}",
            )

            log.info("Approval %s marked rejected in diagnosis store", req.id)

        except Exception as e:
            log.error("Failed to process rejected approval %s: %s", req.id, e)


def _expire_old(store: ApprovalStore) -> None:
    now = datetime.now(timezone.utc)
    with store._lock:
        for req in list(store._requests.values()):
            if req.status == "pending":
                created = datetime.strptime(req.created_at, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
                age_hours = (now - created).total_seconds() / 3600
                if age_hours > store._timeout_hours:
                    req.status = "expired"
                    log.info("Approval request expired: %s (age: %.1fh)", req.id, age_hours)
