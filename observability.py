#!/usr/bin/env python3
"""
Observability — HTTP health endpoint, visual metrics dashboard, Prometheus
metrics exporter, and structured logging setup.

Endpoints:
  GET /health        — agent liveness (JSON)
  GET /metrics       — visual HTML dashboard
  GET /metrics/raw   — Prometheus exposition format
  GET /metrics/api   — metrics as JSON (consumed by dashboard JS)
"""

from __future__ import annotations

import re
import time
import uuid
import json
import logging
import secrets
import smtplib
import threading
import urllib.parse
import calendar
from dataclasses import dataclass, asdict
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any

import requests

from config import (
    HEALTH_PORT, METRICS_ENABLED, DIAGNOSIS_HISTORY_SIZE,
    POLL_INTERVAL_SEC, MAX_RESTARTS, DRY_RUN, REPORT_ONLY,
    ENABLE_K8S, ENABLE_DOCKER, WATCH_NAMESPACES, WATCH_ALL_NAMESPACES,
    LOKI_URL, PROMETHEUS_URL, N8N_WEBHOOK_URL, SMTP_USER,
    SMTP_HOST, SMTP_PORT, SMTP_PASSWORD,
    DIAGNOSIS_PROVIDER_CHAIN, WATCH_EVENTS_ENABLED,
    DASHBOARD_USER, DASHBOARD_PASSWORD,
    APPROVAL_DASHBOARD_URL,
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_ALLOWED_DOMAINS, GOOGLE_REDIRECT_URI,
    GEMINI_API_KEY, CHAT_ENABLED, CHAT_TIMEOUT_SEC, CHAT_MAX_TURNS, CHAT_PROVIDER_CHAIN,
)
from storage import StorageBackend
from notifications import send_welcome_email, send_password_reset_email

log = logging.getLogger("observability")


# ══════════════════════════════════════════════════════════════════════════════
#  STRUCTURED LOGGING
# ══════════════════════════════════════════════════════════════════════════════

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


def setup_logging(json_mode: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    if json_mode:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
    root.addHandler(handler)


# ══════════════════════════════════════════════════════════════════════════════
#  AGENT METRICS
# ══════════════════════════════════════════════════════════════════════════════

class AgentMetrics:
    def __init__(self) -> None:
        self.heal_actions: dict[str, int] = {}
        self.heal_by_platform: dict[str, int] = {}
        self.heal_by_route: dict[str, int] = {}
        self.llm_calls: dict[str, int] = {}
        self.llm_errors: dict[str, int] = {}
        self.llm_latencies: dict[str, list[float]] = {}
        self.heal_latencies: list[float] = []
        self.rollbacks: int = 0
        self.pdb_blocks: int = 0
        self.start_time = time.time()
        self._lock = threading.Lock()

    def record_heal(self, action: str, platform: str, route: str, latency: float) -> None:
        with self._lock:
            self.heal_actions[action] = self.heal_actions.get(action, 0) + 1
            self.heal_by_platform[platform] = self.heal_by_platform.get(platform, 0) + 1
            self.heal_by_route[route] = self.heal_by_route.get(route, 0) + 1
            self.heal_latencies.append(latency)

    def record_llm_call(self, provider: str, latency: float, success: bool) -> None:
        with self._lock:
            self.llm_calls[provider] = self.llm_calls.get(provider, 0) + 1
            if not success:
                self.llm_errors[provider] = self.llm_errors.get(provider, 0) + 1
            self.llm_latencies.setdefault(provider, []).append(latency)

    def record_rollback(self) -> None:
        with self._lock:
            self.rollbacks += 1

    def record_pdb_block(self) -> None:
        with self._lock:
            self.pdb_blocks += 1

    def to_dict(self) -> dict:
        with self._lock:
            uptime = time.time() - self.start_time
            total_heals = sum(self.heal_actions.values())
            total_errors = sum(self.llm_errors.values())
            total_calls = sum(self.llm_calls.values())

            providers = {}
            for p in set(list(self.llm_calls.keys()) + list(self.llm_errors.keys())):
                calls = self.llm_calls.get(p, 0)
                errors = self.llm_errors.get(p, 0)
                lats = self.llm_latencies.get(p, [])
                avg_lat = sum(lats) / len(lats) if lats else 0
                success_rate = ((calls - errors) / calls * 100) if calls > 0 else 0
                providers[p] = {
                    "calls": calls,
                    "errors": errors,
                    "avg_latency": round(avg_lat, 2),
                    "success_rate": round(success_rate, 1),
                }

            return {
                "uptime_seconds": round(uptime),
                "total_heals": total_heals,
                "total_llm_calls": total_calls,
                "total_llm_errors": total_errors,
                "rollbacks": self.rollbacks,
                "pdb_blocks": self.pdb_blocks,
                "heal_actions": dict(self.heal_actions),
                "heal_by_platform": dict(self.heal_by_platform),
                "heal_by_route": dict(self.heal_by_route),
                "providers": providers,
                "last_updated": time.strftime("%H:%M:%S UTC", time.gmtime()),
            }

    def to_prometheus_text(self) -> str:
        lines: list[str] = []
        lines.append("# HELP healer_uptime_seconds Agent uptime in seconds")
        lines.append("# TYPE healer_uptime_seconds gauge")
        lines.append(f"healer_uptime_seconds {time.time() - self.start_time:.0f}")

        lines.append("# HELP healer_heal_actions_total Total healing actions executed")
        lines.append("# TYPE healer_heal_actions_total counter")
        for action, count in self.heal_actions.items():
            lines.append(f'healer_heal_actions_total{{action="{action}"}} {count}')

        lines.append("# HELP healer_heal_by_platform_total Actions by platform")
        lines.append("# TYPE healer_heal_by_platform_total counter")
        for plat, count in self.heal_by_platform.items():
            lines.append(f'healer_heal_by_platform_total{{platform="{plat}"}} {count}')

        lines.append("# HELP healer_heal_by_route_total Actions by route")
        lines.append("# TYPE healer_heal_by_route_total counter")
        for route, count in self.heal_by_route.items():
            lines.append(f'healer_heal_by_route_total{{route="{route}"}} {count}')

        lines.append("# HELP healer_llm_calls_total LLM calls by provider")
        lines.append("# TYPE healer_llm_calls_total counter")
        for provider, count in self.llm_calls.items():
            lines.append(f'healer_llm_calls_total{{provider="{provider}"}} {count}')

        lines.append("# HELP healer_llm_errors_total LLM errors by provider")
        lines.append("# TYPE healer_llm_errors_total counter")
        for provider, count in self.llm_errors.items():
            lines.append(f'healer_llm_errors_total{{provider="{provider}"}} {count}')

        lines.append("# HELP healer_llm_latency_seconds LLM call latency")
        lines.append("# TYPE healer_llm_latency_seconds summary")
        for provider, latencies in self.llm_latencies.items():
            if latencies:
                avg = sum(latencies) / len(latencies)
                lines.append(f'healer_llm_latency_seconds{{provider="{provider}",quantile="avg"}} {avg:.2f}')

        lines.append("# HELP healer_rollbacks_total Total rollbacks")
        lines.append("# TYPE healer_rollbacks_total counter")
        lines.append(f"healer_rollbacks_total {self.rollbacks}")

        lines.append("# HELP healer_pdb_blocks_total PDB violations blocked")
        lines.append("# TYPE healer_pdb_blocks_total counter")
        lines.append(f"healer_pdb_blocks_total {self.pdb_blocks}")

        return "\n".join(lines) + "\n"


metrics = AgentMetrics()


# ══════════════════════════════════════════════════════════════════════════════
#  DIAGNOSIS HISTORY STORE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class DiagnosisRecord:
    id: str
    timestamp: str
    platform: str
    name: str
    namespace: str
    location: str
    deployment: str
    status: str
    restarts: int
    action: str
    route: str
    is_developer_issue: bool
    llm_model: str
    llm_latency: float
    summary: str
    root_cause: str
    recommendation: str
    logs: str
    action_result: str
    cost_data: str
    success: bool
    deleted: bool = False


class DiagnosisStore:
    def __init__(self, max_size: int = 50) -> None:
        self._records: list[DiagnosisRecord] = []
        self._max_size = max_size
        self._lock = threading.Lock()

    def record(self, **kwargs: Any) -> None:
        rec = DiagnosisRecord(
            id=uuid.uuid4().hex[:12],
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            **kwargs,
        )
        with self._lock:
            self._records.append(rec)
            if len(self._records) > self._max_size:
                self._records = self._records[-self._max_size:]

    def to_list(self) -> list[dict]:
        with self._lock:
            return [asdict(r) for r in reversed(self._records)]

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "total": len(self._records),
                "records": [asdict(r) for r in reversed(self._records)],
            }

    def mark_deleted_by_resource(self, alive_keys: set[str], platform: str | None = None) -> int:
        with self._lock:
            count = 0
            for rec in self._records:
                if rec.deleted:
                    continue
                if platform and rec.platform != platform:
                    continue
                if rec.platform == "k8s":
                    key = f"k8s/{rec.namespace}/{rec.name}"
                elif rec.platform == "docker":
                    key = f"docker/{rec.location}/{rec.name}"
                else:
                    continue
                if key not in alive_keys:
                    rec.deleted = True
                    count += 1
            return count

    def update_by_approval_id(self, approval_id: str, **updates: Any) -> DiagnosisRecord | None:
        marker = f"[APPROVAL PENDING] id={approval_id}"
        with self._lock:
            for rec in reversed(self._records):
                if marker in (rec.action_result or ""):
                    for k, v in updates.items():
                        if hasattr(rec, k):
                            setattr(rec, k, v)
                    return rec
        return None


diagnosis_store = DiagnosisStore(max_size=DIAGNOSIS_HISTORY_SIZE)


# ══════════════════════════════════════════════════════════════════════════════
#  SERVICE STATUS — Live Connectivity Checks
# ══════════════════════════════════════════════════════════════════════════════

class ServiceStatus:
    """Tracks actual runtime connectivity for each external service."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._status: dict[str, dict[str, Any]] = {
            "k8s":        {"configured": bool(ENABLE_K8S),        "connected": False, "detail": ""},
            "docker":     {"configured": bool(ENABLE_DOCKER),     "connected": False, "detail": ""},
            "loki":       {"configured": bool(LOKI_URL),          "connected": False, "detail": ""},
            "prometheus": {"configured": bool(PROMETHEUS_URL),    "connected": False, "detail": ""},
            "n8n":        {"configured": bool(N8N_WEBHOOK_URL),   "connected": False, "detail": ""},
            "email":      {"configured": bool(SMTP_USER and SMTP_PASSWORD), "connected": False, "detail": ""},
        }
        self._last_check: float = 0
        self._CHECK_INTERVAL = 30  # seconds

    # ── Setters (called by agent.py) ──────────────────────────────────────────

    def set_platform(self, name: str, connected: bool, detail: str = "") -> None:
        with self._lock:
            if name in self._status:
                self._status[name]["connected"] = connected
                self._status[name]["detail"] = detail

    # ── Connectivity checks ───────────────────────────────────────────────────

    def check_all(self) -> None:
        now = time.time()
        if now - self._last_check < self._CHECK_INTERVAL:
            return
        self._last_check = now

        with self._lock:
            self._check_loki()
            self._check_prometheus()
            self._check_n8n()
            self._check_email()

    def _check_loki(self) -> None:
        if not LOKI_URL:
            return
        try:
            resp = requests.get(f"{LOKI_URL}/ready", timeout=3)
            self._status["loki"]["connected"] = resp.status_code == 200
            self._status["loki"]["detail"] = f"HTTP {resp.status_code}"
        except requests.exceptions.ConnectionError:
            self._status["loki"]["connected"] = False
            self._status["loki"]["detail"] = "connection refused"
        except requests.exceptions.Timeout:
            self._status["loki"]["connected"] = False
            self._status["loki"]["detail"] = "timeout"
        except Exception as e:
            self._status["loki"]["connected"] = False
            self._status["loki"]["detail"] = str(e)[:80]

    def _check_prometheus(self) -> None:
        if not PROMETHEUS_URL:
            return
        try:
            resp = requests.get(f"{PROMETHEUS_URL}/api/v1/status/config", timeout=3)
            self._status["prometheus"]["connected"] = resp.status_code == 200
            self._status["prometheus"]["detail"] = f"HTTP {resp.status_code}"
        except requests.exceptions.ConnectionError:
            self._status["prometheus"]["connected"] = False
            self._status["prometheus"]["detail"] = "connection refused"
        except requests.exceptions.Timeout:
            self._status["prometheus"]["connected"] = False
            self._status["prometheus"]["detail"] = "timeout"
        except Exception as e:
            self._status["prometheus"]["connected"] = False
            self._status["prometheus"]["detail"] = str(e)[:80]

    def _check_n8n(self) -> None:
        if not N8N_WEBHOOK_URL:
            return
        try:
            resp = requests.head(N8N_WEBHOOK_URL, timeout=3)
            self._status["n8n"]["connected"] = resp.status_code in (200, 201, 404, 405)
            self._status["n8n"]["detail"] = f"HTTP {resp.status_code}"
        except requests.exceptions.ConnectionError:
            self._status["n8n"]["connected"] = False
            self._status["n8n"]["detail"] = "connection refused"
        except requests.exceptions.Timeout:
            self._status["n8n"]["connected"] = False
            self._status["n8n"]["detail"] = "timeout"
        except Exception as e:
            self._status["n8n"]["connected"] = False
            self._status["n8n"]["detail"] = str(e)[:80]

    def _check_email(self) -> None:
        if not (SMTP_USER and SMTP_PASSWORD):
            return
        try:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=3)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.quit()
            self._status["email"]["connected"] = True
            self._status["email"]["detail"] = f"{SMTP_HOST}:{SMTP_PORT}"
        except smtplib.SMTPException as e:
            self._status["email"]["connected"] = False
            self._status["email"]["detail"] = str(e)[:80]
        except Exception as e:
            self._status["email"]["connected"] = False
            self._status["email"]["detail"] = str(e)[:80]

    def to_dict(self) -> dict:
        with self._lock:
            return {k: dict(v) for k, v in self._status.items()}


service_status = ServiceStatus()

_dashboard_config = {
    "poll_interval": POLL_INTERVAL_SEC,
    "max_restarts": MAX_RESTARTS,
    "dry_run": DRY_RUN,
    "report_only": REPORT_ONLY,
    "enable_k8s": ENABLE_K8S,
    "enable_docker": ENABLE_DOCKER,
    "watch_namespaces": WATCH_NAMESPACES if not WATCH_ALL_NAMESPACES else ["*"],
    "provider_chain": DIAGNOSIS_PROVIDER_CHAIN,
    "events_enabled": WATCH_EVENTS_ENABLED,
    "google_sso": bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
    "chat_enabled": CHAT_ENABLED,
    "chat_provider_chain": CHAT_PROVIDER_CHAIN,
    "chat_timeout_ms": (CHAT_TIMEOUT_SEC + 30) * 1000,
}


# ══════════════════════════════════════════════════════════════════════════════
#  CHAT ASSISTANT — Read-only Q&A backed by the LLM provider chain
# ══════════════════════════════════════════════════════════════════════════════

_chat_registry: dict | None = None
_chat_gemini_model: Any = None
_chat_providers_imported = False


def _ensure_chat_backend():
    global _chat_registry, _chat_gemini_model, _chat_providers_imported
    if _chat_providers_imported:
        return _chat_registry, _chat_gemini_model
    from providers import build_provider_registry
    _chat_registry = build_provider_registry()
    if GEMINI_API_KEY:
        try:
            import google.generativeai as _genai
            _genai.configure(api_key=GEMINI_API_KEY)
            _chat_gemini_model = _genai.GenerativeModel("gemini-2.5-flash")
        except Exception as e:
            log.warning("Chat: Gemini init failed: %s", e)
    _chat_providers_imported = True
    return _chat_registry, _chat_gemini_model


def _chat_context_block() -> str:
    lines: list[str] = []

    md = metrics.to_dict()
    lines.append("- Agent metrics: %d heal action(s), %d LLM call(s), %d rollback(s), %d PDB block(s)" % (
        md.get("total_heals", 0), md.get("total_llm_calls", 0),
        md.get("rollbacks", 0), md.get("pdb_blocks", 0)))

    recs = diagnosis_store.to_list()[:8]
    if recs:
        lines.append("- Recent diagnoses (newest first):")
        for r in recs:
            target = r.get("name", "?")
            where = r.get("namespace") or r.get("location") or ""
            lines.append("  * %s [%s] %s on %s/%s -> %s (%s)" % (
                r.get("timestamp", "?"), r.get("platform", "?"),
                r.get("issue", ""), where, target,
                r.get("action", r.get("action_result", "")), r.get("route", "?")))
    else:
        lines.append("- No diagnoses recorded yet.")

    if _approval_store:
        try:
            ap = _approval_store.to_dict()
            pending = ap.get("pending_count", 0)
            lines.append("- Approvals: %d pending" % pending)
        except Exception:
            lines.append("- Approvals: unavailable")

    try:
        svc = service_status.to_dict()
        status_parts = []
        for name, st in svc.items():
            state = "connected" if st.get("connected") else "unavailable"
            if st.get("configured"):
                status_parts.append("%s=%s" % (name, state))
        lines.append("- Service connectivity: %s" % (", ".join(status_parts) or "none configured"))
    except Exception:
        pass

    return "\n".join(lines)


def _build_chat_prompt(message: str, history: list[dict]) -> str:
    context = _chat_context_block()
    prompt = (
        "You are Healix Assistant, a friendly and knowledgeable SRE teammate for the "
        "Healix Kubernetes/Docker auto-healer dashboard. Talk naturally and warmly, like "
        "a helpful coworker — never like a robot.\n\n"
        "STYLE RULES:\n"
        "- If the user greets you (hi, hello, hey, yo...), greet them back warmly and add "
        "a one-line teaser of current status (e.g. 'Everything's looking good — 0 heals so "
        "far' or 'There's 1 heal waiting for approval').\n"
        "- Keep replies short and conversational. One or two sentences is usually enough; "
        "use a short list only when it genuinely helps.\n"
        "- Answer exactly what was asked. Don't dump raw data unless it's useful.\n"
        "- When things are healthy, say so reassuringly.\n"
        "- If the live data doesn't contain the answer, say that simply and suggest what "
        "they could ask instead.\n"
        "- Use the exact names/numbers from the live data.\n"
        "- You are read-only: never propose or trigger any healing action.\n\n"
        "LIVE SYSTEM DATA:\n%s\n\n"
        "EXAMPLES OF GOOD REPLIES:\n"
        "User: hi\n"
        "Assistant: Hey! Good to see you. Quick status: 0 heals so far, 1 approval pending, "
        "and everything's connected except n8n. What would you like to dig into?\n\n"
        "User: give me a quick health summary\n"
        "Assistant: Sure — here's the short version: no heals have run yet, k8s, docker, "
        "loki and prometheus are all connected, n8n is unreachable, and there's 1 approval "
        "waiting on your call.\n\n"
        "User: which container is unhealthy\n"
        "Assistant: The data shows two recent items: a dev issue on "
        "WILASSETA0233/breaking_env_demo, and demo/test-auto-healed-7957b7f456-2ntrc which "
        "has a suggested memory-limit increase still awaiting approval.\n\n"
        "CONVERSATION:\n" % context
    )
    for turn in history[-CHAT_MAX_TURNS * 2:]:
        role = turn.get("role")
        content = str(turn.get("content", ""))[:2000]
        if role == "user":
            prompt += "User: %s\n" % content
        elif role == "assistant":
            prompt += "Assistant: %s\n" % content
    prompt += "User: %s\nAssistant:" % message
    return prompt


def _handle_chat(self) -> None:
    if not CHAT_ENABLED:
        self._respond(404, {"error": "chat disabled"})
        return
    cookie = self.headers.get("Cookie", "")
    if not _validate_session(cookie):
        self._respond(401, {"error": "unauthorized"})
        return
    data = self._read_body() or {}

    message = str(data.get("message", "")).strip()[:2000]
    if not message:
        self._respond(400, {"error": "empty message"})
        return

    history = data.get("history") or []
    if not isinstance(history, list):
        history = []
    history = [h for h in history if isinstance(h, dict)][-CHAT_MAX_TURNS * 2:]

    try:
        from providers import chat_with_providers
        registry, gemini_model = _ensure_chat_backend()
        prompt = _build_chat_prompt(message, history)
        reply, provider = chat_with_providers(prompt, registry, gemini_model, CHAT_PROVIDER_CHAIN)
        if not reply:
            self._respond(502, {"error": "No LLM provider available. Check API keys / Ollama.", "ok": False})
            return
        self._respond(200, {"ok": True, "reply": reply.strip(), "provider": provider})
    except (BrokenPipeError, ConnectionResetError):
        log.info("Chat: client disconnected before reply")
    except Exception as e:
        log.error("Chat handler error: %s", e)
        try:
            self._respond(500, {"error": "Chat failed", "ok": False})
        except (BrokenPipeError, ConnectionResetError):
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION MANAGEMENT — Dashboard Login
# ══════════════════════════════════════════════════════════════════════════════

_SESSION_EXPIRY_SEC = 8 * 3600  # 8 hours
_sessions: dict[str, dict] = {}  # token -> {expiry, username, perms}


def _generate_session_token(username: str, perms: dict) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        "expiry": time.time() + _SESSION_EXPIRY_SEC,
        "username": username,
        "perms": perms,
    }
    return token


def _validate_session(cookie_header: str) -> dict | None:
    if not cookie_header:
        return None
    now = time.time()
    for part in cookie_header.split(";"):
        kv = part.strip().split("=", 1)
        if len(kv) == 2 and kv[0] == "session_id":
            token = kv[1]
            data = _sessions.get(token)
            if data and data["expiry"] > now:
                return data
            elif data:
                del _sessions[token]
            return None
    return None


def _check_perm(cookie_header: str, perm: str) -> bool:
    session = _validate_session(cookie_header)
    return bool(session and session.get("perms", {}).get(perm, False))


def _prune_sessions() -> None:
    now = time.time()
    expired = [t for t, data in _sessions.items() if data["expiry"] <= now]
    for t in expired:
        del _sessions[t]

def _refresh_user_sessions(user_id: int) -> None:
    if not _storage:
        return
    users = _storage.list_users()
    target = next((u for u in users if u["id"] == user_id), None)
    if not target:
        return
    new_perms = {
        "can_view_dashboard": target.get("can_view_dashboard", False),
        "can_view_pods": target.get("can_view_pods", False),
        "can_view_containers": target.get("can_view_containers", False),
        "can_view_approvals": target.get("can_view_approvals", False),
        "can_approve": target.get("can_approve", False),
        "can_admin": target.get("can_admin", False),
    }
    for s in _sessions.values():
        if s.get("username") == target["username"]:
            s["perms"] = new_perms

def _update_session_user(cookie_header: str, session: dict,
                         username: str | None = None,
                         profile_pic: str | None = None) -> None:
    old = session.get("username")
    if username is not None and username != old:
        session["username"] = username
        for s in _sessions.values():
            if s is not session and s.get("username") == old:
                s["username"] = username
    if profile_pic is not None:
        session["profile_pic"] = profile_pic

# ══════════════════════════════════════════════════════════════════════════════
#  LOGIN PAGE HTML
# ══════════════════════════════════════════════════════════════════════════════

_GOOGLE_SSO_BLOCK = """  <div class="login-divider"><span>or continue with</span></div>
  <a href="/auth/google" class="google-btn" onclick="sessionStorage.setItem('healixFresh','1')">
    <svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
    Sign in with Google
  </a>"""


def _render_login_html() -> str:
    sso_enabled = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
    return _LOGIN_HTML.replace("__GOOGLE_SSO__", _GOOGLE_SSO_BLOCK if sso_enabled else "")

_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0a0e17">
<title>Healix — Login</title>
<style>
  :root {
    --bg: #0a0e17; --surface: rgba(22,27,34,0.6); --border: rgba(48,54,61,0.5);
    --text: #e6edf3; --text2: #8b949e; --text3: #484f58;
    --blue: #58a6ff; --red: #f85149; --green: #3fb950;
    --input-bg: rgba(13,17,23,0.6);
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg); color: var(--text); min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    overflow: hidden;
    position: relative;
  }
  .login-grid {
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(48,54,61,0.15) 1px, transparent 1px),
      linear-gradient(90deg, rgba(48,54,61,0.15) 1px, transparent 1px);
    background-size: 60px 60px;
    mask-image: radial-gradient(ellipse at 50% 50%, black 30%, transparent 70%);
    -webkit-mask-image: radial-gradient(ellipse at 50% 50%, black 30%, transparent 70%);
  }
  .login-glow {
    position: fixed; border-radius: 50%; filter: blur(100px); pointer-events: none; z-index: 0;
  }
  .login-glow:nth-child(1) { width: 600px; height: 600px; background: rgba(88,166,255,0.08); top: -20%; left: -10%; }
  .login-glow:nth-child(2) { width: 500px; height: 500px; background: rgba(188,140,255,0.06); bottom: -15%; right: -10%; }
  @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes float { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
  .login-card {
    width: 100%; max-width: 460px; padding: 52px 48px 44px;
    background: rgba(22,27,34,0.55); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
    border: 1px solid rgba(48,54,61,0.35); border-radius: 20px;
    box-shadow: 0 24px 80px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04);
    animation: fadeInUp 0.6s ease; position: relative; z-index: 1;
  }
  .login-brand { text-align: center; margin-bottom: 32px; }
  .login-brand .logo-wrap {
    width: 64px; height: 64px; margin: 0 auto 16px;
    background: linear-gradient(135deg, rgba(88,166,255,0.15), rgba(88,166,255,0.05));
    border-radius: 18px; display: flex; align-items: center; justify-content: center;
    border: 1px solid rgba(88,166,255,0.15); animation: float 4s ease-in-out infinite;
  }
  .login-brand .logo-wrap svg { width: 32px; height: 32px; color: var(--blue); }
  .login-brand h1 { font-size: 24px; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 4px; }
  .login-brand p { font-size: 14px; color: var(--text2); }
  .login-field { margin-bottom: 16px; }
  .login-field label {
    display: flex; align-items: center; gap: 6px;
    font-size: 13px; font-weight: 600; color: var(--text2);
    letter-spacing: 0.3px; margin-bottom: 6px;
  }
  .login-field label svg { width: 15px; height: 15px; opacity: 0.6; }
  .login-field input {
    width: 100%; padding: 13px 16px; font-size: 15px; color: var(--text);
    background: var(--input-bg); border: 1px solid rgba(48,54,61,0.5);
    border-radius: 10px; outline: none; transition: all 0.2s;
  }
  .login-field input:hover { border-color: rgba(48,54,61,0.8); }
  .login-field input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(88,166,255,0.12), 0 0 20px rgba(88,166,255,0.05); }
  .login-field input::placeholder { color: var(--text3); font-size: 14px; }
  .login-btn {
    width: 100%; padding: 14px 0; margin-top: 6px; font-size: 15px; font-weight: 600;
    color: #fff; background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
    border: none; border-radius: 10px; cursor: pointer; transition: all 0.25s;
    position: relative; overflow: hidden;
  }
  .login-btn:hover { background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%); box-shadow: 0 6px 24px rgba(46,160,67,0.3); transform: translateY(-1px); }
  .login-btn:active { transform: scale(0.98); }
  .login-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
  .login-btn .spinner {
    display: none; width: 18px; height: 18px; border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff; border-radius: 50%; animation: spin 0.6s linear infinite;
    margin: 0 auto;
  }
  .login-error {
    margin-top: 12px; padding: 10px 14px; font-size: 13px; color: var(--red);
    background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.2);
    border-radius: 10px; text-align: center; display: none;
  }
  .login-divider { display: flex; align-items: center; gap: 16px; margin: 20px 0; color: var(--text3); font-size: 13px; }
  .login-divider::before, .login-divider::after { content: ''; flex: 1; height: 1px; background: linear-gradient(90deg, transparent, rgba(48,54,61,0.5), transparent); }
  .google-btn {
    display: flex; align-items: center; justify-content: center; gap: 10px;
    width: 100%; padding: 13px; border-radius: 10px;
    border: 1px solid rgba(48,54,61,0.4); background: rgba(22,27,34,0.4);
    color: var(--text); font-size: 15px; font-weight: 500;
    text-decoration: none; transition: all 0.2s;
  }
  .google-btn:hover { background: rgba(48,54,61,0.3); border-color: var(--blue); box-shadow: 0 0 20px rgba(88,166,255,0.06); }
  .login-footer { text-align: center; margin-top: 20px; }
  .login-footer a { color: var(--text2); font-size: 14px; text-decoration: none; transition: color 0.2s; }
  .login-footer a:hover { color: var(--blue); }
  .login-footer .sep { color: var(--text3); margin: 0 8px; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Grafana-style Splash Loader ────────────────── */
  #login-splash {
    position: fixed; inset: 0; z-index: 9999; background: #0a0e17;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 18px; transition: opacity 0.55s ease; will-change: opacity;
  }
  #login-splash.fade { opacity: 0; pointer-events: none; }
  .splash-logo { position: relative; display: flex; align-items: center; justify-content: center; animation: splashBounce 1.15s ease-in-out infinite; }
  .splash-logo svg { width: 72px; height: 72px; color: var(--blue); filter: drop-shadow(0 0 14px rgba(88,166,255,0.4)); }
  .splash-ring { position: absolute; inset: -12px; border-radius: 50%; border: 2px solid transparent; border-top-color: var(--blue); border-right-color: rgba(188,140,255,0.6); animation: spin 1.4s linear infinite; opacity: 0.7; }
  @keyframes splashBounce {
    0%, 100% { transform: translateY(0) scale(1); }
    42% { transform: translateY(-26px) scale(1.06); }
    62% { transform: translateY(0) scale(0.97); }
  }
  .splash-brand { font-size: 26px; font-weight: 800; color: #e6edf3; letter-spacing: -0.5px; }
  .splash-brand span { color: var(--blue); }
  .splash-sub { font-size: 12px; color: #8b949e; letter-spacing: 2.5px; text-transform: uppercase; }
</style>
</head>
<body>
<div id="login-splash">
  <div class="splash-logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
    <div class="splash-ring"></div>
  </div>
  <div class="splash-brand">Healix</div>
  <div class="splash-sub">AI-Powered Self-Healing Platform</div>
</div>
<div class="login-glow"></div>
<div class="login-glow"></div>
<div class="login-grid"></div>
<div class="login-card">
  <div class="login-brand">
    <a href="/" style="text-decoration:none;color:inherit">
    <div class="logo-wrap">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
    </div>
    <h1>Healix</h1>
    <p>AI-Powered Self-Healing Platform</p>
    </a>
  </div>
  <form id="loginForm" onsubmit="return doLogin(event)">
    <div class="login-field">
      <label>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
        Username
      </label>
      <input type="text" id="username" name="username" placeholder="Enter your username" autocomplete="username" required autofocus>
    </div>
    <div class="login-field">
      <label>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Password
      </label>
      <input type="password" id="password" name="password" placeholder="Enter your password" autocomplete="current-password" required>
    </div>
    <div class="login-error" id="loginError"></div>
    <button type="submit" class="login-btn" id="loginBtn"><span id="loginBtnText">Sign In</span><div class="spinner" id="loginSpinner"></div></button>
    <div class="login-footer">
      <a href="/forgot">Forgot password?</a>
    </div>
  </form>
  __GOOGLE_SSO__
</div>
<script>
function doLogin(e) {
  e.preventDefault();
  var errEl = document.getElementById('loginError');
  var btn = document.getElementById('loginBtn');
  var btnText = document.getElementById('loginBtnText');
  var spinner = document.getElementById('loginSpinner');
  errEl.style.display = 'none';
  btn.disabled = true;
  btnText.style.display = 'none';
  spinner.style.display = 'block';
  var u = document.getElementById('username').value;
  var p = document.getElementById('password').value;
  var body = 'username=' + encodeURIComponent(u) + '&password=' + encodeURIComponent(p);
  fetch('/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: body,
    redirect: 'manual'
  }).then(function(r) {
    if (r.status === 200) {
      sessionStorage.setItem('healixFresh', '1');
      window.location.href = '/metrics';
    } else {
      return r.json();
    }
  }).then(function(j) {
    btn.disabled = false;
    btnText.style.display = '';
    spinner.style.display = 'none';
    if (j && j.error) {
      errEl.textContent = j.error;
      errEl.style.display = 'block';
    }
  }).catch(function() {
    btn.disabled = false;
    btnText.style.display = '';
    spinner.style.display = 'none';
    errEl.textContent = 'Connection failed';
    errEl.style.display = 'block';
  });
  return false;
}

window.addEventListener('load', function() {
  setTimeout(function() {
    var s = document.getElementById('login-splash');
    if (s) s.classList.add('fade');
    setTimeout(function() { if (s) s.remove(); }, 700);
  }, 1600);
});
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  FORGOT PASSWORD PAGE HTML
# ══════════════════════════════════════════════════════════════════════════════

_FORGOT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0a0e17">
<title>Healix — Forgot Password</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0e17; color: #e6edf3; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: rgba(22,27,34,0.75); border: 1px solid rgba(48,54,61,0.6); border-radius: 12px; padding: 40px; width: 420px; backdrop-filter: blur(12px); }
  h1 { font-size: 20px; margin-bottom: 4px; color: #e6edf3; }
  p.sub { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
  .field { margin-bottom: 16px; }
  .field label { display: block; font-size: 13px; font-weight: 500; color: #8b949e; margin-bottom: 4px; }
  .field input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid rgba(48,54,61,0.6); background: rgba(13,17,23,0.8); color: #e6edf3; font-size: 14px; outline: none; }
  .field input:focus { border-color: #58a6ff; }
  .btn { width: 100%; padding: 10px; border: none; border-radius: 8px; background: #1f6feb; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; margin-top: 8px; }
  .btn:hover { background: #388bfd; }
  .msg { background: rgba(63,185,80,0.15); color: #3fb950; padding: 12px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; display: none; }
  .error { background: rgba(248,81,73,0.15); color: #f85149; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; display: none; }
  .back { display: block; text-align: center; margin-top: 16px; color: #8b949e; font-size: 13px; text-decoration: none; }
  .back:hover { color: #58a6ff; }
</style>
</head>
<body>
<div class="card">
  <h1>Reset Password</h1>
  <p class="sub">Enter your email and we'll send you a reset link</p>
  <div class="msg" id="forgotMsg"></div>
  <div class="error" id="forgotError"></div>
  <form id="forgotForm" onsubmit="return doForgot(event)">
    <div class="field">
      <label for="f_email">Email</label>
      <input type="email" id="f_email" required autofocus>
    </div>
    <button type="submit" class="btn">Send Reset Link</button>
  </form>
  <a href="/login" class="back">Back to Login</a>
</div>
<script>
function doForgot(e) {
  e.preventDefault();
  var msgEl = document.getElementById('forgotMsg');
  var errEl = document.getElementById('forgotError');
  msgEl.style.display = 'none'; errEl.style.display = 'none';
  var em = document.getElementById('f_email').value;
  fetch('/forgot', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'email='+encodeURIComponent(em)
  }).then(function(r){return r.json();}).then(function(j){
    if (j.ok) { msgEl.textContent = 'If that email exists, a reset link has been sent.'; msgEl.style.display = 'block'; }
    else { errEl.textContent = j.error || 'Something went wrong'; errEl.style.display = 'block'; }
  }).catch(function(){ errEl.textContent = 'Connection failed'; errEl.style.display = 'block'; });
  return false;
}
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════════
#  RESET PASSWORD PAGE HTML
# ══════════════════════════════════════════════════════════════════════════════

_RESET_HTML_PREFIX = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0a0e17">
<title>Healix — Reset Password</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, system-ui, sans-serif; background: #0a0e17; color: #e6edf3; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: rgba(22,27,34,0.75); border: 1px solid rgba(48,54,61,0.6); border-radius: 12px; padding: 40px; width: 420px; backdrop-filter: blur(12px); }
  h1 { font-size: 20px; margin-bottom: 4px; color: #e6edf3; }
  p.sub { color: #8b949e; font-size: 14px; margin-bottom: 24px; }
  .field { margin-bottom: 16px; }
  .field label { display: block; font-size: 13px; font-weight: 500; color: #8b949e; margin-bottom: 4px; }
  .field input { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid rgba(48,54,61,0.6); background: rgba(13,17,23,0.8); color: #e6edf3; font-size: 14px; outline: none; }
  .field input:focus { border-color: #58a6ff; }
  .btn { width: 100%; padding: 10px; border: none; border-radius: 8px; background: #1f6feb; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; margin-top: 8px; }
  .btn:hover { background: #388bfd; }
  .error { background: rgba(248,81,73,0.15); color: #f85149; padding: 10px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>Set New Password</h1>
  <p class="sub">Enter your new password below</p>
  <div class="error" id="resetError"></div>
  <form id="resetForm" onsubmit="return doReset(event)">
    <div class="field">
      <label for="r_password">New Password</label>
      <input type="password" id="r_password" required minlength="6">
    </div>
    <div class="field">
      <label for="r_confirm">Confirm Password</label>
      <input type="password" id="r_confirm" required minlength="6">
    </div>
    <input type="hidden" id="r_token" value="__TOKEN__">
    <button type="submit" class="btn">Update Password</button>
  </form>
</div>
<script>
function doReset(e) {
  e.preventDefault();
  var errEl = document.getElementById('resetError');
  errEl.style.display = 'none';
  var p = document.getElementById('r_password').value;
  var c = document.getElementById('r_confirm').value;
  if (p !== c) { errEl.textContent = 'Passwords do not match'; errEl.style.display = 'block'; return false; }
  var token = document.getElementById('r_token').value;
  fetch('/reset/' + encodeURIComponent(token), {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: 'password=' + encodeURIComponent(p)
  }).then(function(r){return r.json();}).then(function(j){
    if (j.ok) { window.location.href = '/login'; }
    else { errEl.textContent = j.error || 'Reset failed'; errEl.style.display = 'block'; }
  }).catch(function(){ errEl.textContent = 'Connection failed'; errEl.style.display = 'block'; });
  return false;
}
</script>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════════
#  HTML DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" id="metaThemeColor" content="#0a0e17">
<title>Healix — Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2/dist/chartjs-plugin-zoom.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-annotation@3/dist/chartjs-plugin-annotation.min.js"></script>
<style>
  :root {
    --bg: #0a0e17; --surface: rgba(22,27,34,0.75); --surface2: rgba(30,37,48,0.8);
    --border: rgba(48,54,61,0.6); --border-glow: rgba(88,166,255,0.15);
    --text: #e6edf3; --text2: #8b949e; --text3: #484f58;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #58a6ff; --purple: #bc8cff; --cyan: #39d2c0; --orange: #f0883e;
    --glass-bg: rgba(22,27,34,0.6); --glass-border: rgba(48,54,61,0.4);
    --header-bg: rgba(10,14,23,0.85); --card-shadow: rgba(0,0,0,0.3);
    --input-bg: rgba(10,14,23,0.6); --box-bg: rgba(10,14,23,0.5);
    --log-bg: rgba(10,14,23,0.7); --sp-bg: rgba(13,17,23,0.95);
    --tooltip-bg: rgba(13,17,23,0.92); --toast-bg: rgba(22,27,34,0.95);
    --backdrop-bg: rgba(0,0,0,0.6); --border-subtle: rgba(48,54,61,0.3);
    --hover-tint: rgba(88,166,255,0.06); --font-mono: 'JetBrains Mono', 'SF Mono', Consolas, monospace;
  }
  .light {
    --bg: #f6f8fa; --surface: rgba(255,255,255,0.75); --surface2: rgba(246,248,250,0.8);
    --border: rgba(208,215,222,0.6); --border-glow: rgba(9,105,218,0.15);
    --text: #000000; --text2: #333333; --text3: #555555;
    --green: #1a7f37; --red: #cf222e; --yellow: #9a6700;
    --blue: #0969da; --purple: #8250df; --cyan: #0e7c6b; --orange: #bc4c00;
    --glass-bg: rgba(255,255,255,0.6); --glass-border: rgba(208,215,222,0.4);
    --header-bg: rgba(255,255,255,0.85); --card-shadow: rgba(0,0,0,0.08);
    --input-bg: rgba(246,248,250,0.8); --box-bg: rgba(246,248,250,0.5);
    --log-bg: rgba(246,248,250,0.7); --sp-bg: rgba(255,255,255,0.95);
    --tooltip-bg: rgba(255,255,255,0.95); --toast-bg: rgba(255,255,255,0.95);
    --backdrop-bg: rgba(0,0,0,0.3); --border-subtle: rgba(208,215,222,0.3);
    --hover-tint: rgba(9,105,218,0.06);
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; font-weight: 450; }

  /* ── Animated Background ────────────────────────── */
  .bg-canvas { position: fixed; inset: 0; z-index: -1; overflow: hidden; pointer-events: none; }
  .bg-gradient { position: absolute; inset: -50%; width: 200%; height: 200%; background: radial-gradient(ellipse 60% 50% at 15% 30%, rgba(88,166,255,0.08) 0%, transparent 60%), radial-gradient(ellipse 50% 40% at 80% 70%, rgba(188,140,255,0.06) 0%, transparent 60%), radial-gradient(ellipse 40% 30% at 50% 20%, rgba(57,210,192,0.04) 0%, transparent 50%); animation: bgShift 20s ease-in-out infinite alternate; }
  @keyframes bgShift { 0% { transform: translate(0, 0) rotate(0deg); } 25% { transform: translate(2%, 1%) rotate(2deg); } 50% { transform: translate(-1%, 2%) rotate(-1deg); } 75% { transform: translate(1%, -1%) rotate(1deg); } 100% { transform: translate(-2%, -1%) rotate(-2deg); } }
  .bg-orb { position: absolute; border-radius: 50%; filter: blur(80px); opacity: 0.15; animation: orbFloat 12s ease-in-out infinite; }
  .bg-orb:nth-child(1) { width: 500px; height: 500px; background: var(--blue); top: -10%; left: -5%; animation-delay: 0s; }
  .bg-orb:nth-child(2) { width: 400px; height: 400px; background: var(--purple); bottom: -8%; right: -5%; animation-delay: -4s; }
  .bg-orb:nth-child(3) { width: 300px; height: 300px; background: var(--cyan); top: 40%; left: 60%; animation-delay: -8s; }
  .bg-orb:nth-child(4) { width: 200px; height: 200px; background: var(--orange); top: 60%; left: 10%; animation-delay: -2s; opacity: 0.08; }
  @keyframes orbFloat { 0% { transform: translate(0, 0) scale(1); } 33% { transform: translate(30px, -20px) scale(1.05); } 66% { transform: translate(-20px, 15px) scale(0.95); } 100% { transform: translate(0, 0) scale(1); } }
  .bg-grid { position: absolute; inset: 0; background-image: radial-gradient(circle, var(--border-subtle) 1px, transparent 1px); background-size: 40px 40px; opacity: 0.3; mask-image: radial-gradient(ellipse 80% 60% at 50% 40%, black 20%, transparent 70%); -webkit-mask-image: radial-gradient(ellipse 80% 60% at 50% 40%, black 20%, transparent 70%); }
  .light .bg-gradient { opacity: 0.5; }
  .light .bg-orb { opacity: 0.06; }
  .light .bg-grid { opacity: 0.15; }
  .light .bg-particles { opacity: 0.3; }

  /* ── Floating Particles ─────────────────────────── */
  .bg-particles { position: absolute; inset: 0; pointer-events: none; z-index: 0; }
  a { color: var(--blue); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* ── Animations ──────────────────────────────────── */
  @keyframes fadeInUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
  @keyframes slideInRight { from { opacity: 0; transform: translateX(30px); } to { opacity: 1; transform: translateX(0); } }
  @keyframes pulseGreen { 0%,100% { box-shadow: 0 0 8px var(--green); } 50% { box-shadow: 0 0 20px var(--green); } }
  @keyframes pulseRed { 0%,100% { box-shadow: 0 0 0 rgba(248,81,73,0); border-color: var(--glass-border); } 50% { box-shadow: 0 0 16px 2px rgba(248,81,73,0.3); border-color: rgba(248,81,73,0.5); } }
  @keyframes pulseOrange { 0%,100% { box-shadow: 0 0 0 rgba(240,136,62,0); border-color: var(--glass-border); } 50% { box-shadow: 0 0 16px 2px rgba(240,136,62,0.3); border-color: rgba(240,136,62,0.5); } }
  @keyframes glowGreen { 0%,100% { box-shadow: 0 0 0 rgba(63,185,80,0); } 50% { box-shadow: 0 0 14px 2px rgba(63,185,80,0.15); } }
  @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Fixed Header ──────────────────────────────── */
  .hdr { position: fixed; top: 0; left: 0; right: 0; z-index: 200; background: var(--header-bg); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border-bottom: 1px solid var(--glass-border); height: 60px; display: flex; align-items: center; padding: 0 28px; gap: 20px; }
  .hdr-brand { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
  .hdr-brand svg { width: 28px; height: 28px; }
  .logo-spin { animation: spin 4s linear infinite; }
  .hdr-brand h1 { font-size: 17px; font-weight: 800; color: var(--text); white-space: nowrap; letter-spacing: -0.3px; }
  .hdr-brand h1 span { color: var(--text2); font-weight: 400; font-size: 12px; margin-left: 6px; }
  .hdr-sep { width: 1px; height: 26px; background: var(--glass-border); flex-shrink: 0; }
  .hdr-status { display: flex; align-items: center; gap: 14px; flex-shrink: 0; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .status-dot.healthy { background: var(--green); box-shadow: 0 0 10px var(--green); animation: pulseGreen 2s ease-in-out infinite; }
  .status-dot.unhealthy { background: var(--red); box-shadow: 0 0 10px var(--red); }
  .hdr-pill { font-size: 12px; color: var(--text2); }
  .hdr-pill strong { color: var(--text); font-weight: 600; }
  .hdr-spacer { flex: 1; }
  .hdr-right { display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
  .hdr-user { display: flex; align-items: center; gap: 8px; }
  .hdr-user-menu { position: relative; flex-shrink: 0; }
  .hdr-user-btn { display: flex; align-items: center; justify-content: center; gap: 4px; width: 40px; height: 40px; background: none; border: 1px solid var(--glass-border); border-radius: 50%; cursor: pointer; color: var(--text2); transition: all 0.2s; }
  .hdr-user-btn:hover { border-color: var(--blue); background: var(--hover-tint); color: var(--blue); }
  .hdr-user-icon { display: flex; align-items: center; justify-content: center; position: relative; }
  .hdr-user-icon .hdr-person { display: block; }
  .hdr-user-icon .hdr-avatar { display: none; width: 34px; height: 34px; border-radius: 50%; object-fit: cover; }
  .hdr-user-icon.has-photo .hdr-person { display: none; }
  .hdr-user-icon.has-photo .hdr-avatar { display: block; }
  .hdr-chevron { display: none; }
  .hdr-user-dropdown {
    position: absolute; right: 0; top: calc(100% + 8px); min-width: 220px; z-index: 300;
    background: var(--sp-bg); border: 1px solid var(--glass-border); border-radius: 10px;
    box-shadow: 0 8px 28px var(--card-shadow); padding: 6px; display: none;
  }
  .hdr-user-menu.open .hdr-user-dropdown { display: block; animation: fadeIn 0.15s ease; }
  .hdr-user-dropdown-head { padding: 10px 12px; border-bottom: 1px solid var(--border-subtle); margin-bottom: 4px; font-size: 12px; color: var(--text3); }
  .hdr-user-dropdown-head .hd-name { font-size: 14px; font-weight: 700; color: var(--text); }
  .hdr-user-dropdown-head .hd-mail { font-size: 12px; color: var(--text3); margin-top: 2px; word-break: break-all; }
  .hdr-user-dropdown-item {
    display: flex; align-items: center; gap: 10px; padding: 9px 12px; border-radius: 7px;
    font-size: 13px; color: var(--text); cursor: pointer; transition: all 0.15s;
  }
  .hdr-user-dropdown-item:hover { background: var(--hover-tint); color: var(--blue); }
  .hdr-user-dropdown-item.danger { color: var(--red); }
  .hdr-user-dropdown-item.danger:hover { background: rgba(248,81,73,0.1); color: var(--red); }
  .hdr-user-dropdown-sep { height: 1px; background: var(--border-subtle); margin: 6px 8px; }
  .dd-chev { margin-left: auto; opacity: 0.5; transition: transform 0.2s; }
  .dd-has-sub.open .dd-chev { transform: rotate(90deg); }
  .hdr-user-dropdown-panel { display: none; padding: 6px 10px 8px; }
  .hdr-user-dropdown-panel.open { display: block; animation: fadeIn 0.15s ease; }
  .dd-clr-picker { border: none; background: var(--hover-tint); justify-content: space-between; }
  .dm-option { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-radius: 7px; font-size: 13px; color: var(--text2); cursor: pointer; transition: all 0.15s; }
  .dm-option:hover { background: var(--hover-tint); color: var(--text); }
  .dm-option.active { color: var(--blue); background: rgba(88,166,255,0.1); }
  .dm-check { visibility: hidden; font-size: 12px; }
  .dm-option.active .dm-check { visibility: visible; }
  .hdr-avatar { width: 26px; height: 26px; border-radius: 50%; border: 1px solid var(--glass-border); object-fit: cover; }
  .hdr-email { font-size: 12px; color: var(--text2); white-space: nowrap; max-width: 180px; overflow: hidden; text-overflow: ellipsis; }
  .clr-picker { display: flex; align-items: center; gap: 4px; padding: 3px; border-radius: 8px; border: 1px solid var(--glass-border); background: var(--surface2); }
  .clr-dot { width: 16px; height: 16px; border-radius: 50%; border: 2px solid transparent; cursor: pointer; padding: 0; transition: all 0.2s; }
  .clr-dot:hover { transform: scale(1.25); }
  .clr-dot.active { border-color: var(--text); box-shadow: 0 0 6px rgba(255,255,255,0.2); }
  .hdr-time { font-size: 11px; color: var(--text2); font-family: var(--font-mono); }
  .hdr-clock-toggle { cursor: pointer; padding: 4px 8px; border-radius: 6px; transition: background 0.2s; display: inline-flex; align-items: center; gap: 5px; font-size: 11px; color: var(--text2); font-family: var(--font-mono); border: 1px solid var(--glass-border); }
  .hdr-clock-toggle:hover { background: var(--hover-tint); color: var(--text); }
  .tz-label { font-size: 9px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; }
  .hdr-tabs { display: flex; gap: 2px; }
  .tab-btn { background: none; border: none; color: var(--text2); font-size: 13px; font-weight: 500; padding: 8px 16px; cursor: pointer; border-radius: 6px; transition: all 0.2s; position: relative; }
  .tab-btn:hover { color: var(--text); background: var(--hover-tint); }
  .tab-btn.active { color: var(--blue); background: rgba(88,166,255,0.1); }
  .tab-btn.active::after { content: ''; position: absolute; bottom: -10px; left: 16px; right: 16px; height: 2px; background: var(--blue); border-radius: 1px; }
  .tab-badge { display: inline-block; background: var(--red); color: #fff; font-size: 10px; font-weight: 700; padding: 1px 5px; border-radius: 8px; margin-left: 4px; min-width: 16px; text-align: center; }
  .perm-tog { display: inline-block; padding: 3px 10px; margin: 2px 3px; border-radius: 12px; font-size: 11px; font-weight: 500; cursor: pointer; border: 1px solid; transition: all 0.15s; user-select: none; }
  .perm-tog:hover { opacity: 0.85; transform: scale(1.04); }
  .perm-tog.active { box-shadow: 0 2px 8px rgba(0,0,0,0.2); }

  /* ── Main Content ──────────────────────────────── */
  .main { padding-top: 76px; padding-bottom: 40px; width: 100%; padding-left: 20px; padding-right: 20px; }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; animation: fadeIn 0.3s ease; }

  /* ── Stat Cards (Glassmorphism) ────────────────── */
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin-bottom: 20px; }
  .stat-card { background: var(--glass-bg); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 20px 18px; text-align: center; transition: all 0.3s cubic-bezier(0.4,0,0.2,1); position: relative; overflow: hidden; opacity: 0; animation: fadeInUp 0.5s ease forwards; }
  .stat-card:nth-child(1) { animation-delay: 0.05s; }
  .stat-card:nth-child(2) { animation-delay: 0.1s; }
  .stat-card:nth-child(3) { animation-delay: 0.15s; }
  .stat-card:nth-child(4) { animation-delay: 0.2s; }
  .stat-card:nth-child(5) { animation-delay: 0.25s; }
  .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 14px 14px 0 0; }
  .stat-card.green::before { background: linear-gradient(90deg, var(--green), transparent); }
  .stat-card.blue::before { background: linear-gradient(90deg, var(--blue), transparent); }
  .stat-card.yellow::before { background: linear-gradient(90deg, var(--yellow), transparent); }
  .stat-card.purple::before { background: linear-gradient(90deg, var(--purple), transparent); }
  .stat-card.red::before { background: linear-gradient(90deg, var(--red), transparent); }
  .stat-card:hover { border-color: var(--border-glow); transform: translateY(-3px); box-shadow: 0 8px 32px var(--card-shadow); }
  .stat-card .value { font-size: 32px; font-weight: 700; line-height: 1.1; margin-bottom: 6px; transition: transform 0.3s cubic-bezier(0.4,0,0.2,1); }
  .stat-card .value.bump { transform: scale(1.12); }
  .stat-card .label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 500; }
  .stat-card.green .value { color: var(--green); }
  .stat-card.red .value { color: var(--red); }
  .stat-card.yellow .value { color: var(--yellow); }
  .stat-card.blue .value { color: var(--blue); }
  .stat-card.purple .value { color: var(--purple); }

  /* ── System Status Grid ────────────────────────── */
  .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 20px; }
  .status-item { background: var(--glass-bg); backdrop-filter: blur(8px); border: 1px solid var(--glass-border); border-radius: 10px; padding: 14px 16px; display: flex; align-items: center; gap: 10px; opacity: 0; animation: fadeInUp 0.5s ease forwards; transition: border-color 0.2s; }
  .status-item:hover { border-color: var(--border-glow); }
  .status-item:nth-child(1) { animation-delay: 0.3s; }
  .status-item:nth-child(2) { animation-delay: 0.35s; }
  .status-item:nth-child(3) { animation-delay: 0.4s; }
  .status-item:nth-child(4) { animation-delay: 0.45s; }
  .status-item:nth-child(5) { animation-delay: 0.5s; }
  .status-item:nth-child(6) { animation-delay: 0.55s; }
  .si-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .si-dot.on { background: var(--green); box-shadow: 0 0 8px rgba(63,185,80,0.4); }
  .si-dot.off { background: var(--text3); }
  .si-label { font-size: 12px; color: var(--text); font-weight: 500; }
  .si-sub { font-size: 10px; color: var(--text2); margin-top: 2px; }

  /* ── Panels ────────────────────────────────────── */
  .panels { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px; }
  @media (max-width: 900px) { .panels { grid-template-columns: 1fr; } }
  .panel { background: var(--glass-bg); backdrop-filter: blur(10px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 22px; opacity: 0; animation: fadeInUp 0.5s ease forwards; animation-delay: 0.35s; transition: border-color 0.2s; }
  .panel:hover { border-color: var(--border-glow); }
  .panel-title { font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
  .panel-title::before { content: ''; width: 3px; height: 14px; border-radius: 2px; background: var(--blue); }
  .full-panel { margin-bottom: 20px; animation-delay: 0.4s; }

  /* ── Bar Chart (Interactive) ───────────────────── */
  .bar-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; position: relative; }
  .bar-label { width: 140px; font-size: 13px; color: var(--text); text-align: right; flex-shrink: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bar-track { flex: 1; height: 28px; background: var(--surface2); border-radius: 6px; overflow: hidden; position: relative; }
  .bar-fill { height: 100%; border-radius: 6px; transition: width 0.8s cubic-bezier(0.4,0,0.2,1); display: flex; align-items: center; padding-left: 12px; font-size: 12px; font-weight: 600; color: #fff; min-width: 0; position: relative; }
  .bar-fill.green { background: linear-gradient(90deg, #1a7f37, var(--green)); }
  .bar-fill.blue { background: linear-gradient(90deg, #1f6feb, var(--blue)); }
  .bar-fill.purple { background: linear-gradient(90deg, #8957e5, var(--purple)); }
  .bar-fill.yellow { background: linear-gradient(90deg, #9e6a03, var(--yellow)); }
  .bar-fill.orange { background: linear-gradient(90deg, #bd561d, var(--orange)); }
  .bar-fill.red { background: linear-gradient(90deg, #da3633, var(--red)); }
  .bar-fill.cyan { background: linear-gradient(90deg, #1a7f8a, var(--cyan)); }
  .bar-count { width: 40px; font-size: 13px; font-weight: 600; color: var(--text); text-align: right; flex-shrink: 0; }
  .bar-empty { color: var(--text2); font-size: 13px; font-style: italic; padding: 20px; text-align: center; }
  .bar-tooltip { display: none; position: absolute; top: -36px; left: 50%; transform: translateX(-50%); background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; font-size: 12px; color: var(--text); white-space: nowrap; z-index: 10; pointer-events: none; box-shadow: 0 4px 12px rgba(0,0,0,0.4); }
  .bar-tooltip::after { content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%); border: 5px solid transparent; border-top-color: var(--border); }
  .bar-row:hover .bar-tooltip { display: block; }

  /* ── Donut Chart ───────────────────────────────── */
  .donut-wrap { display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }
  .donut-center { font-family: var(--font-mono); }
  .donut-legend { display: flex; flex-direction: column; gap: 10px; }
  .donut-legend-item { display: flex; align-items: center; gap: 10px; font-size: 13px; cursor: pointer; transition: opacity 0.2s; }
  .donut-legend-item:hover { opacity: 0.8; }
  .donut-legend-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }
  .donut-legend-count { color: var(--text2); font-size: 12px; margin-left: auto; font-family: var(--font-mono); }

  /* ── Activity Feed ─────────────────────────────── */
  .feed-wrap { background: var(--glass-bg); backdrop-filter: blur(10px); border: 1px solid var(--glass-border); border-radius: 14px; overflow: hidden; margin-bottom: 20px; opacity: 0; animation: fadeInUp 0.5s ease forwards; animation-delay: 0.5s; }
  .feed-head { padding: 16px 22px 0; font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; display: flex; align-items: center; gap: 8px; }
  .feed-head::before { content: ''; width: 3px; height: 14px; border-radius: 2px; background: var(--green); }
  .feed-pulse { width: 6px; height: 6px; border-radius: 50%; background: var(--green); margin-left: 8px; animation: pulseGreen 2s infinite; }
  .feed { max-height: 280px; overflow-y: auto; padding: 12px 22px 16px; }
  .feed::-webkit-scrollbar { width: 6px; }
  .feed::-webkit-scrollbar-track { background: transparent; }
  .feed::-webkit-scrollbar-thumb { background: var(--text3); border-radius: 3px; }
  .feed-item { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border-subtle); cursor: pointer; transition: background 0.15s; border-radius: 6px; padding-left: 8px; padding-right: 8px; margin: 0 -8px; }
  .feed-item:hover { background: var(--hover-tint); }
  .feed-item:last-child { border-bottom: none; }
  .feed-time { font-size: 11px; color: var(--text2); font-family: var(--font-mono); flex-shrink: 0; width: 60px; }
  .feed-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .feed-dot.heal { background: var(--green); box-shadow: 0 0 6px rgba(63,185,80,0.4); }
  .feed-dot.alert { background: var(--red); box-shadow: 0 0 6px rgba(248,81,73,0.4); }
  .feed-dot.warn { background: var(--yellow); box-shadow: 0 0 6px rgba(210,153,34,0.4); }
  .feed-dot.info { background: var(--blue); box-shadow: 0 0 6px rgba(88,166,255,0.4); }
  .feed-dot.removed { background: var(--text3); box-shadow: none; }
  .feed-name { font-size: 13px; font-weight: 500; color: var(--text); flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .feed-action { font-size: 12px; color: var(--text2); flex-shrink: 0; }
  .feed-icon { font-size: 14px; flex-shrink: 0; }
  .feed-empty { color: var(--text2); font-size: 13px; font-style: italic; padding: 32px; text-align: center; }

  /* ── Vertical Timeline ─────────────────────────── */
  .vtl { display: flex; flex-direction: column; padding: 0; }
  .vtl-filters { display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }
  .vtl-filter { background: none; border: 1px solid var(--glass-border); color: var(--text2); font-size: 12px; font-weight: 500; padding: 6px 14px; cursor: pointer; border-radius: 20px; transition: all 0.2s; }
  .vtl-filter:hover { border-color: var(--blue); color: var(--text); }
  .vtl-filter.active { background: rgba(88,166,255,0.12); border-color: var(--blue); color: var(--blue); }
  .vtl-item { display: flex; gap: 16px; position: relative; padding-bottom: 20px; cursor: pointer; transition: opacity 0.2s; }
  .vtl-item:hover { opacity: 0.85; }
  .vtl-item:last-child { padding-bottom: 0; }
  .vtl-item::before { content: ''; position: absolute; left: 11px; top: 24px; bottom: 0; width: 2px; background: var(--glass-border); }
  .vtl-item:last-child::before { display: none; }
  .vtl-dot { width: 24px; height: 24px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; border: 2px solid var(--bg); z-index: 2; transition: transform 0.2s; }
  .vtl-item:hover .vtl-dot { transform: scale(1.2); }
  .vtl-dot.critical { background: var(--red); box-shadow: 0 0 12px rgba(248,81,73,0.4); }
  .vtl-dot.warning { background: var(--yellow); box-shadow: 0 0 10px rgba(210,153,34,0.3); }
  .vtl-dot.success { background: var(--green); box-shadow: 0 0 10px rgba(63,185,80,0.3); }
  .vtl-dot.info { background: var(--blue); box-shadow: 0 0 8px rgba(88,166,255,0.3); }
  .vtl-body { flex: 1; min-width: 0; }
  .vtl-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap; }
  .vtl-name { font-size: 14px; font-weight: 600; color: var(--text); }
  .vtl-meta { font-size: 12px; color: var(--text2); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .vtl-sep { color: var(--text3); }
  .vtl-empty { color: var(--text2); font-size: 13px; font-style: italic; padding: 40px; text-align: center; }

  /* ── Provider Table ────────────────────────────── */
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500; padding: 10px 14px; border-bottom: 1px solid var(--glass-border); }
  td { padding: 12px 14px; font-size: 13px; border-bottom: 1px solid var(--border-subtle); }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--hover-tint); }
  .provider-name { font-weight: 600; }
  .provider-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px; }
  .rate-good { color: var(--green); font-weight: 600; }
  .rate-warn { color: var(--yellow); font-weight: 600; }
  .rate-bad { color: var(--red); font-weight: 600; }
  .latency { font-family: var(--font-mono); font-size: 13px; }
  .rate-bar { width: 80px; height: 6px; background: var(--border-subtle); border-radius: 3px; overflow: hidden; display: inline-block; vertical-align: middle; margin-left: 8px; }
  .rate-bar-fill { height: 100%; border-radius: 3px; transition: width 0.6s ease; }

  /* ── Diagnosis Cards ───────────────────────────── */
  .diag-card { background: var(--glass-bg); backdrop-filter: blur(8px); border: 1px solid var(--glass-border); border-radius: 12px; margin-bottom: 10px; transition: all 0.25s cubic-bezier(0.4,0,0.2,1); cursor: pointer; opacity: 0; animation: slideInRight 0.4s ease forwards; }
  .diag-card:hover { border-color: var(--blue); transform: translateX(4px); box-shadow: 0 4px 20px var(--card-shadow); }
  .diag-card.critical { animation: slideInRight 0.4s ease forwards, pulseRed 3s ease-in-out 0.4s infinite; }
  .diag-card.healed { animation: slideInRight 0.4s ease forwards, glowGreen 4s ease-in-out 0.4s infinite; }
  .diag-card.approval-pending { animation: slideInRight 0.4s ease forwards, pulseOrange 3s ease-in-out 0.4s infinite; border-color: rgba(240,136,62,0.4); }
  .diag-row { display: flex; align-items: center; gap: 10px; padding: 14px 18px; }
  .diag-name { font-weight: 700; font-size: 14px; color: var(--text); flex: 1; font-family: var(--font-mono); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .diag-ts { font-size: 11px; color: var(--text2); flex-shrink: 0; }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; flex-shrink: 0; }
  .badge-k8s { background: rgba(88,166,255,0.12); color: var(--blue); }
  .badge-docker { background: rgba(188,140,255,0.12); color: var(--purple); }
  .badge-oom { background: rgba(248,81,73,0.12); color: var(--red); }
  .badge-crash { background: rgba(240,136,62,0.12); color: var(--orange); }
  .badge-error { background: rgba(210,153,34,0.12); color: var(--yellow); }
  .badge-other { background: rgba(139,148,158,0.12); color: var(--text2); }
  .badge-healed { background: rgba(63,185,80,0.12); color: var(--green); }
  .badge-dev { background: rgba(248,81,73,0.12); color: var(--red); }
  .badge-escalate { background: rgba(210,153,34,0.12); color: var(--yellow); }
  .badge-rollback { background: rgba(240,136,62,0.12); color: var(--orange); }
  .badge-approval { background: rgba(240,136,62,0.18); color: var(--orange); border: 1px solid rgba(240,136,62,0.3); }
  .badge-rejected { background: rgba(248,81,73,0.12); color: var(--red); }
  .badge-removed { background: rgba(139,148,158,0.08); color: var(--text3); text-decoration: line-through; }
  .diag-card.removed { opacity: 0.45; border-style: dashed; border-color: var(--text3); pointer-events: none; }
  .diag-empty { color: var(--text2); font-size: 13px; font-style: italic; padding: 40px; text-align: center; }

  /* ── Filter Pills ──────────────────────────────── */
  .filter-pills { display: flex; gap: 6px; margin-bottom: 8px; }
  .pill-filter { background: var(--input-bg); border: 1px solid var(--glass-border); border-radius: 20px; padding: 5px 16px; font-size: 12px; font-weight: 600; color: var(--text2); cursor: pointer; transition: all 0.2s; }
  .pill-filter:hover { border-color: var(--blue); color: var(--text); }
  .pill-filter.active { background: var(--blue); border-color: var(--blue); color: #fff; }

  /* ── Card Hover Tooltip ────────────────────────── */
  .card-tooltip { display: none; position: fixed; z-index: 400; background: var(--tooltip-bg); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid var(--glass-border); border-radius: 10px; padding: 12px 16px; max-width: 340px; pointer-events: none; box-shadow: 0 8px 32px var(--card-shadow); font-size: 12px; line-height: 1.7; color: var(--text); }
  .card-tooltip strong { font-size: 13px; color: var(--text); font-family: var(--font-mono); }
  .card-tooltip .badge { margin: 2px 2px 0 0; }

  /* ── Filter Bar ────────────────────────────────── */
  .filter-bar { margin-bottom: 14px; }
  .filter-input-wrap { position: relative; }
  .filter-input-wrap input { width: 100%; background: var(--input-bg); border: 1px solid var(--glass-border); border-radius: 8px; padding: 10px 36px 10px 14px; color: var(--text); font-size: 13px; outline: none; transition: all 0.2s; box-sizing: border-box; }
  .filter-input-wrap input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(88,166,255,0.1); }
  .filter-input-wrap input::placeholder { color: var(--text3); }
  .filter-clear { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text2); font-size: 18px; cursor: pointer; padding: 4px 8px; border-radius: 4px; transition: color 0.15s; }
  .filter-clear:hover { color: var(--red); }

  /* ── Bottom Sheet ────────────────────────────────── */
  .sp-backdrop { position: fixed; inset: 0; background: var(--backdrop-bg); z-index: 300; opacity: 0; pointer-events: none; transition: opacity 0.15s ease; backdrop-filter: blur(4px); }
  .sp-backdrop.open { opacity: 1; pointer-events: auto; }
  .sp { position: fixed; bottom: 0; left: 0; right: 0; height: 55vh; max-width: 100%; background: var(--sp-bg); backdrop-filter: blur(20px); border-top: 1px solid var(--glass-border); z-index: 310; transform: translateY(100%); transition: transform 0.18s cubic-bezier(0.16, 1, 0.3, 1); display: flex; flex-direction: column; border-radius: 16px 16px 0 0; }
  .sp.open { transform: translateY(0); }
  .sp-handle { width: 40px; height: 4px; background: var(--text3); border-radius: 2px; margin: 10px auto 0; flex-shrink: 0; }
  .sp-head { display: flex; align-items: center; gap: 12px; padding: 12px 24px 14px; border-bottom: 1px solid var(--glass-border); flex-shrink: 0; }
  .sp-close { background: none; border: 1px solid var(--glass-border); color: var(--text2); width: 32px; height: 32px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 18px; transition: all 0.2s; flex-shrink: 0; }
  .sp-close:hover { border-color: var(--red); color: var(--red); background: rgba(248,81,73,0.08); }
  .sp-title { font-weight: 700; font-size: 16px; color: var(--text); font-family: var(--font-mono); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; letter-spacing: -0.3px; }
  .sp-badges { display: flex; gap: 6px; flex-shrink: 0; }
  .sp-body { flex: 1; overflow-y: auto; padding: 20px 24px; }
  .sp-section { margin-bottom: 18px; }
  .sp-section-title { font-size: 11px; font-weight: 700; color: var(--text2); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid var(--glass-border); }
  .sp-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px 18px; }
  .sp-field .lbl { font-size: 10px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 3px; font-weight: 600; }
  .sp-field .val { font-size: 13.5px; color: var(--text); word-break: break-all; line-height: 1.6; font-weight: 500; }
  .sp-field .val.mono { font-family: var(--font-mono); }
  .sp-box { background: var(--box-bg); border: 1px solid var(--glass-border); border-radius: 10px; padding: 12px; margin-bottom: 8px; }
  .sp-box:last-child { margin-bottom: 0; }
  .sp-box .blbl { font-size: 10px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; font-weight: 700; }
  .sp-box .bval { font-size: 13.5px; color: var(--text); line-height: 1.7; font-weight: 500; }
  .sp-box .bval.mono { font-family: var(--font-mono); }
  .sp-log { background: var(--log-bg); border: 1px solid var(--glass-border); border-radius: 10px; padding: 14px; max-height: 200px; overflow-y: auto; position: relative; }
  .sp-log pre { font-family: var(--font-mono); font-size: 11.5px; line-height: 1.7; color: var(--text2); white-space: pre-wrap; word-break: break-all; margin: 0; }
  .log-indicator { position: sticky; bottom: 0; text-align: center; padding: 8px; background: linear-gradient(transparent, rgba(10,14,23,0.9) 40%); font-size: 11px; color: var(--blue); cursor: pointer; display: none; border-radius: 0 0 10px 10px; }
  .log-indicator:hover { color: var(--text); }
  .log-indicator.visible { display: block; }

  /* ── Side Panel Content Animations ──────────────── */
  @keyframes spFadeSlideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes spFadeSlideLeft { from { opacity: 0; transform: translateX(-16px); } to { opacity: 1; transform: translateX(0); } }
  @keyframes spFadeIn { from { opacity: 0; } to { opacity: 1; } }
  .sp.open .sp-field { opacity: 0; animation: spFadeSlideUp 0.3s ease forwards; }
  .sp.open .sp-field:nth-child(1) { animation-delay: 0.05s; }
  .sp.open .sp-field:nth-child(2) { animation-delay: 0.08s; }
  .sp.open .sp-field:nth-child(3) { animation-delay: 0.11s; }
  .sp.open .sp-field:nth-child(4) { animation-delay: 0.14s; }
  .sp.open .sp-field:nth-child(5) { animation-delay: 0.17s; }
  .sp.open .sp-field:nth-child(6) { animation-delay: 0.20s; }
  .sp.open .sp-field:nth-child(7) { animation-delay: 0.23s; }
  .sp.open .sp-field:nth-child(8) { animation-delay: 0.26s; }
  .sp.open .sp-field:nth-child(9) { animation-delay: 0.29s; }
  .sp.open .sp-section-title { opacity: 0; animation: spFadeIn 0.3s ease forwards; }
  .sp.open .sp-section:nth-child(1) .sp-section-title { animation-delay: 0.02s; }
  .sp.open .sp-section:nth-child(2) .sp-section-title { animation-delay: 0.12s; }
  .sp.open .sp-section:nth-child(3) .sp-section-title { animation-delay: 0.22s; }
  .sp.open .sp-box { opacity: 0; animation: spFadeSlideLeft 0.35s ease forwards; }
  .sp.open .sp-box:nth-child(1) { animation-delay: 0.15s; }
  .sp.open .sp-box:nth-child(2) { animation-delay: 0.22s; }
  .sp.open .sp-box:nth-child(3) { animation-delay: 0.29s; }
  .sp.open .sp-box:nth-child(4) { animation-delay: 0.36s; }
  .sp.open .sp-log { opacity: 0; animation: spFadeIn 0.4s ease 0.3s forwards; }
  .sp-box.summary { border-left: 3px solid var(--green); }
  .sp-box.root-cause { border-left: 3px solid var(--red); }
  .sp-box.recommendation { border-left: 3px solid var(--blue); }
  .sp-box.cost { border-left: 3px solid var(--purple); }
  .sp.open .sp-handle { background: var(--blue); box-shadow: 0 0 8px rgba(88,166,255,0.4); transition: all 0.3s ease 0.1s; }

  /* ── Toast Notifications ───────────────────────── */
  #toasts { position: fixed; top: 72px; right: 24px; z-index: 500; display: flex; flex-direction: column; gap: 8px; pointer-events: none; }
  .toast { background: var(--toast-bg); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 12px; padding: 12px 18px; display: flex; align-items: center; gap: 10px; box-shadow: 0 8px 32px var(--card-shadow); transform: translateX(120%); transition: transform 0.4s cubic-bezier(0.4,0,0.2,1), opacity 0.3s; pointer-events: auto; max-width: 400px; }
  .toast.show { transform: translateX(0); }
  .toast.hide { opacity: 0; transform: translateX(30px); }
  .toast-icon { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .toast-icon.heal { background: var(--green); box-shadow: 0 0 8px var(--green); }
  .toast-icon.alert { background: var(--red); box-shadow: 0 0 8px var(--red); }
  .toast-icon.warn { background: var(--yellow); box-shadow: 0 0 8px var(--yellow); }
  .toast-msg { font-size: 12px; color: var(--text); line-height: 1.4; }
  .toast-msg strong { color: var(--text); }

  /* ── Theme Toggle ────────────────────────────────── */

  /* ── Metrics Tab ────────────────────────────────── */
  .metrics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px; }
  .metrics-stat-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
  .metrics-stat-card { background: var(--glass-bg); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 16px 18px; display: flex; align-items: center; gap: 14px; position: relative; overflow: hidden; transition: all 0.25s cubic-bezier(0.4,0,0.2,1); cursor: default; }
  .metrics-stat-card:hover { border-color: var(--border-glow); box-shadow: 0 8px 32px rgba(0,0,0,0.3); transform: translateY(-2px); }
  .metrics-stat-card::after { content: ''; position: absolute; inset: 0; border-radius: 14px; opacity: 0; transition: opacity 0.3s; background: linear-gradient(135deg, rgba(255,255,255,0.04) 0%, transparent 50%); pointer-events: none; }
  .metrics-stat-card:hover::after { opacity: 1; }
  .metrics-stat-card .stat-accent { width: 4px; height: 48px; border-radius: 3px; flex-shrink: 0; }
  .metrics-stat-card.green .stat-accent { background: var(--green); }
  .metrics-stat-card.blue .stat-accent { background: var(--blue); }
  .metrics-stat-card.red .stat-accent { background: var(--red); }
  .metrics-stat-card.purple .stat-accent { background: var(--purple); }
  .metrics-stat-card .stat-body { flex: 1; min-width: 0; }
  .metrics-stat-card .stat-val { font-size: 26px; font-weight: 800; color: var(--text); line-height: 1.1; letter-spacing: -0.5px; }
  .metrics-stat-card.green .stat-val { color: var(--green); }
  .metrics-stat-card.blue .stat-val { color: var(--blue); }
  .metrics-stat-card.red .stat-val { color: var(--red); }
  .metrics-stat-card.purple .stat-val { color: var(--purple); }
  .metrics-stat-card .stat-label { font-size: 10px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 500; margin-top: 2px; }
  .metrics-stat-card .stat-trend { font-size: 11px; font-weight: 600; margin-left: auto; flex-shrink: 0; display: flex; align-items: center; gap: 3px; }
  .metrics-stat-card .stat-trend.up { color: var(--green); }
  .metrics-stat-card .stat-trend.down { color: var(--red); }
  .metrics-stat-card .stat-trend.flat { color: var(--text3); }
  .metrics-stat-card .stat-sparkline { width: 64px; height: 32px; flex-shrink: 0; margin-left: auto; }
  .metrics-stat-card .stat-sparkline canvas { width: 100% !important; height: 100% !important; display: block; }
  .metrics-chart-card { background: var(--glass-bg); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 20px; opacity: 0; animation: fadeInUp 0.5s ease forwards; transition: all 0.25s cubic-bezier(0.4,0,0.2,1); }
  .metrics-chart-card:hover { border-color: var(--border-glow); box-shadow: 0 8px 32px rgba(0,0,0,0.2); transform: translateY(-1px); }
  .metrics-chart-card h3 { font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
  .metrics-chart-card h3::before { content: ''; width: 3px; height: 14px; background: var(--blue); border-radius: 2px; }
  .metrics-chart-card h3 .chart-desc { font-weight: 400; font-size: 10px; color: var(--text3); text-transform: none; letter-spacing: 0; margin-left: auto; }
  .metrics-chart-card canvas { width: 100% !important; max-height: 260px; }
  .metrics-chart-card.gauge-card { display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .metrics-chart-card.full-width { grid-column: 1 / -1; }
  .metrics-empty { color: var(--text2); font-size: 13px; font-style: italic; padding: 40px; text-align: center; grid-column: 1 / -1; }
  .metrics-toolbar { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
  .metrics-toolbar-label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; }
  .metrics-range-btns { display: flex; gap: 2px; background: var(--surface2); border-radius: 8px; padding: 3px; }
  .range-btn { background: none; border: none; color: var(--text2); font-size: 12px; font-weight: 500; padding: 5px 12px; border-radius: 6px; cursor: pointer; transition: all 0.2s; font-family: var(--font-mono); }
  .range-btn:hover { color: var(--text); background: var(--hover-tint); }
  .range-btn.active { color: var(--blue); background: rgba(88,166,255,0.12); font-weight: 600; }
  .metrics-refresh-select { background: var(--surface2); border: 1px solid var(--glass-border); color: var(--text2); font-size: 11px; font-weight: 500; padding: 4px 8px; border-radius: 6px; cursor: pointer; font-family: var(--font-mono); outline: none; transition: border-color 0.2s; margin-left: auto; }
  .metrics-refresh-select:hover, .metrics-refresh-select:focus { border-color: var(--blue); color: var(--text); }
  .metrics-last-updated { font-size: 10px; color: var(--text3); font-family: var(--font-mono); }
  .metrics-gauge-wrap { position: relative; width: 100%; max-width: 220px; aspect-ratio: 1; margin: 0 auto; }
  .metrics-gauge-ring { position: absolute; inset: 0; border-radius: 50%; background: conic-gradient(var(--gauge-color) 0deg, rgba(48,54,61,0.3) 0deg); transition: background 0.6s ease; }
  .metrics-gauge-ring::before { content: ''; position: absolute; inset: 18%; border-radius: 50%; background: var(--glass-bg); }
  .gauge-center-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; pointer-events: none; }
  .gauge-center-label .gauge-val { font-size: 24px; font-weight: 800; color: var(--gauge-color); line-height: 1; letter-spacing: -0.5px; transition: color 0.6s ease; }
  .gauge-center-label .gauge-sub { font-size: 9px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.6px; margin-top: 5px; font-weight: 600; }
  @media (max-width: 900px) { .metrics-grid { grid-template-columns: 1fr; } .metrics-stat-row { grid-template-columns: repeat(2, 1fr); } .metrics-stat-card .stat-sparkline { width: 48px; } }

  /* ── Approvals Tab ────────────────────────────────── */
  .approval-card { background: var(--glass-bg); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 20px; margin-bottom: 12px; }
  .approval-card.pending { border-left: 4px solid var(--orange); }
  .approval-card.approved { border-left: 4px solid var(--green); }
  .approval-card.rejected { border-left: 4px solid var(--red); }
  .approval-card.executed { border-left: 4px solid var(--blue); }
  .approval-card.expired { border-left: 4px solid var(--text3); opacity: 0.6; }
  .approval-card.removed { border-left: 4px solid var(--text3); opacity: 0.45; border-style: dashed; }
  .approval-header { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
  .approval-header .name { font-size: 15px; font-weight: 600; color: var(--text); }
  .approval-status { font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .approval-status.pending { background: rgba(240,136,62,0.15); color: var(--orange); }
  .approval-status.approved { background: rgba(63,185,80,0.15); color: var(--green); }
  .approval-status.rejected { background: rgba(248,81,73,0.15); color: var(--red); }
  .approval-status.executed { background: rgba(88,166,255,0.15); color: var(--blue); }
  .approval-status.expired { background: rgba(139,148,158,0.15); color: var(--text3); }
  .approval-status.removed { background: rgba(139,148,158,0.08); color: var(--text3); text-decoration: line-through; }
  .approval-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px; }
  .approval-meta .field { font-size: 12px; }
  .approval-meta .field .lbl { color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; font-size: 10px; font-weight: 600; }
  .approval-meta .field .val { color: var(--text); font-size: 13px; margin-top: 2px; }
  .approval-meta .field .val.mono { font-family: var(--font-mono); }
  .approval-actions { display: flex; gap: 8px; margin-top: 12px; }
  .approval-btn { padding: 8px 20px; border-radius: 8px; border: none; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
  .approval-btn.approve { background: var(--green); color: #fff; }
  .approval-btn.approve:hover { filter: brightness(1.1); }
  .approval-btn.reject { background: var(--red); color: #fff; }
  .approval-btn.reject:hover { filter: brightness(1.1); }
  .approval-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .approval-empty { color: var(--text2); font-size: 13px; font-style: italic; padding: 40px; text-align: center; }
  .approval-section-title { font-size: 12px; font-weight: 700; color: var(--text2); text-transform: uppercase; letter-spacing: 1px; margin: 20px 0 10px; padding-bottom: 6px; border-bottom: 1px solid var(--glass-border); }
  .approval-section-title:first-child { margin-top: 0; }

  /* ── Footer ────────────────────────────────────── */
  .footer { text-align: center; padding: 14px 24px; border-top: 1px solid var(--glass-border); font-size: 11px; color: var(--text3); }
  .footer a { margin-left: 10px; color: var(--text2); }
  .footer a:hover { color: var(--blue); }

  @media (max-width: 1200px) { .stats { grid-template-columns: repeat(3, 1fr); } }
  @media (max-width: 768px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .stat-card:nth-child(5) { grid-column: span 2; }
    .status-grid { grid-template-columns: repeat(2, 1fr); }
    .hdr-tabs { display: none; }
    .hdr { padding: 0 16px; gap: 12px; }
    .main { padding-left: 12px; padding-right: 12px; }
  }

  /* ── Change Password Modal ──────────────────────── */
  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); z-index: 1000; align-items: center; justify-content: center; }
  .modal-overlay.active { display: flex; }
  .modal-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 28px 32px; max-width: 400px; width: 90%; box-shadow: 0 16px 48px rgba(0,0,0,0.4); }
  .modal-card h2 { margin: 0 0 4px; font-size: 18px; color: var(--text); }
  .modal-card p { color: var(--text2); font-size: 13px; margin: 0 0 18px; }
  .modal-field { margin-bottom: 14px; }
  .modal-field label { display: block; font-size: 11px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
  .modal-field input { width: 100%; padding: 10px 12px; font-size: 14px; color: var(--text); background: rgba(13,17,23,0.8); border: 1px solid var(--border); border-radius: 8px; outline: none; transition: border-color 0.2s; box-sizing: border-box; }
  .modal-field input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(88,166,255,0.1); }
  .modal-actions { display: flex; gap: 10px; margin-top: 18px; }
  .modal-btn { flex: 1; padding: 10px 0; font-size: 13px; font-weight: 600; border: none; border-radius: 8px; cursor: pointer; transition: all 0.2s; }
  .modal-btn.primary { background: var(--blue); color: #fff; }
  .modal-btn.primary:hover { box-shadow: 0 4px 12px rgba(88,166,255,0.3); }
  .modal-btn.secondary { background: rgba(48,54,61,0.6); color: var(--text2); }
  .profile-row { display: flex; justify-content: space-between; align-items: center; padding: 11px 0; border-bottom: 1px solid var(--border-subtle); }
  .profile-row:last-of-type { border-bottom: none; }
  .profile-label { font-size: 12px; font-weight: 600; color: var(--text3); text-transform: uppercase; letter-spacing: 0.5px; }
  .profile-value { font-size: 14px; color: var(--text); word-break: break-all; text-align: right; }
  .profile-avatar-wrap { position: relative; width: 84px; height: 84px; margin: 0 auto 16px; }
  .profile-avatar { width: 84px; height: 84px; border-radius: 50%; background: var(--hover-tint); border: 2px dashed var(--border); display: flex; align-items: center; justify-content: center; color: var(--text3); overflow: hidden; }
  .profile-avatar img { width: 100%; height: 100%; object-fit: cover; }
  .profile-avatar-edit { position: absolute; right: -4px; bottom: -2px; width: 28px; height: 28px; border-radius: 50%; background: var(--blue); color: #fff; display: flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: 0 2px 8px rgba(0,0,0,0.4); transition: transform 0.15s; }
  .profile-avatar-edit:hover { transform: scale(1.1); }
  .profile-pic-remove { position: absolute; top: -4px; left: -4px; width: 24px; height: 24px; border-radius: 50%; background: var(--red); color: #fff; border: none; font-size: 12px; cursor: pointer; box-shadow: 0 2px 8px rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; }
  .modal-btn.secondary:hover { background: rgba(48,54,61,0.9); color: var(--text); }
  .modal-msg { margin-top: 12px; padding: 10px 14px; font-size: 13px; border-radius: 8px; text-align: center; display: none; }
  .modal-msg.success { display: block; background: rgba(63,185,80,0.1); color: var(--green); border: 1px solid rgba(63,185,80,0.2); }
  .modal-msg.error { display: block; background: rgba(248,81,73,0.08); color: var(--red); border: 1px solid rgba(248,81,73,0.2); }

  /* ── Reports Tab ───────────────────────────────── */
  .report-block { max-width: 560px; }
  .report-desc { color: var(--text2); font-size: 13px; line-height: 1.5; margin-bottom: 20px; }
  .report-range-row { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }
  .report-range-label { font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; }
  .report-actions { display: flex; }
  .report-actions .modal-btn { flex: 0 0 auto; padding: 11px 22px; }

  /* ── Boot Splash (crack -> join logo) ───────────── */
  #boot-splash { position: fixed; inset: 0; z-index: 9998; background: #0a0e17; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 20px; opacity: 1; transition: opacity 0.6s ease; will-change: opacity; }
  #boot-splash.fade { opacity: 0; pointer-events: none; }
  .boot-shard-wrap { position: relative; width: 108px; height: 108px; }
  .boot-shard { position: absolute; inset: 0; }
  .boot-shard svg { width: 108px; height: 108px; color: var(--blue, #58a6ff); filter: drop-shadow(0 0 12px rgba(88,166,255,0.35)); }
  .boot-shard.s1 { clip-path: polygon(0 0, 50% 0, 50% 50%, 0 50%); --dx: -52px; --dy: -52px; --dr: -22deg; animation: bootJoin 0.9s cubic-bezier(0.22, 1.2, 0.36, 1) 0.0s forwards; }
  .boot-shard.s2 { clip-path: polygon(50% 0, 100% 0, 100% 50%, 50% 50%); --dx: 52px; --dy: -52px; --dr: 22deg; animation: bootJoin 0.9s cubic-bezier(0.22, 1.2, 0.36, 1) 0.08s forwards; }
  .boot-shard.s3 { clip-path: polygon(0 50%, 50% 50%, 50% 100%, 0 100%); --dx: -52px; --dy: 52px; --dr: 22deg; animation: bootJoin 0.9s cubic-bezier(0.22, 1.2, 0.36, 1) 0.16s forwards; }
  .boot-shard.s4 { clip-path: polygon(50% 50%, 100% 50%, 100% 100%, 50% 100%); --dx: 52px; --dy: 52px; --dr: -22deg; animation: bootJoin 0.9s cubic-bezier(0.22, 1.2, 0.36, 1) 0.24s forwards; }
  @keyframes bootJoin {
    0% { transform: translate(var(--dx), var(--dy)) rotate(var(--dr)); opacity: 0; }
    55% { opacity: 1; }
    78% { transform: translate(calc(var(--dx) * -0.22), calc(var(--dy) * -0.22)) rotate(calc(var(--dr) * -0.35)); }
    100% { transform: translate(0, 0) rotate(0); opacity: 1; }
  }
  @keyframes bootShake {
    0%, 100% { transform: translate(0, 0); }
    12% { transform: translate(-3px, 2px) rotate(-0.6deg); }
    28% { transform: translate(3px, -2px) rotate(0.6deg); }
    44% { transform: translate(-2px, -2px) rotate(-0.4deg); }
    60% { transform: translate(2px, 2px) rotate(0.4deg); }
  }
  .boot-shake { animation: bootShake 0.55s ease-out 0.05s both; }
  .boot-crack { position: absolute; inset: 0; pointer-events: none; opacity: 1; animation: bootCrackFade 0.75s ease-out 0.1s forwards; }
  .boot-crack svg { width: 108px; height: 108px; color: rgba(139, 148, 158, 0.9); }
  @keyframes bootCrackFade { 0% { opacity: 1; } 70% { opacity: 0.35; } 100% { opacity: 0; } }
  .boot-glow { position: absolute; left: 50%; top: 50%; width: 140px; height: 140px; transform: translate(-50%, -50%); border-radius: 50%; background: radial-gradient(circle, rgba(88,166,255,0.35) 0%, rgba(88,166,255,0) 65%); opacity: 0; animation: bootGlowPulse 0.5s ease-out 0.78s forwards; }
  @keyframes bootGlowPulse { 0% { opacity: 0; transform: translate(-50%, -50%) scale(0.5); } 60% { opacity: 1; } 100% { opacity: 0; transform: translate(-50%, -50%) scale(1.25); } }
  .boot-status { font-size: 15px; font-weight: 600; color: #8b949e; letter-spacing: 1.5px; text-transform: uppercase; min-height: 20px; }
  .boot-status .dot { color: var(--blue, #58a6ff); }
  .boot-welcome { font-size: 22px; font-weight: 800; color: #e6edf3; letter-spacing: -0.5px; opacity: 0; transform: translateY(8px); transition: opacity 0.45s ease, transform 0.45s ease; }
  .boot-welcome span { color: var(--blue, #58a6ff); }
  .boot-welcome.show { opacity: 1; transform: translateY(0); }
  /* ── P4: Micro-interactions & polish ─────────────────────────────────── */
  .btn-ripple { position: relative; overflow: hidden; }
  .ripple { position: absolute; border-radius: 50%; background: rgba(255,255,255,0.35); transform: scale(0); animation: rippleAnim .55s ease-out forwards; pointer-events: none; }
  @keyframes rippleAnim { to { transform: scale(2.6); opacity: 0; } }
  .light .ripple { background: rgba(0,0,0,0.14); }
  .stat-card, .metrics-stat-card { transition: transform .18s ease-out, box-shadow .25s ease, border-color .2s ease; }
  .hdr-brand h1 { background: linear-gradient(90deg, var(--text,#e6edf3) 0%, var(--blue,#58a6ff) 50%, var(--text,#e6edf3) 100%); background-size: 200% auto; -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; color: transparent; animation: shimmer 5s linear infinite; }
  .sk-wrap { padding: 8px 0; }
  .sk-row { display: flex; gap: 12px; padding: 13px 2px; border-bottom: 1px solid var(--border-subtle,#1f2733); }
  .sk-cell { height: 14px; border-radius: 6px; background: linear-gradient(90deg, rgba(140,160,190,0.10) 25%, rgba(140,160,190,0.22) 37%, rgba(140,160,190,0.10) 63%); background-size: 200% 100%; animation: shimmer 1.4s linear infinite; }
  body { transition: background-color .28s ease, color .28s ease; }
  .theme-xfade { animation: themeFade .34s ease; }
  @keyframes themeFade { 0% { opacity: .45; } 100% { opacity: 1; } }
  .tab-panel.exiting { animation: tabOut .18s ease forwards; }
  @keyframes tabOut { to { opacity: 0; transform: translateX(-8px); } }
  @media (prefers-reduced-motion: reduce) {
    .ripple { display: none; }
    .hdr-brand h1, .sk-cell { animation: none !important; }
  }
  #boot-splash.spin .boot-shard-wrap { animation: bootSpin 1.6s linear infinite; }
  #boot-splash.spin .boot-shard { animation: none; opacity: 1; }
  #boot-splash.spin .boot-crack, #boot-splash.spin .boot-glow,
  #boot-splash.spin .boot-status, #boot-splash.spin .boot-welcome { display: none; }
  @keyframes bootSpin { to { transform: rotate(360deg); } }
</style>
</head>
 <body>

<div id="boot-splash">
  <div class="boot-shard-wrap boot-shake">
    <div class="boot-glow"></div>
    <div class="boot-shard s1">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
    </div>
    <div class="boot-shard s2">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
    </div>
    <div class="boot-shard s3">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
    </div>
    <div class="boot-shard s4">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
    </div>
    <div class="boot-crack">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="0.9"><path d="M12 2 L12 5 M12 8 L12 11 M12 14 L12 17 M12 20 L12 22 M2 12 L5 12 M8 12 L11 12 M14 12 L17 12 M20 12 L22 12 M5 5 L7.5 7.5 M16.5 16.5 L19 19 M19 5 L16.5 7.5 M7.5 16.5 L5 19 M6 8 L9.5 11.5 M15 15 L18 18 M18 8 L14.5 11.5 M9.5 12.5 L6 16"/></svg>
    </div>
  </div>
  <div class="boot-status">Initialising Healix<span class="dot" id="boot-dots"></span></div>
  <div class="boot-welcome" id="boot-welcome">Welcome<span id="boot-who"></span></div>
</div>
<script>
(function() {
  var s = document.getElementById('boot-splash');
  if (!s) return;
  var fresh = false;
  try { fresh = sessionStorage.getItem('healixFresh') === '1'; sessionStorage.removeItem('healixFresh'); } catch(e) {}
  if (!fresh) {
    s.classList.add('spin');
    setTimeout(function() { s.classList.add('fade'); }, 1100);
    setTimeout(function() { if (s.parentNode) s.parentNode.removeChild(s); }, 1750);
    return;
  }
  var dots = document.getElementById('boot-dots'), n = 0;
  var dint = setInterval(function() { n = (n + 1) % 4; dots.textContent = '.'.repeat(n); }, 350);
  fetch('/users/me').then(function(r){return r.json();}).then(function(d){
    var who = document.getElementById('boot-who');
    if (who && d && d.username) who.textContent = ', ' + esc(d.username);
  }).catch(function(){});
  setTimeout(function() {
    var w = document.getElementById('boot-welcome');
    if (w) w.classList.add('show');
  }, 1150);
  setTimeout(function() { s.classList.add('fade'); clearInterval(dint); }, 2250);
  setTimeout(function() { if (s.parentNode) s.parentNode.removeChild(s); }, 2900);
})();
</script>

<div class="bg-canvas">
  <div class="bg-gradient"></div>
  <div class="bg-orb"></div>
  <div class="bg-orb"></div>
  <div class="bg-orb"></div>
  <div class="bg-orb"></div>
  <div class="bg-grid"></div>
  <div class="bg-particles" id="bg-particles"></div>
</div>

<div id="toasts"></div>
<div id="card-tooltip" class="card-tooltip"></div>

<header class="hdr">
      <div class="hdr-brand" onclick="switchTab('overview')" style="cursor:pointer">
    <svg class="logo-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--blue)"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
    <h1>Healix</h1>
  </div>
  <div class="hdr-sep"></div>
  <div class="hdr-status">
    <span class="status-dot healthy" id="hdr-dot"></span>
    <span class="hdr-pill">Uptime <strong id="hdr-uptime">—</strong></span>
    <span class="hdr-pill">Checks <strong id="hdr-checks">—</strong></span>
  </div>
  <div class="hdr-spacer"></div>
  <div class="hdr-right">
    <span class="hdr-clock-toggle" id="hdr-clock-toggle" onclick="toggleTimezone()"><span id="hdr-clock"></span><span class="tz-label" id="hdr-tz">LOCAL</span></span>
    <nav class="hdr-tabs">
      <button class="tab-btn active" data-tab="overview">Overview</button>
      <button class="tab-btn" data-tab="pods" id="pods-tab">Pods <span class="tab-badge" id="pod-count" style="display:none">0</span></button>
      <button class="tab-btn" data-tab="containers" id="containers-tab">Containers <span class="tab-badge" id="container-count" style="display:none">0</span></button>
      <button class="tab-btn" data-tab="timeline">Timeline</button>
      <button class="tab-btn" data-tab="llm">LLM</button>
<button class="tab-btn" data-tab="metrics">Metrics</button>
<button class="tab-btn" data-tab="approvals" id="approvals-tab">Approvals <span class="tab-badge" id="approval-count" style="display:none">0</span></button>
<button class="tab-btn" data-tab="reports">Reports</button>
    </nav>
    <div class="hdr-user-menu" id="hdr-user-menu">
      <button class="hdr-user-btn" onclick="toggleUserMenu(event)" title="Account">
        <span class="hdr-user-icon">
          <img class="hdr-avatar" id="hdr-avatar" src="" alt="">
          <svg class="hdr-person" id="hdr-person" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        </span>
        <svg class="hdr-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div class="hdr-user-dropdown" id="hdr-user-dropdown">
        <div class="hdr-user-dropdown-head" id="hdr-user-dropdown-head"></div>
        <div class="hdr-user-dropdown-item" onclick="openProfile();closeUserMenu()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
          Profile
        </div>
        <div class="hdr-user-dropdown-item" id="menu-users-item" onclick="switchTab('users');closeUserMenu()" style="display:none">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
          Users
        </div>
        <div class="hdr-user-dropdown-item" onclick="openChangePwModal();closeUserMenu()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          Change Password
        </div>
        <div class="hdr-user-dropdown-sep"></div>
        <div class="hdr-user-dropdown-item dd-has-sub" onclick="toggleDropdownPanel('theme-color-panel', this)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="13.5" cy="6.5" r=".5"/><circle cx="17.5" cy="10.5" r=".5"/><circle cx="8.5" cy="7.5" r=".5"/><circle cx="6.5" cy="12.5" r=".5"/><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z"/></svg>
          Theme Color
          <svg class="dd-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>
        </div>
        <div class="hdr-user-dropdown-panel" id="theme-color-panel">
          <div class="clr-picker dd-clr-picker" id="clr-picker">
            <button class="clr-dot active" data-clr="blue" style="background:#58a6ff" onclick="setColorTheme('blue')" title="Blue"></button>
            <button class="clr-dot" data-clr="purple" style="background:#bc8cff" onclick="setColorTheme('purple')" title="Purple"></button>
            <button class="clr-dot" data-clr="green" style="background:#3fb950" onclick="setColorTheme('green')" title="Green"></button>
            <button class="clr-dot" data-clr="orange" style="background:#f0883e" onclick="setColorTheme('orange')" title="Orange"></button>
            <button class="clr-dot" data-clr="red" style="background:#f85149" onclick="setColorTheme('red')" title="Red"></button>
            <button class="clr-dot" data-clr="teal" style="background:#39d2c0" onclick="setColorTheme('teal')" title="Teal"></button>
          </div>
        </div>
        <div class="hdr-user-dropdown-item dd-has-sub" onclick="toggleDropdownPanel('display-mode-panel', this)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><rect x="1" y="3" width="18" height="14" rx="2" ry="2"/><line x1="6" y1="21" x2="14" y2="21"/><line x1="10" y1="17" x2="10" y2="21"/><path d="M19 11a3 3 0 0 0 0-6M21 12a5 5 0 0 0-2-9.5"/></svg>
          Display Mode
          <svg class="dd-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>
        </div>
        <div class="hdr-user-dropdown-panel" id="display-mode-panel">
          <div class="dm-option" data-mode="light" onclick="setDisplayMode('light', event)"><span class="dm-check">✓</span>Light</div>
          <div class="dm-option" data-mode="dark" onclick="setDisplayMode('dark', event)"><span class="dm-check">✓</span>Dark</div>
          <div class="dm-option" data-mode="auto" onclick="setDisplayMode('auto', event)"><span class="dm-check">✓</span>Auto</div>
        </div>
        <div class="hdr-user-dropdown-sep"></div>
        <div class="hdr-user-dropdown-item danger" onclick="logout()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          Sign out
        </div>
      </div>
    </div>
  </div>
</header>

<div class="sp-backdrop" id="sp-backdrop" onclick="closeSidePanel()"></div>
<div class="sp" id="side-panel">
  <div class="sp-handle"></div>
  <div class="sp-head">
    <button class="sp-close" onclick="closeSidePanel()">&times;</button>
    <div class="sp-title" id="sp-name">—</div>
    <div class="sp-badges" id="sp-badges"></div>
  </div>
  <div class="sp-body">
    <div class="sp-section">
      <div class="sp-section-title">Details</div>
      <div class="sp-grid" id="sp-details"></div>
    </div>
    <div class="sp-section">
      <div class="sp-section-title">Diagnosis</div>
      <div id="sp-diagnosis"></div>
    </div>
    <div class="sp-section">
      <div class="sp-section-title">Logs</div>
      <div class="sp-log" id="sp-log-wrap">
        <pre id="sp-logs">No logs available</pre>
        <div class="log-indicator" id="log-indicator" onclick="scrollLogsToBottom()">New logs available &darr;</div>
      </div>
    </div>
  </div>
</div>

<main class="main">
  <div id="loading" style="text-align:center;padding:80px;color:var(--text2);font-size:13px">
    <div style="width:32px;height:32px;border:3px solid var(--glass-border);border-top-color:var(--blue);border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 16px"></div>
    Loading metrics...
  </div>
  <style>@keyframes spin { to { transform: rotate(360deg); } }</style>

  <div id="content" style="display:none">

    <div class="tab-panel active" id="panel-overview">
      <div class="stats">
        <div class="stat-card green"><div class="value" id="s-heals">0</div><div class="label">Heals Total</div></div>
        <div class="stat-card blue"><div class="value" id="s-llm-calls">0</div><div class="label">LLM Calls</div></div>
        <div class="stat-card yellow"><div class="value" id="s-rollbacks">0</div><div class="label">Rollbacks</div></div>
        <div class="stat-card purple"><div class="value" id="s-pdb">0</div><div class="label">PDB Blocked</div></div>
        <div class="stat-card red"><div class="value" id="s-errors">0</div><div class="label">LLM Errors</div></div>
      </div>

      <div class="status-grid" id="status-grid"></div>

      <div class="panels">
        <div class="panel">
          <div class="panel-title">Actions by Type</div>
          <div id="chart-actions"></div>
        </div>
        <div class="panel">
          <div class="panel-title">Actions by Route</div>
          <div id="chart-routes"></div>
        </div>
      </div>
      <div class="panels">
        <div class="panel">
          <div class="panel-title">Healing by Platform</div>
          <div id="chart-platforms"></div>
        </div>
        <div class="panel">
          <div class="panel-title">Diagnosis Breakdown</div>
          <div class="donut-wrap" id="donut-wrap">
            <svg id="donut-svg" viewBox="0 0 200 200" width="150" height="150"></svg>
            <div class="donut-legend" id="donut-legend"></div>
          </div>
        </div>
      </div>

      <div class="feed-wrap">
        <div class="feed-head">Live Activity Feed<div class="feed-pulse"></div></div>
        <div class="feed" id="activity-feed">
          <div class="feed-empty">No activity yet — waiting for diagnoses...</div>
        </div>
      </div>
    </div>

    <div class="tab-panel" id="panel-pods">
      <div class="panel full-panel">
        <div class="panel-title">Failing K8s Pods</div>
        <div class="filter-bar">
          <div class="filter-pills">
            <button class="pill-filter active" data-pill="pods" onclick="setDiagFilter('pods','active')">Active</button>
            <button class="pill-filter" data-pill="pods" onclick="setDiagFilter('pods','removed')">Removed</button>
          </div>
          <div class="filter-input-wrap"><input type="text" id="filter-pods" placeholder="Filter by name, status, route..." oninput="filterCards('pods')"><button class="filter-clear" id="filter-pods-clear" onclick="clearFilter('pods')" style="display:none">&times;</button></div>
        </div>
        <div id="diag-list-pods"></div>
      </div>
    </div>

    <div class="tab-panel" id="panel-containers">
      <div class="panel full-panel">
        <div class="panel-title">Failing Docker Containers</div>
        <div class="filter-bar">
          <div class="filter-pills">
            <button class="pill-filter active" data-pill="containers" onclick="setDiagFilter('containers','active')">Active</button>
            <button class="pill-filter" data-pill="containers" onclick="setDiagFilter('containers','removed')">Removed</button>
          </div>
          <div class="filter-input-wrap"><input type="text" id="filter-containers" placeholder="Filter by name, status, route..." oninput="filterCards('containers')"><button class="filter-clear" id="filter-containers-clear" onclick="clearFilter('containers')" style="display:none">&times;</button></div>
        </div>
        <div id="diag-list-containers"></div>
      </div>
    </div>

    <div class="tab-panel" id="panel-timeline">
      <div class="panel full-panel">
        <div class="panel-title">Diagnosis Timeline</div>
        <div class="vtl-filters" id="vtl-filters">
          <button class="vtl-filter active" data-filter="all" onclick="setTimelineFilter('all')">All</button>
          <button class="vtl-filter" data-filter="critical" onclick="setTimelineFilter('critical')">Critical</button>
          <button class="vtl-filter" data-filter="warning" onclick="setTimelineFilter('warning')">Warning</button>
          <button class="vtl-filter" data-filter="success" onclick="setTimelineFilter('success')">Resolved</button>
          <button class="vtl-filter" data-filter="removed" onclick="setTimelineFilter('removed')">Removed</button>
        </div>
        <div class="vtl" id="vtl-track"></div>
      </div>
    </div>

    <div class="tab-panel" id="panel-llm">
      <div class="panel full-panel">
        <div class="panel-title">LLM Provider Performance</div>
        <table>
          <thead><tr><th>Provider</th><th>Calls</th><th>Errors</th><th>Avg Latency</th><th>Trend</th><th>Success Rate</th></tr></thead>
          <tbody id="provider-table"></tbody>
        </table>
      </div>
    </div>

    <div class="tab-panel" id="panel-metrics">
      <div class="metrics-stat-row">
        <div class="metrics-stat-card green">
          <div class="stat-accent"></div>
          <div class="stat-body"><div class="stat-val" id="kpi-total-heals">0</div><div class="stat-label">Total Heals</div></div>
          <div class="stat-sparkline"><canvas id="spark-heals"></canvas></div>
          <div class="stat-trend" id="trend-heals"></div>
        </div>
        <div class="metrics-stat-card blue">
          <div class="stat-accent"></div>
          <div class="stat-body"><div class="stat-val" id="kpi-llm-calls">0</div><div class="stat-label">LLM Calls</div></div>
          <div class="stat-sparkline"><canvas id="spark-llm"></canvas></div>
          <div class="stat-trend" id="trend-llm"></div>
        </div>
        <div class="metrics-stat-card red">
          <div class="stat-accent"></div>
          <div class="stat-body"><div class="stat-val" id="kpi-errors">0</div><div class="stat-label">Errors</div></div>
          <div class="stat-sparkline"><canvas id="spark-errors"></canvas></div>
          <div class="stat-trend" id="trend-errors"></div>
        </div>
        <div class="metrics-stat-card purple">
          <div class="stat-accent"></div>
          <div class="stat-body"><div class="stat-val" id="kpi-uptime">0m</div><div class="stat-label">Uptime</div></div>
          <div class="stat-sparkline"><canvas id="spark-uptime"></canvas></div>
          <div class="stat-trend" id="trend-uptime"></div>
        </div>
      </div>
      <div class="metrics-toolbar">
        <span class="metrics-toolbar-label">Time Range</span>
        <div class="metrics-range-btns">
          <button class="range-btn active" data-range="5m">5m</button>
          <button class="range-btn" data-range="10m">10m</button>
          <button class="range-btn" data-range="30m">30m</button>
          <button class="range-btn" data-range="1h">1h</button>
          <button class="range-btn" data-range="all">All</button>
        </div>
        <select class="metrics-refresh-select" id="metrics-refresh-interval">
          <option value="5000">5s</option>
          <option value="10000">10s</option>
          <option value="30000">30s</option>
          <option value="60000">1m</option>
        </select>
        <span class="metrics-last-updated" id="metrics-last-updated"></span>
      </div>
      <div class="metrics-grid">
        <div class="metrics-chart-card full-width"><h3>Heals Over Time</h3><canvas id="chart-heals-time"></canvas></div>
        <div class="metrics-chart-card gauge-card"><h3>System Health</h3><div class="metrics-gauge-wrap"><div class="metrics-gauge-ring" id="gauge-ring"></div><div class="gauge-center-label"><div class="gauge-val" id="gauge-val">0%</div><div class="gauge-sub">System Health</div></div></div></div>
        <div class="metrics-chart-card"><h3>Heal Actions</h3><canvas id="chart-heal-actions"></canvas></div>
        <div class="metrics-chart-card"><h3>Route Outcomes</h3><canvas id="chart-route-outcomes"></canvas></div>
        <div class="metrics-chart-card"><h3>Namespace Activity</h3><canvas id="chart-namespace"></canvas></div>
        <div class="metrics-chart-card"><h3>Status Breakdown</h3><canvas id="chart-status"></canvas></div>
      </div>
    </div>

    <div class="tab-panel" id="panel-approvals">
      <div class="panel full-panel">
        <div class="panel-title">Pending Approvals</div>
        <div class="filter-bar">
          <div class="filter-pills">
            <button class="pill-filter active" data-pill="approvals" onclick="setApprovalFilter('active')">Active</button>
            <button class="pill-filter" data-pill="approvals" onclick="setApprovalFilter('removed')">Removed</button>
          </div>
        </div>
        <div id="approvals-list"><div class="approval-empty">No pending approvals</div></div>
      </div>
    </div>

    <div class="tab-panel" id="panel-users">
      <div class="panel full-panel">
        <div class="panel-title">User Management</div>
        <div id="users-list"><div class="approval-empty">Loading users...</div></div>
      </div>
    </div>

    <div class="tab-panel" id="panel-reports">
      <div class="panel full-panel">
        <div class="panel-title">Download Reports</div>
        <div class="report-block">
          <div class="report-desc">Generate a PDF summary of incidents, heals, failures, platforms, actions and affected resources for a selected period.</div>
          <div class="report-range-row">
            <span class="report-range-label">Period</span>
            <div class="metrics-range-btns">
              <button class="range-btn active" data-range="1" onclick="setReportRange(this,1)">1d</button>
              <button class="range-btn" data-range="3" onclick="setReportRange(this,3)">3d</button>
              <button class="range-btn" data-range="7" onclick="setReportRange(this,7)">7d</button>
              <button class="range-btn" data-range="14" onclick="setReportRange(this,14)">14d</button>
            </div>
          </div>
          <div class="report-actions">
            <button class="modal-btn primary" id="report-download-btn" onclick="downloadReport(7)">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-3px;margin-right:6px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Download Report
            </button>
          </div>
        </div>
      </div>
    </div>

  </div>
</main>

<footer class="footer">
  Auto-refresh &middot; <a href="/metrics/raw">Prometheus</a> &middot; <a href="/diagnoses">Diagnoses</a> &middot; <a href="/health">Health</a>
</footer>

<script>
var CONFIG = __CONFIG__;
var COLORS = ['green','blue','purple','yellow','orange','cyan','red'];
var PROVIDER_COLORS = {groq:'green',cerebras:'purple',gemini:'blue',mistral:'cyan',openrouter:'orange',ollama:'yellow'};
var ROUTE_COLORS = {auto_healed:'green',dev_issue:'red',needs_escalation:'yellow',rollback:'orange',needs_approval:'orange',rejected:'red'};
var VALID_TABS = ['overview','pods','containers','timeline','llm','metrics','approvals','users','reports'];

var _k8sRecs = [], _dockerRecs = [], _selectedTab = 'overview', _canViewApprovals = true, _canViewPods = true, _canViewContainers = true;
var _prevStats = {heals:0,calls:0,rollbacks:0,pdb:0,errors:0};
var _prevDiagCount = 0, _latencyHistory = {}, _allRecs = [], _spRecId = null;
var _timelineFilter = 'all';
var _diagFilter = {pods:'active', containers:'active'};
var _approvalFilter = 'active';
var _statusRendered = false;
var _knownDiagIds = {};
var _showCreateForm = false;
function findRecById(id){
  for(var i=0;i<_allRecs.length;i++){if(_allRecs[i].id===id)return _allRecs[i];}
  return null;
}

var _useUTC = localStorage.getItem('dashboard_tz') === 'utc';

function updateClock() {
  var el = document.getElementById('hdr-clock');
  var lbl = document.getElementById('hdr-tz');
  if (!el) return;
  if (_useUTC) {
    el.textContent = new Date().toUTCString().split(' ')[4];
    if (lbl) lbl.textContent = 'UTC';
  } else {
    el.textContent = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    if (lbl) lbl.textContent = 'LOCAL';
  }
}
function fmtTimestamp(ts) {
  if (!ts) return '';
  if (_useUTC) return ts;
  var parts = ts.replace(' UTC','').split(' ');
  var d = new Date(parts[0] + 'T' + parts[1] + 'Z');
  return d.toLocaleString();
}
// ── Live Network Graph (Canvas-based) ───────────────────────────
function initNetworkGraph() {
  var container = document.getElementById('bg-particles');
  if (!container || container._initialized) return;
  container._initialized = true;
  var canvas = document.createElement('canvas');
  canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;pointer-events:none';
  container.appendChild(canvas);
  var ctx = canvas.getContext('2d');
  var W, H;
  function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  window.addEventListener('resize', resize);
  resize();
  var nodeCount = 60;
  var nodes = [];
  for (var i = 0; i < nodeCount; i++) {
    var angle = Math.random() * Math.PI * 2;
    var radius = 50 + Math.random() * Math.min(W, H) * 0.4;
    nodes.push({
      cx: W/2 + Math.cos(angle) * radius,
      cy: H/2 + Math.sin(angle) * radius,
      size: 1.5 + Math.random() * 2.5,
      speed: 0.08 + Math.random() * 0.15,
      orbitRadius: radius,
      drift: 0.2 + Math.random() * 0.5,
      phase: Math.random() * Math.PI * 2,
      opacity: 0.2 + Math.random() * 0.4,
    });
  }
  var connections = [];
  for (var i = 0; i < nodeCount; i++) {
    for (var j = i + 1; j < nodeCount; j++) {
      var dx = nodes[i].cx - nodes[j].cx;
      var dy = nodes[i].cy - nodes[j].cy;
      var dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < Math.min(W, H) * 0.35 && Math.random() < 0.35) {
        connections.push({ a: i, b: j, maxDist: dist });
      }
    }
  }
  var startTime = Date.now();
  var mouse = { x: W/2, y: H/2, active: false };
  canvas.addEventListener('mousemove', function(e) {
    mouse.x = e.clientX; mouse.y = e.clientY; mouse.active = true;
  });
  canvas.addEventListener('mouseleave', function() { mouse.active = false; });
  function animate() {
    var t = (Date.now() - startTime) / 1000;
    ctx.clearRect(0, 0, W, H);
    var isLight = document.documentElement.classList.contains('light');
    var col = isLight ? '150,170,200' : '255,255,255';
    var am = isLight ? 0.25 : 1;
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      n.cx = W/2 + Math.cos(t * n.speed + n.phase) * n.orbitRadius;
      n.cy = H/2 + Math.sin(t * n.speed * 0.8 + n.phase * 1.2) * (n.orbitRadius * 0.8);
      n.cx += Math.sin(t * n.drift + n.phase) * 20;
      n.cy += Math.cos(t * n.drift * 0.7 + n.phase) * 15;
    }
    for (var i = 0; i < connections.length; i++) {
      var conn = connections[i];
      var na = nodes[conn.a], nb = nodes[conn.b];
      var dx = na.cx - nb.cx, dy = na.cy - nb.cy;
      var dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < conn.maxDist * 1.8) {
        var alpha = (1 - dist / (conn.maxDist * 1.8)) * 0.25 * am;
        if (mouse.active) {
          var mdx = (na.cx + nb.cx) / 2 - mouse.x;
          var mdy = (na.cy + nb.cy) / 2 - mouse.y;
          var mDist = Math.sqrt(mdx * mdx + mdy * mdy);
          if (mDist < 200) alpha += (1 - mDist / 200) * 0.35 * am;
        }
        ctx.strokeStyle = 'rgba(' + col + ',' + Math.min(alpha, 0.5) + ')';
        ctx.lineWidth = 0.5 + alpha * 1.5;
        ctx.beginPath();
        ctx.moveTo(na.cx, na.cy);
        ctx.lineTo(nb.cx, nb.cy);
        ctx.stroke();
      }
    }
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var alpha = n.opacity;
      if (mouse.active) {
        var mdx = n.cx - mouse.x, mdy = n.cy - mouse.y;
        var mDist = Math.sqrt(mdx * mdx + mdy * mdy);
        if (mDist < 150) alpha += (1 - mDist / 150) * 0.5;
      }
      ctx.fillStyle = 'rgba(' + col + ',' + Math.min(alpha * am, 0.8) + ')';
      ctx.beginPath();
      ctx.arc(n.cx, n.cy, n.size, 0, Math.PI * 2);
      ctx.fill();
      var glow = ctx.createRadialGradient(n.cx, n.cy, 0, n.cx, n.cy, n.size * 4);
      glow.addColorStop(0, 'rgba(' + col + ',0.06)');
      glow.addColorStop(1, 'rgba(' + col + ',0)');
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(n.cx, n.cy, n.size * 4, 0, Math.PI * 2);
      ctx.fill();
    }
    requestAnimationFrame(animate);
  }
  animate();
}
window.addEventListener('load', initNetworkGraph);
function toggleTimezone() {
  _useUTC = !_useUTC;
  localStorage.setItem('dashboard_tz', _useUTC ? 'utc' : 'local');
  updateClock();
  if (_allRecs.length) {
    renderDiagnoses(_allRecs);
    if (_spRecId) {
      var r = _allRecs.find(function(x){return x.id===_spRecId;});
      if (r) openSidePanel(r);
    }
  }
}
var _displayMode = localStorage.getItem('dashboard_display_mode') || 'auto';

function _syncDisplayMenu() {
  document.querySelectorAll('.dm-option').forEach(function(el){
    el.classList.toggle('active', el.dataset.mode === _displayMode);
  });
}
function _applyDisplayMode() {
  var light = false;
  if (_displayMode === 'light') light = true;
  else if (_displayMode === 'auto') light = !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
  document.documentElement.classList.toggle('light', light);
  var mt = document.getElementById('metaThemeColor');
  if (mt) mt.content = light ? '#ffffff' : '#0a0e17';
  var sc = localStorage.getItem('dashboard_color');
  if (sc) setColorTheme(sc);
  _syncDisplayMenu();
  if (_selectedTab === 'metrics' && _lastMetricsData) { destroyAllMetricCharts(); buildAllMetricCharts(_lastMetricsData, _lastDiagsData); }
}
function setDisplayMode(mode, ev) {
  if (ev && ev.stopPropagation) ev.stopPropagation();
  _displayMode = mode;
  localStorage.setItem('dashboard_display_mode', mode);
  var root = document.documentElement;
  root.classList.add('theme-xfade');
  _applyDisplayMode();
  setTimeout(function(){ root.classList.remove('theme-xfade'); }, 380);
}
function toggleDropdownPanel(id, item) {
  document.querySelectorAll('.hdr-user-dropdown-panel').forEach(function(p){p.classList.remove('open');});
  document.querySelectorAll('.dd-has-sub').forEach(function(i){i.classList.remove('open');});
  var panel = document.getElementById(id);
  if (panel && !panel.classList.contains('open')) {
    panel.classList.add('open');
    if (item) item.classList.add('open');
  }
}
var _colorThemes = {
  blue:   {blue:'#58a6ff', dark:'#58a6ff', light:'#0969da'},
  purple: {blue:'#bc8cff', dark:'#bc8cff', light:'#8250df'},
  green:  {blue:'#3fb950', dark:'#3fb950', light:'#1a7f37'},
  orange: {blue:'#f0883e', dark:'#f0883e', light:'#bc4c00'},
  red:    {blue:'#f85149', dark:'#f85149', light:'#cf222e'},
  teal:   {blue:'#39d2c0', dark:'#39d2c0', light:'#0e7c6b'},
};
function setColorTheme(name) {
  var t = _colorThemes[name] || _colorThemes.blue;
  var isLight = document.documentElement.classList.contains('light');
  var c = isLight ? t.light : t.dark;
  document.documentElement.style.setProperty('--blue', c);
  document.querySelectorAll('.clr-dot').forEach(function(b){b.classList.toggle('active',b.dataset.clr===name);});
  localStorage.setItem('dashboard_color', name);
  if (_selectedTab === 'metrics' && _lastMetricsData) { destroyAllMetricCharts(); buildAllMetricCharts(_lastMetricsData, _lastDiagsData); }
}
var _savedColor = localStorage.getItem('dashboard_color');
if (_savedColor && _colorThemes[_savedColor]) setColorTheme(_savedColor);
_applyDisplayMode();
if (typeof Chart !== 'undefined') { var _tc = getChartColors(); Chart.defaults.color = _tc.text; Chart.defaults.borderColor = _tc.border; Chart.defaults.devicePixelRatio = window.devicePixelRatio || 1; if (Chart.register) { try { Chart.register(ChartZoom); } catch(e){} try { Chart.register(ChartAnnotation); } catch(e){} } }
setInterval(updateClock, 1000);
updateClock();

function pollStatus() {
  fetch('/status').then(function(r){return r.json();}).then(function(d){renderSystemStatus(d);}).catch(function(){});
}
pollStatus();
setInterval(pollStatus, 30000);

function switchTab(name) {
  if ((name === 'approvals' && !_canViewApprovals) || (name === 'pods' && !_canViewPods) || (name === 'containers' && !_canViewContainers)) { name = 'overview'; }
  var prev = _selectedTab;
  _selectedTab = name;
  document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.toggle('active',b.dataset.tab===name);});
  document.querySelectorAll('.tab-panel').forEach(function(p){
    var on = p.id === 'panel-' + name;
    if (on) { p.classList.remove('exiting'); p.classList.add('active'); }
    else if (p.classList.contains('active')) {
      p.classList.remove('active');
      p.classList.add('exiting');
      setTimeout(function(){ p.classList.remove('exiting'); }, 200);
    }
  });
  history.replaceState(null,'','#'+name);
  if (prev === 'metrics' && name !== 'metrics') destroyAllMetricCharts();
  if (name === 'metrics' && _lastMetricsData) { setTimeout(function(){buildAllMetricCharts(_lastMetricsData, _lastDiagsData);}, 50); }
}
document.querySelectorAll('.tab-btn').forEach(function(b){b.addEventListener('click',function(){switchTab(b.dataset.tab);});});
(function(){var h=location.hash.replace('#','');if(VALID_TABS.includes(h))switchTab(h);})();
document.querySelectorAll('#panel-metrics .range-btn').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('#panel-metrics .range-btn').forEach(function(x){x.classList.remove('active');});b.classList.add('active');_metricsTimeRange=b.dataset.range;if(_lastMetricsData)buildAllMetricCharts(_lastMetricsData,_lastDiagsData);});});
document.getElementById('metrics-refresh-interval').addEventListener('change',function(){
  var ms = parseInt(this.value);
  clearInterval(_pollInterval);
  _pollInterval = setInterval(poll, ms);
});

function animateValue(el,from,to,dur) {
  if(from===to){el.textContent=to;return;}
  dur=dur||600;var st=performance.now(),init=from;
  function tick(now){var p=Math.min((now-st)/dur,1);var e=1-Math.pow(1-p,3);el.textContent=Math.round(init+(to-init)*e);if(p<1)requestAnimationFrame(tick);}
  requestAnimationFrame(tick);
  el.classList.add('bump');setTimeout(function(){el.classList.remove('bump');},300);
}

function showToast(name,status,route) {
  var c=document.getElementById('toasts');
  var ic=route==='auto_healed'?'heal':(route==='rejected'?'alert':(route==='needs_approval'?'warn':(status&&status.toLowerCase().indexOf('oom')!==-1?'alert':'warn')));
  var t=document.createElement('div');t.className='toast';
  t.innerHTML='<div class="toast-icon '+ic+'"></div><div class="toast-msg"><strong>'+esc(name)+'</strong> &mdash; '+esc(status||'')+' ('+esc(route||'')+')</div>';
  c.appendChild(t);
  requestAnimationFrame(function(){requestAnimationFrame(function(){t.classList.add('show');});});
  setTimeout(function(){t.classList.add('hide');setTimeout(function(){t.remove();},400);},4000);
}

function openSidePanel(rec) {
  _spRecId=rec.id;
  document.getElementById('sp-name').textContent=rec.name;
  var spRoute = rec.deleted ? 'removed' : rec.route;
  document.getElementById('sp-badges').innerHTML=platformBadge(rec.platform)+statusBadge(rec.status)+routeBadge(spRoute);
  document.getElementById('sp-details').innerHTML=[
    ['Namespace',rec.namespace,''],['Location',rec.location,''],['Deployment',rec.deployment,''],
    ['Restarts',rec.restarts,''],['Action',rec.action,'mono'],
    ['LLM Model',rec.llm_model+' ('+rec.llm_latency+'s)','mono'],
    ['Dev Issue',rec.is_developer_issue?'Yes':'No',''],['Result',rec.action_result,'mono'],
    ['Timestamp',fmtTimestamp(rec.timestamp),'mono'],
  ].map(function(i){return '<div class="sp-field"><div class="lbl">'+i[0]+'</div><div class="val '+i[2]+'">'+esc(String(i[1]))+'</div></div>';}).join('');
  var dh='';
  dh+='<div class="sp-box summary"><div class="blbl">Summary</div><div class="bval">'+esc(rec.summary)+'</div></div>';
  dh+='<div class="sp-box root-cause"><div class="blbl">Root Cause</div><div class="bval">'+esc(rec.root_cause)+'</div></div>';
  dh+='<div class="sp-box recommendation"><div class="blbl">Recommendation</div><div class="bval">'+esc(rec.recommendation)+'</div></div>';
  if(rec.cost_data)dh+='<div class="sp-box cost"><div class="blbl">Cost Impact</div><div class="bval mono">'+esc(rec.cost_data)+'</div></div>';
  document.getElementById('sp-diagnosis').innerHTML=dh;
  document.getElementById('sp-logs').textContent=rec.logs||'(no logs available)';
  document.getElementById('log-indicator').classList.remove('visible');
  document.getElementById('sp-backdrop').classList.add('open');
  document.getElementById('side-panel').classList.add('open');
}
function closeSidePanel(){_spRecId=null;document.getElementById('sp-backdrop').classList.remove('open');document.getElementById('side-panel').classList.remove('open');}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeSidePanel();});
function scrollLogsToBottom(){var w=document.getElementById('sp-log-wrap');w.scrollTop=w.scrollHeight;document.getElementById('log-indicator').classList.remove('visible');}

function fmtUptime(s){if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m '+(s%60)+'s';return Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';}

function makeBars(el,data,cl) {
  var c=document.getElementById(el);
  if(!data||Object.keys(data).length===0){c.innerHTML='<div class="bar-empty">No data yet</div>';return;}
  var mx=Math.max.apply(null,Object.values(data).concat([1]));
  var h='';
  Object.entries(data).sort(function(a,b){return b[1]-a[1];}).forEach(function(pair){
    var k=pair[0],v=pair[1],pct=(v/mx*100).toFixed(1);
    var barCl=cl[Object.keys(data).indexOf(pair[0])%cl.length];
    h+='<div class="bar-row"><div class="bar-tooltip">'+esc(k)+': <strong>'+v+'</strong></div><div class="bar-label">'+esc(k)+'</div><div class="bar-track"><div class="bar-fill '+barCl+'" style="width:'+pct+'%">'+(parseFloat(pct)>18?v:'')+'</div></div><div class="bar-count">'+v+'</div></div>';
  });
  c.innerHTML=h;
}

function renderDonut(hbr) {
  var svg=document.getElementById('donut-svg'),legend=document.getElementById('donut-legend');
  var data=hbr||{},entries=Object.entries(data);
  var total=entries.reduce(function(s,e){return s+e[1];},0);
  if(total===0){svg.innerHTML='<text x="100" y="105" text-anchor="middle" fill="var(--text2)" font-size="13">No data</text>';legend.innerHTML='';return;}
  var cx=100,cy=100,r=68,circ=2*Math.PI*r,sh='',off=0;
  var cols={auto_healed:'var(--green)',dev_issue:'var(--red)',needs_escalation:'var(--yellow)',rollback:'var(--orange)'};
  entries.forEach(function(p){
    var k=p[0],v=p[1],pct=v/total,d=pct*circ,g=circ-d,col=cols[k]||'var(--blue)';
    sh+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+col+'" stroke-width="22" stroke-dasharray="'+d+' '+g+'" stroke-dashoffset="'+(-off)+'" style="transition:all 0.6s ease;cursor:pointer"><title>'+esc(k)+': '+v+'</title></circle>';
    off+=d;
  });
  sh+='<text x="'+cx+'" y="'+(cy-4)+'" text-anchor="middle" fill="#fff" font-size="26" font-weight="700">'+total+'</text>';
  sh+='<text x="'+cx+'" y="'+(cy+14)+'" text-anchor="middle" fill="var(--text2)" font-size="10">TOTAL</text>';
  svg.innerHTML=sh;
  var lh='';
  entries.forEach(function(p){
    var k=p[0],v=p[1],col=cols[k]||'var(--blue)';
    lh+='<div class="donut-legend-item"><div class="donut-legend-dot" style="background:'+col+'"></div><span>'+esc(k.replace(/_/g,' '))+'</span><span class="donut-legend-count">'+v+'</span></div>';
  });
  legend.innerHTML=lh;
}

function renderSparkline(vals) {
  if(!vals||vals.length<2)return '<svg viewBox="0 0 80 24" width="80" height="24"><text x="40" y="16" text-anchor="middle" fill="var(--text3)" font-size="10">&mdash;</text></svg>';
  var mn=Math.min.apply(null,vals),mx=Math.max.apply(null,vals),rng=mx-mn||1;
  var w=80,h=24,pd=2;
  var pts=vals.map(function(v,i){var x=(i/(vals.length-1))*(w-pd*2)+pd;var y=h-pd-((v-mn)/rng)*(h-pd*2);return x.toFixed(1)+','+y.toFixed(1);}).join(' ');
  var lc=vals[vals.length-1]>mn+rng*0.7?'var(--red)':'var(--green)';
  var last=pts.split(' ').pop().split(',');
  return '<svg viewBox="0 0 '+w+' '+h+'" width="'+w+'" height="'+h+'"><polyline points="'+pts+'" fill="none" stroke="'+lc+'" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.7"/><circle cx="'+last[0]+'" cy="'+last[1]+'" r="2.5" fill="'+lc+'"/></svg>';
}

function renderSystemStatus(data) {
  var el=document.getElementById('status-grid');
  if(!el)return;
  var items=[
    {key:'k8s',       label:'Kubernetes', sub:CONFIG.watch_namespaces?CONFIG.watch_namespaces.join(', '):''},
    {key:'docker',    label:'Docker',     sub:'Socket'},
    {key:'loki',      label:'Loki',       sub:'Log source'},
    {key:'prometheus',label:'Prometheus', sub:'Metrics'},
    {key:'n8n',       label:'n8n',        sub:'Webhook'},
    {key:'email',     label:'Email',      sub:'SMTP alerts'},
  ];
  if(!_statusRendered){
    el.innerHTML=items.map(function(it,i){
      return '<div class="status-item" id="si-'+it.key+'" style="animation-delay:'+(0.3+i*0.05)+'s"><div class="si-dot off"></div><div><div class="si-label">'+it.label+'</div>'+(it.sub?'<div class="si-sub">'+it.sub+'</div>':'')+'</div></div>';
    }).join('');
    _statusRendered = true;
  }
  if(data){
    items.forEach(function(it){
      var s=data[it.key];
      if(!s)return;
      var dot=document.querySelector('#si-'+it.key+' .si-dot');
      if(!dot)return;
      dot.className='si-dot '+(s.connected?'on':'off');
      var subEl=document.querySelector('#si-'+it.key+' .si-sub');
      if(subEl)subEl.textContent=s.connected?'Connected':'Not connected';
    });
  }
}

function renderActivityFeed(recs) {
  var el=document.getElementById('activity-feed');
  if(!el)return;
  if(!recs||recs.length===0){
    smartUpdate(el,[{id:'feed-empty',html:'<div class="feed-empty" data-id="feed-empty">No activity yet &mdash; waiting for diagnoses...</div>'}]);
    return;
  }
  var recent=recs.slice(0,20);
  var items=recent.map(function(r){
    var dotCls=r.deleted?'removed':(r.route==='auto_healed'?'heal':(r.route==='rejected'?'alert':(r.route==='needs_approval'?'warn':(r.status&&r.status.toLowerCase().indexOf('oom')!==-1?'alert':(r.route==='dev_issue'?'alert':'warn')))));
    var icon=r.deleted?'\u2716':(r.route==='auto_healed'?'\u2713':(r.route==='rejected'?'\u2717':(r.route==='needs_approval'?'\u23F3':(r.route==='dev_issue'?'\u2717':'\u26A0'))));
    var timeShort=fmtTimestamp(r.timestamp)?fmtTimestamp(r.timestamp).split(' ').pop():'';
    var html='<div class="feed-item" data-id="'+r.id+'" onclick="openSidePanel(findRecById(\''+r.id+'\'))">'
      +'<span class="feed-time">'+esc(timeShort)+'</span>'
      +'<span class="feed-dot '+dotCls+'"></span>'
      +'<span class="feed-name">'+esc(r.name)+'</span>'
      +'<span class="feed-action">'+esc(r.action)+'</span>'
      +'<span class="feed-icon">'+icon+'</span></div>';
    return {id:r.id, html:html};
  });
  smartUpdate(el, items);
}

function setTimelineFilter(f) {
  _timelineFilter=f;
  document.querySelectorAll('.vtl-filter').forEach(function(b){b.classList.toggle('active',b.dataset.filter===f);});
  renderTimeline(_allRecs);
}

function renderTimeline(recs) {
  var el=document.getElementById('vtl-track');
  if(!recs||recs.length===0){smartUpdate(el,[{id:'vtl-empty',html:'<div class="vtl-empty" data-id="vtl-empty">No timeline data yet</div>'}]);return;}
  var items=recs.slice().reverse();
  if(_timelineFilter==='all'){
    items=items.filter(function(r){return !r.deleted;});
  }else if(_timelineFilter==='removed'){
    items=items.filter(function(r){return r.deleted;});
  }else{
    items=items.filter(function(r){
      if(r.deleted) return false;
      var s=(r.status||'').toLowerCase();
      if(_timelineFilter==='critical')return s.indexOf('oom')!==-1||s.indexOf('crashloop')!==-1||r.route==='rejected';
      if(_timelineFilter==='warning')return s.indexOf('error')!==-1||s.indexOf('failed')!==-1||r.route==='needs_approval';
      if(_timelineFilter==='success')return r.route==='auto_healed';
      return true;
    });
  }
  if(items.length===0){smartUpdate(el,[{id:'vtl-empty',html:'<div class="vtl-empty" data-id="vtl-empty">No entries match this filter</div>'}]);return;}
  var updateItems=items.map(function(r){
    var sev='info',s=(r.status||'').toLowerCase();
    if(s.indexOf('oom')!==-1||s.indexOf('crashloop')!==-1||r.route==='rejected')sev='critical';
    else if(s.indexOf('error')!==-1||s.indexOf('failed')!==-1||r.route==='needs_approval')sev='warning';
    else if(r.route==='auto_healed')sev='success';
    var ts=fmtTimestamp(r.timestamp)?fmtTimestamp(r.timestamp):'';
    var displayRoute = r.deleted ? 'removed' : r.route;
    var html='<div class="vtl-item" data-id="'+r.id+'" onclick="openSidePanel(findRecById(\''+r.id+'\'))"><div class="vtl-dot '+sev+'"></div><div class="vtl-body"><div class="vtl-header"><span class="vtl-name">'+esc(r.name)+'</span>'+platformBadge(r.platform)+statusBadge(r.status)+routeBadge(displayRoute)+'</div><div class="vtl-meta"><span>'+esc(ts)+'</span><span class="vtl-sep">&middot;</span><span>'+esc(r.action)+'</span><span class="vtl-sep">&middot;</span><span>'+esc(r.llm_model)+'</span></div></div></div>';
    return {id:r.id, html:html};
  });
  smartUpdate(el, updateItems);
}

function showCardTooltip(e,id) {
  var r=findRecById(id);if(!r)return;
  var tip=document.getElementById('card-tooltip');
  var displayRoute = r.deleted ? 'removed' : r.route;
  tip.innerHTML='<strong>'+esc(r.name)+'</strong><br>'
    +platformBadge(r.platform)+statusBadge(r.status)+routeBadge(displayRoute)+'<br>'
    +'<span style="color:var(--text2)">Action:</span> '+esc(r.action)+'<br>'
    +'<span style="color:var(--text2)">Restarts:</span> '+r.restarts+'&nbsp;&nbsp;'
    +'<span style="color:var(--text2)">Model:</span> '+esc(r.llm_model)+'<br>'
    +'<span style="color:var(--text2)">Time:</span> '+esc(fmtTimestamp(r.timestamp));
  tip.style.display='block';
  positionTooltip(e);
}
function hideCardTooltip(){document.getElementById('card-tooltip').style.display='none';}
function positionTooltip(e){
  var tip=document.getElementById('card-tooltip');
  var tx=e.clientX+14,ty=e.clientY-10;
  var tw=tip.offsetWidth,th=tip.offsetHeight;
  if(tx+tw>window.innerWidth-8)tx=e.clientX-tw-14;
  if(ty+th>window.innerHeight-8)ty=e.clientY-th-10;
  if(ty<8)ty=8;
  tip.style.left=tx+'px';tip.style.top=ty+'px';
}

function filterCards(type) {
  var input=document.getElementById('filter-'+type),clearBtn=document.getElementById('filter-'+type+'-clear');
  var q=(input.value||'').toLowerCase();clearBtn.style.display=q?'':'none';
  var recs=type==='pods'?_k8sRecs:_dockerRecs;
  var listEl=document.getElementById(type==='pods'?'diag-list-pods':'diag-list-containers');
  listEl.querySelectorAll('.diag-card').forEach(function(card,i){
    if(i>=recs.length)return;var r=recs[i];
    var hay=(r.name+' '+r.status+' '+r.route+' '+r.action).toLowerCase();
    card.style.display=(q&&hay.indexOf(q)===-1)?'none':'';
  });
}
function clearFilter(type){document.getElementById('filter-'+type).value='';filterCards(type);}

function setDiagFilter(platform, mode) {
  _diagFilter[platform] = mode;
  document.querySelectorAll('.pill-filter[data-pill="'+platform+'"]').forEach(function(b){
    b.classList.toggle('active', b.textContent.toLowerCase() === mode);
  });
  renderDiagnoses(_allRecs);
}

function setApprovalFilter(mode) {
  _approvalFilter = mode;
  document.querySelectorAll('.pill-filter[data-pill="approvals"]').forEach(function(b){
    b.classList.toggle('active', b.textContent.toLowerCase() === mode);
  });
  if (_lastApprovalsData) {
    renderApprovals(_lastApprovalsData);
  } else {
    fetchApprovals();
  }
}

function buildCardHtml(rec) {
  var cls='diag-card';
  if(rec.deleted) cls+=' removed';
  else if(isCritical(rec.status))cls+=' critical';
  else if(rec.route==='auto_healed')cls+=' healed';
  else if(rec.route==='needs_approval')cls+=' approval-pending';
  var displayRoute = rec.deleted ? 'removed' : rec.route;
  return '<div class="'+cls+'" data-id="'+rec.id+'" onclick="openSidePanel(findRecById(\''+rec.id+'\'))" onmouseenter="showCardTooltip(event,\''+rec.id+'\')" onmousemove="positionTooltip(event)" onmouseleave="hideCardTooltip()"><div class="diag-row"><span class="diag-name">'+esc(rec.name)+'</span>'+platformBadge(rec.platform)+statusBadge(rec.status)+routeBadge(displayRoute)+'<span class="diag-ts">'+esc(fmtTimestamp(rec.timestamp))+'</span></div></div>';
}

function renderDiagnoses(recs) {
  var nr=recs||[],nc=nr.length;
  if(_prevDiagCount>0&&nc>_prevDiagCount){var newest=nr[0];if(newest)showToast(newest.name,newest.status,newest.route);}
  _prevDiagCount=nc;_allRecs=nr;_k8sRecs=[];_dockerRecs=[];
  _allRecs.forEach(function(r){if(r.platform==='docker')_dockerRecs.push(r);else _k8sRecs.push(r);});

  var podsEl=document.getElementById('diag-list-pods'),podBadge=document.getElementById('pod-count');
  if (!_canViewPods) {
    if (podsEl) podsEl.innerHTML = '<div class="diag-empty">You do not have permission to view this section. Contact an administrator to request access.</div>';
    if (podBadge) podBadge.style.display = 'none';
  } else {
    var visibleK8s = _k8sRecs.filter(function(r){return _diagFilter.pods==='active'?!r.deleted:r.deleted;});
    if(visibleK8s.length>0){podBadge.textContent=visibleK8s.length;podBadge.style.display='';}else{podBadge.style.display='none';}
    var podItems=[];
    if(visibleK8s.length===0)podItems.push({id:'empty-k8s-'+_diagFilter.pods,html:'<div class="diag-empty" data-id="empty-k8s-'+_diagFilter.pods+'">No '+( _diagFilter.pods==='active' ? 'failing K8s pods' : 'removed K8s pods' )+' recorded yet</div>'});
    else visibleK8s.forEach(function(r){podItems.push({id:r.id,html:buildCardHtml(r)});});
    smartUpdate(podsEl, podItems);
  }

  var ctrEl=document.getElementById('diag-list-containers'),ctrBadge=document.getElementById('container-count');
  if (!_canViewContainers) {
    if (ctrEl) ctrEl.innerHTML = '<div class="diag-empty">You do not have permission to view this section. Contact an administrator to request access.</div>';
    if (ctrBadge) ctrBadge.style.display = 'none';
  } else {
    var visibleDocker = _dockerRecs.filter(function(r){return _diagFilter.containers==='active'?!r.deleted:r.deleted;});
    if(visibleDocker.length>0){ctrBadge.textContent=visibleDocker.length;ctrBadge.style.display='';}else{ctrBadge.style.display='none';}
    var ctrItems=[];
    if(visibleDocker.length===0)ctrItems.push({id:'empty-docker-'+_diagFilter.containers,html:'<div class="diag-empty" data-id="empty-docker-'+_diagFilter.containers+'">No '+( _diagFilter.containers==='active' ? 'failing Docker containers' : 'removed Docker containers' )+' recorded yet</div>'});
    else visibleDocker.forEach(function(r){ctrItems.push({id:r.id,html:buildCardHtml(r)});});
    smartUpdate(ctrEl, ctrItems);
  }

  _knownDiagIds = {};
  _allRecs.forEach(function(r){ _knownDiagIds[r.id] = true; });

  renderTimeline(nr);
  renderActivityFeed(nr);

  if(_spRecId){
    var oRec=null;for(var i=0;i<nr.length;i++){if(nr[i].id===_spRecId){oRec=nr[i];break;}}
    if(oRec){var logsEl=document.getElementById('sp-logs'),newLogs=oRec.logs||'(no logs available)';
      if(logsEl.textContent!==newLogs){var lw=document.getElementById('sp-log-wrap'),wasBot=lw.scrollHeight-lw.scrollTop-lw.clientHeight<40;
        logsEl.textContent=newLogs;if(wasBot)lw.scrollTop=lw.scrollHeight;else document.getElementById('log-indicator').classList.add('visible');}}
  }
}

function rateClass(r){return r>=95?'rate-good':r>=70?'rate-warn':'rate-bad';}
function esc(s){return s?s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'):'';}
function statusBadge(s){s=(s||'').toLowerCase();if(s.indexOf('oom')!==-1)return '<span class="badge badge-oom">OOM</span>';if(s.indexOf('crashloop')!==-1||s.indexOf('restartloop')!==-1)return '<span class="badge badge-crash">CrashLoop</span>';if(s.indexOf('error')!==-1||s.indexOf('failed')!==-1)return '<span class="badge badge-error">Error</span>';if(s.indexOf('running')!==-1)return '<span class="badge badge-healed">Running</span>';return s?'<span class="badge badge-other">'+esc(s)+'</span>':'';}
function routeBadge(r){r=(r||'').toLowerCase();if(r==='auto_healed')return '<span class="badge badge-healed">healed</span>';if(r==='dev_issue')return '<span class="badge badge-dev">dev</span>';if(r==='rollback')return '<span class="badge badge-rollback">rollback</span>';if(r==='needs_escalation')return '<span class="badge badge-escalate">escalation</span>';if(r==='needs_approval')return '<span class="badge badge-approval">needs approval</span>';if(r==='rejected')return '<span class="badge badge-rejected">rejected</span>';if(r==='removed')return '<span class="badge badge-removed">removed</span>';return '<span class="badge badge-other">'+esc(r)+'</span>';}
function platformBadge(p){return p==='k8s'?'<span class="badge badge-k8s">K8s</span>':'<span class="badge badge-docker">Docker</span>';}
function isCritical(s){s=(s||'').toLowerCase();return s.indexOf('oom')!==-1||s.indexOf('crashloop')!==-1||s.indexOf('restartloop')!==-1;}

function update(d) {
  document.getElementById('loading').style.display='none';
  document.getElementById('content').style.display='';
  animateValue(document.getElementById('s-heals'),_prevStats.heals,d.total_heals);
  animateValue(document.getElementById('s-llm-calls'),_prevStats.calls,d.total_llm_calls);
  animateValue(document.getElementById('s-rollbacks'),_prevStats.rollbacks,d.rollbacks);
  animateValue(document.getElementById('s-pdb'),_prevStats.pdb,d.pdb_blocks);
  animateValue(document.getElementById('s-errors'),_prevStats.errors,d.total_llm_errors);
  _prevStats={heals:d.total_heals,calls:d.total_llm_calls,rollbacks:d.rollbacks,pdb:d.pdb_blocks,errors:d.total_llm_errors};
  document.getElementById('hdr-uptime').textContent=fmtUptime(d.uptime_seconds);
  document.getElementById('hdr-checks').textContent=d.total_heals+d.total_llm_calls;
  document.getElementById('hdr-dot').className='status-dot healthy';
  makeBars('chart-actions',d.heal_actions,COLORS);
  makeBars('chart-routes',d.heal_by_route,COLORS);
  makeBars('chart-platforms',d.heal_by_platform,['blue','cyan']);
  renderDonut(d.heal_by_route);
  renderSystemStatus();

  var tbody=document.getElementById('provider-table');
  var provs=d.providers||{},names=Object.keys(provs).sort(function(a,b){return provs[b].calls-provs[a].calls;});
  if(names.length===0){tbody.innerHTML='<tr><td colspan="6" style="color:var(--text2);font-style:italic">No LLM calls yet</td></tr>';return;}
  var h='';
  names.forEach(function(name){
    var p=provs[name],dc=PROVIDER_COLORS[name]||'blue';
    if(!_latencyHistory[name])_latencyHistory[name]=[];
    if(p.avg_latency>0){_latencyHistory[name].push(p.avg_latency);if(_latencyHistory[name].length>10)_latencyHistory[name]=_latencyHistory[name].slice(-10);}
    var rc=rateClass(p.success_rate);
    var barCol=p.success_rate>=95?'var(--green)':p.success_rate>=70?'var(--yellow)':'var(--red)';
    h+='<tr><td><span class="provider-dot" style="background:var(--'+dc+')"></span><span class="provider-name">'+name+'</span></td>'
      +'<td>'+p.calls+'</td>'
      +'<td>'+(p.errors>0?'<span style="color:var(--red)">'+p.errors+'</span>':'<span style="color:var(--green)">0</span>')+'</td>'
      +'<td class="latency">'+p.avg_latency+'s</td>'
      +'<td>'+renderSparkline(_latencyHistory[name])+'</td>'
      +'<td class="'+rc+'">'+p.success_rate+'%<span class="rate-bar"><span class="rate-bar-fill" style="width:'+p.success_rate+'%;background:'+barCol+'"></span></span></td></tr>';
  });
  tbody.innerHTML=h;
}

var _metricsCharts = {};
var _metricsTimeRange = '5m';
var _healsTimeHistory = [];
var _llmLatencyHist = {};
var _statHistory = [];
var _pollInterval = null;

function snapshotMetrics(d) {
  var now = new Date();
  var ts = now.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  _healsTimeHistory.push({ts:ts, date:now, val:d.total_heals});
  if (_healsTimeHistory.length > 720) _healsTimeHistory = _healsTimeHistory.slice(-720);
  var provs = d.providers || {};
  Object.keys(provs).forEach(function(name) {
    if (!_llmLatencyHist[name]) _llmLatencyHist[name] = [];
    if (provs[name].avg_latency > 0) {
      _llmLatencyHist[name].push({ts:ts, date:now, val:provs[name].avg_latency});
      if (_llmLatencyHist[name].length > 720) _llmLatencyHist[name] = _llmLatencyHist[name].slice(-720);
    }
  });
  _statHistory.push({ts:ts, date:now, heals:d.total_heals, llm:d.total_llm_calls, errors:d.total_llm_errors, uptime:d.uptime_seconds});
  if (_statHistory.length > 200) _statHistory = _statHistory.slice(-200);
}

function filterByTimeRange(arr) {
  var now = Date.now();
  var ranges = {'5m':300000, '10m':600000, '30m':1800000, '1h':3600000, 'all':Infinity};
  var ms = ranges[_metricsTimeRange] || Infinity;
  if (ms === Infinity) return arr;
  return arr.filter(function(p){ return (now - p.date.getTime()) <= ms; });
}

function getChartColors() {
  var style = getComputedStyle(document.documentElement);
  return {
    text: style.getPropertyValue('--text2').trim() || '#8b949e',
    border: style.getPropertyValue('--glass-border').trim() || 'rgba(48,54,61,0.4)',
    grid: style.getPropertyValue('--border-subtle').trim() || 'rgba(48,54,61,0.3)',
    green: style.getPropertyValue('--green').trim() || '#3fb950',
    red: style.getPropertyValue('--red').trim() || '#f85149',
    blue: style.getPropertyValue('--blue').trim() || '#58a6ff',
    purple: style.getPropertyValue('--purple').trim() || '#bc8cff',
    yellow: style.getPropertyValue('--yellow').trim() || '#d29922',
    cyan: style.getPropertyValue('--cyan').trim() || '#39d2c0',
    orange: style.getPropertyValue('--orange').trim() || '#f0883e'
  };
}

function destroyMetricChart(key) {
  if (_metricsCharts[key]) { _metricsCharts[key].destroy(); _metricsCharts[key] = null; }
}

function buildMetricsKPIs(d) {
  document.getElementById('kpi-total-heals').textContent = d.total_heals;
  document.getElementById('kpi-llm-calls').textContent = d.total_llm_calls;
  document.getElementById('kpi-errors').textContent = d.total_llm_errors;
  document.getElementById('kpi-uptime').textContent = fmtUptime(d.uptime_seconds);
  var h = _statHistory;
  if (h.length < 2) return;
  var cur = h[h.length-1];
  var prev = h[0];
  var trends = {
    heals: cur.heals - prev.heals,
    llm: cur.llm - prev.llm,
    errors: cur.errors - prev.errors,
    uptime: cur.uptime - prev.uptime
  };
  ['heals','llm','errors','uptime'].forEach(function(k) {
    var el = document.getElementById('trend-' + k);
    if (trends[k] > 0) { el.className = 'stat-trend up'; el.innerHTML = '\u25B2 +' + trends[k]; }
    else if (trends[k] < 0) { el.className = 'stat-trend down'; el.innerHTML = '\u25BC ' + trends[k]; }
    else { el.className = 'stat-trend flat'; el.innerHTML = '\u2014'; }
  });
}

function buildStatSparklines() {
  var h = _statHistory;
  if (h.length < 2) return;
  var c = getChartColors();
  var sparkConfigs = {
    sparkHeals: {key:'heals',color:c.green}, sparkLlm: {key:'llm',color:c.blue},
    sparkErrors: {key:'errors',color:c.red}, sparkUptime: {key:'uptime',color:c.purple}
  };
  Object.keys(sparkConfigs).forEach(function(id) {
    destroyMetricChart(id);
    var cfg = sparkConfigs[id];
    var data = h.map(function(p){return p[cfg.key];});
    var min = Math.min.apply(null, data);
    var max = Math.max.apply(null, data);
    var range = max - min || 1;
    var normalized = data.map(function(v){return (v-min)/range;});
    var ctx = document.getElementById(id);
    if (!ctx) return;
    var grad = ctx.getContext('2d').createLinearGradient(0,0,0,32);
    grad.addColorStop(0, cfg.color+'66');
    grad.addColorStop(1, cfg.color+'05');
    _metricsCharts[id] = new Chart(ctx, {
      type:'line',
      data:{labels:data.map(function(){return '';}), datasets:[{data:normalized,borderColor:cfg.color,backgroundColor:grad,fill:true,tension:0.4,pointRadius:0,borderWidth:1.5}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{enabled:false}},scales:{x:{display:false},y:{display:false,beginAtZero:true}},animation:false}
    });
  });
}

function updateHealthGauge(d) {
  var el = document.getElementById('gauge-ring');
  var valEl = document.getElementById('gauge-val');
  if (!el || !valEl) return;
  var totalCalls = d.total_llm_calls || 1;
  var errors = d.total_llm_errors || 0;
  var pct = Math.max(0, Math.min(100, Math.round((1 - errors/totalCalls) * 100)));
  var color = pct >= 90 ? 'var(--green)' : pct >= 70 ? 'var(--yellow)' : 'var(--red)';
  var degrees = (pct / 100) * 360;
  el.style.setProperty('--gauge-color', color);
  el.style.background = 'conic-gradient(' + color + ' 0deg ' + degrees + 'deg, rgba(48,54,61,0.3) ' + degrees + 'deg 360deg)';
  valEl.textContent = pct + '%';
  valEl.style.color = color;
}

function buildChartHealsOverTime() {
  var filtered = filterByTimeRange(_healsTimeHistory);
  if (filtered.length < 2) return;
  destroyMetricChart('healsTime');
  var c = getChartColors();
  var labels = filtered.map(function(h){return h.ts;});
  var data = filtered.map(function(h,i){
    if (i===0) return 0;
    var dtSec = (h.date.getTime()-filtered[i-1].date.getTime())/1000;
    var delta = h.val-filtered[i-1].val;
    return dtSec>0 ? parseFloat((delta/dtSec*60).toFixed(2)) : 0;
  });
  var ctx = document.getElementById('chart-heals-time');
  var grad = ctx.getContext('2d').createLinearGradient(0,0,0,260);
  grad.addColorStop(0, c.green+'55');
  grad.addColorStop(0.5, c.green+'22');
  grad.addColorStop(1, c.green+'05');
  _metricsCharts.healsTime = new Chart(ctx, {
    type:'line',
    data:{labels:labels, datasets:[{label:'Heals/min',data:data,borderColor:c.green,backgroundColor:grad,fill:true,tension:0.35,pointRadius:0,pointHoverRadius:5,pointHoverBackgroundColor:c.green,pointHoverBorderColor:'#fff',pointHoverBorderWidth:2,borderWidth:2}]},
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:'rgba(13,17,23,0.94)', titleColor:c.text, bodyColor:c.text, titleFont:{weight:'600'},
          padding:12, cornerRadius:8, displayColors:true, boxPadding:4,
          callbacks:{
            title:function(its){return its[0].label;},
            label:function(ct){
              var v=ct.parsed.y.toFixed(1);
              var totalHeals = _healsTimeHistory.length>0 ? _healsTimeHistory[_healsTimeHistory.length-1].val : 0;
              return 'Heal Rate: '+v+' heals/min';
            }
          }
        },
        zoom:{pan:{enabled:true,mode:'x',threshold:5},zoom:{wheel:{enabled:true},pinch:{enabled:true},mode:'x',drag:{enabled:true,backgroundColor:'rgba(88,166,255,0.08)',borderColor:c.blue,borderWidth:1}}}
      },
      scales:{
        x:{ticks:{color:c.text,maxTicksLimit:12,font:{size:10},maxRotation:0},grid:{color:c.grid}},
        y:{beginAtZero:true,ticks:{color:c.text,font:{size:10}},grid:{color:c.grid}}
      }
    }
  });
}

function buildChartHealActions(recs) {
  var actions = {};
  recs.forEach(function(r){actions[r.action]=(actions[r.action]||0)+1;});
  var keys = Object.keys(actions);
  if (keys.length === 0) return;
  destroyMetricChart('healActions');
  var c = getChartColors();
  var palette = [c.green, c.blue, c.purple, c.cyan, c.orange, c.yellow, c.red];
  var total = keys.reduce(function(s,k){return s+actions[k];}, 0);
  var ctx = document.getElementById('chart-heal-actions');
  _metricsCharts.healActions = new Chart(ctx, {
    type:'bar',
    data:{labels:keys.map(function(k){return k.replace(/_/g,' ');}), datasets:[{data:keys.map(function(k){return actions[k];}), backgroundColor:palette.slice(0,keys.length), borderRadius:6, barThickness:28}]},
    options:{
      indexAxis:'y',responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:'rgba(13,17,23,0.94)', titleColor:c.text, bodyColor:c.text,
          padding:12, cornerRadius:8, displayColors:true, boxPadding:4,
          callbacks:{
            title:function(its){return its[0].label;},
            label:function(ct){
              var pct = total > 0 ? (ct.parsed.x/total*100).toFixed(1) : 0;
              return 'Count: '+ct.parsed.x+'  ('+pct+'%)';
            }
          }
        }
      },
      scales:{x:{beginAtZero:true,ticks:{color:c.text,stepSize:1,font:{size:10}},grid:{color:c.grid}},y:{ticks:{color:c.text,font:{size:11}},grid:{display:false}}}
    }
  });
}

function buildChartRouteOutcomes(d) {
  var routes = d.heal_by_route || {};
  var keys = Object.keys(routes);
  if (keys.length === 0) return;
  destroyMetricChart('routeOutcomes');
  var c = getChartColors();
  var colorMap = {auto_healed:c.green, dev_issue:c.red, needs_escalation:c.yellow, rollback:c.orange, needs_approval:c.orange, rejected:c.red};
  var total = keys.reduce(function(s,k){return s+routes[k];}, 0);
  var ctx = document.getElementById('chart-route-outcomes');
  _metricsCharts.routeOutcomes = new Chart(ctx, {
    type:'doughnut',
    data:{labels:keys.map(function(k){return k.replace(/_/g,' ');}), datasets:[{data:keys.map(function(k){return routes[k];}), backgroundColor:keys.map(function(k){return colorMap[k]||c.blue}), borderWidth:0}]},
      options:{
        responsive:true, maintainAspectRatio:true, cutout:'65%',
        plugins:{
          legend:{position:'bottom',labels:{color:c.text,font:{size:11,weight:'600'},padding:14,usePointStyle:true,pointStyle:'circle'}},
          tooltip:{
            backgroundColor:'rgba(13,17,23,0.94)', titleColor:c.text, bodyColor:c.text,
            padding:12, cornerRadius:8, displayColors:true, boxPadding:4,
            callbacks:{
              label:function(ct){
                var pct = total > 0 ? (ct.parsed/total*100).toFixed(1) : 0;
                return ct.label+': '+ct.parsed+'  ('+pct+'%)';
              }
            }
          }
        }
      }
    });
  }

  function buildChartNamespace(recs) {
  var ns = {};
  recs.forEach(function(r){if(r.namespace)ns[r.namespace]=(ns[r.namespace]||0)+1;});
  var keys = Object.keys(ns).sort(function(a,b){return ns[b]-ns[a];}).slice(0,8);
  if (keys.length === 0) return;
  destroyMetricChart('namespace');
  var c = getChartColors();
  var maxV = Math.max.apply(null, keys.map(function(k){return ns[k];}));
  var colors = keys.map(function(k){var r=ns[k]/maxV; return r>0.7?c.red:r>0.4?c.yellow:c.blue;});
  var ctx = document.getElementById('chart-namespace');
  _metricsCharts.namespace = new Chart(ctx, {
    type:'bar',
    data:{labels:keys, datasets:[{data:keys.map(function(k){return ns[k];}), backgroundColor:colors, borderRadius:6, barThickness:24}]},
    options:{
      responsive:true,maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:'rgba(13,17,23,0.94)', titleColor:c.text, bodyColor:c.text,
          padding:12, cornerRadius:8, displayColors:false,
          callbacks:{
            title:function(its){return its[0].label;},
            label:function(ct){return 'Incidents: '+ct.parsed.y;}
          }
        }
      },
      scales:{x:{ticks:{color:c.text,font:{size:10}},grid:{display:false}},y:{beginAtZero:true,ticks:{color:c.text,stepSize:1,font:{size:10}},grid:{color:c.grid}}}
    }
  });
}

function buildChartStatus(recs) {
  var st = {};
  recs.forEach(function(r){st[r.status]=(st[r.status]||0)+1;});
  var keys = Object.keys(st);
  if (keys.length === 0) return;
  destroyMetricChart('status');
  var c = getChartColors();
  var palette = [c.red, c.orange, c.yellow, c.blue, c.purple, c.cyan, c.green];
  var total = keys.reduce(function(s,k){return s+st[k];}, 0);
  var ctx = document.getElementById('chart-status');
  _metricsCharts.status = new Chart(ctx, {
    type:'doughnut',
    data:{labels:keys, datasets:[{data:keys.map(function(k){return st[k];}), backgroundColor:palette.slice(0,keys.length), borderWidth:0}]},
      options:{
        responsive:true, maintainAspectRatio:true, cutout:'65%',
      plugins:{
        legend:{position:'bottom',labels:{color:c.text,font:{size:11,weight:'600'},padding:14,usePointStyle:true,pointStyle:'circle'}},
        tooltip:{
          backgroundColor:'rgba(13,17,23,0.94)', titleColor:c.text, bodyColor:c.text,
          padding:12, cornerRadius:8, displayColors:true, boxPadding:4,
          callbacks:{
            label:function(ct){
              var pct = total > 0 ? (ct.parsed/total*100).toFixed(1) : 0;
              return ct.label+': '+ct.parsed+'  ('+pct+'%)';
            }
          }
        }
      }
    }
  });
}

function buildAllMetricCharts(d, recs) {
  if (_selectedTab !== 'metrics') return;
  var now = new Date();
  document.getElementById('metrics-last-updated').textContent = 'Updated ' + now.toLocaleTimeString();
  buildMetricsKPIs(d);
  buildStatSparklines();
  updateHealthGauge(d);
  buildChartHealsOverTime();
  buildChartHealActions(recs);
  buildChartRouteOutcomes(d);
  buildChartNamespace(recs);
  buildChartStatus(recs);
}

function destroyAllMetricCharts() {
  Object.keys(_metricsCharts).forEach(function(k){destroyMetricChart(k);});
}

var _lastMetricsData = null;
var _lastDiagsData = [];
var _lastApprovalsData = [];

function renderApprovals(data) {
  var el = document.getElementById('approvals-list');
  var countEl = document.getElementById('approval-count');
  if (!el) return;
  var allReqs = data.requests || [];
  var reqs = allReqs.filter(function(r){
    if (_approvalFilter === 'active') return !r.deleted;
    return r.deleted;
  });
  var pending = reqs.filter(function(r){return r.deleted?false:r.status==='pending';});
  var completed = reqs.filter(function(r){return r.deleted?false:r.status!=='pending';});
  var removed = reqs.filter(function(r){return r.deleted;});
  if (countEl) {
    var activePending = allReqs.filter(function(r){return !r.deleted && r.status==='pending';});
    if (activePending.length > 0) { countEl.textContent = activePending.length; countEl.style.display = ''; }
    else { countEl.style.display = 'none'; }
  }
  function renderCard(r) {
    var isDel = r.deleted;
    var cardCls = isDel ? 'approval-card removed' : 'approval-card '+r.status;
    var statusHtml = isDel ? '<span class="approval-status removed">removed</span>' : '<span class="approval-status '+r.status+'">'+r.status+'</span>';
    var actions = '';
    if (r.status === 'pending' && !isDel) {
      actions = '<div class="approval-actions">'
        + '<button class="approval-btn approve" onclick="doApproval(\''+r.id+'\',\'approve\',this)">Approve & Execute</button>'
        + '<button class="approval-btn reject" onclick="doApproval(\''+r.id+'\',\'reject\',this)">Reject</button>'
        + '</div>';
    }
    var extra = '';
    if (r.approved_by) extra += '<div class="field"><div class="lbl">'+(r.status==='rejected'?'Rejected By':'Approved By')+'</div><div class="val">'+esc(r.approved_by)+'</div></div>';
    if (r.approved_at) extra += '<div class="field"><div class="lbl">'+(r.status==='rejected'?'Rejected At':'Approved At')+'</div><div class="val mono">'+esc(r.approved_at)+'</div></div>';
    if (r.rejected_by) extra += '<div class="field"><div class="lbl">Rejected By</div><div class="val">'+esc(r.rejected_by)+'</div></div>';
    if (r.action_result) extra += '<div class="field" style="grid-column:1/-1"><div class="lbl">Result</div><div class="val mono" style="font-size:11px">'+esc(r.action_result)+'</div></div>';
    return '<div class="'+cardCls+'" data-id="'+r.id+'">'
      + '<div class="approval-header"><span class="name">'+esc(r.name)+'</span>'
      + platformBadge(r.platform)+statusBadge(r.issue_type)
      + statusHtml
      + '<span style="margin-left:auto;font-size:11px;color:var(--text2);font-family:var(--font-mono)">'+esc(r.id)+'</span></div>'
      + '<div class="approval-meta">'
      + '<div class="field"><div class="lbl">Location</div><div class="val">'+esc(r.location)+'</div></div>'
      + '<div class="field"><div class="lbl">Action</div><div class="val mono">'+esc(r.action)+'</div></div>'
      + '<div class="field"><div class="lbl">Restarts</div><div class="val mono">'+r.restarts+'</div></div>'
      + '<div class="field"><div class="lbl">Model</div><div class="val mono">'+esc(r.used_model)+'</div></div>'
      + '<div class="field" style="grid-column:1/-1"><div class="lbl">Summary</div><div class="val">'+esc(r.summary)+'</div></div>'
      + '<div class="field" style="grid-column:1/-1"><div class="lbl">Root Cause</div><div class="val">'+esc(r.root_cause)+'</div></div>'
      + '<div class="field" style="grid-column:1/-1"><div class="lbl">Recommendation</div><div class="val">'+esc(r.recommendation)+'</div></div>'
      + extra
      + '</div>'
      + actions
      + '</div>';
  }
  var items = [];
  if (reqs.length === 0) {
    items.push({id:'empty-all-'+_approvalFilter, html:'<div class="approval-empty" data-id="empty-all-'+_approvalFilter+'">No '+( _approvalFilter==='active' ? 'approvals' : 'removed approvals' )+' yet</div>'});
  } else {
    if (_approvalFilter === 'active') {
      items.push({id:'title-pending', html:'<div class="approval-section-title" data-id="title-pending">Pending Approvals ('+pending.length+')</div>'});
      if (pending.length === 0) {
        items.push({id:'empty-pending', html:'<div class="approval-empty" data-id="empty-pending">No pending approvals</div>'});
      } else {
        var sortedPending = pending.sort(function(a,b){return b.created_at > a.created_at ? 1 : -1;});
        sortedPending.forEach(function(r){items.push({id:r.id, html:renderCard(r)});});
      }
      if (completed.length > 0) {
        items.push({id:'title-history', html:'<div class="approval-section-title" data-id="title-history">Approval History ('+completed.length+')</div>'});
        var sortedCompleted = completed.sort(function(a,b){return b.created_at > a.created_at ? 1 : -1;});
        sortedCompleted.forEach(function(r){items.push({id:r.id, html:renderCard(r)});});
      }
    } else {
      items.push({id:'title-removed', html:'<div class="approval-section-title" data-id="title-removed">Removed Approvals ('+removed.length+')</div>'});
      removed.sort(function(a,b){return b.created_at > a.created_at ? 1 : -1;}).forEach(function(r){items.push({id:r.id, html:renderCard(r)});});
    }
  }
  smartUpdate(el, items);
}

function smartUpdate(el, items) {
  var existing = {};
  Array.from(el.children).forEach(function(c){
    var id = c.getAttribute('data-id');
    if (id) existing[id] = c;
    c._keep = false;
  });
  var frag = document.createDocumentFragment();
  items.forEach(function(item){
    var temp = document.createElement('div');
    temp.innerHTML = item.html;
    frag.appendChild(temp.firstChild);
  });
  var newChildren = Array.from(frag.children);
  newChildren.forEach(function(nc, idx){
    var id = nc.getAttribute('data-id');
    var oc = id ? existing[id] : null;
    if (oc) {
      oc._keep = true;
      if (oc.innerHTML !== nc.innerHTML) {
        oc.innerHTML = nc.innerHTML;
      }
    } else {
      nc._keep = true;
      nc.style.opacity = '0';
      nc.style.transform = 'translateY(8px)';
      nc.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
      var ref = el.children[idx];
      if (ref) el.insertBefore(nc, ref);
      else el.appendChild(nc);
      requestAnimationFrame(function(){nc.style.opacity='1';nc.style.transform='translateY(0)';});
    }
  });
  Array.from(el.children).forEach(function(c){
    if (!c._keep) {
      c.style.transition = 'opacity 0.15s, transform 0.15s';
      c.style.opacity = '0';
      c.style.transform = 'scale(0.95)';
      setTimeout(function(){if(c.parentNode)el.removeChild(c);},150);
    }
  });
}

function doApproval(id, action, btn) {
  if (btn) { btn.disabled = true; btn.textContent = action === 'approve' ? 'Approving...' : 'Rejecting...'; }
  fetch('/'+action+'/'+id, {method:'POST'}).then(function(r){return r.json();}).then(function(d){
    if (d.ok) { fetchApprovals(); } else { if (btn) { btn.disabled = false; btn.textContent = action === 'approve' ? 'Approve & Execute' : 'Reject'; } }
  }).catch(function(){ if (btn) { btn.disabled = false; btn.textContent = action === 'approve' ? 'Approve & Execute' : 'Reject'; } });
}

function fetchApprovals() {
  if (!_canViewApprovals) {
    var el = document.getElementById('approvals-list');
    if (el) el.innerHTML = '<div class="approval-empty">You do not have permission to view this section. Contact an administrator to request access.</div>';
    var bc = document.getElementById('approval-count');
    if (bc) bc.style.display = 'none';
    return;
  }
  fetch('/approvals').then(function(r){return r.json();}).then(function(d){
    var s = JSON.stringify(d);
    if (s !== JSON.stringify(_lastApprovalsData)) {
      _lastApprovalsData = d;
      renderApprovals(d);
    }
  }).catch(function(){});
}

// ── Users tab ──────────────────────────────────────
function showTableSkeleton(el) {
  if (!el) return;
  var cols = [18, 34, 26, 12, 10];
  var html = '<div class="sk-wrap">';
  for (var r = 0; r < 4; r++) {
    html += '<div class="sk-row">';
    for (var c = 0; c < cols.length; c++) {
      html += '<div class="sk-cell" style="width:' + cols[c] + '%"></div>';
    }
    html += '</div>';
  }
  html += '</div>';
  el.innerHTML = html;
}
function fetchUsers() {
  var el = document.getElementById('users-list');
  if (el && el.getElementsByTagName('table').length === 0 && !el.querySelector('.sk-wrap')) {
    showTableSkeleton(el);
  }
  fetch('/users').then(function(r){return r.json();}).then(function(d){
    renderUsers(d.users||[]);
  }).catch(function(){});
}
function renderUsers(users) {
  var el = document.getElementById('users-list');
  if (!el) return;

  var focusedEl = document.activeElement;
  var focusedId = focusedEl && focusedEl.id;
  var selStart, selEnd;
  if (focusedId && focusedEl.tagName === 'INPUT') {
    selStart = focusedEl.selectionStart;
    selEnd = focusedEl.selectionEnd;
  }

  var saved = {};
  if (_showCreateForm) {
    ['nu-user','nu-email'].forEach(function(id){
      var inp = document.getElementById(id);
      if (inp) saved[id] = inp.value;
    });
    var permsKeys = ['can_view_dashboard','can_view_pods','can_view_containers','can_view_approvals','can_approve','can_admin'];
    permsKeys.forEach(function(k){
      var cb = document.getElementById('nu-'+k);
      if (cb) saved['nu-'+k] = cb.checked;
    });
  }

  var html = '<div style="margin-bottom:16px"><button class="tab-btn active" onclick="showCreateUserForm()" style="display:inline-flex;align-items:center;gap:6px">+ Add User</button></div>';
  html += '<div id="create-user-form" style="display:'+(_showCreateForm?'block':'none')+';background:var(--surface);border:1px solid var(--glass-border);border-radius:8px;padding:20px;margin-bottom:20px">';
  html += '<div style="font-size:14px;font-weight:600;margin-bottom:12px">Create New User</div>';
  html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">';
  html += '<div><label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Username</label><input id="nu-user" style="width:100%;padding:8px 10px;border-radius:6px;border:1px solid var(--glass-border);background:var(--bg);color:var(--text);font-size:13px"></div>';
  html += '<div><label style="font-size:12px;color:var(--text2);display:block;margin-bottom:4px">Email</label><input id="nu-email" type="email" style="width:100%;padding:8px 10px;border-radius:6px;border:1px solid var(--glass-border);background:var(--bg);color:var(--text);font-size:13px"></div>';
  html += '</div>';
  html += '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px">';
  var perms = [
    {key:'can_view_dashboard',label:'View Dashboard'},
    {key:'can_view_pods',label:'View Pods'},
    {key:'can_view_containers',label:'View Containers'},
    {key:'can_view_approvals',label:'View Approvals'},
    {key:'can_approve',label:'Can Approve'},
    {key:'can_admin',label:'Admin'},
  ];
  for (var i=0;i<perms.length;i++) {
    var chk = saved['nu-'+perms[i].key] !== undefined ? saved['nu-'+perms[i].key] : (perms[i].key === 'can_view_dashboard');
    html += '<label style="display:flex;align-items:center;gap:6px;font-size:13px;color:var(--text);cursor:pointer"><input type="checkbox" id="nu-'+perms[i].key+'"'+(chk?' checked':'')+'> '+perms[i].label+'</label>';
  }
  html += '</div><div style="display:flex;gap:8px">';
  html += '<button onclick="submitNewUser()" style="padding:8px 20px;background:var(--green);color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600;font-size:13px">Create User</button>';
  html += '<button onclick="_showCreateForm=false;document.getElementById(\'create-user-form\').style.display=\'none\'" style="padding:8px 20px;background:transparent;color:var(--text2);border:1px solid var(--glass-border);border-radius:6px;cursor:pointer;font-size:13px">Cancel</button>';
  html += '</div><div id="nu-error" style="color:var(--red);font-size:13px;margin-top:8px;display:none"></div></div>';

  html += '<table style="width:100%;border-collapse:collapse;font-size:13px">';
  html += '<thead><tr style="border-bottom:1px solid var(--glass-border);color:var(--text2);font-size:12px;text-transform:uppercase;letter-spacing:0.5px">';
  html += '<th style="text-align:left;padding:8px 12px">Username</th><th style="text-align:left;padding:8px 12px">Email</th><th style="text-align:left;padding:8px 12px">Permissions</th><th style="text-align:left;padding:8px 12px">Created</th><th style="text-align:left;padding:8px 12px"></th>';
  html += '</tr></thead><tbody>';
  for (var i=0;i<users.length;i++) {
    var u = users[i];
    var permsHtml = '';
    var allPerms = [
      {key:'can_view_dashboard', label:'Dashboard', color:'var(--green,#3fb950)'},
      {key:'can_view_pods', label:'Pods', color:'var(--blue,#58a6ff)'},
      {key:'can_view_containers', label:'Containers', color:'var(--cyan,#39d2c0)'},
      {key:'can_view_approvals', label:'Approvals', color:'var(--text2,#8b949e)'},
      {key:'can_approve', label:'Approve', color:'var(--orange,#d29922)'},
      {key:'can_admin', label:'Admin', color:'var(--purple,#8957e5)'},
    ];
    for (var pi=0;pi<allPerms.length;pi++) {
      var pk = allPerms[pi];
      var active = u[pk.key] ? ' active' : '';
      permsHtml += '<span class="perm-tog'+active+'" onclick="togglePerm(this)" data-user="'+u.id+'" data-perm="'+pk.key+'" style="border-color:'+pk.color+';color:'+(u[pk.key]?'#fff':pk.color)+';background:'+(u[pk.key]?pk.color:'transparent')+'">'+pk.label+'</span>';
    }
    var created = u.created_at ? u.created_at.split('T')[0] : '';
    html += '<tr style="border-bottom:1px solid var(--glass-border)">';
    html += '<td style="padding:10px 12px;font-weight:600">'+esc(u.username)+'</td>';
    html += '<td style="padding:10px 12px;color:var(--text2)">'+esc(u.email)+'</td>';
    html += '<td style="padding:10px 12px">'+permsHtml+'</td>';
    html += '<td style="padding:10px 12px;color:var(--text2);font-size:12px">'+created+'</td>';
    html += '<td style="padding:10px 12px;text-align:right"><button onclick="deleteUser('+u.id+')" style="padding:4px 12px;background:var(--red,#f85149);color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:12px">Delete</button></td>';
    html += '</tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;

  if (_showCreateForm) {
    ['nu-user','nu-email'].forEach(function(id){
      var inp = document.getElementById(id);
      if (inp && saved[id] !== undefined) inp.value = saved[id];
    });
  }

  if (focusedId) {
    var el2 = document.getElementById(focusedId);
    if (el2 && el2.tagName === 'INPUT') {
      el2.focus();
      if (selStart !== undefined && selEnd !== undefined) el2.setSelectionRange(selStart, selEnd);
    }
  }
}
function showCreateUserForm() {
  _showCreateForm = !_showCreateForm;
  var f = document.getElementById('create-user-form');
  if (f) f.style.display = _showCreateForm ? 'block' : 'none';
}
function submitNewUser() {
  var errEl = document.getElementById('nu-error');
  errEl.style.display = 'none';
  var u = document.getElementById('nu-user').value;
  var em = document.getElementById('nu-email').value;
  if (!u || !em) { errEl.textContent = 'Username and email required'; errEl.style.display = 'block'; return; }
  var perms = {};
  perms.can_view_dashboard = document.getElementById('nu-can_view_dashboard').checked;
  perms.can_view_pods = document.getElementById('nu-can_view_pods').checked;
  perms.can_view_containers = document.getElementById('nu-can_view_containers').checked;
  perms.can_view_approvals = document.getElementById('nu-can_view_approvals').checked;
  perms.can_approve = document.getElementById('nu-can_approve').checked;
  perms.can_admin = document.getElementById('nu-can_admin').checked;
  fetch('/users/create', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: u, email: em, permissions: perms})
  }).then(function(r){return r.json();}).then(function(j){
    if (j.ok) { _showCreateForm=false; fetchUsers(); }
    else { errEl.textContent = j.error || 'Failed'; errEl.style.display = 'block'; }
  }).catch(function(){ errEl.textContent = 'Connection failed'; errEl.style.display = 'block'; });
}
function deleteUser(id) {
  if (!confirm('Delete this user?')) return;
  fetch('/users/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_id: id})
  }).then(function(r){return r.json();}).then(function(j){
    if (j.ok) fetchUsers();
  }).catch(function(){});
}
function togglePerm(el) {
  var active = el.classList.toggle('active');
  var userId = parseInt(el.dataset.user);
  var permKey = el.dataset.perm;
  var color = el.style.borderColor;
  el.style.color = active ? '#fff' : color;
  el.style.background = active ? color : 'transparent';
  var perms = {};
  perms[permKey] = active;
  fetch('/users/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_id: userId, permissions: perms})
  }).catch(function(){});
}
function logout() {
  fetch('/logout', {method:'POST'}).then(function(){
    window.location.href = '/login';
  }).catch(function(){
    window.location.href = '/login';
  });
}
function toggleUserMenu(e) {
  e.stopPropagation();
  document.getElementById('hdr-user-menu').classList.toggle('open');
}
function closeUserMenu() {
  document.getElementById('hdr-user-menu').classList.remove('open');
}
document.addEventListener('click', function(e) {
  var m = document.getElementById('hdr-user-menu');
  if (m && m.classList.contains('open') && !m.contains(e.target)) {
    m.classList.remove('open');
  }
});
function checkUserPermissions(cb) {
  fetch('/users/me').then(function(r){
    if (r.status === 200) return r.json();
    return null;
  }).then(function(d){
    if (d && d.perms) {
      var p = d.perms;
      var ut = document.getElementById('menu-users-item');
      if (ut) ut.style.display = p.can_admin ? '' : 'none';
      var at = document.getElementById('approvals-tab');
      if (at) {
        _canViewApprovals = p.can_view_approvals || false;
        at.style.display = _canViewApprovals ? '' : 'none';
      }
      if (!_canViewApprovals && _selectedTab === 'approvals') {
        switchTab('overview');
      }
      var pt = document.getElementById('pods-tab');
      if (pt) {
        _canViewPods = p.can_view_pods || false;
        pt.style.display = _canViewPods ? '' : 'none';
      }
      if (!_canViewPods && _selectedTab === 'pods') {
        switchTab('overview');
      }
      var ct = document.getElementById('containers-tab');
      if (ct) {
        _canViewContainers = p.can_view_containers || false;
        ct.style.display = _canViewContainers ? '' : 'none';
      }
      if (!_canViewContainers && _selectedTab === 'containers') {
        switchTab('overview');
      }
    }
    if (d && d.google_user) {
      var g = d.google_user;
      var av = document.getElementById('hdr-avatar');
      if (g.picture) av.src = g.picture; else av.removeAttribute('src');
      var icon = document.querySelector('#hdr-user-menu .hdr-user-icon');
      if (icon) icon.classList.toggle('has-photo', !!g.picture);
      var head = document.getElementById('hdr-user-dropdown-head');
      head.innerHTML = '<div class="hd-name">' + esc(g.name || g.email || 'User') + '</div><div class="hd-mail">' + esc(g.email || '') + '</div>';
    } else if (d && d.username) {
      var icon = document.querySelector('#hdr-user-menu .hdr-user-icon');
      if (icon) icon.classList.toggle('has-photo', !!d.profile_pic);
      var av = document.getElementById('hdr-avatar');
      if (d.profile_pic) av.src = d.profile_pic; else av.removeAttribute('src');
      var head = document.getElementById('hdr-user-dropdown-head');
      head.innerHTML = '<div class="hd-name">' + esc(d.username) + '</div><div class="hd-mail">' + esc(d.email || '') + '</div>';
    }
    document.getElementById('hdr-user-menu').style.display = 'block';
    if (cb) cb();
  }).catch(function(){if (cb) cb();});
}

// ── Change Password Modal ──────────────────────────────────────
function openChangePwModal() {
  document.getElementById('pw-modal').classList.add('active');
  var m = document.getElementById('pw-msg');
  m.style.display = 'none';
  m.className = 'modal-msg';
  document.getElementById('pw-old').value = '';
  document.getElementById('pw-new').value = '';
  document.getElementById('pw-confirm').value = '';
  document.getElementById('pw-old').focus();
}
function closeChangePwModal() {
  document.getElementById('pw-modal').classList.remove('active');
}
function closeProfile() {
  document.getElementById('profile-modal').classList.remove('active');
}
function _setProfilePreview(pic) {
  var img = document.getElementById('profile-avatar-img');
  var svg = document.getElementById('profile-avatar-preview').querySelector('svg');
  var rm = document.getElementById('profile-pic-remove');
  if (pic) {
    img.src = pic;
    img.style.display = '';
    svg.style.display = 'none';
    rm.style.display = '';
  } else {
    img.style.display = 'none';
    img.removeAttribute('src');
    svg.style.display = '';
    rm.style.display = 'none';
  }
}
function openProfile() {
  fetch('/users/me').then(function(r){return r.json();}).then(function(d){
    if (!d) return;
    document.getElementById('profile-username-input').value = d.username || '';
    document.getElementById('profile-email').textContent = (d.google_user && d.google_user.email) ? d.google_user.email : (d.email || '—');
    var role = d.role || '';
    if (d.google_user) role = 'Google SSO' + (role ? ' · ' + role : '');
    if (!role && d.perms && d.perms.can_admin) role = 'Admin';
    if (!role) role = 'User';
    document.getElementById('profile-role').textContent = role;
    _setProfilePreview(d.profile_pic || '');
    var msg = document.getElementById('profile-msg');
    msg.style.display = 'none';
    msg.className = 'modal-msg';
    document.getElementById('profile-modal').classList.add('active');
  }).catch(function(){
    document.getElementById('profile-modal').classList.add('active');
  });
}
function removeProfilePic() {
  _setProfilePreview('');
}
function saveProfile() {
  var username = document.getElementById('profile-username-input').value.trim();
  var pic = document.getElementById('profile-avatar-img').src || '';
  var msg = document.getElementById('profile-msg');
  msg.style.display = 'none';
  msg.className = 'modal-msg';
  if (username.length < 3 || username.length > 32) {
    msg.textContent = 'Username must be 3-32 characters';
    msg.style.display = 'block';
    msg.className = 'modal-msg error';
    return;
  }
  var payload = {username: username, profile_pic: pic};
  fetch('/users/profile', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  }).then(function(r){return r.json();}).then(function(j){
    if (j.ok) {
      msg.textContent = 'Profile updated';
      msg.style.display = 'block';
      msg.className = 'modal-msg success';
      setTimeout(function(){ closeProfile(); }, 900);
      checkUserPermissions();
    } else {
      msg.textContent = j.error || 'Update failed';
      msg.style.display = 'block';
      msg.className = 'modal-msg error';
    }
  }).catch(function(){
    msg.textContent = 'Update failed';
    msg.style.display = 'block';
    msg.className = 'modal-msg error';
  });
}
function _profilePicChosen(e) {
  var f = e.target.files && e.target.files[0];
  if (!f) return;
  if (f.size > 400000) { alert('Image too large. Max 400KB.'); return; }
  var rd = new FileReader();
  rd.onload = function(ev) { _setProfilePreview(ev.target.result); };
  rd.readAsDataURL(f);
}
function _bindProfilePicInput() {
  var el = document.getElementById('profile-pic-input');
  if (el && !el.dataset.bound) {
    el.dataset.bound = '1';
    el.addEventListener('change', _profilePicChosen);
  }
}
window.addEventListener('load', _bindProfilePicInput);
function submitChangePw() {
  var old = document.getElementById('pw-old').value;
  var pw = document.getElementById('pw-new').value;
  var cf = document.getElementById('pw-confirm').value;
  var msg = document.getElementById('pw-msg');
  msg.style.display = 'none';
  msg.className = 'modal-msg';
  if (!old || !pw || !cf) { msg.className = 'modal-msg error'; msg.textContent = 'All fields are required'; msg.style.display = 'block'; return; }
  if (pw !== cf) { msg.className = 'modal-msg error'; msg.textContent = 'New passwords do not match'; msg.style.display = 'block'; return; }
  if (pw.length < 6) { msg.className = 'modal-msg error'; msg.textContent = 'Password must be at least 6 characters'; msg.style.display = 'block'; return; }
  fetch('/change-password', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({old_password: old, new_password: pw})
  }).then(function(r){ return r.json().then(function(j){ return {status: r.status, body: j}; }); })
    .then(function(res){
      if (res.status === 200) {
        msg.className = 'modal-msg success';
        msg.textContent = 'Password changed successfully';
        msg.style.display = 'block';
        document.getElementById('pw-old').value = '';
        document.getElementById('pw-new').value = '';
        document.getElementById('pw-confirm').value = '';
        setTimeout(closeChangePwModal, 2000);
      } else {
        msg.className = 'modal-msg error';
        msg.textContent = res.body.error || 'Failed to change password';
        msg.style.display = 'block';
      }
    }).catch(function(){
      msg.className = 'modal-msg error';
      msg.textContent = 'Connection failed';
      msg.style.display = 'block';
    });
}
document.addEventListener('click', function(e) {
  if (e.target.classList.contains('modal-overlay')) closeChangePwModal();
});

function downloadReport(days) {
  var a = document.createElement('a');
  a.href = '/api/report?days=' + days;
  a.download = 'healix-report-' + days + 'd.pdf';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function setReportRange(btn, days) {
  document.querySelectorAll('#panel-reports .range-btn').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  document.getElementById('report-download-btn').onclick = function(){downloadReport(days);};
}

function poll() {
  checkUserPermissions(function() {
    fetchApprovals();
    if (_selectedTab === 'users') fetchUsers();
  });
  fetch('/metrics/api').then(function(r){return r.json();}).then(function(d){_lastMetricsData=d; snapshotMetrics(d); update(d); buildAllMetricCharts(d,_lastDiagsData);}).catch(function(){});
  fetch('/diagnoses').then(function(r){return r.json();}).then(function(d){_lastDiagsData=d.records||[]; renderDiagnoses(_lastDiagsData); if(_lastMetricsData) buildAllMetricCharts(_lastMetricsData,_lastDiagsData);}).catch(function(){});
}
poll();
_pollInterval = setInterval(poll,5000);
setInterval(function(){if(_selectedTab==='users')fetchUsers();}, 10000);
// ── P4: Micro-interactions & polish ─────────────────────────────────────────
function p4ReduceMotion() { return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
function p4NoHover() { return window.matchMedia && window.matchMedia('(hover: none)').matches; }
(function initRipple(){
  if (p4ReduceMotion()) return;
  document.addEventListener('pointerdown', function(e){
    var btn = e.target && e.target.closest ? e.target.closest('button, .tab-btn, [role="button"], .vtl-dot') : null;
    if (!btn) return;
    if (getComputedStyle(btn).overflow === 'visible') btn.style.overflow = 'hidden';
    var r = btn.getBoundingClientRect();
    var size = Math.max(r.width, r.height) * 2.2;
    var s = document.createElement('span');
    s.className = 'ripple';
    s.style.width = s.style.height = size + 'px';
    s.style.left = (e.clientX - r.left - size / 2) + 'px';
    s.style.top = (e.clientY - r.top - size / 2) + 'px';
    btn.appendChild(s);
    setTimeout(function(){ if (s.parentNode) s.parentNode.removeChild(s); }, 600);
  });
})();
(function initTilt(){
  if (p4NoHover() || p4ReduceMotion()) return;
  document.addEventListener('pointermove', function(e){
    var card = e.target && e.target.closest ? e.target.closest('.stat-card, .metrics-stat-card') : null;
    if (card) {
      if (card.style.animation !== 'none') {
        var op = getComputedStyle(card).opacity || '1';
        card.style.animation = 'none';
        card.style.opacity = op;
      }
      var r = card.getBoundingClientRect();
      var px = (e.clientX - r.left) / r.width - 0.5;
      var py = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform = 'perspective(700px) rotateX(' + (-py * 4).toFixed(2) + 'deg) rotateY(' + (px * 4).toFixed(2) + 'deg) translateY(-1px)';
    }
  });
  document.addEventListener('pointerout', function(e){
    var card = e.target && e.target.closest ? e.target.closest('.stat-card, .metrics-stat-card') : null;
    if (card) card.style.transform = '';
  });
})();
</script>

<div class="modal-overlay" id="pw-modal">
  <div class="modal-card">
    <h2>Change Password</h2>
    <p>Enter your current password and a new password.</p>
    <div class="modal-field">
      <label for="pw-old">Current Password</label>
      <input type="password" id="pw-old" autocomplete="current-password">
    </div>
    <div class="modal-field">
      <label for="pw-new">New Password</label>
      <input type="password" id="pw-new" autocomplete="new-password">
    </div>
    <div class="modal-field">
      <label for="pw-confirm">Confirm New Password</label>
      <input type="password" id="pw-confirm" autocomplete="new-password">
    </div>
    <div class="modal-msg" id="pw-msg"></div>
    <div class="modal-actions">
      <button class="modal-btn secondary" onclick="closeChangePwModal()">Cancel</button>
      <button class="modal-btn primary" onclick="submitChangePw()">Change Password</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="profile-modal">
  <div class="modal-card profile-card">
    <h2>Profile</h2>
    <p>Edit your Healix account details.</p>
    <div class="profile-avatar-wrap">
      <div class="profile-avatar" id="profile-avatar-preview">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="42" height="42"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        <img id="profile-avatar-img" src="" alt="" style="display:none">
      </div>
      <label class="profile-avatar-edit" for="profile-pic-input" title="Upload photo">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
      </label>
      <input type="file" id="profile-pic-input" accept="image/*" style="display:none">
      <button class="profile-pic-remove" id="profile-pic-remove" onclick="removeProfilePic()" style="display:none" title="Remove photo">✕</button>
    </div>
    <div class="modal-field">
      <label for="profile-username-input">Username</label>
      <input type="text" id="profile-username-input" autocomplete="username">
    </div>
    <div class="profile-row">
      <span class="profile-label">Email</span>
      <span class="profile-value" id="profile-email">—</span>
    </div>
    <div class="profile-row">
      <span class="profile-label">Role</span>
      <span class="profile-value" id="profile-role">—</span>
    </div>
    <div class="modal-msg" id="profile-msg"></div>
    <div class="modal-actions">
      <button class="modal-btn secondary" onclick="closeProfile()">Cancel</button>
      <button class="modal-btn primary" onclick="saveProfile()">Save</button>
    </div>
  </div>
</div>

<!-- Chat Assistant -->
<style>
  .chat-fab {
    position: fixed; right: 22px; bottom: 22px; z-index: 1001;
    width: 56px; height: 56px; border-radius: 50%; border: 1px solid var(--border-glow);
    background: var(--surface); backdrop-filter: blur(10px);
    display: flex; align-items: center; justify-content: center; cursor: pointer;
    box-shadow: 0 6px 24px var(--card-shadow); transition: transform 0.2s ease, box-shadow 0.2s ease;
  }
  .chat-fab:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(88,166,255,0.18); }
  .chat-fab svg { width: 26px; height: 26px; color: var(--blue); }
  .chat-fab-label {
    position: fixed; right: 92px; bottom: 38px; z-index: 1001;
    max-width: 250px; padding: 10px 14px;
    background: var(--surface); border: 1px solid var(--border-glow); border-radius: 12px;
    box-shadow: 0 8px 28px var(--card-shadow); backdrop-filter: blur(10px);
    font-size: 13px; font-weight: 500; color: var(--text); line-height: 1.45;
    opacity: 0; transform: translateX(8px); transition: opacity 0.3s ease, transform 0.3s ease;
  }
  .chat-fab-label.show { opacity: 1; transform: translateX(0); }
  .chat-fab-label.hidden { opacity: 0; pointer-events: none; }
  .chat-fab-label::before {
    content: ''; position: absolute; right: -6px; top: 50%; transform: translateY(-50%) rotate(45deg);
    width: 12px; height: 12px; background: var(--surface); border-right: 1px solid var(--border-glow);
    border-top: 1px solid var(--border-glow);
  }
  .chat-fab-label .chat-caret { display: inline-block; width: 2px; height: 14px; background: var(--blue); margin-left: 2px; vertical-align: -2px; animation: chatCaretBlink 0.85s step-end infinite; }
  @keyframes chatCaretBlink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
  .chat-panel {
    position: fixed; right: 22px; bottom: 90px; z-index: 1001;
    width: 368px; max-width: calc(100vw - 32px); height: 480px; max-height: calc(100vh - 140px);
    background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
    box-shadow: 0 18px 50px var(--card-shadow); backdrop-filter: blur(14px);
    display: flex; flex-direction: column; overflow: hidden;
    opacity: 0; transform: translateY(12px) scale(0.97); pointer-events: none;
    transition: opacity 0.2s ease, transform 0.2s ease;
  }
  .chat-panel.open { opacity: 1; transform: translateY(0) scale(1); pointer-events: auto; }
  .chat-head {
    display: flex; align-items: center; gap: 10px; padding: 14px 16px;
    border-bottom: 1px solid var(--border-subtle); background: var(--header-bg);
  }
  .chat-head svg { width: 22px; height: 22px; color: var(--blue); }
  .chat-head .chat-title { font-size: 14px; font-weight: 700; color: var(--text); }
  .chat-head .chat-sub { font-size: 11px; color: var(--text2); }
  .chat-head .chat-close { margin-left: auto; cursor: pointer; color: var(--text2); font-size: 18px; line-height: 1; background: none; border: none; padding: 4px; }
  .chat-head .chat-close:hover { color: var(--text); }
  .chat-body { flex: 1; overflow-y: auto; padding: 14px; display: flex; flex-direction: column; gap: 10px; }
  .chat-msg { max-width: 82%; padding: 9px 12px; border-radius: 12px; font-size: 13px; line-height: 1.5; white-space: pre-wrap; word-break: break-word; }
  .chat-msg.user { align-self: flex-end; background: var(--blue); color: #fff; border-bottom-right-radius: 4px; }
  .chat-msg.bot { align-self: flex-start; background: var(--box-bg); border: 1px solid var(--border-subtle); color: var(--text); border-bottom-left-radius: 4px; }
  .chat-msg.err { align-self: flex-start; background: rgba(248,81,73,0.12); border: 1px solid rgba(248,81,73,0.35); color: var(--red); }
  .chat-msg .chat-provider { display: block; margin-top: 6px; font-size: 10px; color: var(--text3); text-transform: uppercase; letter-spacing: 0.6px; }
  .chat-typing { align-self: flex-start; display: none; gap: 4px; padding: 10px 14px; background: var(--box-bg); border: 1px solid var(--border-subtle); border-radius: 12px; border-bottom-left-radius: 4px; }
  .chat-typing.show { display: flex; }
  .chat-typing span { width: 7px; height: 7px; border-radius: 50%; background: var(--text2); animation: chatBlink 1.2s infinite; }
  .chat-typing span:nth-child(2) { animation-delay: 0.2s; }
  .chat-typing span:nth-child(3) { animation-delay: 0.4s; }
  @keyframes chatBlink { 0%, 80%, 100% { opacity: 0.25; transform: scale(0.9); } 40% { opacity: 1; transform: scale(1); } }
  .chat-foot { display: flex; gap: 8px; padding: 12px; border-top: 1px solid var(--border-subtle); background: var(--header-bg); }
  .chat-foot input {
    flex: 1; padding: 10px 12px; border-radius: 8px; border: 1px solid var(--border-subtle);
    background: var(--input-bg); color: var(--text); font-size: 13px; outline: none;
  }
  .chat-foot input:focus { border-color: var(--blue); }
  .chat-foot button {
    border: none; border-radius: 8px; padding: 0 16px; background: var(--blue); color: #fff;
    font-size: 13px; font-weight: 600; cursor: pointer;
  }
  .chat-foot button:disabled { opacity: 0.55; cursor: default; }
</style>
<div class="chat-fab" id="chatFab" onclick="toggleChat()" title="Healix Assistant">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/>    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
</div>
<div class="chat-fab-label" id="chatFabLabel"></div>
<div class="chat-panel" id="chatPanel">
  <div class="chat-head">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
    <div>
      <div class="chat-title">Healix Assistant</div>
      <div class="chat-sub">Read-only · Live system Q&A</div>
    </div>
    <button class="chat-close" onclick="toggleChat()">&times;</button>
  </div>
  <div class="chat-body" id="chatBody"></div>
  <div class="chat-typing" id="chatTyping"><span></span><span></span><span></span></div>
  <div class="chat-foot">
    <input type="text" id="chatInput" placeholder="Ask about system health..." autocomplete="off" onkeydown="if(event.key==='Enter')sendChat()">
    <button id="chatSendBtn" onclick="sendChat()">Send</button>
  </div>
</div>
<script>
var _chatOpen = false, _chatHistory = [], _chatInited = false;
var _twLabel = null, _twText = '', _twPaused = false, _twTimer = null;
function _twUsername() {
  var hd = document.querySelector('.hd-name');
  if (hd && hd.textContent.trim()) return hd.textContent.trim();
  return 'Healix admin';
}
function _twClear() {
  if (!_twLabel) return;
  _twLabel.innerHTML = '';
  _twLabel.classList.remove('show');
}
function _twType() {
  if (!_twLabel || _twPaused) return;
  var i = 0;
  _twLabel.classList.add('show');
  var caret = document.createElement('span');
  caret.className = 'chat-caret';
  _twTypeLoop(i, caret);
}
function _twTypeLoop(i, caret) {
  if (_twPaused) return;
  if (i <= _twText.length) {
    _twLabel.textContent = _twText.slice(0, i);
    if (i < _twText.length) { _twLabel.appendChild(caret); }
    i++;
    _twTimer = setTimeout(function() { _twTypeLoop(i, caret); }, 35);
  } else {
    _twTimer = setTimeout(function() {
      if (_twPaused) return;
      _twLabel.textContent = _twText;
      _twTimer = setTimeout(function() { _twClear(); _twTimer = setTimeout(_twType, 1500); }, 4000);
    }, 600);
  }
}
function startChatTypewriter() {
  _twLabel = document.getElementById('chatFabLabel');
  if (!_twLabel) return;
  _twText = 'Hey ' + _twUsername() + ', how can I assist you?';
  setTimeout(_twType, 300);
}
function toggleChat() {
  var p = document.getElementById('chatPanel');
  _chatOpen = !_chatOpen;
  p.classList.toggle('open', _chatOpen);
  if (_twLabel) _twLabel.classList.toggle('hidden', _chatOpen);
  _twPaused = _chatOpen;
  if (_chatOpen) {
    if (_twTimer) clearTimeout(_twTimer);
    document.getElementById('chatInput').focus();
    if (!_chatInited) {
      _chatInited = true;
      addChatMsg('bot', 'Hi! I can answer questions about Healix health, diagnoses, metrics, approvals and service connectivity. Try "give me a quick health summary".');
    }
  } else {
    setTimeout(function() { if (!_twPaused) _twType(); }, 250);
  }
}
window.addEventListener('load', function() {
  setTimeout(startChatTypewriter, 3200);
});
function addChatMsg(role, text) {
  var body = document.getElementById('chatBody');
  var div = document.createElement('div');
  div.className = 'chat-msg ' + (role === 'user' ? 'user' : 'bot');
  div.textContent = text;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
  return div;
}
function setTyping(on) {
  var t = document.getElementById('chatTyping');
  t.classList.toggle('show', on);
  document.getElementById('chatSendBtn').disabled = on;
}
function sendChat() {
  var input = document.getElementById('chatInput');
  var msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  addChatMsg('user', msg);
  _chatHistory.push({role: 'user', content: msg});
  setTyping(true);
  var aborter = new AbortController();
  var timer = setTimeout(function() { aborter.abort(); }, (CONFIG && CONFIG.chat_timeout_ms) || 70000);
  fetch('/chat', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: msg, history: _chatHistory.slice(-12)}),
    signal: aborter.signal
  }).then(function(r) {
    clearTimeout(timer);
    if (r.status === 401) { window.location.href = '/login'; throw new Error('unauthorized'); }
    return r.json();
  }).then(function(j) {
    setTyping(false);
    if (j && j.ok) {
      _chatHistory.push({role: 'assistant', content: j.reply});
      var el = addChatMsg('bot', j.reply);
      if (j.provider) {
        var p = document.createElement('span');
        p.className = 'chat-provider';
        p.textContent = 'via ' + j.provider;
        el.appendChild(p);
      }
    } else if (j && j.error) {
      addChatMsg('err', j.error);
    }
  }).catch(function(e) {
    clearTimeout(timer);
    setTyping(false);
    if (e && e.message === 'unauthorized') return;
    if (e && e.name === 'AbortError') {
      addChatMsg('err', 'Still thinking... the LLM provider is slow. Try again or check the provider chain.');
    } else {
      addChatMsg('err', 'Connection failed. Is the agent running?');
    }
  });
}
</script>

</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH HTTP SERVER
# ══════════════════════════════════════════════════════════════════════════════

class _HealthState:
    last_heartbeat: float = time.time()
    is_healthy: bool = False


_health_state = _HealthState()

_approval_store = None

def set_approval_store(store) -> None:
    global _approval_store
    _approval_store = store


def get_approval_store():
    return _approval_store


_storage = None
_circuit_breaker = None


def set_storage(s) -> None:
    global _storage
    _storage = s


def set_circuit_breaker(cb) -> None:
    global _circuit_breaker
    _circuit_breaker = cb


def heartbeat() -> None:
    _health_state.last_heartbeat = time.time()
    _health_state.is_healthy = True


def mark_unhealthy() -> None:
    _health_state.is_healthy = False


def _clean_report_text(s: str) -> str:
    return (s or "").encode("latin-1", errors="replace").decode("latin-1")


_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@\-]{3,32}$")
_IMAGE_DATAURL_RE = re.compile(r"^data:image/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+/=]+$")


def _lerp(c1, c2, t):
    return tuple(int(a + (b - a) * t) for a, b in zip(c1, c2))


def _hgrad(pdf, x, y, w, h, c1, c2, radius=0):
    from fpdf.enums import Corner
    if w <= 0 or h <= 0:
        return
    steps = max(2, int(w * 2))
    sw = w / steps
    for i in range(steps):
        c = _lerp(c1, c2, i / (steps - 1))
        rc = False
        if radius and i == 0:
            rc = (Corner.TOP_LEFT, Corner.BOTTOM_LEFT)
        if radius and i == steps - 1:
            rc = (Corner.TOP_RIGHT, Corner.BOTTOM_RIGHT)
        pdf.set_fill_color(*c)
        pdf.rect(x + i * sw, y, sw + 0.05, h, "F", round_corners=rc, corner_radius=radius)


def _vgrad(pdf, x, y, w, h, c1, c2, radius=0):
    from fpdf.enums import Corner
    if w <= 0 or h <= 0:
        return
    steps = max(2, int(h * 2))
    sh = h / steps
    for i in range(steps):
        c = _lerp(c1, c2, i / (steps - 1))
        rc = False
        if radius and i == 0:
            rc = (Corner.TOP_LEFT, Corner.TOP_RIGHT)
        if radius and i == steps - 1:
            rc = (Corner.BOTTOM_LEFT, Corner.BOTTOM_RIGHT)
        pdf.set_fill_color(*c)
        pdf.rect(x, y + i * sh, w, sh + 0.05, "F", round_corners=rc, corner_radius=radius)


def generate_report(days: int = 7) -> bytes:
    from io import BytesIO
    from fpdf import FPDF

    INK = (31, 36, 48)
    MUTED = (107, 114, 128)
    BORDER = (226, 232, 240)
    TRACK = (241, 245, 249)
    WHITE = (255, 255, 255)
    HDR_A = (30, 58, 138)
    HDR_B = (37, 99, 235)
    HDR_C = (6, 182, 212)
    BLUE = (37, 99, 235)
    VIOLET = (139, 92, 246)
    GREEN = (16, 185, 129)
    RED = (239, 68, 68)
    ORANGE = (249, 115, 22)

    now = time.time()

    class _ReportPDF(FPDF):
        def footer(self) -> None:
            self.set_y(-16)
            _hgrad(self, 0, self.get_y() - 1, 210, 1.2, HDR_A, HDR_C)
            self.set_y(-14)
            self.set_font("Helvetica", "", 8)
            self.set_text_color(MUTED[0], MUTED[1], MUTED[2])
            self.cell(0, 10,
                      f"Healix | Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now))} | Page {self.page_no()}",
                      align="C")

    start_ts = now - max(1, int(days)) * 86400
    all_recs = diagnosis_store.to_list()
    recs = [r for r in all_recs if _ts_to_epoch(r.get("timestamp", "")) >= start_ts]
    total = len(recs)
    success = sum(1 for r in recs if r.get("success"))
    failed = total - success
    success_rate = round(success / total * 100, 1) if total else 0.0

    platforms: dict[str, int] = {}
    actions: dict[str, int] = {}
    by_day: dict[str, int] = {}
    resources: dict[str, int] = {}
    for r in recs:
        p = r.get("platform", "unknown")
        platforms[p] = platforms.get(p, 0) + 1
        ac = r.get("action", "unknown")
        actions[ac] = actions.get(ac, 0) + 1
        day = (r.get("timestamp") or "-----")[5:10]
        by_day[day] = by_day.get(day, 0) + 1
        nm = r.get("name", "unknown")
        resources[nm] = resources.get(nm, 0) + 1
    resources = dict(sorted(resources.items(), key=lambda x: -x[1])[:8])
    mc = metrics.to_dict()

    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(12, 12, 12)
    pdf.add_page()

    def _space(y, need):
        if y + need > 266:
            pdf.add_page()
            return 20
        return y

    def _section_title(y, title, c1, c2):
        _hgrad(pdf, 12, y, 5, 7, c1, c2, radius=1.5)
        pdf.set_xy(21, y + 0.4)
        pdf.set_font("Helvetica", "B", 12.5)
        pdf.set_text_color(INK[0], INK[1], INK[2])
        pdf.cell(150, 7, title)
        pdf.set_draw_color(*BORDER)
        pdf.set_line_width(0.5)
        pdf.line(12, y + 9.5, 198, y + 9.5)
        return y + 13

    # ── Gradient header ────────────────────────────────────────
    _hgrad(pdf, 0, 0, 210, 30, HDR_A, HDR_C)
    pdf.set_fill_color(*WHITE)
    pdf.rect(12, 6, 16, 16, "F", round_corners=True, corner_radius=3)
    pdf.set_draw_color(*HDR_B)
    pdf.set_line_width(1.3)
    pts = [(15.5, 14.5), (17, 14.5), (18.5, 8.5), (20, 19.5), (21.5, 14.5), (24, 14.5)]
    for i in range(len(pts) - 1):
        pdf.line(pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1])
    pdf.set_xy(33, 6.5)
    pdf.set_font("Helvetica", "B", 19)
    pdf.set_text_color(*WHITE)
    pdf.cell(80, 9, "Healix Report")
    pdf.set_xy(33, 16.5)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(219, 234, 254)
    pdf.cell(90, 5, "AI-Powered Self-Healing Platform")
    pdf.set_xy(118, 7.5)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(199, 227, 255)
    pdf.cell(80, 4.5, "REPORT PERIOD", align="R")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(118, 13.5)
    pdf.cell(80, 5,
             f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(start_ts))}  ->  {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now))}",
             align="R")
    pdf.set_fill_color(*HDR_C)
    pdf.rect(0, 30, 210, 1.2, "F")

    y = 40

    # ── Summary ────────────────────────────────────────────────
    y = _space(y, 80)
    y = _section_title(y, "Summary", BLUE, VIOLET)

    if total:
        if success_rate >= 90:
            tint, dot, msg = (220, 252, 231), GREEN, (
                f"Great health - {success_rate:.0f}% success rate "
                f"({success} of {total} incidents auto-healed successfully).")
        elif success_rate >= 60:
            tint, dot, msg = (254, 243, 199), ORANGE, (
                f"Moderate health - {success_rate:.0f}% success rate "
                f"({success} of {total} incidents healed, {failed} failed).")
        else:
            tint, dot, msg = (254, 226, 226), RED, (
                f"Attention needed - only {success_rate:.0f}% success rate "
                f"({failed} of {total} incidents failed to heal).")
    else:
        tint, dot, msg = (224, 242, 254), BLUE, (
            "No incidents in this period - the platform is running smoothly.")
    pdf.set_fill_color(*tint)
    pdf.rect(12, y, 186, 9, "F", round_corners=True, corner_radius=4.5)
    pdf.set_fill_color(*dot)
    pdf.rect(19, y + 3, 3, 3, "F", round_corners=True, corner_radius=1.5)
    pdf.set_xy(26, y + 2.4)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(INK[0], INK[1], INK[2])
    pdf.cell(170, 4.5, msg)
    y += 12

    kpis = [
        ("Total Incidents", str(total), (148, 163, 184), (100, 116, 139)),
        ("Successful Heals", str(success), GREEN, (5, 150, 105)),
        ("Failed", str(failed), RED, (185, 28, 28)),
        ("Success Rate", f"{success_rate:.0f}%", BLUE, VIOLET),
    ]
    gap = 3.0
    cw = (186 - gap * 3) / 4
    for i, (label, value, c1, c2) in enumerate(kpis):
        cx = 12 + i * (cw + gap)
        pdf.set_draw_color(*BORDER)
        pdf.set_line_width(0.4)
        pdf.set_fill_color(*WHITE)
        pdf.rect(cx, y, cw, 24, "DF", round_corners=True, corner_radius=2.5)
        _hgrad(pdf, cx + 1, y + 1, cw - 2, 3, c1, c2, radius=1.5)
        pdf.set_xy(cx + 6, y + 8)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(*c1)
        pdf.cell(cw - 12, 8, value)
        pdf.set_xy(cx + 6, y + 18)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(cw - 12, 4, label)
    y += 28

    chips = [
        ("LLM Calls", str(mc.get("total_llm_calls", 0)), BLUE),
        ("LLM Errors", str(mc.get("total_llm_errors", 0)), RED),
        ("Rollbacks", str(mc.get("rollbacks", 0)), ORANGE),
        ("PDB Blocks", str(mc.get("pdb_blocks", 0)), VIOLET),
        ("Uptime", f"{mc.get('uptime_seconds', 0) // 3600}h", (20, 184, 166)),
    ]
    chw = (186 - 4 * 2) / 5
    for i, (lab, val, col) in enumerate(chips):
        cx = 12 + i * (chw + 2)
        pdf.set_fill_color(*TRACK)
        pdf.rect(cx, y, chw, 7, "F", round_corners=True, corner_radius=3.5)
        pdf.set_fill_color(*col)
        pdf.rect(cx + 3, y + 2.25, 2.5, 2.5, "F", round_corners=True, corner_radius=1.2)
        pdf.set_xy(cx + 7, y + 1.4)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*INK)
        pdf.cell(chw - 10, 4.2, f"{lab}: {val}")
    y += 11

    # ── Incidents per day ──────────────────────────────────────
    y = _space(y, 45)
    y = _section_title(y, "Incidents Per Day", VIOLET, BLUE)
    track_h = 16
    pdf.set_fill_color(*TRACK)
    pdf.rect(12, y + 6, 186, track_h, "F", round_corners=True, corner_radius=3)
    if by_day:
        max_day = max(by_day.values())
        days_sorted = sorted(by_day.items())
        slot = 186.0 / len(days_sorted)
        for i, (day, cnt) in enumerate(days_sorted):
            bw = max(3.0, slot - 5)
            bx = 12 + i * slot + (slot - bw) / 2
            bh = max(1.5, (cnt / max_day) * (track_h - 6))
            _vgrad(pdf, bx, y + 6 + (track_h - bh) + 2, bw, bh, BLUE, VIOLET)
            pdf.set_xy(bx - 3, y + 1.5)
            pdf.set_font("Helvetica", "B", 7.5)
            pdf.set_text_color(79, 70, 229)
            pdf.cell(bw + 6, 4, str(cnt), align="C")
            pdf.set_xy(bx - 3, y + 6 + track_h + 3)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*MUTED)
            pdf.cell(bw + 6, 4, day, align="C")
        y += 6 + track_h + 10
    else:
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MUTED)
        pdf.set_xy(12, y + 6)
        pdf.cell(186, 6, "No incidents recorded in this period.")
        y += 6 + track_h + 10

    # ── Breakdowns: platform | action ─────────────────────────
    y = _space(y, 40)
    y = _section_title(y, "Activity Breakdown", GREEN, VIOLET)

    def _bar_row(bx, ry, label, value, maxv, track_w, c1, c2):
        pdf.set_xy(bx, ry)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*INK)
        pdf.cell(38, 5, _clean_report_text(label)[:22])
        pdf.set_fill_color(*TRACK)
        pdf.rect(bx + 38, ry + 0.6, track_w, 4.2, "F", round_corners=True, corner_radius=2.1)
        if maxv:
            _hgrad(pdf, bx + 38, ry + 0.6, max(1.5, track_w * value / maxv), 4.2, c1, c2)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*c1)
        pdf.cell(10, 5, str(value), align="R")

    max_plat = max(platforms.values()) if platforms else 0
    max_act = max(actions.values()) if actions else 0
    plat_items = sorted(platforms.items(), key=lambda x: -x[1])
    act_items = sorted(actions.items(), key=lambda x: -x[1])
    rows = max(len(plat_items), len(act_items), 1)
    pdf.set_xy(12, y)
    pdf.set_font("Helvetica", "B", 9.5)
    pdf.set_text_color(*INK)
    pdf.cell(90, 5, "By Platform")
    pdf.set_xy(108, y)
    pdf.cell(90, 5, "By Action")
    y += 7
    for i in range(rows):
        ry = y + i * 7
        if i < len(plat_items):
            _bar_row(12, ry, plat_items[i][0], plat_items[i][1], max_plat, 40, GREEN, (20, 184, 166))
        if i < len(act_items):
            _bar_row(108, ry, act_items[i][0], act_items[i][1], max_act, 40, VIOLET, BLUE)
    y += rows * 7 + 6

    # ── Most affected resources ────────────────────────────────
    if resources:
        y = _space(y, 30 + len(resources) * 5.6)
        y = _section_title(y, "Most Affected Resources", ORANGE, RED)
        max_res = max(resources.values())
        for nm, cnt in resources.items():
            pdf.set_xy(12, y)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*INK)
            pdf.cell(92, 5, _clean_report_text(nm)[:46])
            pdf.set_fill_color(*TRACK)
            pdf.rect(106, y + 0.6, 60, 4.2, "F", round_corners=True, corner_radius=2.1)
            _hgrad(pdf, 106, y + 0.6, max(1.5, 60 * cnt / max_res), 4.2, ORANGE, RED)
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*RED)
            pdf.cell(12, 5, str(cnt), align="R")
            y += 5.6
        y += 6

    # ── Incident table ─────────────────────────────────────────
    y = _space(y, 40)
    y = _section_title(y, "Recent Incidents", BLUE, VIOLET)
    col_w = [9, 24, 40, 24, 18, 71]
    heads = ["#", "Date", "Resource", "Platform", "Status", "Action"]

    def _table_head(yy):
        pdf.set_fill_color(224, 242, 254)
        pdf.rect(12, yy, 186, 7, "F", round_corners=True, corner_radius=2)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(30, 58, 138)
        x = 12
        for w, h in zip(col_w, heads):
            pdf.set_xy(x, yy + 1.6)
            pdf.cell(w, 4, h, align="C" if w < 30 else "L")
            x += w
        return yy + 8

    if recs:
        y = _table_head(y)
        last_page = pdf.page_no()
        for idx, r in enumerate(recs[:40]):
            row_y = pdf.get_y()
            if pdf.page_no() != last_page:
                last_page = pdf.page_no()
                row_y = _table_head(row_y)
            ts = (r.get("timestamp") or "")[5:16]
            nm = _clean_report_text(r.get("name", ""))[:20]
            pl = _clean_report_text(r.get("platform", ""))[:10]
            st = "OK" if r.get("success") else "FAIL"
            ac = _clean_report_text(r.get("action", ""))[:30]
            row_fill = WHITE if idx % 2 == 0 else (248, 250, 252)
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(*INK)
            pdf.set_fill_color(*row_fill)
            x = 12
            for ci, (w, v) in enumerate(zip(col_w, [str(idx + 1), ts, nm, pl, st, ac])):
                if ci == 4:
                    pdf.rect(x, row_y, w, 6.2, "F")
                    if st == "OK":
                        pill, tcol = (220, 252, 231), (22, 101, 52)
                    else:
                        pill, tcol = (254, 226, 226), (153, 27, 27)
                    pw = 11
                    px = x + (w - pw) / 2
                    pdf.set_fill_color(*pill)
                    pdf.rect(px, row_y + 1.1, pw, 4.2, "F", round_corners=True, corner_radius=2.1)
                    pdf.set_font("Helvetica", "B", 7.5)
                    pdf.set_text_color(*tcol)
                    pdf.set_xy(px, row_y + 1.5)
                    pdf.cell(pw, 3.4, st, align="C")
                    x += w
                    continue
                pdf.set_xy(x, row_y + 1.1)
                pdf.cell(w, 4.4, v, align="C" if w < 30 else "L", fill=True)
                x += w
            pdf.set_y(row_y + 6.2)
    else:
        pdf.set_fill_color(*TRACK)
        pdf.rect(12, y, 186, 18, "F", round_corners=True, corner_radius=3)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*MUTED)
        pdf.set_xy(12, y + 6)
        pdf.cell(186, 6, "No incidents recorded in this period.", align="C")

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def _ts_to_epoch(ts: str) -> float:
    try:
        t = ts.replace(" UTC", "").strip()
        return calendar.timegm(time.strptime(t, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, OSError):
        return 0


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            age = time.time() - _health_state.last_heartbeat
            if _health_state.is_healthy and age < 120:
                self._respond(200, {"status": "healthy", "last_heartbeat_age_sec": round(age, 1)})
            else:
                self._respond(503, {"status": "unhealthy", "last_heartbeat_age_sec": round(age, 1)})

        elif self.path == "/login" or self.path == "/":
            self._respond_html(200, _render_login_html())

        elif self.path == "/auth/google":
            if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
                self._respond(400, {"error": "Google SSO not configured"})
                return
            redirect_uri = GOOGLE_REDIRECT_URI or (
                "http://" + self.headers.get("Host", "localhost:" + str(HEALTH_PORT)) + "/auth/google/callback"
            )
            oauth_state = secrets.token_urlsafe(16)
            params = urllib.parse.urlencode({
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid email profile",
                "access_type": "online",
                "prompt": "select_account",
                "state": oauth_state,
            })
            self.send_response(302)
            self.send_header("Location", "https://accounts.google.com/o/oauth2/v2/auth?" + params)
            self.send_header("Set-Cookie", f"oauth_state={oauth_state}; Path=/; HttpOnly; SameSite=Lax")
            self.end_headers()

        elif self.path.startswith("/auth/google/callback"):
            if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
                self._respond_html(200, "<html><body><h2>Google SSO not configured</h2></body></html>")
                return
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            code = params.get("code", [None])[0]
            error = params.get("error", [None])[0]
            state = params.get("state", [None])[0]
            cookie_state = ""
            for part in self.headers.get("Cookie", "").split(";"):
                kv = part.strip().split("=", 1)
                if len(kv) == 2 and kv[0] == "oauth_state":
                    cookie_state = kv[1]
            if not state or not cookie_state or state != cookie_state:
                self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Sign-In Failed</h2><p style='color:#8b949e'>Invalid OAuth state. Please try again.</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                return
            if error or not code:
                self._respond_html(200, f"<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Google Sign-In Failed</h2><p style='color:#8b949e'>{error or 'No authorization code received'}</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                return
            try:
                redirect_uri = GOOGLE_REDIRECT_URI or (
                    "http://" + self.headers.get("Host", "localhost:" + str(HEALTH_PORT)) + "/auth/google/callback"
                )
                resp = requests.post("https://oauth2.googleapis.com/token", data={
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                }, timeout=10)
                token_data = resp.json()
                id_token = token_data.get("id_token")
                if not id_token:
                    self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Authentication Failed</h2><p style='color:#8b949e'>Could not verify identity</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                    return
                # ── Server-side verification of the id_token ──
                info_resp = requests.get(
                    "https://oauth2.googleapis.com/tokeninfo",
                    params={"id_token": id_token}, timeout=10,
                )
                info = info_resp.json()
                if info_resp.status_code != 200 or not info.get("email"):
                    self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Authentication Failed</h2><p style='color:#8b949e'>Could not verify identity</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                    return
                if info.get("aud") != GOOGLE_CLIENT_ID:
                    log.error("Google SSO: audience mismatch (aud=%s)", info.get("aud"))
                    self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Authentication Failed</h2><p style='color:#8b949e'>Token validation failed</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                    return
                if info.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
                    log.error("Google SSO: unexpected issuer (iss=%s)", info.get("iss"))
                    self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Authentication Failed</h2><p style='color:#8b949e'>Token validation failed</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                    return
                if str(info.get("email_verified", "")).lower() not in ("true", "1"):
                    log.error("Google SSO: unverified email (%s)", info.get("email"))
                    self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Authentication Failed</h2><p style='color:#8b949e'>Email is not verified</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                    return
                email = info.get("email", "")
                name = info.get("name", email.split("@")[0])
                picture = info.get("picture", "")
                email_domain = email.split("@")[-1] if "@" in email else ""
                allowed_domains = [d.strip() for d in GOOGLE_ALLOWED_DOMAINS.split(",") if d.strip()]
                if email_domain not in allowed_domains:
                    allowed_display = ", ".join(f"@{d}" for d in allowed_domains) or "configured domains"
                    self._respond_html(200, f"<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Access Denied</h2><p style='color:#8b949e'>Only {allowed_display} email addresses are allowed.</p><p style='color:#8b949e;font-size:13px'>Your email: {email}</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
                    return
                username = email.split("@")[0] + "@" + email_domain
                user = None
                if _storage:
                    user = _storage.get_user_by_email(email)
                    if not user:
                        rand_password = secrets.token_urlsafe(12)
                        user = _storage.create_user(
                            username=username, email=email, password=rand_password,
                            can_view_dashboard=True, can_view_pods=True,
                            can_view_containers=True, can_view_approvals=False,
                            can_approve=False, can_admin=False,
                        )
                    if user:
                        perms = {
                            "can_view_dashboard": user.get("can_view_dashboard", True),
                            "can_view_pods": user.get("can_view_pods", True),
                            "can_view_containers": user.get("can_view_containers", True),
                            "can_view_approvals": user.get("can_view_approvals", False),
                            "can_approve": user.get("can_approve", False),
                            "can_admin": user.get("can_admin", False),
                        }
                        _prune_sessions()
                        token = _generate_session_token(username, perms)
                        _sessions[token]["google_user"] = {
                            "email": email, "name": name, "picture": picture,
                        }
                        self.send_response(302)
                        self.send_header("Location", "/metrics")
                        self.send_header("Set-Cookie", f"oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
                        self.send_header("Set-Cookie", f"session_id={token}; Path=/; HttpOnly; SameSite=Lax")
                        self.end_headers()
                        return
                self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Account Setup Failed</h2><p style='color:#8b949e'>Could not create or find your account.</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")
            except Exception as e:
                log.error("Google SSO error: %s", e)
                self._respond_html(200, f"<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Authentication Error</h2><p style='color:#8b949e'>Something went wrong. Please try again.</p><a href='/login' style='color:#58a6ff'>Back to Login</a></div></body></html>")

        elif self.path == "/forgot":
            self._respond_html(200, _FORGOT_HTML)

        elif self.path.startswith("/reset/") and len(self.path) > len("/reset/"):
            token = self.path.split("/reset/")[1].split("/")[0]
            if _storage:
                user = _storage.verify_reset_token(token)
                if user:
                    html = _RESET_HTML_PREFIX.replace("__TOKEN__", token)
                    self._respond_html(200, html)
                else:
                    self._respond_html(200, "<html><body style='font-family:sans-serif;background:#0a0e17;color:#e6edf3;display:flex;justify-content:center;align-items:center;min-height:100vh'><div style='text-align:center'><h2>Invalid or Expired Link</h2><p style='color:#8b949e'>This password reset link is invalid or has expired.</p><a href='/forgot' style='color:#58a6ff'>Request a new one</a></div></body></html>")
            else:
                self._respond(404, {"error": "not found"})

        elif self.path == "/status" and METRICS_ENABLED:
            service_status.check_all()
            self._respond(200, service_status.to_dict())

        elif self.path == "/users/me":
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if session:
                self._respond(200, {
                    "username": session["username"],
                    "email": session.get("email"),
                    "role": session.get("role"),
                    "perms": session["perms"],
                    "google_user": session.get("google_user"),
                    "profile_pic": session.get("profile_pic"),
                })
            else:
                self._respond(401, {"error": "unauthorized"})

        elif self.path == "/users" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _check_perm(cookie, "can_admin"):
                self._respond(401, {"error": "unauthorized"})
                return
            if _storage:
                users = _storage.list_users()
                self._respond(200, {"users": users})
            else:
                self._respond(200, {"users": []})

        elif self.path == "/metrics" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session:
                self._respond_html(200, _render_login_html())
                return
            body = _DASHBOARD_HTML.replace("__CONFIG__", json.dumps(_dashboard_config)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/metrics/raw" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _validate_session(cookie):
                self._respond(401, {"error": "unauthorized"})
                return
            body = metrics.to_prometheus_text().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/metrics/api" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _validate_session(cookie):
                self._respond(401, {"error": "unauthorized"})
                return
            body = json.dumps(metrics.to_dict()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/diagnoses") and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _validate_session(cookie):
                self._respond(401, {"error": "unauthorized"})
                return
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            deleted_param = params.get("deleted", [None])[0]
            if deleted_param is not None:
                show_deleted = deleted_param.lower() == "true"
                if show_deleted:
                    filtered = [r for r in diagnosis_store.to_list() if r.get("deleted")]
                else:
                    filtered = [r for r in diagnosis_store.to_list() if not r.get("deleted")]
                body = json.dumps({"total": len(filtered), "records": filtered}).encode()
            else:
                body = json.dumps(diagnosis_store.to_dict()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/api/report") and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _validate_session(cookie):
                self._respond(401, {"error": "unauthorized"})
                return
            try:
                qs = urllib.parse.urlparse(self.path).query
                qp = urllib.parse.parse_qs(qs)
                days = int((qp.get("days") or ["7"])[0] or 7)
                days = min(max(days, 1), 30)
                pdf_bytes = generate_report(days)
                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Disposition", f'attachment; filename="healix-report-{days}d-{time.strftime("%Y%m%d")}.pdf"')
                self.send_header("Content-Length", str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
            except Exception as e:
                log.error("PDF report error: %s", e)
                self._respond(500, {"error": "Failed to generate report"})

        elif self.path == "/approvals" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session:
                self._respond(401, {"error": "unauthorized"})
                return
            if not session["perms"].get("can_view_approvals", False):
                self._respond(401, {"error": "forbidden"})
                return
            if _approval_store:
                body = json.dumps(_approval_store.to_dict()).encode()
            else:
                body = json.dumps({"requests": [], "pending_count": 0}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/circuit/breaker") and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _validate_session(cookie):
                self._respond(401, {"error": "unauthorized"})
                return
            if not _circuit_breaker:
                self._respond(200, {"enabled": False, "circuits": []})
                return
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            target_id = params.get("target_id", [None])[0]
            if target_id:
                state = _circuit_breaker.get_state(target_id)
                self._respond(200, {"enabled": True, "circuits": [state]})
            else:
                self._respond(200, {
                    "enabled": True,
                    "threshold": _circuit_breaker.threshold,
                    "window_min": _circuit_breaker.window_min,
                    "cooldown_min": _circuit_breaker.cooldown_min,
                    "note": "Pass ?target_id=... for specific state",
                })

        elif self.path.startswith("/approve/") and len(self.path) > len("/approve/"):
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session or not session["perms"].get("can_approve", False):
                self._respond(401, {"error": "unauthorized"})
                return
            approval_id = self.path.split("/approve/")[1].split("/")[0]
            self._handle_approval_link(approval_id, "approve")

        elif self.path.startswith("/reject/") and len(self.path) > len("/reject/"):
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session or not session["perms"].get("can_approve", False):
                self._respond(401, {"error": "unauthorized"})
                return
            approval_id = self.path.split("/reject/")[1].split("/")[0]
            self._handle_approval_link(approval_id, "reject")

        else:
            self._respond(404, {"error": "not found"})

    def _read_body(self) -> dict:
        try:
            cl = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(cl).decode("utf-8", errors="replace")
            ct = self.headers.get("Content-Type", "")
            if "application/json" in ct:
                return json.loads(raw)
            else:
                params = urllib.parse.parse_qs(raw)
                return {k: v[0] for k, v in params.items()}
        except Exception:
            return {}

    def do_POST(self) -> None:
        if self.path == "/login":
            data = self._read_body()
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()

            if not _storage:
                self._respond(500, {"error": "Database not available"})
                return

            user = _storage.verify_password(username, password)
            if user:
                _prune_sessions()
                perms = {
                    "can_view_dashboard": user.get("can_view_dashboard", True),
                    "can_view_pods": user.get("can_view_pods", False),
                    "can_view_containers": user.get("can_view_containers", False),
                    "can_view_approvals": user.get("can_view_approvals", False),
                    "can_approve": user.get("can_approve", False),
                    "can_admin": user.get("can_admin", False),
                }
                token = _generate_session_token(username, perms)
                _sessions[token]["email"] = user.get("email")
                _sessions[token]["profile_pic"] = user.get("profile_pic")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session_id={token}; Path=/; HttpOnly; SameSite=Strict")
                body = json.dumps({"ok": True}).encode()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._respond(401, {"error": "Invalid username or password"})

        elif self.path == "/logout":
            cookie = self.headers.get("Cookie", "")
            if cookie:
                for part in cookie.split(";"):
                    kv = part.strip().split("=", 1)
                    if len(kv) == 2 and kv[0] == "session_id":
                        _sessions.pop(kv[1], None)
            self.send_response(200)
            self.send_header("Set-Cookie", "session_id=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
            body = json.dumps({"ok": True}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/change-password":
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session:
                self._respond(401, {"error": "Not authenticated"})
                return
            data = self._read_body()
            old_pw = data.get("old_password", "").strip()
            new_pw = data.get("new_password", "").strip()
            if not old_pw or not new_pw:
                self._respond(400, {"error": "All fields are required"})
                return
            if len(new_pw) < 6:
                self._respond(400, {"error": "Password must be at least 6 characters"})
                return
            if not _storage:
                self._respond(500, {"error": "Database not available"})
                return
            user = _storage.verify_password(session["username"], old_pw)
            if not user:
                self._respond(401, {"error": "Old password is incorrect"})
                return
            _storage.update_password(user["id"], new_pw)
            self._respond(200, {"ok": True})

        elif self.path == "/users/profile":
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session:
                self._respond(401, {"error": "unauthorized"})
                return
            if not _storage:
                self._respond(500, {"error": "Database not available"})
                return
            data = self._read_body()
            username = (data.get("username") or "").strip() or None
            profile_pic = data.get("profile_pic")
            if isinstance(profile_pic, str) and not profile_pic:
                profile_pic = ""
            if username is not None and (len(username) < 3 or len(username) > 32):
                self._respond(400, {"error": "Username must be 3-32 characters"})
                return
            if username is not None and not _USERNAME_RE.match(username):
                self._respond(400, {"error": "Username may only contain letters, numbers, and . _ @ -"})
                return
            if profile_pic is not None and len(profile_pic) > 500000:
                self._respond(400, {"error": "Profile image too large"})
                return
            if profile_pic and not _IMAGE_DATAURL_RE.match(profile_pic):
                self._respond(400, {"error": "Profile image must be a PNG, JPEG, GIF or WebP data URL"})
                return
            user = _storage.get_user_by_username(session["username"])
            if not user:
                self._respond(401, {"error": "unauthorized"})
                return
            ok = _storage.update_user_profile(user["id"], username=username, profile_pic=profile_pic)
            if not ok:
                self._respond(400, {"error": "Username already taken"})
                return
            _update_session_user(cookie, session, username=username, profile_pic=profile_pic)
            self._respond(200, {"ok": True})

        elif self.path == "/forgot":
            data = self._read_body()
            email = data.get("email", "").strip()
            if not email or not _storage:
                self._respond(200, {"ok": True})  # Don't reveal if email exists
                return
            token = _storage.set_reset_token(email)
            if token:
                host = self.headers.get("Host", f"localhost:{HEALTH_PORT}")
                reset_link = f"http://{host}/reset/{token}"
                send_password_reset_email(email, reset_link)
            self._respond(200, {"ok": True})

        elif self.path.startswith("/reset/") and len(self.path) > len("/reset/"):
            token = self.path.split("/reset/")[1].split("/")[0]
            data = self._read_body()
            password = data.get("password", "").strip()
            if not password or len(password) < 6:
                self._respond(400, {"error": "Password must be at least 6 characters"})
                return
            if not _storage:
                self._respond(500, {"error": "Database not available"})
                return
            user = _storage.verify_reset_token(token)
            if user:
                _storage.update_password(user["id"], password)
                _storage.clear_reset_token(user["id"])
                self._respond(200, {"ok": True})
            else:
                self._respond(400, {"error": "Invalid or expired reset token"})

        elif self.path == "/users/create" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _check_perm(cookie, "can_admin"):
                self._respond(401, {"error": "unauthorized"})
                return
            data = self._read_body()
            username = data.get("username", "").strip()
            email = data.get("email", "").strip()
            perms = data.get("permissions", {})
            if not _storage:
                self._respond(500, {"error": "Database not available"})
                return
            if not username or not email:
                self._respond(400, {"error": "Username and email required"})
                return
            rand_password = secrets.token_urlsafe(12)
            user = _storage.create_user(
                username=username, email=email, password=rand_password,
                can_view_dashboard=perms.get("can_view_dashboard", True),
                can_view_pods=perms.get("can_view_pods", False),
                can_view_containers=perms.get("can_view_containers", False),
                can_view_approvals=perms.get("can_view_approvals", False),
                can_approve=perms.get("can_approve", False),
                can_admin=perms.get("can_admin", False),
            )
            if user:
                send_welcome_email(email, username, rand_password)
                self._respond(200, {"ok": True})
            else:
                self._respond(400, {"error": "Username or email already exists"})

        elif self.path == "/users/delete" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session or not session["perms"].get("can_admin", False):
                self._respond(401, {"error": "unauthorized"})
                return
            data = self._read_body()
            user_id = data.get("user_id")
            if not user_id or not _storage:
                self._respond(400, {"error": "Invalid request"})
                return
            _storage.delete_user(int(user_id))
            self._respond(200, {"ok": True})

        elif self.path == "/users/update" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _check_perm(cookie, "can_admin"):
                self._respond(401, {"error": "unauthorized"})
                return
            data = self._read_body()
            user_id = data.get("user_id")
            permissions = data.get("permissions", {})
            if not user_id or not permissions or not _storage:
                self._respond(400, {"error": "Invalid request"})
                return
            if not _storage.update_user_permissions(int(user_id), **permissions):
                self._respond(400, {"error": "User not found"})
                return
            _refresh_user_sessions(int(user_id))
            self._respond(200, {"ok": True})

        elif self.path.startswith("/approve/") and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session or not session["perms"].get("can_approve", False):
                self._respond(401, {"error": "unauthorized"})
                return
            approval_id = self.path.split("/approve/")[1].strip("/").split("?")[0].split("#")[0]
            log.info("[APPROVE] Dashboard approve requested for id=%s", approval_id)
            if _approval_store and _approval_store.approve(approval_id, by="dashboard"):
                log.info("[APPROVE] Successfully approved id=%s", approval_id)
                self._respond(200, {"ok": True, "id": approval_id, "status": "approved"})
            else:
                log.info("[APPROVE] Failed to approve id=%s (not found or already processed)", approval_id)
                self._respond(400, {"ok": False, "error": "Approval not found or already processed"})

        elif self.path.startswith("/reject/") and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            session = _validate_session(cookie)
            if not session or not session["perms"].get("can_approve", False):
                self._respond(401, {"error": "unauthorized"})
                return
            approval_id = self.path.split("/reject/")[1].strip("/").split("?")[0].split("#")[0]
            log.info("[REJECT] Dashboard reject requested for id=%s", approval_id)
            if _approval_store and _approval_store.reject(approval_id, by="dashboard"):
                log.info("[REJECT] Successfully rejected id=%s", approval_id)
                self._respond(200, {"ok": True, "id": approval_id, "status": "rejected"})
            else:
                log.info("[REJECT] Failed to reject id=%s (not found or already processed)", approval_id)
                self._respond(400, {"ok": False, "error": "Approval not found or already processed"})

        elif self.path == "/chat" and METRICS_ENABLED:
            _handle_chat(self)
        else:
            self._respond(404, {"error": "not found"})

    def _handle_approval_link(self, approval_id: str, action: str) -> None:
        if not _approval_store:
            self._respond_html(200, "<html><body><h2>Approval system not configured</h2></body></html>")
            return
        req = _approval_store.get(approval_id)
        if not req:
            self._respond_html(200, "<html><body><h2>Approval not found</h2><p>ID: " + approval_id + "</p></body></html>")
            return
        if action == "approve":
            ok = _approval_store.approve(approval_id, by="email-link")
            label = "Approved" if ok else "Already processed"
            color = "#27ae60" if ok else "#888"
        else:
            ok = _approval_store.reject(approval_id, by="email-link")
            label = "Rejected" if ok else "Already processed"
            color = "#c0392b" if ok else "#888"
        html = f"""<!DOCTYPE html><html><head><style>
body {{ font-family: -apple-system, Arial, sans-serif; background: #f4f6f9; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
.card {{ background: #fff; border-radius: 12px; padding: 40px; max-width: 480px; text-align: center; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
h2 {{ color: {color}; margin-bottom: 8px; }}
p {{ color: #666; font-size: 14px; }}
.badge {{ display: inline-block; background: {color}20; color: {color}; padding: 4px 16px; border-radius: 20px; font-weight: 600; font-size: 14px; margin: 12px 0; }}
.meta {{ font-size: 12px; color: #999; margin-top: 16px; }}
</style></head><body><div class="card">
<h2>{label}</h2>
<div class="badge">{action.upper()}</div>
<p>{req.target.get('name', 'Unknown')} &mdash; {req.location}</p>
<p>Action: <strong>{req.action}</strong></p>
<div class="meta">Approval ID: {approval_id}<br>Healix</div>
</div></body></html>"""
        self._respond_html(200, html)

    def _respond(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_html(self, code: int, html: str) -> None:
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def start_health_server() -> threading.Thread | None:
    if not METRICS_ENABLED:
        log.info("Metrics disabled (METRICS_ENABLED=false) — health server not started")
        return None

    def _serve() -> None:
        try:
            server = ThreadingHTTPServer(("0.0.0.0", HEALTH_PORT), _HealthHandler)
            server.daemon_threads = True
            log.info("Health server listening on :%d (/health, /metrics, /metrics/raw, /metrics/api, /diagnoses)", HEALTH_PORT)
            server.serve_forever()
        except Exception as e:
            log.error("Health server failed: %s", e)

    t = threading.Thread(target=_serve, daemon=True, name="health-server")
    t.start()
    return t
