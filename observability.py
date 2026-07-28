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

import time
import uuid
import json
import logging
import secrets
import smtplib
import threading
import urllib.parse
from dataclasses import dataclass, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
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
)

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
}


# ══════════════════════════════════════════════════════════════════════════════
#  SESSION MANAGEMENT — Dashboard Login
# ══════════════════════════════════════════════════════════════════════════════

_SESSION_EXPIRY_SEC = 8 * 3600  # 8 hours
_sessions: dict[str, float] = {}  # token -> expiry timestamp


def _generate_session_token() -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + _SESSION_EXPIRY_SEC
    return token


def _validate_session(cookie_header: str) -> bool:
    if not cookie_header:
        return False
    now = time.time()
    for part in cookie_header.split(";"):
        kv = part.strip().split("=", 1)
        if len(kv) == 2 and kv[0] == "session_id":
            token = kv[1]
            expiry = _sessions.get(token)
            if expiry and expiry > now:
                return True
            elif expiry:
                del _sessions[token]
            return False
    return False


def _prune_sessions() -> None:
    now = time.time()
    expired = [t for t, exp in _sessions.items() if exp <= now]
    for t in expired:
        del _sessions[t]


# ══════════════════════════════════════════════════════════════════════════════
#  LOGIN PAGE HTML
# ══════════════════════════════════════════════════════════════════════════════

_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Healing Agent — Login</title>
<style>
  :root {
    --bg: #0a0e17; --surface: rgba(22,27,34,0.75); --border: rgba(48,54,61,0.6);
    --text: #e6edf3; --text2: #8b949e; --blue: #58a6ff; --red: #f85149;
    --green: #3fb950;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text); min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    background-image: radial-gradient(ellipse at 20% 50%, rgba(88,166,255,0.04) 0%, transparent 50%),
                      radial-gradient(ellipse at 80% 20%, rgba(188,140,255,0.03) 0%, transparent 50%);
  }
  @keyframes fadeInUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
  .login-card {
    width: 100%; max-width: 380px; padding: 40px 36px;
    background: rgba(22,27,34,0.6); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(48,54,61,0.4); border-radius: 16px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    animation: fadeInUp 0.5s ease;
  }
  .login-brand { text-align: center; margin-bottom: 32px; }
  .login-brand svg { width: 48px; height: 48px; margin-bottom: 12px; }
  .login-brand h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.3px; margin-bottom: 4px; }
  .login-brand p { font-size: 13px; color: var(--text2); }
  .login-field { margin-bottom: 16px; }
  .login-field label { display: block; font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
  .login-field input {
    width: 100%; padding: 10px 14px; font-size: 14px; color: var(--text);
    background: rgba(13,17,23,0.8); border: 1px solid rgba(48,54,61,0.6);
    border-radius: 8px; outline: none; transition: border-color 0.2s;
  }
  .login-field input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(88,166,255,0.1); }
  .login-btn {
    width: 100%; padding: 11px 0; margin-top: 8px; font-size: 14px; font-weight: 600;
    color: #fff; background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
    border: none; border-radius: 8px; cursor: pointer; transition: all 0.2s;
  }
  .login-btn:hover { background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%); box-shadow: 0 4px 16px rgba(46,160,67,0.3); }
  .login-btn:active { transform: scale(0.98); }
  .login-error {
    margin-top: 12px; padding: 10px 14px; font-size: 13px; color: var(--red);
    background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.2);
    border-radius: 8px; text-align: center; display: none;
  }
</style>
</head>
<body>
<div class="login-card">
  <div class="login-brand">
    <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="24" cy="24" r="22" stroke="rgba(88,166,255,0.3)" stroke-width="2"/>
      <path d="M16 24l6 6 10-12" stroke="#3fb950" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <h1>AI Healing Agent</h1>
    <p>Dashboard Login</p>
  </div>
  <form id="loginForm" onsubmit="return doLogin(event)">
    <div class="login-field">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" autocomplete="username" required autofocus>
    </div>
    <div class="login-field">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autocomplete="current-password" required>
    </div>
    <div class="login-error" id="loginError"></div>
    <button type="submit" class="login-btn">Sign In</button>
  </form>
</div>
<script>
function doLogin(e) {
  e.preventDefault();
  var errEl = document.getElementById('loginError');
  errEl.style.display = 'none';
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
      window.location.href = '/metrics';
    } else {
      return r.json();
    }
  }).then(function(j) {
    if (j && j.error) {
      errEl.textContent = j.error;
      errEl.style.display = 'block';
    }
  }).catch(function() {
    errEl.textContent = 'Connection failed';
    errEl.style.display = 'block';
  });
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
<title>AI Healing Agent — Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
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
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; overflow-x: hidden; background-image: radial-gradient(ellipse at 20% 50%, rgba(88,166,255,0.04) 0%, transparent 50%), radial-gradient(ellipse at 80% 20%, rgba(188,140,255,0.03) 0%, transparent 50%); }
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

  /* ── Fixed Header ──────────────────────────────── */
  .hdr { position: fixed; top: 0; left: 0; right: 0; z-index: 200; background: var(--header-bg); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border-bottom: 1px solid var(--glass-border); height: 60px; display: flex; align-items: center; padding: 0 28px; gap: 20px; }
  .hdr-brand { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
  .hdr-brand svg { width: 28px; height: 28px; }
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
  .theme-toggle { background: none; border: 1px solid var(--glass-border); color: var(--text2); width: 32px; height: 32px; border-radius: 8px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s; flex-shrink: 0; }
  .theme-toggle:hover { border-color: var(--blue); color: var(--blue); background: var(--hover-tint); }
  .theme-toggle svg { width: 16px; height: 16px; }
  .light .theme-icon-dark { display: none; }
  .light .theme-icon-light { display: block; }
  :root:not(.light) .theme-icon-dark { display: block; }
  :root:not(.light) .theme-icon-light { display: none; }

  /* ── Metrics Tab ────────────────────────────────── */
  .metrics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 20px; }
  .metrics-kpi { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
  .metrics-kpi-card { background: var(--glass-bg); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 18px; text-align: center; }
  .metrics-kpi-card .kpi-val { font-size: 28px; font-weight: 700; color: var(--text); line-height: 1.2; }
  .metrics-kpi-card .kpi-label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; margin-top: 6px; font-weight: 500; }
  .metrics-kpi-card.green .kpi-val { color: var(--green); }
  .metrics-kpi-card.red .kpi-val { color: var(--red); }
  .metrics-kpi-card.blue .kpi-val { color: var(--blue); }
  .metrics-kpi-card.purple .kpi-val { color: var(--purple); }
  .metrics-chart-card { background: var(--glass-bg); backdrop-filter: blur(12px); border: 1px solid var(--glass-border); border-radius: 14px; padding: 20px; opacity: 0; animation: fadeInUp 0.5s ease forwards; }
  .metrics-chart-card h3 { font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
  .metrics-chart-card h3::before { content: ''; width: 3px; height: 14px; background: var(--blue); border-radius: 2px; }
  .metrics-chart-card canvas { width: 100% !important; max-height: 260px; }
  .metrics-chart-card.full-width { grid-column: 1 / -1; }
  .metrics-empty { color: var(--text2); font-size: 13px; font-style: italic; padding: 40px; text-align: center; grid-column: 1 / -1; }
  .metrics-toolbar { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
  .metrics-toolbar-label { font-size: 11px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; }
  .metrics-range-btns { display: flex; gap: 2px; background: var(--surface2); border-radius: 8px; padding: 3px; }
  .range-btn { background: none; border: none; color: var(--text2); font-size: 12px; font-weight: 500; padding: 5px 12px; border-radius: 6px; cursor: pointer; transition: all 0.2s; font-family: var(--font-mono); }
  .range-btn:hover { color: var(--text); background: var(--hover-tint); }
  .range-btn.active { color: var(--blue); background: rgba(88,166,255,0.12); font-weight: 600; }
  @media (max-width: 900px) { .metrics-grid { grid-template-columns: 1fr; } .metrics-kpi { grid-template-columns: repeat(2, 1fr); } }

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
</style>
</head>
<body>

<div id="toasts"></div>
<div id="card-tooltip" class="card-tooltip"></div>

<header class="hdr">
  <div class="hdr-brand">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--blue)"><path d="M12 2a3 3 0 0 0-3 3v1a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/><circle cx="12" cy="12" r="3"/></svg>
    <h1>AI Healer <span>v9</span></h1>
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
    <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
      <svg class="theme-icon-dark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      <svg class="theme-icon-light" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
    </button>
    <nav class="hdr-tabs">
      <button class="tab-btn active" data-tab="overview">Overview</button>
      <button class="tab-btn" data-tab="pods">Pods <span class="tab-badge" id="pod-count" style="display:none">0</span></button>
      <button class="tab-btn" data-tab="containers">Containers <span class="tab-badge" id="container-count" style="display:none">0</span></button>
      <button class="tab-btn" data-tab="timeline">Timeline</button>
      <button class="tab-btn" data-tab="llm">LLM</button>
<button class="tab-btn" data-tab="metrics">Metrics</button>
<button class="tab-btn" data-tab="approvals">Approvals <span class="tab-badge" id="approval-count" style="display:none">0</span></button>
    </nav>
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
      <div class="metrics-kpi">
        <div class="metrics-kpi-card green"><div class="kpi-val" id="kpi-total-heals">0</div><div class="kpi-label">Total Heals</div></div>
        <div class="metrics-kpi-card blue"><div class="kpi-val" id="kpi-llm-calls">0</div><div class="kpi-label">LLM Calls</div></div>
        <div class="metrics-kpi-card red"><div class="kpi-val" id="kpi-errors">0</div><div class="kpi-label">Errors</div></div>
        <div class="metrics-kpi-card purple"><div class="kpi-val" id="kpi-uptime">0m</div><div class="kpi-label">Uptime</div></div>
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
      </div>
      <div class="metrics-grid">
        <div class="metrics-chart-card full-width"><h3>Heals Over Time</h3><canvas id="chart-heals-time"></canvas></div>
        <div class="metrics-chart-card full-width"><h3>LLM Latency Trend</h3><canvas id="chart-llm-latency"></canvas></div>
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
var VALID_TABS = ['overview','pods','containers','timeline','llm','metrics','approvals'];

var _k8sRecs = [], _dockerRecs = [], _selectedTab = 'overview';
var _prevStats = {heals:0,calls:0,rollbacks:0,pdb:0,errors:0};
var _prevDiagCount = 0, _latencyHistory = {}, _allRecs = [], _spRecId = null;
var _timelineFilter = 'all';
var _diagFilter = {pods:'active', containers:'active'};
var _approvalFilter = 'active';
var _statusRendered = false;
var _knownDiagIds = {};
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
function toggleTheme() {
  document.documentElement.classList.toggle('light');
  localStorage.setItem('dashboard_theme', document.documentElement.classList.contains('light') ? 'light' : 'dark');
  if (_selectedTab === 'metrics' && _lastMetricsData) { destroyAllMetricCharts(); buildAllMetricCharts(_lastMetricsData, _lastDiagsData); }
}
if (localStorage.getItem('dashboard_theme') === 'light') document.documentElement.classList.add('light');
if (typeof Chart !== 'undefined') { var _tc = getChartColors(); Chart.defaults.color = _tc.text; Chart.defaults.borderColor = _tc.border; }
setInterval(updateClock, 1000);
updateClock();

function pollStatus() {
  fetch('/status').then(function(r){return r.json();}).then(function(d){renderSystemStatus(d);}).catch(function(){});
}
pollStatus();
setInterval(pollStatus, 30000);

function switchTab(name) {
  var prev = _selectedTab;
  _selectedTab = name;
  document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.toggle('active',b.dataset.tab===name);});
  document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.toggle('active',p.id==='panel-'+name);});
  history.replaceState(null,'','#'+name);
  if (prev === 'metrics' && name !== 'metrics') destroyAllMetricCharts();
  if (name === 'metrics' && _lastMetricsData) { setTimeout(function(){buildAllMetricCharts(_lastMetricsData, _lastDiagsData);}, 50); }
}
document.querySelectorAll('.tab-btn').forEach(function(b){b.addEventListener('click',function(){switchTab(b.dataset.tab);});});
(function(){var h=location.hash.replace('#','');if(VALID_TABS.includes(h))switchTab(h);})();
document.querySelectorAll('.range-btn').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('.range-btn').forEach(function(x){x.classList.remove('active');});b.classList.add('active');_metricsTimeRange=b.dataset.range;if(_lastMetricsData)buildAllMetricCharts(_lastMetricsData,_lastDiagsData);});});

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
  var visibleK8s = _k8sRecs.filter(function(r){return _diagFilter.pods==='active'?!r.deleted:r.deleted;});
  if(visibleK8s.length>0){podBadge.textContent=visibleK8s.length;podBadge.style.display='';}else{podBadge.style.display='none';}
  var podItems=[];
  if(visibleK8s.length===0)podItems.push({id:'empty-k8s-'+_diagFilter.pods,html:'<div class="diag-empty" data-id="empty-k8s-'+_diagFilter.pods+'">No '+( _diagFilter.pods==='active' ? 'failing K8s pods' : 'removed K8s pods' )+' recorded yet</div>'});
  else visibleK8s.forEach(function(r){podItems.push({id:r.id,html:buildCardHtml(r)});});
  smartUpdate(podsEl, podItems);

  var ctrEl=document.getElementById('diag-list-containers'),ctrBadge=document.getElementById('container-count');
  var visibleDocker = _dockerRecs.filter(function(r){return _diagFilter.containers==='active'?!r.deleted:r.deleted;});
  if(visibleDocker.length>0){ctrBadge.textContent=visibleDocker.length;ctrBadge.style.display='';}else{ctrBadge.style.display='none';}
  var ctrItems=[];
  if(visibleDocker.length===0)ctrItems.push({id:'empty-docker-'+_diagFilter.containers,html:'<div class="diag-empty" data-id="empty-docker-'+_diagFilter.containers+'">No '+( _diagFilter.containers==='active' ? 'failing Docker containers' : 'removed Docker containers' )+' recorded yet</div>'});
  else visibleDocker.forEach(function(r){ctrItems.push({id:r.id,html:buildCardHtml(r)});});
  smartUpdate(ctrEl, ctrItems);

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
  _metricsCharts.healsTime = new Chart(ctx, {
    type:'line',
    data:{labels:labels, datasets:[{label:'Heals/min',data:data,borderColor:c.green,backgroundColor:c.green+'18',fill:true,tension:0.4,pointRadius:0,pointHoverRadius:4,borderWidth:2}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return ctx.parsed.y.toFixed(1)+' heals/min';}}}},scales:{x:{ticks:{color:c.text,maxTicksLimit:12,font:{size:10},maxRotation:0},grid:{color:c.grid}},y:{beginAtZero:true,ticks:{color:c.text,font:{size:10}},grid:{color:c.grid}}}}
  });
}

function buildChartLLMLatency() {
  var names = Object.keys(_llmLatencyHist);
  if (names.length === 0) return;
  destroyMetricChart('llmLatency');
  var c = getChartColors();
  var palette = [c.green, c.blue, c.purple, c.cyan, c.orange, c.yellow];
  var filtered = names.map(function(name){return filterByTimeRange(_llmLatencyHist[name]);});
  var maxLen = Math.max.apply(null, filtered.map(function(f){return f.length;}));
  if (maxLen === 0) return;
  var labels = [];
  for (var i = 0; i < maxLen; i++) labels.push('');
  var datasets = names.map(function(name, i) {
    var f = filterByTimeRange(_llmLatencyHist[name]);
    return {label:name, data:f.map(function(h){return h.val;}), borderColor:palette[i%palette.length], backgroundColor:'transparent', tension:0.3, pointRadius:0, pointHoverRadius:3, borderWidth:2};
  });
  var ctx = document.getElementById('chart-llm-latency');
  _metricsCharts.llmLatency = new Chart(ctx, {
    type:'line',
    data:{labels:labels, datasets:datasets},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:c.text,font:{size:11},usePointStyle:true,pointStyle:'circle'}}},scales:{x:{ticks:{display:false},grid:{color:c.grid}},y:{beginAtZero:true,ticks:{color:c.text,callback:function(v){return v+'s'},font:{size:10}},grid:{color:c.grid}}}}
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
  var ctx = document.getElementById('chart-heal-actions');
  _metricsCharts.healActions = new Chart(ctx, {
    type:'bar',
    data:{labels:keys.map(function(k){return k.replace(/_/g,' ');}), datasets:[{data:keys.map(function(k){return actions[k];}), backgroundColor:palette.slice(0,keys.length), borderRadius:6, barThickness:28}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{color:c.text,stepSize:1,font:{size:10}},grid:{color:c.grid}},y:{ticks:{color:c.text,font:{size:11}},grid:{display:false}}}}
  });
}

function buildChartRouteOutcomes(d) {
  var routes = d.heal_by_route || {};
  var keys = Object.keys(routes);
  if (keys.length === 0) return;
  destroyMetricChart('routeOutcomes');
  var c = getChartColors();
  var colorMap = {auto_healed:c.green, dev_issue:c.red, needs_escalation:c.yellow, rollback:c.orange, needs_approval:c.orange, rejected:c.red};
  var ctx = document.getElementById('chart-route-outcomes');
  _metricsCharts.routeOutcomes = new Chart(ctx, {
    type:'doughnut',
    data:{labels:keys.map(function(k){return k.replace(/_/g,' ');}), datasets:[{data:keys.map(function(k){return routes[k];}), backgroundColor:keys.map(function(k){return colorMap[k]||c.blue}), borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{position:'bottom',labels:{color:c.text,font:{size:11},padding:12,usePointStyle:true,pointStyle:'circle'}}}}
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
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:c.text,font:{size:10}},grid:{display:false}},y:{beginAtZero:true,ticks:{color:c.text,stepSize:1,font:{size:10}},grid:{color:c.grid}}}}
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
  var ctx = document.getElementById('chart-status');
  _metricsCharts.status = new Chart(ctx, {
    type:'doughnut',
    data:{labels:keys, datasets:[{data:keys.map(function(k){return st[k];}), backgroundColor:palette.slice(0,keys.length), borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{position:'bottom',labels:{color:c.text,font:{size:11},padding:12,usePointStyle:true,pointStyle:'circle'}}}}
  });
}

function buildAllMetricCharts(d, recs) {
  if (_selectedTab !== 'metrics') return;
  buildMetricsKPIs(d);
  buildChartHealsOverTime();
  buildChartLLMLatency();
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
  fetch('/approvals').then(function(r){return r.json();}).then(function(d){
    var s = JSON.stringify(d);
    if (s !== JSON.stringify(_lastApprovalsData)) {
      _lastApprovalsData = d;
      renderApprovals(d);
    }
  }).catch(function(){});
}

function poll() {
  fetch('/metrics/api').then(function(r){return r.json();}).then(function(d){_lastMetricsData=d; snapshotMetrics(d); update(d); buildAllMetricCharts(d,_lastDiagsData);}).catch(function(){});
  fetch('/diagnoses').then(function(r){return r.json();}).then(function(d){_lastDiagsData=d.records||[]; renderDiagnoses(_lastDiagsData); if(_lastMetricsData) buildAllMetricCharts(_lastMetricsData,_lastDiagsData);}).catch(function(){});
  fetchApprovals();
}
poll();
setInterval(poll,5000);
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


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            age = time.time() - _health_state.last_heartbeat
            if _health_state.is_healthy and age < 120:
                self._respond(200, {"status": "healthy", "last_heartbeat_age_sec": round(age, 1)})
            else:
                self._respond(503, {"status": "unhealthy", "last_heartbeat_age_sec": round(age, 1)})

        elif self.path == "/status" and METRICS_ENABLED:
            service_status.check_all()
            self._respond(200, service_status.to_dict())

        elif self.path == "/metrics" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _validate_session(cookie):
                self._respond_html(200, _LOGIN_HTML)
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

        elif self.path == "/approvals" and METRICS_ENABLED:
            cookie = self.headers.get("Cookie", "")
            if not _validate_session(cookie):
                self._respond(401, {"error": "unauthorized"})
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
            approval_id = self.path.split("/approve/")[1].split("/")[0]
            self._handle_approval_link(approval_id, "approve")

        elif self.path.startswith("/reject/") and len(self.path) > len("/reject/"):
            approval_id = self.path.split("/reject/")[1].split("/")[0]
            self._handle_approval_link(approval_id, "reject")

        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/login":
            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(raw)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            if username == DASHBOARD_USER and password == DASHBOARD_PASSWORD:
                _prune_sessions()
                token = _generate_session_token()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session_id={token}; Path=/; HttpOnly; SameSite=Strict")
                body = json.dumps({"ok": True}).encode()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._respond(401, {"error": "Invalid username or password"})

        elif self.path.startswith("/approve/") and METRICS_ENABLED:
            approval_id = self.path.split("/approve/")[1].strip("/").split("?")[0].split("#")[0]
            log.info("[APPROVE] Dashboard approve requested for id=%s", approval_id)
            if _approval_store and _approval_store.approve(approval_id, by="dashboard"):
                log.info("[APPROVE] Successfully approved id=%s", approval_id)
                self._respond(200, {"ok": True, "id": approval_id, "status": "approved"})
            else:
                log.info("[APPROVE] Failed to approve id=%s (not found or already processed)", approval_id)
                self._respond(400, {"ok": False, "error": "Approval not found or already processed"})

        elif self.path.startswith("/reject/") and METRICS_ENABLED:
            approval_id = self.path.split("/reject/")[1].strip("/").split("?")[0].split("#")[0]
            log.info("[REJECT] Dashboard reject requested for id=%s", approval_id)
            if _approval_store and _approval_store.reject(approval_id, by="dashboard"):
                log.info("[REJECT] Successfully rejected id=%s", approval_id)
                self._respond(200, {"ok": True, "id": approval_id, "status": "rejected"})
            else:
                log.info("[REJECT] Failed to reject id=%s (not found or already processed)", approval_id)
                self._respond(400, {"ok": False, "error": "Approval not found or already processed"})

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
<div class="meta">Approval ID: {approval_id}<br>AI Healing Agent v9</div>
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
            server = HTTPServer(("0.0.0.0", HEALTH_PORT), _HealthHandler)
            log.info("Health server listening on :%d (/health, /metrics, /metrics/raw, /metrics/api, /diagnoses)", HEALTH_PORT)
            server.serve_forever()
        except Exception as e:
            log.error("Health server failed: %s", e)

    t = threading.Thread(target=_serve, daemon=True, name="health-server")
    t.start()
    return t
