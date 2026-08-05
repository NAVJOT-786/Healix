#!/usr/bin/env python3
"""
Configuration — all environment variables loaded and validated in one place.
"""

import os
import socket
from dotenv import load_dotenv

load_dotenv()

# ── Core ──────────────────────────────────────────────────────────────────────

GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
POLL_INTERVAL_SEC = int(os.getenv("POLL_INTERVAL_SEC", "30"))
MAX_RESTARTS      = int(os.getenv("MAX_RESTARTS", "3"))
DRY_RUN           = os.getenv("DRY_RUN", "false").lower() == "true"
LOG_TAIL_LINES    = int(os.getenv("LOG_TAIL_LINES", "50"))
REPORT_ONLY       = os.getenv("REPORT_ONLY", "true").lower() == "true"

# ── Namespaces ────────────────────────────────────────────────────────────────

_WATCH_RAW = os.getenv("WATCH_NAMESPACES", "default,demo").strip()
WATCH_ALL_NAMESPACES = _WATCH_RAW == "*"
WATCH_NAMESPACES: list[str] = [] if WATCH_ALL_NAMESPACES else _WATCH_RAW.split(",")

# ── Platforms ─────────────────────────────────────────────────────────────────

ENABLE_K8S    = os.getenv("ENABLE_K8S", "true").lower() == "true"
ENABLE_DOCKER = os.getenv("ENABLE_DOCKER", "false").lower() == "true"
DOCKER_HOST_LABEL = os.getenv("DOCKER_HOST_LABEL", "").strip() or socket.gethostname()

# ── Ollama ────────────────────────────────────────────────────────────────────

OLLAMA_ENABLED             = os.getenv("OLLAMA_ENABLED", "false").lower() == "true"
OLLAMA_URL                 = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL               = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_TIMEOUT_SEC         = int(os.getenv("OLLAMA_TIMEOUT_SEC", "60"))
OLLAMA_KEEP_ALIVE          = os.getenv("OLLAMA_KEEP_ALIVE", "-1")
OLLAMA_WARMUP_TIMEOUT_SEC  = int(os.getenv("OLLAMA_WARMUP_TIMEOUT_SEC", "300"))

# ── Groq ──────────────────────────────────────────────────────────────────────

GROQ_API_KEY   = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL     = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL  = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_TIMEOUT   = int(os.getenv("GROQ_TIMEOUT_SEC", "30"))

# ── Cerebras ──────────────────────────────────────────────────────────────────

CEREBRAS_API_KEY  = os.getenv("CEREBRAS_API_KEY", "")
CEREBRAS_MODEL    = os.getenv("CEREBRAS_MODEL", "qwen3-235b")
CEREBRAS_BASE_URL = os.getenv("CEREBRAS_BASE_URL", "https://api.cerebras.ai/v1")
CEREBRAS_TIMEOUT  = int(os.getenv("CEREBRAS_TIMEOUT_SEC", "30"))

# ── Mistral ───────────────────────────────────────────────────────────────────

MISTRAL_API_KEY  = os.getenv("MISTRAL_API_KEY", "")
MISTRAL_MODEL    = os.getenv("MISTRAL_MODEL", "codestral-latest")
MISTRAL_BASE_URL = os.getenv("MISTRAL_BASE_URL", "https://api.mistral.ai/v1")
MISTRAL_TIMEOUT  = int(os.getenv("MISTRAL_TIMEOUT_SEC", "30"))

# ── OpenRouter ────────────────────────────────────────────────────────────────

OPENROUTER_API_KEY  = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL    = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-r1:free")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
OPENROUTER_TIMEOUT  = int(os.getenv("OPENROUTER_TIMEOUT_SEC", "30"))

# ── Provider Chain ────────────────────────────────────────────────────────────

DIAGNOSIS_PROVIDER_CHAIN_RAW = os.getenv(
    "DIAGNOSIS_PROVIDER_CHAIN", "groq,ollama,cerebras,gemini,mistral,openrouter"
)
DIAGNOSIS_PROVIDER_CHAIN: list[str] = [
    p.strip() for p in DIAGNOSIS_PROVIDER_CHAIN_RAW.split(",") if p.strip()
]

# ── Loki ──────────────────────────────────────────────────────────────────────

LOKI_URL               = os.getenv("LOKI_URL", "").rstrip("/")
LOKI_LOOKBACK_MINUTES  = int(os.getenv("LOKI_LOOKBACK_MINUTES", "30"))
LOKI_QUERY_LIMIT       = int(os.getenv("LOKI_QUERY_LIMIT", "200"))
LOKI_TIMEOUT_SEC       = int(os.getenv("LOKI_TIMEOUT_SEC", "10"))
LOKI_K8S_LABEL_TEMPLATE = os.getenv(
    "LOKI_K8S_LABEL_TEMPLATE", '{namespace="$namespace", pod="$pod"}'
)
LOKI_DOCKER_LABEL_TEMPLATE = os.getenv("LOKI_DOCKER_LABEL_TEMPLATE", "")

DOCKER_LOKI_PROBE_TEMPLATES: list[str] = [
    '{host="$host", container_name="$container"}',
    '{host="$host", container="$container"}',
    '{instance="$host", container_name="$container"}',
    '{instance="$host", container="$container"}',
    '{instance="$host", container="$container_name"}',
]
LOKI_PROBE_TIMEOUT_SEC = 3

# ── Prometheus ────────────────────────────────────────────────────────────────

PROMETHEUS_URL         = os.getenv("PROMETHEUS_URL", "").rstrip("/")
PROMETHEUS_TIMEOUT_SEC = int(os.getenv("PROMETHEUS_TIMEOUT_SEC", "5"))

# ── n8n ───────────────────────────────────────────────────────────────────────

N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "")
N8N_TIMEOUT_SEC = int(os.getenv("N8N_TIMEOUT_SEC", "5"))

# ── Email ─────────────────────────────────────────────────────────────────────

SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_FROM    = os.getenv("EMAIL_FROM", SMTP_USER)

_DEV_EMAILS_RAW = os.getenv(
    "DEV_EMAILS",
    "navjot.singh@marblex.ai,jatin.chib@thewitslab.com,dishab.kaushal@thewitslab.com",
)
DEV_EMAILS = [e.strip() for e in _DEV_EMAILS_RAW.split(",") if e.strip()]

_OPS_EMAILS_RAW = os.getenv("OPS_EMAILS", _DEV_EMAILS_RAW)
OPS_EMAILS = [e.strip() for e in _OPS_EMAILS_RAW.split(",") if e.strip()]

# ── Rollback ──────────────────────────────────────────────────────────────────

HEAL_VERIFY_ENABLED    = os.getenv("HEAL_VERIFY_ENABLED", "true").lower() == "true"
HEAL_VERIFY_DELAY_SEC  = int(os.getenv("HEAL_VERIFY_DELAY_SEC", "60"))

# ── Event-driven ──────────────────────────────────────────────────────────────

WATCH_EVENTS_ENABLED = os.getenv("WATCH_EVENTS_ENABLED", "true").lower() == "true"
WATCH_EVENTS_DEBOUNCE_SEC = int(os.getenv("WATCH_EVENTS_DEBOUNCE_SEC", "300"))

# ── Observability ─────────────────────────────────────────────────────────────

HEALTH_PORT    = int(os.getenv("HEALTH_PORT", "8080"))
METRICS_ENABLED = os.getenv("METRICS_ENABLED", "true").lower() == "true"
DIAGNOSIS_HISTORY_SIZE = int(os.getenv("DIAGNOSIS_HISTORY_SIZE", "200"))

# ── Chat Assistant ───────────────────────────────────────────────────────────

CHAT_ENABLED     = os.getenv("CHAT_ENABLED", "true").lower() == "true"
CHAT_TIMEOUT_SEC = int(os.getenv("CHAT_TIMEOUT_SEC", "300"))
CHAT_MAX_TURNS   = int(os.getenv("CHAT_MAX_TURNS", "6"))
CHAT_PROVIDER_CHAIN: list[str] = [
    p.strip() for p in os.getenv("CHAT_PROVIDER_CHAIN", "").split(",") if p.strip()
] or (["ollama"] if OLLAMA_ENABLED else list(DIAGNOSIS_PROVIDER_CHAIN))

# ── Dashboard Auth ───────────────────────────────────────────────────────────

DASHBOARD_USER     = os.getenv("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "admin")

# ── Google SSO ────────────────────────────────────────────────────────────────

GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_ALLOWED_DOMAINS = os.getenv("GOOGLE_ALLOWED_DOMAINS", "thewitslab.com,marblex.ai")
GOOGLE_REDIRECT_URI  = os.getenv("GOOGLE_REDIRECT_URI", "")

# ── Cost Estimation ───────────────────────────────────────────────────────────

COST_PER_GB_HOUR = float(os.getenv("COST_PER_GB_HOUR", "0.0000016"))
COST_PER_CPU_HOUR = float(os.getenv("COST_PER_CPU_HOUR", "0.0056"))

# ── Approval Mode (Human-in-the-Loop) ───────────────────────────────────────

APPROVAL_MODE          = os.getenv("APPROVAL_MODE", "false").lower() == "true"
APPROVAL_TIMEOUT_HOURS = int(os.getenv("APPROVAL_TIMEOUT_HOURS", "24"))
APPROVAL_DASHBOARD_URL = os.getenv("APPROVAL_DASHBOARD_URL", "")

# ── Email Reply Reader (IMAP) ───────────────────────────────────────────────

IMAP_ENABLED      = os.getenv("IMAP_ENABLED", "false").lower() == "true"
IMAP_HOST         = os.getenv("IMAP_HOST", "imap.gmail.com")
IMAP_PORT         = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER         = os.getenv("IMAP_USER", "")
IMAP_PASSWORD     = os.getenv("IMAP_PASSWORD", "")
IMAP_POLL_INTERVAL = int(os.getenv("IMAP_POLL_INTERVAL", "30"))

# ── Database ─────────────────────────────────────────────────────

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://healer:healer@localhost:5432/healer")

# ── Circuit Breaker ──────────────────────────────────────────────

CIRCUIT_BREAKER_ENABLED    = os.getenv("CIRCUIT_BREAKER_ENABLED", "true").lower() == "true"
CIRCUIT_BREAKER_THRESHOLD  = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "3"))
CIRCUIT_BREAKER_WINDOW_MIN = int(os.getenv("CIRCUIT_BREAKER_WINDOW_MIN", "60"))
CIRCUIT_BREAKER_COOLDOWN_MIN = int(os.getenv("CIRCUIT_BREAKER_COOLDOWN_MIN", "1440"))


def validate() -> list[str]:
    """Return list of config warnings (non-fatal)."""
    warnings: list[str] = []
    if not GEMINI_API_KEY:
        warnings.append("GEMINI_API_KEY not set — Gemini provider disabled")
    if not ENABLE_K8S and not ENABLE_DOCKER:
        warnings.append("Both ENABLE_K8S and ENABLE_DOCKER are false — nothing to watch")
    if ENABLE_DOCKER:
        try:
            import docker as _d
            _d.from_env()
        except Exception:
            warnings.append("ENABLE_DOCKER=true but Docker daemon unreachable")
    return warnings
