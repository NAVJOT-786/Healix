# Healix — K8s & Docker AI Auto-Healer (Modular Multi-Provider Edition)

A self-healing agent that monitors Kubernetes pods and Docker containers, diagnoses issues using a configurable chain of 6 LLM providers, and automatically applies fixes with rollback safety, PDB awareness, and cost estimation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Docker Container                               │
│                                                                         │
│  ┌──────────────┐    monitors    ┌──────────────────────────────┐       │
│  │  watchdog.sh  │──────────────>│         agent.py             │       │
│  │  (sidecar)    │  restarts if  │      (thin orchestrator)     │       │
│  │              │  agent dies    │  ┌────────────────────────┐  │       │
│  └──────────────┘                │  │    Monitor Loop        │  │       │
│                                  │  │    (every 30s)         │  │       │
│                                  │  └────────┬───────────────┘  │       │
│                                  └───────────┼──────────────────┘       │
│                                              │                          │
│              ┌───────────────────────────────┼───────────────┐          │
│              ▼                               ▼               ▼          │
│  ┌──────────────────┐  ┌─────────────────────┐  ┌──────────────┐       │
│  │  k8s_events.py   │  │  prometheus.py      │  │  loki.py     │       │
│  │  K8s Warning     │  │  CPU + Memory       │  │  Logs        │       │
│  │  events          │  │  metrics            │  │              │       │
│  └──────────────────┘  └─────────────────────┘  └──────────────┘       │
│              │                     │                    │                │
│              └──────────────┬──────┘────────────────────┘                │
│                             ▼                                           │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  prompts.py — system prompt + few-shot examples            │        │
│  │  + resource limits in prompt + ambiguity rules              │        │
│  └────────────────────────────┬────────────────────────────────┘        │
│                               ▼                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    MULTI-PROVIDER CHAIN (providers.py)            │  │
│  │                                                                   │  │
│  │  Groq → Ollama → Cerebras → Gemini → Mistral → OpenRouter       │  │
│  └──────────────────────────────┬────────────────────────────────────┘  │
│                                 ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  JSON validation + output checks (agent.py)               │        │
│  └────────────────────────────┬────────────────────────────────┘        │
│                               ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  pdbs.py — PDB safety check before bounce/scale           │        │
│  └────────────────────────────┬────────────────────────────────┘        │
│                               ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  approval.py — Human-in-the-loop gate (when enabled)       │        │
│  │  ApprovalStore + executor thread + email button links      │        │
│  └────────────────────────────┬────────────────────────────────┘        │
│                               ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  k8s_engine.py / docker_engine.py — execute action         │        │
│  │  (multi-container support + deployment fallback)            │        │
│  └────────────────────────────┬────────────────────────────────┘        │
│                               ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  rollback.py — verify heal, auto-rollback if failed        │        │
│  └────────────────────────────┬────────────────────────────────┘        │
│                               ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  cost.py — estimate compute cost impact                    │        │
│  │  notifications.py — email + n8n + approval emails          │        │
│  │  email_reader.py — IMAP polling + reply parsing            │        │
│  └─────────────────────────────────────────────────────────────┘        │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────┐        │
│  │  observability.py — /health + /metrics + /approvals + UI   │        │
│  └─────────────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env   # edit with your API keys and endpoints

# 2. Build and run
docker compose up -d --build

# 3. Check logs
docker compose logs -f ai-healer

# 4. Check health
curl http://localhost:9990/health

# 5. Open the dashboard (login required)
#    - http://localhost:9990/metrics  → visual HTML dashboard
#    - http://localhost:9990/metrics/raw → Prometheus text format
curl http://localhost:9990/metrics/raw
```

### Minimal `.env` (required)

```env
GEMINI_API_KEY=your-key-here
ENABLE_K8S=true
ENABLE_DOCKER=false
WATCH_NAMESPACES=*
OLLAMA_ENABLED=false
REPORT_ONLY=true
```

---

## File Structure

| File | Purpose | Lines |
|---|---|---|
| `agent.py` | Main orchestrator — wires all modules, runs monitor loop | ~915 |
| `config.py` | All environment variables loaded and validated | ~210 |
| `providers.py` | LLM provider registry, callers, chain logic, plain-text chat caller | ~280 |
| `prompts.py` | System prompt, few-shot examples, prompt builder | ~180 |
| `k8s_engine.py` | K8s client, pod health, deployment helpers, actions, event watcher | ~350 |
| `docker_engine.py` | Docker client, container health, actions | ~130 |
| `loki.py` | Loki log fetching, Docker label auto-detection | ~120 |
| `pdbs.py` | Pod Disruption Budget checks before bounce/scale | ~100 |
| `rollback.py` | Post-heal verification and automatic rollback | ~100 |
| `cost.py` | Cost estimation for restarts, memory changes, downtime | ~80 |
| `notifications.py` | Email senders (dev, resolution, infra, rollback, approval) + n8n | ~430 |
| `observability.py` | Health server, metrics, diagnosis store, auth/SSO, profiles, dashboard UI, approvals tab, PDF reports, chat assistant | ~4800 |
| `prometheus.py` | Fetches CPU/memory metrics from Prometheus for LLM context | ~178 |
| `k8s_events.py` | Fetches Kubernetes Warning events for diagnosis context | ~167 |
| `approval.py` | Approval store, request/response, executor thread for human-in-the-loop | ~330 |
| `email_reader.py` | IMAP polling, reply parsing for approve/reject via email | ~180 |
| `storage.py` | PostgreSQL backend — users, circuit breaker, diagnoses, approvals, audit log | ~610 |
| `circuit_breaker.py` | Circuit breaker state machine | ~120 |
| `watchdog.sh` | Sidecar — monitors agent, auto-restarts on crash | ~140 |
| `Dockerfile` | Builds agent container (Python 3.12, non-root, healthcheck) | ~35 |
| `docker-compose.yml` | Runs agent with host networking, Docker socket, kubeconfig | ~56 |
| `.env` | All configuration | ~120 |
| `requirements.txt` | Python dependencies | ~10 |
| `README.md` | This file | — |

---

## Healix Features

### 1. Auto-Remediation Rollback (`rollback.py`)

After executing `increase_memory_limit`, `bounce_deployment`, or `scale_deployment`, the agent waits 60s (configurable) and checks if the pod recovered. If still crashing, it **rolls back the change** and sends a rollback escalation email.

```
Heal action applied → Wait 60s → Re-check pod status
  → Healthy: Send resolution email as normal
  → Still unhealthy: Roll back + send rollback escalation email + n8n alert
```

Config: `HEAL_VERIFY_ENABLED=true`, `HEAL_VERIFY_DELAY_SEC=60`

### 2. Multi-Container Pod Support (`k8s_engine.py`)

- Fetches all container names from the pod spec and includes them in the LLM prompt
- Auto-detects which container was OOMKilled (via `last_state.terminated.reason`)
- Validates container name exists in the Deployment spec before patching
- Falls back to first container if LLM returns an invalid container name

### 3. Event-Driven Triggers (`k8s_engine.py:K8sEventWatcher`)

Background thread watches K8s Events via `kubernetes.watch.Watch()` for sub-second reaction to pod failures, instead of waiting for the next poll cycle.

```
Main thread: polls every 30s (dashboard table + healing)
Watch thread: listens for Warning events in real-time
  → On OOMKilling, BackOff, CrashLoopBackOff, etc.
  → Adds to pending_heals set (debounced to avoid re-triggering)
  → Main loop picks up on next cycle
```

Config: `WATCH_EVENTS_ENABLED=true`, `WATCH_EVENTS_DEBOUNCE_SEC=300`

### 4. Pod Disruption Budget Awareness (`pdbs.py`)

Before executing `bounce_deployment` or `scale_deployment`, checks if a PDB exists and if the action would violate it.

- Lists PDBs in the namespace
- Matches PDB selectors against deployment pod selectors
- Checks `minAvailable` / `maxUnavailable` constraints
- If action would violate PDB → blocks action, sends escalation email

### 5. Cost Estimation (`cost.py`)

Calculates estimated compute cost impact included in all email reports:

- **Restart waste**: resources wasted during CrashLoopBackOff restarts
- **Memory cost change**: additional hourly cost from memory limit increase
- **Bounce downtime**: estimated pod downtime during bounce

Uses configurable rates: `COST_PER_GB_HOUR`, `COST_PER_CPU_HOUR`

### 6. Human-in-the-Loop Approval Flow (`approval.py`, `email_reader.py`)

When `APPROVAL_MODE=true`, every heal pauses for human approval before executing:

```
Pod diagnosed → LLM recommends action → ACTION PAUSED
  → ApprovalRequest created (in-memory, max 50, 24h timeout)
  → Email sent to stakeholders with [Approve] [Reject] buttons
  → Dashboard "Approvals" tab shows pending count + approve/reject buttons
  → Email reply: reply with "approve"/"reject" → IMAP polls every 30s → parses body
  → Approved: Executor picks up → executes → verifies → rollback if needed → updates diagnosis card in-place
  → Rejected: Diagnosis card updates to "rejected" tag
  → Expired after timeout → marked expired, no action taken
```

**Dashboard integration:**
- Approvals tab with badge count (polls `/approvals` every 5s)
- Approve/Reject buttons with `POST /approve/{id}` / `POST /reject/{id}`
- Email button links to `{APPROVAL_DASHBOARD_URL}/approve/{id}` with HTML confirmation page
- Diagnosis cards transition: `needs_approval` (orange pulse) → `healed` / `rollback` / `rejected`

**Email reply parsing:**
- Subject must contain `[AI-Heal-Approve: {id}]` (auto-included in approval email)
- Body scanned for keyword sets: approve/yes/ok/proceed/go/confirm or reject/no/deny/cancel/decline
- From field recorded as `email:{sender}` in approval store

Config: `APPROVAL_MODE=true`, `IMAP_ENABLED=true`, `IMAP_USER`, `IMAP_PASSWORD`

### 7. PostgreSQL Persistence (`storage.py`)

Replaces all in-memory stores with persistent PostgreSQL tables:

| Table | Purpose |
|---|---|
| `diagnoses` | Full diagnosis history — filtered by route, platform, time range |
| `approvals` | Persistent approval requests across agent restarts |
| `circuit_breaker` | Heal attempt tracking for circuit breaker state |
| `audit_log` | Immutable append-only event log for compliance |

Database connection is auto-initialized on agent startup. If PostgreSQL is unreachable, the agent logs a warning and falls back to in-memory operation.

Config: `DATABASE_URL=postgresql://healer:healer@localhost:5432/healer`

### 8. Circuit Breaker (`circuit_breaker.py`)

Prevents repeated failed heals on the same target. Three-state machine:

```
CLOSED  → (3 failures in 60m) → OPEN    → (24h cooldown expires) → HALF-OPEN
                                                                    ↓
HALF-OPEN → (heal succeeds)   → CLOSED  (reset failure counter)
HALF-OPEN → (heal fails)      → OPEN    (start new cooldown)
```

Integrated at every entry point: K8s watch, Docker watch, and approval executor. Configurable via `.env`:

| Variable | Default | Description |
|---|---|---|
| `CIRCUIT_BREAKER_ENABLED` | `true` | Enable circuit breaker |
| `CIRCUIT_BREAKER_THRESHOLD` | `3` | Max failures before opening |
| `CIRCUIT_BREAKER_WINDOW_MIN` | `60` | Window in minutes |
| `CIRCUIT_BREAKER_COOLDOWN_MIN` | `1440` | Cooldown in minutes (24h) |

### 9. Smart DOM Dashboard Updates

Instead of destroying and rebuilding the UI on every 5s poll, the dashboard now uses DOM diffing:

- Cards and feed items tracked via `data-id` attributes
- Only changed cards update in-place (no flicker)
- New items fade in smoothly (`translateY(8px)` + opacity)
- Removed items fade out (`scale(0.95)` + opacity → remove after 150ms)
- Scroll position preserved across refreshes

The `smartUpdate()` function compares existing DOM children with incoming data, creating a minimal diff set (add, update, remove) — ensuring smooth transitions across approval cards, activity feed, timeline, and diagnosis card grids.

### 10. Authentication & Google SSO

The dashboard is protected by a session cookie (`SameSite=Strict`) and supports two login paths:

- **Password login** — `POST /login` with `DASHBOARD_USER` / `DASHBOARD_PASSWORD` credentials.
- **Google Sign-In** — `GET /auth/google` → OAuth 2.0 flow → `GET /auth/google/callback`:
  - OAuth `state` token with CSRF protection
  - Identity verified server-side via Google `tokeninfo` (audience, issuer, `email_verified`)
  - Domain allow-list check via `GOOGLE_ALLOWED_DOMAINS` (default `thewitslab.com,marblex.ai`)
  - First-time Google users are auto-provisioned into the Postgres `users` table

> **Note:** If Google rejects sign-in with `Error 403: org_internal`, the Google OAuth app's User Type is set to **Internal**. Switch it to **External** in Google Cloud Console (OAuth consent screen) so accounts outside your org's domain can sign in.

Config: `DASHBOARD_USER`, `DASHBOARD_PASSWORD`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_ALLOWED_DOMAINS`, `GOOGLE_REDIRECT_URI`

### 11. User Profiles

- Account dropdown in the header (theme color + display mode)
- Profile editing with photo upload — `POST /users/profile`
- Server-side validation: username must match `^[A-Za-z0-9._@\-]{3,32}$`; photo must be empty or a `data:image/(png|jpe?g|gif|webp);base64,...` URL
- All usernames are HTML-escaped in the dashboard header and the admin Users table to prevent stored XSS

### 12. Premium PDF Reports

The Reports tab generates a branded, gradient-styled PDF summary:

```
GET /api/report?days=N   (1 ≤ N ≤ 30)  →  healix-report-Nd-YYYYMMDD.pdf
```

Includes KPI cards, per-day trend bar chart, platform/route breakdowns, top-resource list, and incident table with status pills. Requires authentication; generated with `fpdf2`.

### 13. Boot Splash

On every dashboard load the Healix logo cracks apart and snaps back together (jagged crack lines, join glow, "Initialising Healix…" status, then "Welcome, <user>"), before the overlay fades out. On a reload the logo simply spins with no text.

### 14. Chat Assistant (read-only)

A floating chat widget (bottom-right FAB) answers questions about the live system. By default it uses **Ollama** (via `CHAT_PROVIDER_CHAIN`), keeping Groq reserved for the diagnosis flow.

- `POST /chat` (auth required) accepts `{message, history}` and returns `{ok, reply, provider}`
- The bot is given live context each turn: recent diagnoses, agent metrics (heals/LLM calls/rollbacks/PDB blocks), pending approvals, and service connectivity
- Conversational tone: friendly greetings, short answers, reassurance when healthy
- Read-only — it never proposes or triggers healing actions
- Typing indicator + bubble history in the dashboard; each message is one LLM call

Config: `CHAT_ENABLED`, `CHAT_TIMEOUT_SEC`, `CHAT_MAX_TURNS`, `CHAT_PROVIDER_CHAIN`

---

## Code Quality

| Aspect | Legacy | Healix |
|---|---|---|
| File structure | 1 monolithic `agent.py` (1420 lines) | 14 focused modules (~100-350 lines each) |
| Type hints | None | All function signatures |
| Input validation | `json.loads()` only | Validate action in allowed list, bool type, required keys |
| Container validation | Blind patch by LLM param | Validates container exists in Deployment spec |
| Error handling | Silent `pass` in helpers | Structured logging at debug level |
| LLM prompt | Basic rules only | Few-shot examples, ambiguity rules, resource context |
| Logging | `rich.console` only | Structured JSON + rich console (configurable) |

---

## LLM Provider Chain

| Priority | Provider | Model | Free Tier | Best For |
|---|---|---|---|---|
| 1 | **Groq** | llama-3.3-70b-versatile | ~1,000 req/day | Fastest inference |
| 2 | **Ollama** | qwen2.5:7b | Unlimited | Primary offline diagnosis |
| 3 | **Cerebras** | qwen3-235b | ~1M tokens/day | 1M context window |
| 4 | **Gemini** | gemini-2.5-flash | ~1,500 req/day | Multimodal support |
| 5 | **Mistral** | codestral-latest | ~1B tokens/month | Code-specialized |
| 6 | **OpenRouter** | deepseek/deepseek-r1:free | 50 req/day | Best reasoning |

All cloud providers use OpenAI-compatible APIs. Disabled by default — add API key to enable.

### Customizing Chain

```bash
# In .env
DIAGNOSIS_PROVIDER_CHAIN=groq,gemini    # Try only Groq then Gemini
```

---

## Configuration Reference

### Core

| Variable | Default | Description |
|---|---|---|
| `GEMINI_API_KEY` | — | Google Gemini API key (required) |
| `REPORT_ONLY` | `true` | `true` = diagnose only, `false` = execute fixes |
| `DRY_RUN` | `false` | `true` = log actions without executing |
| `POLL_INTERVAL_SEC` | `30` | Seconds between monitor loops |
| `MAX_RESTARTS` | `3` | Restart threshold before healing |
| `LOG_TAIL_LINES` | `50` | Log lines to fetch |

### Platforms

| Variable | Default | Description |
|---|---|---|
| `ENABLE_K8S` | `true` | Enable Kubernetes monitoring |
| `ENABLE_DOCKER` | `false` | Enable Docker monitoring |
| `WATCH_NAMESPACES` | `default,demo` | Comma-separated or `*` for all |
| `DOCKER_HOST_LABEL` | hostname | Docker host label |

### LLM Providers

| Variable | Default | Description |
|---|---|---|
| `OLLAMA_ENABLED` | `false` | Use Ollama as primary |
| `OLLAMA_MODEL` | `qwen2.5:14b` | Ollama model |
| `GROQ_API_KEY` | — | Groq API key |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Groq model |
| `CEREBRAS_API_KEY` | — | Cerebras API key |
| `CEREBRAS_MODEL` | `qwen3-235b` | Cerebras model |
| `MISTRAL_API_KEY` | — | Mistral API key |
| `MISTRAL_MODEL` | `codestral-latest` | Mistral model |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `OPENROUTER_MODEL` | `deepseek/deepseek-r1:free` | OpenRouter model |
| `DIAGNOSIS_PROVIDER_CHAIN` | `ollama,groq,...` | Comma-separated chain order |

### Loki

| Variable | Default | Description |
|---|---|---|
| `LOKI_URL` | — | Loki endpoint |
| `LOKI_LOOKBACK_MINUTES` | `30` | Log lookback window |
| `LOKI_QUERY_LIMIT` | `200` | Max log lines |
| `LOKI_TIMEOUT_SEC` | `10` | Request timeout |

### Prometheus

| Variable | Default | Description |
|---|---|---|
| `PROMETHEUS_URL` | — | Prometheus endpoint |
| `PROMETHEUS_TIMEOUT_SEC` | `5` | Request timeout |

### n8n

| Variable | Default | Description |
|---|---|---|
| `N8N_WEBHOOK_URL` | — | n8n webhook endpoint |
| `N8N_TIMEOUT_SEC` | `5` | Request timeout |

### Email

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `EMAIL_FROM` | same as `SMTP_USER` | Sender address |
| `DEV_EMAILS` | team emails | Comma-separated dev recipients |
| `OPS_EMAILS` | same as `DEV_EMAILS` | Comma-separated ops recipients |

### Database

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://healer:healer@localhost:5432/healer` | PostgreSQL connection string |

### Circuit Breaker

| Variable | Default | Description |
|---|---|---|
| `CIRCUIT_BREAKER_ENABLED` | `true` | Enable circuit breaker |
| `CIRCUIT_BREAKER_THRESHOLD` | `3` | Heal failures before circuit opens |
| `CIRCUIT_BREAKER_WINDOW_MIN` | `60` | Rolling window in minutes |
| `CIRCUIT_BREAKER_COOLDOWN_MIN` | `1440` | Cooldown in minutes (24h) |

### Rollback

| Variable | Default | Description |
|---|---|---|
| `HEAL_VERIFY_ENABLED` | `true` | Enable post-heal verification |
| `HEAL_VERIFY_DELAY_SEC` | `60` | Seconds to wait before checking |

### Event-Driven

| Variable | Default | Description |
|---|---|---|
| `WATCH_EVENTS_ENABLED` | `true` | Enable K8s event watcher thread |
| `WATCH_EVENTS_DEBOUNCE_SEC` | `300` | Min seconds between re-triggers per pod |

### Observability

| Variable | Default | Description |
|---|---|---|
| `HEALTH_PORT` | `8080` | HTTP health/metrics port (running config uses `9990`) |
| `METRICS_ENABLED` | `true` | Enable health server + dashboard |

### Cost Estimation

| Variable | Default | Description |
|---|---|---|
| `COST_PER_GB_HOUR` | `0.0000016` | AWS on-demand memory cost |
| `COST_PER_CPU_HOUR` | `0.0056` | AWS on-demand CPU cost |

### Approval Mode

| Variable | Default | Description |
|---|---|---|
| `APPROVAL_MODE` | `false` | Enable human-in-the-loop approval before heals |
| `APPROVAL_TIMEOUT_HOURS` | `24` | Hours before pending approval expires |
| `APPROVAL_DASHBOARD_URL` | — | External URL for email approve/reject buttons |

### Email Reply Reader (IMAP)

| Variable | Default | Description |
|---|---|---|
| `IMAP_ENABLED` | `false` | Enable IMAP polling for email replies |
| `IMAP_HOST` | `imap.gmail.com` | IMAP server |
| `IMAP_PORT` | `993` | IMAP port (SSL) |
| `IMAP_USER` | — | IMAP username (usually same as SMTP_USER) |
| `IMAP_PASSWORD` | — | IMAP password or app password |
| `IMAP_POLL_INTERVAL` | `30` | Seconds between inbox polls |

### Authentication & SSO

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_USER` | `admin` | Admin username for password login |
| `DASHBOARD_PASSWORD` | `admin` | Admin password for password login |
| `GOOGLE_CLIENT_ID` | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | — | Google OAuth client secret |
| `GOOGLE_ALLOWED_DOMAINS` | `thewitslab.com,marblex.ai` | Comma-separated email domains allowed to sign in |
| `GOOGLE_REDIRECT_URI` | derived from Host | OAuth redirect URI (leave empty to auto-derive) |

### Diagnosis History

| Variable | Default | Description |
|---|---|---|
| `DIAGNOSIS_HISTORY_SIZE` | `200` | Max in-memory diagnoses kept for the dashboard |

### Chat Assistant

| Variable | Default | Description |
|---|---|---|
| `CHAT_ENABLED` | `true` | Enable the dashboard chat widget + `POST /chat` |
| `CHAT_TIMEOUT_SEC` | `300` | Per-provider timeout for chat LLM calls (Ollama can be slow) |
| `CHAT_MAX_TURNS` | `6` | Conversation turns sent as context per message |
| `CHAT_PROVIDER_CHAIN` | `ollama` (if Ollama enabled) | Provider order for chat; e.g. `ollama,gemini` for a cloud fallback |

---

## Observability Endpoints

> The dashboard (`/metrics`, `/diagnoses`, `/approvals`, `/api/*`) requires login. Prometheus-style text is served from `/metrics/raw`.

### `GET /health`

Returns agent liveness status.

```json
{"status": "healthy", "last_heartbeat_age_sec": 5.2}
```

### `GET /metrics`

The **visual HTML dashboard** (login required). Serves the Healix dashboard with diagnosis cards, charts, approvals, and reports tabs.

### `GET /metrics/raw`

Prometheus-format metrics for the agent itself:

```
healer_uptime_seconds 3600
healer_heal_actions_total{action="increase_memory_limit"} 12
healer_heal_by_platform_total{platform="k8s"} 45
healer_heal_by_route_total{route="auto_healed"} 38
healer_llm_calls_total{provider="groq"} 52
healer_llm_latency_seconds{provider="groq",quantile="avg"} 2.3
healer_rollbacks_total 2
healer_pdb_blocks_total 1
```

### `GET /metrics/api`

Metrics as JSON, consumed by the dashboard JS.

### `GET /diagnoses`

Returns the in-memory diagnosis history (capped by `DIAGNOSIS_HISTORY_SIZE`, default 200).

### `GET /api/report?days=N`

Generates a premium PDF report for the last `N` days (1–30). Returns `healix-report-Nd-YYYYMMDD.pdf`.

### `GET /login` / `POST /login` / `GET /logout`

Password login page, login POST (form: `username`, `password`), and logout.

### `GET /auth/google` / `GET /auth/google/callback`

Google OAuth 2.0 sign-in flow.

### `GET /users/me` / `POST /users/profile`

Current user info (includes `profile_pic`) and profile updates (username, photo data URL).

### `POST /chat`

Chat Assistant Q&A. Body: `{"message": "...", "history": [{"role": "user|assistant", "content": "..."}]}`. Returns `{"ok": true, "reply": "...", "provider": "groq"}`. Powered by the LLM provider chain with live system context.

### `POST /users/create` / `POST /users/update` / `POST /users/delete`

Admin user management from the dashboard Users tab.

### `GET /approvals`

Returns pending and completed approval requests.

```json
{"requests": [{"id": "abc123", "status": "pending", "name": "pod-xyz", ...}], "pending_count": 3}
```

### `POST /approve/{id}` / `POST /reject/{id}`

Approve or reject a pending approval. Accepts both dashboard (JSON) and email-link (GET) modes.

```
POST /approve/abc123 → {"ok": true, "id": "abc123", "status": "approved"}
GET  /approve/abc123 → HTML confirmation page (for email button clicks)
```

Same for `/reject/{id}`.

### `GET /circuit/breaker`

Returns circuit breaker state and configuration.

```json
{"enabled": true, "state": "closed", "threshold": 3, "window_min": 60, "cooldown_min": 1440}
```

Pass `?target_id=pod-name` for a specific target's state:

```json
{"enabled": true, "state": "open", "target_id": "pod-name", "failures": 3, "retry_after_min": 1380}
```

---

## Self-Healing (Watchdog)

The `watchdog.sh` sidecar ensures the agent itself stays alive:

```
Boot → Start agent.py → Monitor loop (every 10s)
  → Check if agent is alive (PID file + pgrep fallback)
  → If dead: kill orphans → write marker → restart
  → Agent detects marker → sends self-heal notification email
```

---

## Dependencies

```
google-generativeai    # Gemini API
kubernetes             # K8s Python client
python-dotenv          # .env loading
requests               # HTTP (Loki, Prometheus, Ollama, n8n, cloud LLMs)
rich                   # CLI output formatting
docker                 # Docker SDK (optional, for Docker monitoring)
psycopg2-binary        # PostgreSQL adapter (optional, for persistence)
bcrypt                 # Password hashing (dashboard auth)
fpdf2                  # Premium PDF report generation
```

---

## Free API Signups

| Provider | Sign Up | Free Tier |
|---|---|---|
| Groq | https://console.groq.com | ~1,000 req/day, no card |
| Cerebras | https://cloud.cerebras.ai | ~1M tokens/day, no card |
| Mistral | https://console.mistral.ai | ~1B tokens/month, no card |
| OpenRouter | https://openrouter.ai | 50 req/day, no card |
| Gemini | https://aistudio.google.com | ~1,500 req/day, no card |
