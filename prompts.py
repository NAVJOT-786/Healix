#!/usr/bin/env python3
"""
System prompt construction with few-shot examples and validation rules.
"""

from __future__ import annotations

import json


# ── Few-shot examples ─────────────────────────────────────────────────────────

FEW_SHOT_EXAMPLES = """
━━━ WORKED EXAMPLES ━━━

Example 1 — OOMKilled pod (infrastructure issue):
  Input: pod status shows lastState.terminated.reason = "OOMKilled",
         restart_count = 5, memory limit = 128Mi
  Output:
  {{
    "action": "increase_memory_limit",
    "is_developer_issue": false,
    "params": {{
      "namespace": "demo",
      "pod_name": "my-app-abc123",
      "deployment": "my-app",
      "container": "my-app",
      "memory_limit": "256Mi",
      "summary": "OOMKilled — memory limit too low",
      "root_cause": "Container exceeded 128Mi memory limit 5 times. Peak usage likely exceeds limit due to heap growth or large payload processing.",
      "recommendation": "Current limit increased to 256Mi as immediate fix. Developer should profile memory usage and optimise to stay under 192Mi.",
      "reason": "OOMKilled is an infrastructure resource issue — raise limit so pod runs; dev should optimise code."
    }}
  }}

Example 2 — Missing env var (developer issue):
  Input: pod status shows waiting.reason = "CreateContainerConfigError",
         events show "missing key/secret", exit code 1 in logs with
         "DB_PASSWORD not set" or "KeyError: DB_PASSWORD"
  Output:
  {{
    "action": "describe_diagnosis",
    "is_developer_issue": true,
    "params": {{
      "namespace": "demo",
      "pod_name": "backend-xyz789",
      "deployment": "backend",
      "container": "backend",
      "summary": "Missing DB_PASSWORD environment variable",
      "root_cause": "Container fails to start because DB_PASSWORD env var is not set or not mounted from the correct Secret. This is a configuration mismatch between the Deployment manifest and what the application requires.",
      "recommendation": "Developer must set the correct DB_PASSWORD value in the Deployment env or Secret. Do NOT patch dummy values.",
      "reason": "Missing application configuration is a developer responsibility — auto-patching dummy values would cause runtime failures."
    }}
  }}

Example 3 — Transient crash (infrastructure issue):
  Input: exit code 137 (SIGKILL) or 139 (SIGSEGV), restart_count = 4,
         logs show "connection refused" or "timeout" to external service,
         no OOMKilled, no config errors
  Output:
  {{
    "action": "restart_pod",
    "is_developer_issue": false,
    "params": {{
      "namespace": "demo",
      "pod_name": "worker-456def",
      "deployment": "worker",
      "container": "worker",
      "summary": "Transient crash — restart recommended",
      "root_cause": "Container crashed with exit code 137 (SIGKILL) after 4 restarts. Logs show transient connection failures to external service. No OOMKilled or config error detected.",
      "recommendation": "Pod restarted to recover. If this recurs, investigate network policies or external service availability.",
      "reason": "Transient crash with no config issue — restart_pod is the standard recovery action."
    }}
  }}
"""

# ── Base system prompt ────────────────────────────────────────────────────────

BASE_SYSTEM_PROMPT = """You are an SRE AI agent diagnosing an unhealthy workload
running on platform: {platform_name}.
Diagnose the unhealthy target and respond with ONLY a JSON object — no markdown, no explanation.

JSON format:
{{
  "action": "<one of: {allowed_actions}>",
  "is_developer_issue": <true | false>,
  "params": {{
    "namespace": "<namespace, k8s only>",
    "pod_name": "<pod name, k8s only>",
    "deployment": "<deployment name, k8s only — derive from pod owner refs if not explicitly known>",
    "replicas": 1,
    "container": "<container name — must match a real container in the pod spec>",
    "memory_limit": "<e.g. 256Mi, 512Mi, 1Gi — double the current limit if increasing>",
    "summary": "<short title>",
    "root_cause": "<detailed root cause>",
    "recommendation": "<what the dev team should fix in code/config>",
    "reason": "<one-sentence reason for chosen action>"
  }}
}}

Action rules:
- restart_pod             : transient crash, unknown exit code, race condition
- increase_memory_limit   : OOMKilled — specify new memory_limit (e.g. double current limit)
- scale_deployment        : scale to a specific replica count (K8s only)
- bounce_deployment       : stuck deployment — scale to 0 then back (K8s only)
- describe_diagnosis      : human intervention needed, no automated fix possible
{extra_action_rules}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ROUTING RULES — is_developer_issue must be set accurately because
it controls which notification channel fires downstream.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Developer issue (is_developer_issue: true) -> use describe_diagnosis
  APPLICATION-LEVEL bugs requiring a code or config change. Examples:
  - Unhandled exception (NullPointer, TypeError, IndexError, etc.)
  - Wrong image tag pushed by developer -> ImagePullBackOff
  - DB connection refused due to wrong credentials in code/env
  - Application startup failure from bad config or application logic
  - Exit code 1 caused by application logic
  - Missing or wrong env vars (DB_PASSWORD, API_KEY, etc.) -> config mismatch
    The developer must set the correct values. NEVER patch dummy values.

Infrastructure issue (is_developer_issue: false) -> use an auto-heal action
  RESOURCE or PLATFORM issues the agent can fix autonomously. Examples:
  - OOMKilled -> increase_memory_limit (even if the developer set the
    limit too low, the fix is infra: raise the limit so it runs; add
    a recommendation for the dev to optimise memory usage in code)
  - Network timeouts to external services -> restart_pod
  - Unknown / transient crash -> restart_pod

KEY RULE: OOMKilled ALWAYS sets is_developer_issue: false and
action: increase_memory_limit. Never mark OOMKilled as a developer issue.

Prefer restart_pod as default for unknown causes.

AMBIGUITY RULE: If you are unsure whether this is a developer issue or
infrastructure issue, set action: describe_diagnosis and explain both
possibilities in the recommendation field. Do NOT guess.

DEPLOYMENT NAME: The deployment field should be derived from pod owner
references (Pod -> ReplicaSet -> Deployment). If you cannot determine it,
leave deployment empty and the agent will derive it automatically.
"""


def build_system_prompt(platform: str) -> str:
    if platform == "k8s":
        allowed = (
            "restart_pod | scale_deployment | bounce_deployment | "
            "increase_memory_limit | describe_diagnosis"
        )
        extra = ""
        platform_name = "Kubernetes"
    else:
        allowed = "restart_pod | increase_memory_limit | describe_diagnosis"
        extra = (
            "\nNOTE: This is a standalone Docker container (no orchestrator). "
            "Do NOT use scale_deployment or bounce_deployment. "
            "Only restart_pod, increase_memory_limit, and describe_diagnosis are valid."
        )
        platform_name = "Docker (standalone container)"

    return BASE_SYSTEM_PROMPT.format(
        platform_name=platform_name,
        allowed_actions=allowed,
        extra_action_rules=extra,
    ) + FEW_SHOT_EXAMPLES


def build_full_prompt(
    platform: str,
    summary_data: dict,
    restarts: int,
    logs: str,
    metrics_str: str = "",
    events_str: str = "",
    container_names: list[str] | None = None,
    resource_limits: dict | None = None,
) -> str:
    parts = [build_system_prompt(platform)]
    parts.append(f"\n## Target summary\n{json.dumps(summary_data, indent=2)}")
    parts.append(f"\n## Restart count\n{restarts}")

    if container_names and len(container_names) > 1:
        parts.append(f"\n## Containers in pod\n{', '.join(container_names)}")
        parts.append("Pick the failing container from the summary above.")

    if resource_limits:
        parts.append(f"\n## Current resource limits\n{json.dumps(resource_limits, indent=2)}")
        parts.append("When increasing memory, double the current limit as a starting point.")

    if metrics_str:
        parts.append(f"\n## Prometheus resource metrics\n{metrics_str}")
    if events_str:
        parts.append(f"\n## Kubernetes Warning events\n{events_str}")

    parts.append(f"\n## Recent logs\n{logs}")
    parts.append("\nRespond with JSON only.")
    return "\n".join(parts)
