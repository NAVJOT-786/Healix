#!/usr/bin/env python3
"""
Multi-provider LLM caller with configurable fallback chain.
"""

from __future__ import annotations

import re
import time
import json
import logging
import requests
from typing import Any, Callable

from config import (
    OLLAMA_ENABLED, OLLAMA_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT_SEC,
    OLLAMA_KEEP_ALIVE, OLLAMA_WARMUP_TIMEOUT_SEC,
    GROQ_API_KEY, GROQ_MODEL, GROQ_BASE_URL, GROQ_TIMEOUT,
    CEREBRAS_API_KEY, CEREBRAS_MODEL, CEREBRAS_BASE_URL, CEREBRAS_TIMEOUT,
    GEMINI_API_KEY, MISTRAL_API_KEY, MISTRAL_MODEL, MISTRAL_BASE_URL,
    MISTRAL_TIMEOUT, OPENROUTER_API_KEY, OPENROUTER_MODEL,
    OPENROUTER_BASE_URL, OPENROUTER_TIMEOUT, DIAGNOSIS_PROVIDER_CHAIN,
)

log = logging.getLogger("providers")


# ── Callers ───────────────────────────────────────────────────────────────────

def call_openai_compatible(
    provider_name: str, api_key: str, base_url: str,
    model: str, prompt: str, timeout: int = 30,
) -> str:
    resp = requests.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _ollama_keep_alive_value() -> int | str:
    raw = OLLAMA_KEEP_ALIVE.strip()
    try:
        return int(raw)
    except ValueError:
        return raw


def call_ollama(prompt: str, timeout: int | None = None) -> str:
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "keep_alive": _ollama_keep_alive_value(),
        },
        timeout=timeout or OLLAMA_TIMEOUT_SEC,
    )
    resp.raise_for_status()
    return resp.json()["response"]


def warmup_ollama() -> None:
    if not OLLAMA_ENABLED:
        return
    log.info("Warming up Ollama model %s ...", OLLAMA_MODEL)
    try:
        start = time.time()
        call_ollama('Respond with only this JSON: {"status": "ok"}',
                     timeout=OLLAMA_WARMUP_TIMEOUT_SEC)
        log.info("Ollama warmed up (%.1fs)", time.time() - start)
    except Exception as e:
        log.warning("Ollama warmup failed: %s", e)


# ── Registry ──────────────────────────────────────────────────────────────────

ProviderDict = dict[str, Any]


def build_provider_registry() -> dict[str, ProviderDict]:
    registry: dict[str, ProviderDict] = {}

    registry["ollama"] = {
        "enabled": OLLAMA_ENABLED,
        "call": lambda p: call_ollama(p),
        "model": OLLAMA_MODEL,
    }
    registry["groq"] = {
        "enabled": bool(GROQ_API_KEY),
        "call": lambda p: call_openai_compatible(
            "groq", GROQ_API_KEY, GROQ_BASE_URL, GROQ_MODEL, p, GROQ_TIMEOUT),
        "model": GROQ_MODEL,
    }
    registry["cerebras"] = {
        "enabled": bool(CEREBRAS_API_KEY),
        "call": lambda p: call_openai_compatible(
            "cerebras", CEREBRAS_API_KEY, CEREBRAS_BASE_URL, CEREBRAS_MODEL, p,
            CEREBRAS_TIMEOUT),
        "model": CEREBRAS_MODEL,
    }
    registry["gemini"] = {
        "enabled": bool(GEMINI_API_KEY),
        "call": None,
        "model": "gemini-2.5-flash",
    }
    registry["mistral"] = {
        "enabled": bool(MISTRAL_API_KEY),
        "call": lambda p: call_openai_compatible(
            "mistral", MISTRAL_API_KEY, MISTRAL_BASE_URL, MISTRAL_MODEL, p,
            MISTRAL_TIMEOUT),
        "model": MISTRAL_MODEL,
    }
    registry["openrouter"] = {
        "enabled": bool(OPENROUTER_API_KEY),
        "call": lambda p: call_openai_compatible(
            "openrouter", OPENROUTER_API_KEY, OPENROUTER_BASE_URL,
            OPENROUTER_MODEL, p, OPENROUTER_TIMEOUT),
        "model": OPENROUTER_MODEL,
    }
    return registry


def call_gemini_direct(prompt: str, model: Any) -> str:
    response = model.generate_content(prompt)
    return response.text.strip()


# ── Chain caller ──────────────────────────────────────────────────────────────

def call_provider_chain(
    prompt: str,
    registry: dict[str, ProviderDict],
    gemini_model: Any,
) -> tuple[str | None, str]:
    """
    Iterate through the configured provider chain.
    Returns (raw_json_response, provider_name) or (None, "unknown").
    """
    for provider_name in DIAGNOSIS_PROVIDER_CHAIN:
        provider = registry.get(provider_name)
        if not provider or not provider["enabled"]:
            continue

        log.info("Trying %s (%s)...", provider_name, provider["model"])
        start = time.time()

        try:
            if provider_name == "gemini":
                raw = call_gemini_direct(prompt, gemini_model)
            else:
                assert provider["call"] is not None
                raw = provider["call"](prompt)

            raw = raw.strip()
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)
            json.loads(raw)  # validate

            elapsed = time.time() - start
            log.info("✓ %s responded in %.1fs", provider_name, elapsed)
            return raw, provider_name

        except requests.exceptions.RequestException as e:
            log.warning("⚠ %s unreachable (%s) — trying next...", provider_name, e)
        except json.JSONDecodeError:
            log.warning("⚠ %s returned invalid JSON — trying next...", provider_name)
        except Exception as e:
            log.warning("⚠ %s error (%s) — trying next...", provider_name, e)

    return None, "unknown"
