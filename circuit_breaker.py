#!/usr/bin/env python3
"""
Circuit breaker — prevents repeated failed heals on the same target.

States:
  closed  → normal operation
  open    → backoff period, healing blocked
  half-open → cooldown expired, one test heal allowed

Transitions:
  closed  → (threshold exceeded in window) → open
  open    → (cooldown expired)             → half-open
  half-open → (heal succeeds)             → closed
  half-open → (heal fails)               → open
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from storage import StorageBackend

log = logging.getLogger("healer.circuit_breaker")


class CircuitBreaker:
    def __init__(
        self,
        storage: "StorageBackend",
        threshold: int = 3,
        window_min: int = 60,
        cooldown_min: int = 1440,
    ):
        self._storage = storage
        self.threshold = threshold
        self.window_min = window_min
        self.cooldown_min = cooldown_min

    def can_heal(self, target_id: str) -> tuple[bool, str]:
        state = self._storage.get_circuit_state(target_id)
        if state is None:
            return True, "first heal"

        now = datetime.now(timezone.utc)

        if state["state"] == "open":
            cooldown_until = state.get("cooldown_until")
            if cooldown_until and cooldown_until.tzinfo is None:
                cooldown_until = cooldown_until.replace(tzinfo=timezone.utc)
            if cooldown_until and now < cooldown_until:
                remaining = (cooldown_until - now).total_seconds() / 60
                return False, (
                    f"circuit OPEN ({state['heal_count']} failures in "
                    f"{self.window_min}m) — cooldown {remaining:.0f}m remaining"
                )
            self._transition(target_id, "half-open", state)
            return True, "circuit half-open — test heal allowed"

        if state["state"] == "half-open":
            return True, "circuit half-open — test heal"

        if state["state"] == "closed":
            first = state.get("first_heal_at")
            if first and first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            if first and (now - first).total_seconds() / 60 < self.window_min:
                if state["heal_count"] >= self.threshold:
                    cooldown_until = now + timedelta(minutes=self.cooldown_min)
                    state["state"] = "open"
                    state["cooldown_until"] = cooldown_until
                    self._storage.upsert_circuit_state(state)
                    self._storage.audit_log("circuit_opened", target_id, {
                        "heal_count": state["heal_count"],
                        "threshold": self.threshold,
                        "cooldown_until": cooldown_until.isoformat(),
                    })
                    return False, (
                        f"circuit OPENED — {state['heal_count']} heals in "
                        f"{(now - first).total_seconds() / 60:.0f}m, "
                        f"cooldown {self.cooldown_min}m"
                    )

        return True, "circuit closed"

    def record_heal(self, target_id: str, action: str, success: bool) -> None:
        now = datetime.now(timezone.utc)
        state = self._storage.get_circuit_state(target_id)

        if success:
            self._storage.upsert_circuit_state({
                "target_id": target_id,
                "heal_count": 0,
                "state": "closed",
                "first_heal_at": None,
                "last_heal_at": now,
                "last_action": action,
                "last_success": True,
                "cooldown_until": None,
            })
            if state and state["state"] == "half-open":
                self._storage.audit_log("circuit_closed", target_id,
                                        {"action": action})
            log.info("Circuit breaker CLOSED for %s (heal succeeded)", target_id)
        else:
            count = (state["heal_count"] if state else 0) + 1
            first = (state.get("first_heal_at") if state else None) or now
            new_state = "closed"
            cooldown = None
            if state and state["state"] == "half-open":
                new_state = "open"
                cooldown = now + timedelta(minutes=self.cooldown_min)
            self._storage.upsert_circuit_state({
                "target_id": target_id,
                "heal_count": count,
                "state": new_state,
                "first_heal_at": first,
                "last_heal_at": now,
                "last_action": action,
                "last_success": False,
                "cooldown_until": cooldown,
            })
            log.info("Circuit breaker: %s heal %d/%d failed for %s",
                     state["state"] if state else "closed",
                     count, self.threshold, target_id)

    def get_state(self, target_id: str) -> dict:
        state = self._storage.get_circuit_state(target_id)
        if state is None:
            return {"target_id": target_id, "state": "closed",
                    "heal_count": 0, "first_seen": None}
        return {
            "target_id": state["target_id"],
            "state": state["state"],
            "heal_count": state["heal_count"],
            "first_seen": str(state.get("first_heal_at", "")),
            "last_heal": str(state.get("last_heal_at", "")),
            "last_action": state.get("last_action", ""),
            "last_success": state.get("last_success"),
            "cooldown_until": str(state.get("cooldown_until", "")),
        }

    def _transition(self, target_id: str, new_state: str, current: dict) -> None:
        current["state"] = new_state
        self._storage.upsert_circuit_state(current)
        self._storage.audit_log(f"circuit_{new_state}", target_id, {})
