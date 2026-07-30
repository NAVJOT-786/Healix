#!/usr/bin/env python3
"""
PostgreSQL storage backend — circuit breaker, diagnoses, approvals, audit log.
"""

from __future__ import annotations

import json
import logging
import secrets
import uuid
import bcrypt
import psycopg2
import psycopg2.pool
import psycopg2.extras
from datetime import datetime, timezone, timedelta
from typing import Any

log = logging.getLogger("healer.storage")


class StorageBackend:
    def __init__(self, dsn: str, max_conn: int = 5):
        self.pool = psycopg2.pool.ThreadedConnectionPool(1, max_conn, dsn)
        self._migrate()

    def _conn(self):
        return self.pool.getconn()

    def _put(self, conn):
        self.pool.putconn(conn)

    def _migrate(self):
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS circuit_breaker (
                    target_id     TEXT PRIMARY KEY,
                    heal_count    INTEGER NOT NULL DEFAULT 0,
                    state         TEXT NOT NULL DEFAULT 'closed',
                    first_heal_at TIMESTAMPTZ,
                    last_heal_at  TIMESTAMPTZ,
                    last_action   TEXT,
                    last_success  BOOLEAN,
                    cooldown_until TIMESTAMPTZ,
                    updated_at    TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS diagnoses (
                    id                  SERIAL PRIMARY KEY,
                    uuid                TEXT UNIQUE,
                    timestamp           TIMESTAMPTZ DEFAULT NOW(),
                    platform            TEXT, name TEXT, namespace TEXT,
                    location            TEXT, deployment TEXT,
                    status              TEXT, restarts INTEGER,
                    action              TEXT, route TEXT,
                    is_developer_issue  BOOLEAN,
                    llm_model           TEXT, llm_latency REAL,
                    summary             TEXT, root_cause TEXT,
                    recommendation      TEXT, logs TEXT,
                    action_result       TEXT, cost_data TEXT,
                    success             BOOLEAN
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    id                  TEXT PRIMARY KEY,
                    created_at          TIMESTAMPTZ DEFAULT NOW(),
                    status              TEXT NOT NULL DEFAULT 'pending',
                    target_name         TEXT, namespace TEXT,
                    location            TEXT, deployment TEXT,
                    platform            TEXT, issue_type TEXT,
                    restarts            INTEGER, action TEXT,
                    summary             TEXT, root_cause TEXT,
                    recommendation      TEXT,
                    used_model          TEXT, cost_data TEXT,
                    is_developer_issue  BOOLEAN,
                    approved_by         TEXT, approved_at TIMESTAMPTZ,
                    rejected_by         TEXT,
                    action_result       TEXT, rolled_back BOOLEAN DEFAULT FALSE
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id          SERIAL PRIMARY KEY,
                    event       TEXT NOT NULL,
                    target_id   TEXT NOT NULL,
                    details     JSONB,
                    created_at  TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS users (
                    id              SERIAL PRIMARY KEY,
                    username        TEXT UNIQUE NOT NULL,
                    email           TEXT UNIQUE NOT NULL,
                    password_hash   TEXT NOT NULL,
                    can_view_dashboard BOOLEAN DEFAULT TRUE,
                    can_view_pods   BOOLEAN DEFAULT FALSE,
                    can_view_approvals BOOLEAN DEFAULT FALSE,
                    can_approve     BOOLEAN DEFAULT FALSE,
                    can_admin       BOOLEAN DEFAULT FALSE,
                    reset_token     TEXT,
                    reset_token_expiry TIMESTAMPTZ,
                    created_at      TIMESTAMPTZ DEFAULT NOW(),
                    updated_at      TIMESTAMPTZ DEFAULT NOW()
                );
                ALTER TABLE diagnoses ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT FALSE;
                ALTER TABLE approvals ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT FALSE;
                CREATE INDEX IF NOT EXISTS idx_diagnoses_route ON diagnoses(route);
                CREATE INDEX IF NOT EXISTS idx_diagnoses_deleted ON diagnoses(deleted);
                CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
                CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_id);
            """)
            conn.commit()

            cur.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cur.fetchone()[0] == 0:
                pwh = bcrypt.hashpw(b"sharry786", bcrypt.gensalt()).decode()
                cur.execute("""
                    INSERT INTO users (username, email, password_hash,
                        can_view_dashboard, can_view_pods, can_view_approvals,
                        can_approve, can_admin)
                    VALUES (%s, %s, %s, TRUE, TRUE, TRUE, TRUE, TRUE)
                    ON CONFLICT (username) DO NOTHING
                """, ("admin", "admin@healix.local", pwh))
                conn.commit()
                log.info("Default admin user seeded (admin / sharry786)")

            log.info("Database migrated — tables ready")
        except Exception as e:
            log.error("Migration failed: %s", e)
            raise
        finally:
            self._put(conn)

    # ── Circuit Breaker ──────────────────────────────────────────

    def get_circuit_state(self, target_id: str) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM circuit_breaker WHERE target_id = %s", (target_id,))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            self._put(conn)

    def upsert_circuit_state(self, state: dict) -> None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO circuit_breaker
                    (target_id, heal_count, state, first_heal_at, last_heal_at,
                     last_action, last_success, cooldown_until, updated_at)
                VALUES (%(target_id)s, %(heal_count)s, %(state)s,
                        %(first_heal_at)s, %(last_heal_at)s,
                        %(last_action)s, %(last_success)s,
                        %(cooldown_until)s, NOW())
                ON CONFLICT (target_id) DO UPDATE SET
                    heal_count    = EXCLUDED.heal_count,
                    state         = EXCLUDED.state,
                    first_heal_at = EXCLUDED.first_heal_at,
                    last_heal_at  = EXCLUDED.last_heal_at,
                    last_action   = EXCLUDED.last_action,
                    last_success  = EXCLUDED.last_success,
                    cooldown_until= EXCLUDED.cooldown_until,
                    updated_at    = NOW()
            """, state)
            conn.commit()
        finally:
            self._put(conn)

    # ── Diagnoses ────────────────────────────────────────────────

    def record_diagnosis(self, **kwargs) -> str:
        uid = uuid.uuid4().hex[:12]
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO diagnoses
                    (uuid, platform, name, namespace, location, deployment,
                     status, restarts, action, route,
                     is_developer_issue, llm_model, llm_latency,
                     summary, root_cause, recommendation, logs,
                     action_result, cost_data, success)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                uid, kwargs.get("platform"), kwargs.get("name"),
                kwargs.get("namespace", ""), kwargs.get("location"),
                kwargs.get("deployment", ""), kwargs.get("status"),
                kwargs.get("restarts"), kwargs.get("action"), kwargs.get("route"),
                kwargs.get("is_developer_issue"), kwargs.get("llm_model"),
                kwargs.get("llm_latency"), kwargs.get("summary"),
                kwargs.get("root_cause"), kwargs.get("recommendation"),
                kwargs.get("logs"), kwargs.get("action_result"),
                kwargs.get("cost_data"), kwargs.get("success"),
            ))
            conn.commit()
            return uid
        finally:
            self._put(conn)

    def mark_diagnosis_deleted(self, uuid: str) -> bool:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE diagnoses SET deleted = TRUE WHERE uuid = %s", (uuid,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            self._put(conn)

    def mark_stale_diagnoses(self, alive_keys: set[str], platform: str | None = None) -> int:
        conn = self._conn()
        try:
            cur = conn.cursor()
            if platform:
                cur.execute("SELECT uuid, platform, namespace, name, location FROM diagnoses WHERE deleted = FALSE AND platform = %s", (platform,))
            else:
                cur.execute("SELECT uuid, platform, namespace, name, location FROM diagnoses WHERE deleted = FALSE")
            rows = cur.fetchall()
            count = 0
            for row in rows:
                uid, platform, namespace, name, location = row
                if platform == "k8s":
                    key = f"k8s/{namespace}/{name}"
                elif platform == "docker":
                    key = f"docker/{location}/{name}"
                else:
                    continue
                if key not in alive_keys:
                    cur.execute("UPDATE diagnoses SET deleted = TRUE WHERE uuid = %s", (uid,))
                    count += 1
            conn.commit()
            return count
        finally:
            self._put(conn)

    def get_diagnoses(self, limit: int = 50, deleted: bool | None = None) -> list[dict]:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            if deleted is None:
                cur.execute("SELECT * FROM diagnoses ORDER BY timestamp DESC LIMIT %s", (limit,))
            else:
                cur.execute("SELECT * FROM diagnoses WHERE deleted = %s ORDER BY timestamp DESC LIMIT %s", (deleted, limit))
            return [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)

    def mark_approval_deleted(self, approval_id: str) -> bool:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE approvals SET deleted = TRUE WHERE id = %s", (approval_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            self._put(conn)

    def mark_stale_approvals(self, alive_keys: set[str], platform: str | None = None) -> int:
        conn = self._conn()
        try:
            cur = conn.cursor()
            if platform:
                cur.execute("SELECT id, platform, namespace, target_name, location FROM approvals WHERE deleted = FALSE AND platform = %s", (platform,))
            else:
                cur.execute("SELECT id, platform, namespace, target_name, location FROM approvals WHERE deleted = FALSE")
            rows = cur.fetchall()
            count = 0
            for row in rows:
                aid, plat, namespace, target_name, location = row
                if plat == "k8s":
                    key = f"k8s/{namespace}/{target_name}"
                elif plat == "docker":
                    key = f"docker/{location}/{target_name}"
                else:
                    continue
                if key not in alive_keys:
                    cur.execute("UPDATE approvals SET deleted = TRUE WHERE id = %s", (aid,))
                    count += 1
            conn.commit()
            return count
        finally:
            self._put(conn)

    def diagnose_total_count(self) -> int:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM diagnoses")
            return cur.fetchone()[0]
        finally:
            self._put(conn)

    # ── Approvals ────────────────────────────────────────────────

    def create_approval(self, **kwargs) -> None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO approvals
                    (id, status, target_name, namespace, location, deployment,
                     platform, issue_type, restarts, action,
                     summary, root_cause, recommendation,
                     used_model, cost_data, is_developer_issue)
                VALUES (%s, 'pending', %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s)
            """, (
                kwargs["id"], kwargs.get("target_name"),
                kwargs.get("namespace", ""), kwargs.get("location"),
                kwargs.get("deployment", ""), kwargs.get("platform"),
                kwargs.get("issue_type"), kwargs.get("restarts"),
                kwargs.get("action"), kwargs.get("summary"),
                kwargs.get("root_cause"), kwargs.get("recommendation"),
                kwargs.get("used_model"), kwargs.get("cost_data"),
                kwargs.get("is_developer_issue"),
            ))
            conn.commit()
        finally:
            self._put(conn)

    def get_approval(self, approval_id: str) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM approvals WHERE id = %s", (approval_id,))
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            self._put(conn)

    def set_approval_status(self, approval_id: str, status: str,
                            **extra: Any) -> bool:
        conn = self._conn()
        try:
            cur = conn.cursor()
            sets = ["status = %s"]
            params: list[Any] = [status]
            if "approved_by" in extra:
                sets.append("approved_by = %s")
                params.append(extra["approved_by"])
                sets.append("approved_at = NOW()")
            if "rejected_by" in extra:
                sets.append("rejected_by = %s")
                params.append(extra["rejected_by"])
            if "action_result" in extra:
                sets.append("action_result = %s")
                params.append(extra["action_result"])
            if "rolled_back" in extra:
                sets.append("rolled_back = %s")
                params.append(extra["rolled_back"])
            params.append(approval_id)
            cur.execute(
                f"UPDATE approvals SET {', '.join(sets)} WHERE id = %s",
                params,
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            self._put(conn)

    def get_pending_approvals(self) -> list[dict]:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)

    def get_all_approvals(self) -> list[dict]:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM approvals ORDER BY created_at DESC")
            return [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)

    # ── Audit Log ────────────────────────────────────────────────

    def audit_log(self, event: str, target_id: str, details: dict | None = None) -> None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO audit_log (event, target_id, details) VALUES (%s, %s, %s)",
                (event, target_id, json.dumps(details or {})),
            )
            conn.commit()
        finally:
            self._put(conn)

    def get_audit_log(self, limit: int = 100) -> list[dict]:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT %s", (limit,))
            return [dict(r) for r in cur.fetchall()]
        finally:
            self._put(conn)

    # ── Users ────────────────────────────────────────────────────

    def user_count(self) -> int:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users")
            return cur.fetchone()[0]
        finally:
            self._put(conn)

    def create_user(self, username: str, email: str, password: str,
                    can_view_dashboard: bool = True,
                    can_view_pods: bool = False,
                    can_view_approvals: bool = False,
                    can_approve: bool = False,
                    can_admin: bool = False) -> dict | None:
        pwh = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("""
                INSERT INTO users
                    (username, email, password_hash,
                     can_view_dashboard, can_view_pods, can_view_approvals,
                     can_approve, can_admin)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, username, email,
                    can_view_dashboard, can_view_pods, can_view_approvals,
                    can_approve, can_admin, created_at
            """, (username, email, pwh,
                  can_view_dashboard, can_view_pods, can_view_approvals,
                  can_approve, can_admin))
            conn.commit()
            row = cur.fetchone()
            return self._serialize_user(row) if row else None
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            return None
        finally:
            self._put(conn)

    def get_user_by_username(self, username: str) -> dict | None:
        conn = self._conn()
    @staticmethod
    def _serialize_user(row: dict) -> dict:
        d = dict(row)
        d.pop("password_hash", None)
        for key in ("created_at", "updated_at", "reset_token_expiry"):
            if isinstance(d.get(key), datetime):
                d[key] = d[key].isoformat() if d[key] else None
        return d

    def get_user_by_username(self, username: str) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            return self._serialize_user(row) if row else None
        finally:
            self._put(conn)

    def get_user_by_email(self, email: str) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            return self._serialize_user(row) if row else None
        finally:
            self._put(conn)

    def verify_password(self, username: str, password: str) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                return None
            user = dict(row)
            pwh = user.get("password_hash", "")
            if pwh and bcrypt.checkpw(password.encode(), pwh.encode()):
                return self._serialize_user(row)
            return None
        finally:
            self._put(conn)

    def update_user_permissions(self, user_id: int, **perms: bool) -> bool:
        allowed = {"can_view_dashboard", "can_view_pods", "can_view_approvals",
                   "can_approve", "can_admin"}
        sets = []
        params = []
        for k, v in perms.items():
            if k in allowed:
                sets.append(f"{k} = %s")
                params.append(v)
        if not sets:
            return False
        params.append(user_id)
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute(f"UPDATE users SET {', '.join(sets)}, updated_at = NOW() WHERE id = %s", params)
            conn.commit()
            return cur.rowcount > 0
        finally:
            self._put(conn)

    def update_password(self, user_id: int, new_password: str) -> bool:
        pwh = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET password_hash = %s, updated_at = NOW() WHERE id = %s",
                        (pwh, user_id))
            conn.commit()
            return cur.rowcount > 0
        finally:
            self._put(conn)

    def set_reset_token(self, email: str) -> str | None:
        user = self.get_user_by_email(email)
        if not user:
            return None
        token = uuid.uuid4().hex + secrets.token_urlsafe(16)
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE id = %s",
                        (token, expiry, user["id"]))
            conn.commit()
            return token
        finally:
            self._put(conn)

    def verify_reset_token(self, token: str) -> dict | None:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM users WHERE reset_token = %s AND reset_token_expiry > NOW()", (token,))
            row = cur.fetchone()
            return self._serialize_user(row) if row else None
        finally:
            self._put(conn)

    def clear_reset_token(self, user_id: int) -> None:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET reset_token = NULL, reset_token_expiry = NULL WHERE id = %s", (user_id,))
            conn.commit()
        finally:
            self._put(conn)

    def delete_user(self, user_id: int) -> bool:
        conn = self._conn()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            self._put(conn)

    def list_users(self) -> list[dict]:
        conn = self._conn()
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT id, username, email, can_view_dashboard, can_view_pods, can_view_approvals, can_approve, can_admin, created_at FROM users ORDER BY created_at ASC")
            return [self._serialize_user(r) for r in cur.fetchall()]
        finally:
            self._put(conn)
