#!/usr/bin/env python3
"""
Notifications — email senders (dev alert, resolution, infra report, self-heal)
and n8n webhook notifier. Includes cost data in reports.
"""

from __future__ import annotations

import socket
import smtplib
import logging
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import (
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_FROM,
    DEV_EMAILS, OPS_EMAILS, DRY_RUN,
    N8N_WEBHOOK_URL, N8N_TIMEOUT_SEC, APPROVAL_DASHBOARD_URL,
)
from cost import format_cost_summary

log = logging.getLogger("notifications")


# ── SMTP helper ───────────────────────────────────────────────────────────────

def _smtp_send(recipients: list[str], msg: MIMEMultipart, label: str) -> None:
    if not SMTP_USER or not SMTP_PASSWORD:
        log.warning("SMTP not configured — skipping %s email", label)
        return
    if not recipients:
        log.warning("No recipients for %s email", label)
        return
    try:
        if DRY_RUN:
            log.info("[DRY RUN] Would send %s email to: %s", label, ", ".join(recipients))
            return
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, recipients, msg.as_string())
        log.info("%s email sent to: %s", label, ", ".join(recipients))
    except Exception as e:
        log.error("Failed to send %s email: %s", label, e)


# ── Email builders ────────────────────────────────────────────────────────────

def _email_head(title: str, color: str, badge_text: str, badge_color: str,
                badge_extra: str = "") -> str:
    extra_badge = ""
    if badge_extra:
        extra_badge = f'<span class="badge-type">{badge_extra}</span>'
    return f"""<!DOCTYPE html><html><head><style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 20px; }}
.card {{ background: #fff; border-radius: 8px; padding: 28px 32px; max-width: 680px; margin: auto; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }}
h1 {{ color: {color}; font-size: 22px; margin-top: 0; }}
.badge {{ display: inline-block; background: {badge_color}20; color: {badge_color}; border-radius: 4px; padding: 3px 10px; font-size: 13px; font-weight: 600; }}
.badge-type {{ display: inline-block; background: #fef9e7; color: #7d6608; border-radius: 4px; padding: 3px 10px; font-size: 13px; font-weight: 600; margin-left: 6px; }}
.badge-plat {{ display: inline-block; background: #eef1f7; color: #34495e; border-radius: 4px; padding: 3px 10px; font-size: 12px; font-weight: 600; margin-left: 6px; }}
.section {{ margin: 20px 0; }}
.label {{ font-weight: 600; color: #555; font-size: 13px; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 4px; }}
.value {{ color: #222; font-size: 15px; line-height: 1.5; }}
.code {{ background: #1e1e2e; color: #cdd6f4; font-family: monospace; font-size: 13px; border-radius: 6px; padding: 14px 16px; white-space: pre-wrap; word-break: break-all; max-height: 260px; overflow-y: auto; }}
.action-box {{ background: {badge_color}15; border-left: 4px solid {badge_color}; padding: 12px 16px; border-radius: 4px; color: {badge_color}; font-size: 14px; }}
.cost-box {{ background: #eef4fb; border-left: 4px solid #2980b9; padding: 12px 16px; border-radius: 4px; color: #1a5276; font-size: 13px; font-family: monospace; }}
.footer {{ margin-top: 28px; font-size: 12px; color: #aaa; border-top: 1px solid #eee; padding-top: 14px; }}
table.meta {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
table.meta td {{ padding: 6px 10px; font-size: 14px; border-bottom: 1px solid #f0f0f0; }}
table.meta td:first-child {{ color: #777; width: 140px; }}
</style></head><body><div class="card">
<h1>{title}</h1>
<span class="badge" style="background:{badge_color}20;color:{badge_color}">{badge_text}</span>{extra_badge}"""


def _email_meta(name: str, location: str, timestamp: str, extra_rows: str = "") -> str:
    rows = f"""
<tr><td>Name</td><td><strong>{name}</strong></td></tr>
<tr><td>Location</td><td>{location}</td></tr>
<tr><td>Time (UTC)</td><td>{timestamp}</td></tr>{extra_rows}
</table></div>"""
    return f'<div class="section"><table class="meta">{rows}'


def _email_sections(*sections: tuple[str, str, str]) -> str:
    """sections: list of (label, content, box_class)"""
    html = ""
    for label, content, cls in sections:
        html += f'<div class="section"><div class="label">{label}</div><div class="{cls}">{content}</div></div>'
    return html


def _email_footer(agent_version: str = "") -> str:
    return f'<div class="footer">Healix - Dry-run: {"ON" if DRY_RUN else "OFF"}</div></div></body></html>'


# ── Dev alert email ──────────────────────────────────────────────────────────

def send_dev_email(
    target_name: str, location: str, summary: str, root_cause: str,
    recommendation: str, logs_snippet: str, action_result: str,
    platform: str, cost_data: str = "",
) -> None:
    recipients = [e.strip() for e in DEV_EMAILS if e.strip()]
    if not recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    badge_plat = "KUBERNETES" if platform == "k8s" else "DOCKER"

    html = _email_head(
        "Pod / Container Issue - Developer Action Required",
        "#c0392b", "MANUAL INTERVENTION NEEDED", "#c0392b", badge_plat,
    )
    html += _email_meta(target_name, location, ts)
    html += _email_sections(
        ("Summary", summary, "value"),
        ("Root Cause", root_cause, "value"),
        ("Recommendation", recommendation, "value"),
        ("Agent Status", f"The agent could NOT auto-heal this issue. {action_result}", "action-box"),
        ("Recent Logs", logs_snippet[:1800].replace("<", "&lt;").replace(">", "&gt;"), "code"),
    )
    if cost_data:
        html += _email_sections(("Cost Impact", cost_data, "cost-box"))
    html += _email_footer()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Alert] Manual fix required - {target_name} ({location})"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "dev-alert")


# ── Resolution email ─────────────────────────────────────────────────────────

def send_resolution_email(
    target_name: str, location: str, summary: str, root_cause: str,
    action_taken: str, recommendation: str, logs_snippet: str,
    issue_type: str, platform: str, cost_data: str = "",
) -> None:
    recipients = list({e.strip() for e in OPS_EMAILS + DEV_EMAILS if e.strip()})
    if not recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    badge_plat = "KUBERNETES" if platform == "k8s" else "DOCKER"

    html = _email_head(
        "Auto-Healed Successfully",
        "#1a7a3f", "SELF-RESOLVED", "#27ae60", issue_type,
    )
    html += f'<span class="badge-plat">{badge_plat}</span>'
    html += _email_meta(target_name, location, ts, f'\n<tr><td>Issue type</td><td>{issue_type}</td></tr>')
    html += _email_sections(
        ("Summary", summary, "value"),
        ("Root Cause Identified", root_cause, "value"),
        ("Healing Action Applied", action_taken, "action-box"),
        ("Recommendation (to prevent recurrence)", recommendation, "value"),
        ("Recent Logs", logs_snippet[:1800].replace("<", "&lt;").replace(">", "&gt;"), "code"),
    )
    if cost_data:
        html += _email_sections(("Cost Impact", cost_data, "cost-box"))
    html += _email_footer()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Resolved] {issue_type} auto-healed - {target_name} ({location})"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "resolution")


# ── Infra report email ───────────────────────────────────────────────────────

def send_infra_report_email(
    target_name: str, location: str, summary: str, root_cause: str,
    recommended_action: str, recommendation: str, logs_snippet: str,
    issue_type: str, platform: str, cost_data: str = "",
) -> None:
    recipients = list({e.strip() for e in OPS_EMAILS + DEV_EMAILS if e.strip()})
    if not recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    badge_plat = "KUBERNETES" if platform == "k8s" else "DOCKER"

    html = _email_head(
        "Infra Issue Detected - No Auto-Fix Applied",
        "#b8860b", "REPORT ONLY", "#7d6608", badge_plat,
    )
    html += _email_meta(target_name, location, ts, f'\n<tr><td>Issue type</td><td>{issue_type}</td></tr>')
    html += _email_sections(
        ("Summary", summary, "value"),
        ("Root Cause", root_cause, "value"),
        ("Recommended Action (NOT applied - report-only)", recommended_action, "action-box"),
        ("Recommendation", recommendation, "value"),
        ("Recent Logs", logs_snippet[:1800].replace("<", "&lt;").replace(">", "&gt;"), "code"),
    )
    if cost_data:
        html += _email_sections(("Cost Impact", cost_data, "cost-box"))
    html += '<div class="footer">Healix - Mode: REPORT ONLY (no actions executed)</div></div></body></html>'

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Issue Detected] {issue_type} - {target_name} ({location}) - action recommended"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "infra-issue-report")


# ── Self-heal email ──────────────────────────────────────────────────────────

def send_self_heal_email(restarted_at: str) -> None:
    all_recipients = list({e.strip() for e in DEV_EMAILS + OPS_EMAILS if e.strip()})
    if not all_recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    hostname = socket.gethostname()

    html = _email_head(
        "Agent Self-Healed Successfully",
        "#27ae60", "AUTO-RESOLVED", "#27ae60",
    )
    html += _email_meta("ai-healer", hostname, ts,
        f'\n<tr><td>Previous crash at</td><td>{restarted_at}</td></tr>'
        f'\n<tr><td>Recovery method</td><td>Watchdog auto-restart</td></tr>')
    html += _email_sections(
        ("What happened",
         "The Healix process crashed or became unresponsive. "
         "The watchdog sidecar detected the failure and automatically restarted the agent. "
         "No manual intervention was required.",
         "value"),
        ("Current status",
         "Agent is running and actively monitoring containers. All systems operational.",
         "value"),
    )
    html += '<div class="footer">Healix (self-heal notification)</div></div></body></html>'

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Self-Healed] Healix restarted itself on {hostname}"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(all_recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(all_recipients, msg, "self-heal")


# ── Rollback escalation email ────────────────────────────────────────────────

def send_rollback_email(
    target_name: str, location: str, action: str, rollback_msg: str,
    root_cause: str, logs_snippet: str, platform: str,
) -> None:
    recipients = list({e.strip() for e in DEV_EMAILS + OPS_EMAILS if e.strip()})
    if not recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    badge_plat = "KUBERNETES" if platform == "k8s" else "DOCKER"

    html = _email_head(
        "Heal Action Failed - Rollback Applied",
        "#e67e22", "ROLLBACK", "#e67e22", badge_plat,
    )
    html += _email_meta(target_name, location, ts)
    html += _email_sections(
        ("Failed Action", f"{action} was applied but pod did not recover", "action-box"),
        ("Root Cause", root_cause, "value"),
        ("Rollback Applied", rollback_msg, "action-box"),
        ("Recommendation", "Manual investigation required. The automated fix did not resolve the issue.", "value"),
        ("Recent Logs", logs_snippet[:1800].replace("<", "&lt;").replace(">", "&gt;"), "code"),
    )
    html += _email_footer()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Rollback] Heal failed for {target_name} ({location}) — manual action needed"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "rollback-escalation")


# ── Approval request email ───────────────────────────────────────────────────

def send_approval_email(
    approval_id: str,
    target_name: str,
    location: str,
    params: dict,
    issue_type: str,
    platform: str,
    restarts: int,
    cost_data: str,
    logs_snippet: str,
) -> None:
    recipients = [e.strip() for e in DEV_EMAILS + OPS_EMAILS if e.strip()]
    if not recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    badge_plat = "KUBERNETES" if platform == "k8s" else "DOCKER"
    base_url = APPROVAL_DASHBOARD_URL.rstrip("/") if APPROVAL_DASHBOARD_URL else ""
    approve_url = f"{base_url}/approve/{approval_id}" if base_url else ""
    reject_url = f"{base_url}/reject/{approval_id}" if base_url else ""

    action_desc = params.get("action", "unknown")
    reason = params.get("reason", "No reason provided")
    summary = params.get("summary", "Issue detected")
    root_cause = params.get("root_cause", "See logs")
    recommendation = params.get("recommendation", "Review recommended")

    action_buttons = ""
    if approve_url and reject_url:
        action_buttons = f"""
<div style="margin:24px 0;text-align:center">
  <a href="{approve_url}" style="display:inline-block;background:#27ae60;color:#fff;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px;margin:0 8px">APPROVE & EXECUTE</a>
  <a href="{reject_url}" style="display:inline-block;background:#c0392b;color:#fff;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px;margin:0 8px">REJECT</a>
</div>
<div style="text-align:center;color:#888;font-size:12px;margin-bottom:16px">Or reply to this email with: <strong>approve</strong> / <strong>reject</strong></div>"""
    else:
        action_buttons = f"""
<div class="action-box" style="background:#fff3cd;border-left:4px solid #f39c12;color:#856404">
  Approval ID: <strong>{approval_id}</strong> — Set APPROVAL_DASHBOARD_URL in .env to enable one-click approval buttons.
</div>"""

    html = _email_head(
        "Approval Required — Healing Action Paused",
        "#e67e22", "APPROVAL REQUIRED", "#e67e22", badge_plat,
    )
    html += _email_meta(target_name, location, ts, f"""
<tr><td>Approval ID</td><td><strong style="font-family:monospace">{approval_id}</strong></td></tr>
<tr><td>Issue Type</td><td>{issue_type}</td></tr>
<tr><td>Restarts</td><td>{restarts}</td></tr>
<tr><td>Recommended Action</td><td><strong>{action_desc}</strong></td></tr>""")
    html += _email_sections(
        ("Issue Summary", summary, "value"),
        ("Root Cause", root_cause, "value"),
        ("Recommended Action", recommendation, "value"),
        ("Reason", reason, "action-box"),
    )
    if cost_data:
        html += _email_sections(("Estimated Cost Impact", cost_data, "cost-box"))
    html += f"""
<div class="section">
  <div class="label">Action Required</div>
  {action_buttons}
</div>"""
    html += _email_sections(
        ("Logs", logs_snippet[:1800].replace("<", "&lt;").replace(">", "&gt;"), "code"),
    )
    html += _email_footer()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Action Required] Approve healing: {target_name} ({location}) [AI-Heal-Approve: {approval_id}]"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "approval-request")


# ── Approval executed email ──────────────────────────────────────────────────

def send_approval_executed_email(
    approval_id: str,
    target_name: str,
    location: str,
    action: str,
    action_result: str,
    approved_by: str,
    platform: str,
) -> None:
    recipients = [e.strip() for e in DEV_EMAILS + OPS_EMAILS if e.strip()]
    if not recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    badge_plat = "KUBERNETES" if platform == "k8s" else "DOCKER"

    html = _email_head(
        "Healing Action Executed (Approved)",
        "#27ae60", "APPROVAL EXECUTED", "#27ae60", badge_plat,
    )
    html += _email_meta(target_name, location, ts, f"""
<tr><td>Approval ID</td><td><strong style="font-family:monospace">{approval_id}</strong></td></tr>
<tr><td>Action</td><td><strong>{action}</strong></td></tr>
<tr><td>Approved By</td><td>{approved_by}</td></tr>""")
    html += _email_sections(
        ("Execution Result", action_result, "action-box"),
    )
    html += _email_footer()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Approved & Executed] {action} on {target_name} ({location})"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "approval-executed")


# ── Approval rejected email ──────────────────────────────────────────────────

def send_approval_rejected_email(
    approval_id: str,
    target_name: str,
    location: str,
    rejected_by: str,
) -> None:
    recipients = [e.strip() for e in DEV_EMAILS + OPS_EMAILS if e.strip()]
    if not recipients:
        return
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = _email_head(
        "Healing Action Rejected",
        "#c0392b", "REJECTED", "#c0392b",
    )
    html += _email_meta(target_name, location, ts, f"""
<tr><td>Approval ID</td><td><strong style="font-family:monospace">{approval_id}</strong></td></tr>
<tr><td>Rejected By</td><td>{rejected_by}</td></tr>""")
    html += _email_sections(
        ("Status", f"Healing action for <strong>{target_name}</strong> was rejected by {rejected_by}. The issue remains unresolved.", "action-box"),
    )
    html += _email_footer()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Rejected] Healing rejected for {target_name} ({location})"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "approval-rejected")


# ── User welcome email ────────────────────────────────────────────────────────

def send_welcome_email(email: str, username: str, password: str) -> None:
    recipients = [email]

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; margin: 0; padding: 20px; }}
.card {{ background: #fff; border-radius: 12px; padding: 36px 40px; max-width: 520px; margin: 40px auto; box-shadow: 0 4px 24px rgba(0,0,0,0.08); }}
.logo {{ text-align: center; margin-bottom: 24px; }}
.logo svg {{ width: 48px; height: 48px; }}
.logo h1 {{ font-size: 22px; color: #1a1a2e; margin: 8px 0 0; letter-spacing: -0.5px; }}
.badge {{ display: inline-block; background: #27ae6015; color: #27ae60; border-radius: 20px; padding: 4px 14px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }}
h2 {{ font-size: 18px; color: #1a1a2e; margin: 0 0 4px; }}
p {{ color: #555; font-size: 14px; line-height: 1.6; margin: 6px 0; }}
.creds {{ display: grid; gap: 10px; margin: 20px 0; }}
.creds-item {{ background: #f0f4ff; border: 1px solid #d0d9f0; border-radius: 10px; padding: 14px 18px; display: flex; align-items: center; }}
.creds-icon {{ width: 38px; height: 38px; line-height: 38px; text-align: center; border-radius: 8px; font-size: 18px; display: inline-block; vertical-align: middle; flex-shrink: 0; margin-right: 14px; }}
.creds-icon.user {{ background: #e8f0fe; }}
.creds-icon.lock {{ background: #fef3e8; }}
.creds-body {{ flex: 1; min-width: 0; }}
.creds-label {{ font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
.creds-value {{ font-size: 15px; color: #1a1a2e; font-weight: 700; font-family: 'Courier New', monospace; word-break: break-all; margin-top: 2px; }}
.steps {{ margin: 20px 0; }}
.step {{ display: flex; padding: 14px 0; border-bottom: 1px solid #eee; align-items: flex-start; }}
.step:last-child {{ border-bottom: none; }}
.step-num {{ width: 28px; height: 28px; line-height: 28px; text-align: center; border-radius: 50%; background: #27ae60; color: #fff; font-size: 13px; font-weight: 700; display: inline-block; flex-shrink: 0; margin-right: 14px; box-shadow: 0 2px 6px rgba(39,174,96,0.3); }}
.step-text {{ font-size: 14px; color: #333; line-height: 1.5; padding-top: 3px; }}
.warning {{ background: #fff8e6; border-left: 4px solid #f39c12; padding: 12px 16px; border-radius: 6px; font-size: 13px; color: #7d6608; margin: 20px 0; line-height: 1.5; }}
.footer {{ margin-top: 28px; font-size: 12px; color: #aaa; border-top: 1px solid #eee; padding-top: 14px; text-align: center; }}
</style></head><body><div class="card">
<div class="logo">
<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
<circle cx="24" cy="24" r="22" stroke="#27ae60" stroke-width="2"/>
<path d="M16 24l6 6 10-12" stroke="#27ae60" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
<h1>Healix</h1>
</div>
<div style="text-align:center"><span class="badge">Account Created</span></div>
<h2 style="text-align:center">Welcome to Healix!</h2>
<p style="text-align:center">Your autonomous infrastructure healing account is ready.</p>

<div class="creds">
<div class="creds-item"><div class="creds-icon user">&#x1F464;</div><div class="creds-body"><div class="creds-label">Username</div><div class="creds-value">{username}</div></div></div>
<div class="creds-item"><div class="creds-icon lock">&#x1F511;</div><div class="creds-body"><div class="creds-label">Password</div><div class="creds-value">{password}</div></div></div>
</div>

<div class="steps">
<div class="step"><span class="step-num">1</span><span class="step-text">Go to the <strong>Healix Dashboard</strong> at your server address and log in</span></div>
<div class="step"><span class="step-num">2</span><span class="step-text">Use the <strong>username</strong> and <strong>password</strong> shown above to sign in</span></div>
<div class="step"><span class="step-num">3</span><span class="step-text">Change your password in <strong>User Settings</strong> after your first login</span></div>
</div>

<div class="warning">&#x26A0;&#xFE0F; For security, please change your password after first login. Keep these credentials private.</div>

<div class="footer">Healix — Autonomous Infrastructure Healing</div>
</div></body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Welcome to Healix — Your Account Has Been Created"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "user-welcome")


# ── Password reset email ──────────────────────────────────────────────────────

def send_password_reset_email(email: str, reset_link: str) -> None:
    recipients = [email]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = _email_head(
        "Healix — Password Reset Request",
        "#e67e22", "PASSWORD RESET", "#e67e22",
    )
    html += f"""
<div class="section">
  <div class="label">Reset Your Password</div>
  <div class="value" style="margin-top:8px">
    Click the button below to reset your password. This link expires in 1 hour.
  </div>
  <div style="margin:20px 0;text-align:center">
    <a href="{reset_link}" style="display:inline-block;background:#e67e22;color:#fff;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:600;font-size:15px">RESET PASSWORD</a>
  </div>
</div>"""
    html += _email_sections(
        ("Didn't request this?", "If you didn't request a password reset, you can safely ignore this email.", "value"),
    )
    html += _email_footer()

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Healix — Password Reset Request"
    msg["From"] = EMAIL_FROM
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html, "html"))
    _smtp_send(recipients, msg, "password-reset")


# ── n8n Notifier ─────────────────────────────────────────────────────────────

def notify_n8n(payload: dict) -> None:
    if not N8N_WEBHOOK_URL:
        log.info("N8N_WEBHOOK_URL not set — skipping n8n notification")
        return
    try:
        resp = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=N8N_TIMEOUT_SEC)
        if resp.status_code in (200, 201):
            log.info("n8n notified (HTTP %d, route=%s)", resp.status_code, payload.get("route"))
        else:
            log.warning("n8n responded HTTP %d: %s", resp.status_code, resp.text[:120])
    except requests.exceptions.ConnectionError:
        log.error("n8n connection refused — is n8n running on %s?", N8N_WEBHOOK_URL)
    except requests.exceptions.Timeout:
        log.error("n8n webhook timed out after %ds", N8N_TIMEOUT_SEC)
    except Exception as e:
        log.error("n8n notify failed: %s", e)
