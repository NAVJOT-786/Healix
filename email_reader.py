#!/usr/bin/env python3
"""
IMAP email reply reader for approval-based healing.

Polls the inbox for replies to approval emails and parses them
for approve/reject keywords.
"""

from __future__ import annotations

import email
import imaplib
import logging
import re
import threading
import time
from email.header import decode_header
from typing import Any

log = logging.getLogger("healer.email_reader")

APPROVE_KEYWORDS = {"approve", "approved", "yes", "ok", "okay", "go", "go ahead", "proceed", "y", "confirm", "accept"}
REJECT_KEYWORDS = {"reject", "rejected", "no", "deny", "denied", "cancel", "n", "decline", "declined", "abort"}

SUBJECT_PATTERN = re.compile(r"\[AI-Heal-Approve:\s*([a-f0-9]{12})\]")


class EmailReplyReader:
    def __init__(
        self,
        imap_host: str,
        imap_port: int,
        user: str,
        password: str,
        poll_interval: int = 30,
    ) -> None:
        self._host = imap_host
        self._port = imap_port
        self._user = user
        self._password = password
        self._interval = poll_interval
        self._approval_store: Any = None
        self._send_rejected_fn: Any = None
        self._running = False
        self._processed_ids: set[bytes] = set()

    def start(self, approval_store: Any, send_rejected_fn: Any = None) -> threading.Thread:
        self._approval_store = approval_store
        self._send_rejected_fn = send_rejected_fn
        self._running = True
        t = threading.Thread(target=self._poll_loop, daemon=True, name="email-reader")
        t.start()
        log.info("Email reply reader started (IMAP: %s:%d, interval: %ds)", self._host, self._port, self._interval)
        return t

    def stop(self) -> None:
        self._running = False

    def _poll_loop(self) -> None:
        while self._running:
            try:
                self._poll_once()
            except Exception as e:
                log.error("Email reader poll error: %s", e)
            time.sleep(self._interval)

    def _poll_once(self) -> None:
        if not self._user or not self._password:
            return

        mail = None
        try:
            mail = imaplib.IMAP4_SSL(self._host, self._port)
            mail.login(self._user, self._password)
            mail.select("INBOX")

            status, messages = mail.search(None, 'SUBJECT "AI-Heal-Approve"')
            if status != "OK" or not messages[0]:
                log.debug("IMAP poll: no approval emails found")
                return

            msg_ids = messages[0].split()
            new_ids = [mid for mid in msg_ids if mid not in self._processed_ids]
            if not new_ids:
                log.debug("IMAP poll: no new approval emails (%d already processed)", len(msg_ids))
                return

            log.info("IMAP poll: found %d new approval email(s) out of %d", len(new_ids), len(msg_ids))
            for msg_id in new_ids:
                self._process_email(mail, msg_id)
                self._processed_ids.add(msg_id)

        except imaplib.IMAP4.error as e:
            log.warning("IMAP error: %s", e)
        except Exception as e:
            log.error("Email reader error: %s", e)
        finally:
            if mail:
                try:
                    mail.logout()
                except Exception:
                    pass

    def _process_email(self, mail: imaplib.IMAP4, msg_id: bytes) -> None:
        try:
            status, data = mail.fetch(msg_id, "(RFC822)")
            if status != "OK":
                return

            raw = data[0][1]
            msg = email.message_from_bytes(raw)

            subject = self._decode_subject(msg.get("Subject", ""))
            match = SUBJECT_PATTERN.search(subject)
            if not match:
                log.debug("Ignoring email without approval subject: %s", subject[:80])
                return

            approval_id = match.group(1)
            req = self._approval_store.get(approval_id) if self._approval_store else None
            if not req or req.status != "pending":
                log.info("Ignoring email for unknown/completed approval: %s (status: %s)", approval_id, req.status if req else "not found")
                return

            body = self._extract_body(msg)
            decision = self._parse_decision(body)

            if decision == "approve":
                if self._approval_store.approve(approval_id, by=f"email:{msg.get('From', 'unknown')}"):
                    log.info("Email reply APPROVED: %s", approval_id)
            elif decision == "reject":
                if self._approval_store.reject(approval_id, by=f"email:{msg.get('From', 'unknown')}"):
                    log.info("Email reply REJECTED: %s", approval_id)
                    if self._send_rejected_fn:
                        self._send_rejected_fn(
                            approval_id, req.target.get("name", ""),
                            req.location, f"email:{msg.get('From', 'unknown')}",
                        )
            else:
                log.info("Email reply unclear for %s: %s", approval_id, body[:100])

        except Exception as e:
            log.error("Error processing email %s: %s", msg_id, e)

    def _decode_subject(self, subject: str) -> str:
        decoded_parts = decode_header(subject)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(part)
        return " ".join(result)

    def _extract_body(self, msg: email.message.Message) -> str:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                cd = str(part.get("Content-Disposition", ""))
                if ct == "text/plain" and "attachment" not in cd:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html = payload.decode(charset, errors="replace")
                        return re.sub(r"<[^>]+>", " ", html)
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        return ""

    def _parse_decision(self, body: str) -> str | None:
        text = body.lower().strip()
        # Strip quoted reply text: lines starting with > or lines after "On ... wrote:"
        lines = text.split("\n")
        fresh_lines = []
        skip = False
        for line in lines:
            if re.match(r"^>+", line) or re.match(r"^-+$", line.strip()):
                skip = True
            if re.match(r"on .+ wrote:", line):
                skip = True
            if not skip:
                fresh_lines.append(line)
        clean = "\n".join(fresh_lines)
        words = set(re.findall(r"[a-z]+", clean))

        # Check REJECT first — user intent overrides quoted email text
        if words & REJECT_KEYWORDS:
            return "reject"
        if words & APPROVE_KEYWORDS:
            return "approve"
        return None
