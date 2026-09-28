"""Outbound email. Stdlib smtplib only — no vendor SDK for one send() call.

Same philosophy as /health: a missing capability is reported, not faked. With
no SMTP configured the message is logged instead of sent, so the reset flow
is still fully exercisable in dev (the token/link is right there in the log).
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from app.config import settings

log = logging.getLogger(__name__)


def send(to: str, subject: str, body: str) -> bool:
    if not settings.smtp_ready:
        log.info("SMTP not configured — email to %s not sent. Subject: %s\n%s", to, subject, body)
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg.set_content(body)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        log.warning("email send to %s failed: %s", to, exc)
        return False
