# alerts/alert_manager.py
"""
Alert dispatcher — handles console, email, and Slack webhook alerts.
Implements severity-based throttling to prevent alert fatigue.
"""

import json
import smtplib
import requests
from datetime import datetime
from email.mime.text import MIMEText
from collections import defaultdict
from typing import Dict, Any
from config.settings import (
    ALERT_EMAIL_ENABLED, ALERT_EMAIL_TO, ALERT_EMAIL_FROM,
    SMTP_HOST, SMTP_PORT, SLACK_WEBHOOK_URL
)


# Throttle: don't re-alert the same IP more than once per 5 minutes
ALERT_THROTTLE_SECS = 300


class AlertManager:
    def __init__(self):
        # Track last alert time per IP to prevent flooding
        self._last_alerted: Dict[str, datetime] = defaultdict(
            lambda: datetime.min
        )

    def _is_throttled(self, event: Dict[str, Any]) -> bool:
        """Return True if we've recently alerted on this source IP."""
        key    = f"{event.get('ip', 'unknown')}:{','.join(event.get('labels', []))}"
        now    = datetime.now()
        last   = self._last_alerted[key]
        elapsed = (now - last).total_seconds()

        if elapsed < ALERT_THROTTLE_SECS:
            return True

        self._last_alerted[key] = now
        return False

    def _format_alert_message(self, event: Dict[str, Any]) -> str:
        """Format a human-readable alert message."""
        labels = ", ".join(event.get("labels", []))
        return (
            f"[SIEM ALERT]\n"
            f"Time      : {event.get('timestamp', 'N/A')}\n"
            f"Source IP : {event.get('ip', 'N/A')}\n"
            f"Username  : {event.get('username', 'N/A')}\n"
            f"Status    : {event.get('status', 'N/A')}\n"
            f"Risk Score: {event.get('risk_score', 0)}/100\n"
            f"Labels    : {labels}\n"
            f"ML Score  : {event.get('ml_score', 'N/A')}\n"
            f"Raw       : {event.get('raw', '')[:120]}"
        )

    def alert_console(self, event: Dict[str, Any]):
        """Print alert to stdout with clear formatting."""
        msg = self._format_alert_message(event)
        sep = "=" * 60
        print(f"\n{sep}\n{msg}\n{sep}\n")

    def alert_email(self, event: Dict[str, Any]):
        """Send an email alert (requires SMTP config)."""
        if not ALERT_EMAIL_ENABLED:
            return

        try:
            body    = self._format_alert_message(event)
            labels  = ", ".join(event.get("labels", []))
            msg     = MIMEText(body)
            msg["Subject"] = f"[SIEM] {labels} from {event.get('ip', 'unknown')}"
            msg["From"]    = ALERT_EMAIL_FROM
            msg["To"]      = ALERT_EMAIL_TO

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.sendmail(ALERT_EMAIL_FROM, [ALERT_EMAIL_TO], msg.as_string())

            print(f"[Alert] Email sent to {ALERT_EMAIL_TO}")
        except Exception as e:
            print(f"[Alert] Email failed: {e}")

    def alert_slack(self, event: Dict[str, Any]):
        """Send a Slack webhook alert."""
        if not SLACK_WEBHOOK_URL:
            return

        labels     = ", ".join(event.get("labels", []))
        risk_score = event.get("risk_score", 0)

        # Color-code by risk score
        color = "#ff0000" if risk_score >= 75 else "#ff9900" if risk_score >= 50 else "#ffcc00"

        payload = {
            "attachments": [{
                "color":   color,
                "title":   f"SIEM Alert: {labels}",
                "fields": [
                    {"title": "Source IP",  "value": event.get("ip", "N/A"),       "short": True},
                    {"title": "Username",   "value": event.get("username", "N/A"), "short": True},
                    {"title": "Risk Score", "value": str(risk_score),              "short": True},
                    {"title": "Status",     "value": event.get("status", "N/A"),   "short": True},
                ],
                "footer": f"SIEM @ {event.get('timestamp', 'N/A')}"
            }]
        }

        try:
            requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        except Exception as e:
            print(f"[Alert] Slack failed: {e}")

    def dispatch(self, event: Dict[str, Any]):
        """
        Main dispatch method — sends all enabled alert channels.
        Applies throttling to prevent flooding.
        """
        if self._is_throttled(event):
            return

        self.alert_console(event)
        self.alert_email(event)
        self.alert_slack(event)
