# detection/rule_engine.py
"""
Rule-based detection engine.
Evaluates each parsed event against predefined rules.
Maintains an in-memory sliding window for time-based rules.
"""

from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Any
from config.settings import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECS
)


class RuleEngine:
    def __init__(self):
        # Sliding window: ip → deque of timestamps of failed attempts
        self.failed_attempts: Dict[str, deque] = defaultdict(deque)

        # Track distinct IPs per user in a time window
        self.user_ips: Dict[str, Dict] = defaultdict(
            lambda: {"ips": set(), "first_seen": datetime.now()}
        )

    def _cleanup_window(self, ip: str, now: datetime):
        """Remove failed login timestamps outside the time window."""
        window = self.failed_attempts[ip]
        while window and (now - window[0]).total_seconds() > BRUTE_FORCE_WINDOW_SECS:
            window.popleft()

    def check_brute_force(self, event: Dict[str, Any]) -> bool:
        """
        RULE_001: Detect brute force.
        Trigger when >= BRUTE_FORCE_THRESHOLD failed logins from same IP
        within BRUTE_FORCE_WINDOW_SECS seconds.
        """
        if event.get("status") != "failed":
            return False

        ip  = event.get("ip", "")
        now = datetime.fromisoformat(event.get("timestamp", datetime.now().isoformat()))

        # Add this failure to the sliding window
        self.failed_attempts[ip].append(now)
        self._cleanup_window(ip, now)

        count = len(self.failed_attempts[ip])
        if count >= BRUTE_FORCE_THRESHOLD:
            print(f"[RuleEngine] BRUTE_FORCE detected from {ip} ({count} attempts)")
            return True

        return False

    def check_root_login(self, event: Dict[str, Any]) -> bool:
        """
        RULE_002: Any login attempt (success or fail) with username 'root'.
        """
        return event.get("username") == "root"

    def check_off_hours(self, event: Dict[str, Any]) -> bool:
        """
        RULE_003: Successful login between 11PM and 6AM local time.
        """
        if event.get("status") != "success":
            return False
        hour = event.get("hour_of_day", 12)
        return hour >= 23 or hour <= 5

    def check_ip_cycling(self, event: Dict[str, Any]) -> bool:
        """
        RULE_004: Single user logging in from 3+ different IPs
        within 5 minutes.
        """
        username = event.get("username", "")
        ip       = event.get("ip", "")
        if not username or not ip:
            return False

        user_data  = self.user_ips[username]
        first_seen = user_data["first_seen"]
        elapsed    = (datetime.now() - first_seen).total_seconds()

        if elapsed > 300:
            # Reset window
            user_data["ips"]        = {ip}
            user_data["first_seen"] = datetime.now()
            return False

        user_data["ips"].add(ip)
        return len(user_data["ips"]) >= 3

    def evaluate(self, event: Dict[str, Any]) -> List[str]:
        """
        Run all rules against an event.
        Returns a list of triggered rule labels.
        """
        triggered = []

        if self.check_brute_force(event):
            triggered.append("BRUTE_FORCE")

        if self.check_root_login(event):
            triggered.append("ROOT_LOGIN_ATTEMPT")

        if self.check_off_hours(event):
            triggered.append("OFF_HOURS_LOGIN")

        if self.check_ip_cycling(event):
            triggered.append("IP_CYCLING")

        return triggered
