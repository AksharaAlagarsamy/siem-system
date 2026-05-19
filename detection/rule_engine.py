from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Any
from config.settings import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECS

class RuleEngine:
    def __init__(self):
        self.failed_attempts: Dict[str, deque] = defaultdict(deque)
        self.user_ips: Dict[str, Dict] = defaultdict(
            lambda: {"ips": set(), "first_seen": datetime.now()})
        self.ip_usernames: Dict[str, Dict] = defaultdict(
            lambda: {"usernames": set(), "first_seen": datetime.now()})
        self.known_users: set = set()
        self.offender_counts: Dict[str, int] = defaultdict(int)
        self.rule_hits: Dict[str, int] = defaultdict(int)

    def _cleanup_window(self, ip, now):
        window = self.failed_attempts[ip]
        while window and (now - window[0]).total_seconds() > BRUTE_FORCE_WINDOW_SECS:
            window.popleft()

    def check_brute_force(self, event):
        if event.get("status") != "failed": return False
        ip = event.get("ip", "")
        try: now = datetime.fromisoformat(event.get("timestamp", ""))
        except: now = datetime.now()
        self.failed_attempts[ip].append(now)
        self._cleanup_window(ip, now)
        if len(self.failed_attempts[ip]) >= BRUTE_FORCE_THRESHOLD:
            self.offender_counts[ip] += 1
            print(f"[RuleEngine] BRUTE_FORCE from {ip} ({len(self.failed_attempts[ip])} attempts)")
            return True
        return False

    def check_root_login(self, event):
        return event.get("username") == "root"

    def check_off_hours(self, event):
        if event.get("status") != "success": return False
        hour = event.get("hour_of_day", 12)
        return hour >= 23 or hour <= 5

    def check_ip_cycling(self, event):
        username = event.get("username", "")
        ip       = event.get("ip", "")
        if not username or not ip: return False
        data    = self.user_ips[username]
        elapsed = (datetime.now() - data["first_seen"]).total_seconds()
        if elapsed > 300:
            data["ips"] = {ip}; data["first_seen"] = datetime.now(); return False
        data["ips"].add(ip)
        return len(data["ips"]) >= 3

    def check_credential_stuffing(self, event):
        if event.get("status") != "failed": return False
        ip = event.get("ip", ""); username = event.get("username", "")
        if not ip or not username: return False
        data    = self.ip_usernames[ip]
        elapsed = (datetime.now() - data["first_seen"]).total_seconds()
        if elapsed > 120:
            data["usernames"] = {username}; data["first_seen"] = datetime.now(); return False
        data["usernames"].add(username)
        if len(data["usernames"]) >= 5:
            print(f"[RuleEngine] CREDENTIAL_STUFFING from {ip}")
            return True
        return False

    def check_new_user(self, event):
        if event.get("status") != "success": return False
        username = event.get("username", "")
        if not username or username in self.known_users: return False
        self.known_users.add(username)
        return True

    def evaluate(self, event) -> List[str]:
        triggered = []
        checks = [
            ("BRUTE_FORCE",         self.check_brute_force),
            ("ROOT_LOGIN_ATTEMPT",  self.check_root_login),
            ("OFF_HOURS_LOGIN",     self.check_off_hours),
            ("IP_CYCLING",          self.check_ip_cycling),
            ("CREDENTIAL_STUFFING", self.check_credential_stuffing),
            ("NEW_USER_LOGIN",      self.check_new_user),
        ]
        for label, fn in checks:
            if fn(event):
                triggered.append(label)
                self.rule_hits[label] += 1
        return triggered
