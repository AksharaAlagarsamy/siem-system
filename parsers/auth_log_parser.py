import re
from datetime import datetime
from typing import Optional, Dict, Any

PATTERNS = {
    "ssh_auth_iso": re.compile(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+"
        r"(\S+)\s+sshd\[(\d+)\]:\s+"
        r"(Accepted|Failed)\s+\w+\s+for\s+(?:invalid user\s+)?"
        r"(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)"
    ),
    "ssh_auth_old": re.compile(
        r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+sshd\[(\d+)\]:\s+"
        r"(Accepted|Failed)\s+\w+\s+for\s+(?:invalid user\s+)?"
        r"(\S+)\s+from\s+([\d.]+)\s+port\s+(\d+)"
    ),
}

CURRENT_YEAR = datetime.now().year


def parse_auth_log_line(raw_line: str) -> Optional[Dict[str, Any]]:
    # Try ISO format first (newer systems)
    m = PATTERNS["ssh_auth_iso"].search(raw_line)
    if m:
        ts_str, hostname, pid, status, username, ip, port = m.groups()
        try:
            ts = datetime.fromisoformat(ts_str)
        except Exception:
            ts = datetime.now()
        return {
            "timestamp":   ts.isoformat(),
            "hour_of_day": ts.hour,
            "hostname":    hostname,
            "service":     "sshd",
            "pid":         int(pid),
            "username":    username,
            "ip":          ip,
            "port":        int(port),
            "status":      "success" if status == "Accepted" else "failed",
            "event_type":  "ssh_login",
            "raw":         raw_line,
        }

    # Try old format (May 18 15:47:09)
    m = PATTERNS["ssh_auth_old"].search(raw_line)
    if m:
        ts_str, hostname, pid, status, username, ip, port = m.groups()
        try:
            ts = datetime.strptime(f"{CURRENT_YEAR} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        except Exception:
            ts = datetime.now()
        return {
            "timestamp":   ts.isoformat(),
            "hour_of_day": ts.hour,
            "hostname":    hostname,
            "service":     "sshd",
            "pid":         int(pid),
            "username":    username,
            "ip":          ip,
            "port":        int(port),
            "status":      "success" if status == "Accepted" else "failed",
            "event_type":  "ssh_login",
            "raw":         raw_line,
        }

    return {
        "timestamp":  datetime.now().isoformat(),
        "event_type": "unparsed",
        "raw":        raw_line,
    }
