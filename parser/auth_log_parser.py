# parser/auth_log_parser.py
"""
Parses Linux auth.log format into a normalized event dictionary.

Example input line:
  Jan 15 14:23:01 ubuntu-server sshd[12345]: Failed password for bob from 192.168.1.5 port 52341 ssh2

Output schema:
  {
    "timestamp": "2024-01-15T14:23:01",
    "hostname":  "ubuntu-server",
    "service":   "sshd",
    "pid":       12345,
    "username":  "bob",
    "ip":        "192.168.1.5",
    "port":      52341,
    "status":    "failed",
    "raw":       "<original line>"
  }
"""

import re
from datetime import datetime
from typing import Optional, Dict, Any


# Regex patterns for auth.log
PATTERNS = {
    # Matches: "Jan 15 14:23:01 hostname service[pid]: Accepted/Failed password for USER from IP port PORT"
    "ssh_auth": re.compile(
        r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"   # timestamp
        r"(\S+)\s+"                                    # hostname
        r"(\w+)\[(\d+)\]:\s+"                         # service[pid]
        r"(Accepted|Failed)\s+\w+\s+for\s+"           # status
        r"(\S+)\s+from\s+"                             # username
        r"([\d.]+)\s+port\s+(\d+)"                     # IP + port
    ),

    # Matches sudo usage: "USER : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"
    "sudo": re.compile(
        r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+sudo\[\d+\]:\s+"
        r"(\S+)\s+:\s+.*COMMAND=(.*)"
    ),
}

CURRENT_YEAR = datetime.now().year


def parse_auth_log_line(raw_line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single auth.log line into a structured event.
    Returns None if the line doesn't match any known pattern.
    """
    # ── SSH login/failure ──────────────────────────────────────────────────
    m = PATTERNS["ssh_auth"].search(raw_line)
    if m:
        ts_str, hostname, service, pid, status, username, ip, port = m.groups()

        # Parse timestamp (auth.log has no year — assume current year)
        try:
            ts = datetime.strptime(f"{CURRENT_YEAR} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = datetime.now()

        return {
            "timestamp":    ts.isoformat(),
            "hour_of_day":  ts.hour,
            "hostname":     hostname,
            "service":      service,
            "pid":          int(pid),
            "username":     username,
            "ip":           ip,
            "port":         int(port),
            "status":       "success" if status == "Accepted" else "failed",
            "event_type":   "ssh_login",
            "raw":          raw_line,
        }

    # ── Sudo command ───────────────────────────────────────────────────────
    m = PATTERNS["sudo"].search(raw_line)
    if m:
        ts_str, hostname, username, command = m.groups()
        try:
            ts = datetime.strptime(f"{CURRENT_YEAR} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = datetime.now()

        return {
            "timestamp":    ts.isoformat(),
            "hour_of_day":  ts.hour,
            "hostname":     hostname,
            "service":      "sudo",
            "username":     username,
            "command":      command.strip(),
            "event_type":   "sudo_command",
            "raw":          raw_line,
        }

    # Line didn't match any pattern — return raw for debugging
    return {
        "timestamp":  datetime.now().isoformat(),
        "event_type": "unparsed",
        "raw":        raw_line,
    }
