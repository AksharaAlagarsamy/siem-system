# ingestion/log_simulator.py
"""
Simulates realistic auth.log entries for local testing.
Generates:
  - Normal user logins
  - Brute force attacks (rapid failed logins from same IP)
  - Off-hours logins
  - Root login attempts
"""

import random
import time
from datetime import datetime, timedelta
from streaming.producer import SIEMProducer

# Realistic test data pools
NORMAL_USERS  = ["alice", "bob", "carol", "dave", "eve"]
ATTACK_IPS    = ["192.168.100.55", "10.0.0.99", "172.16.5.200"]
NORMAL_IPS    = ["192.168.1.10", "192.168.1.20", "10.10.0.5"]
SERVICES      = ["sshd", "sudo", "su", "login"]

def make_auth_log_line(
    timestamp: datetime,
    status: str,      # "Accepted" or "Failed"
    username: str,
    ip: str,
    service: str = "sshd"
) -> str:
    """Format a line that matches real auth.log format."""
    ts = timestamp.strftime("%b %d %H:%M:%S")
    hostname = "ubuntu-server"
    port = random.randint(40000, 65000)

    if status == "Accepted":
        msg = f"Accepted password for {username} from {ip} port {port} ssh2"
    else:
        msg = f"Failed password for {username} from {ip} port {port} ssh2"

    return f"{ts} {hostname} {service}[{random.randint(1000,9999)}]: {msg}"


class LogSimulator:
    def __init__(self):
        self.producer = SIEMProducer()

    def simulate_normal_traffic(self, count: int = 20, delay: float = 0.5):
        """Simulate normal user login/logout activity."""
        print("[Simulator] Generating normal traffic...")
        for _ in range(count):
            log = make_auth_log_line(
                timestamp=datetime.now(),
                status=random.choice(["Accepted", "Accepted", "Failed"]),  # mostly success
                username=random.choice(NORMAL_USERS),
                ip=random.choice(NORMAL_IPS)
            )
            self.producer.send_raw_log(log)
            time.sleep(delay)

    def simulate_brute_force(self, attacker_ip: str = "192.168.100.55",
                              count: int = 30, delay: float = 0.05):
        """
        Simulate a brute force attack: rapid failed logins
        from a single IP against multiple usernames.
        """
        print(f"[Simulator] Simulating BRUTE FORCE from {attacker_ip}...")
        for i in range(count):
            username = random.choice(NORMAL_USERS + ["root", "admin", "test"])
            log = make_auth_log_line(
                timestamp=datetime.now(),
                status="Failed",
                username=username,
                ip=attacker_ip
            )
            self.producer.send_raw_log(log)
            print(f"  [BruteForce] Attempt {i+1}/{count} — user: {username}")
            time.sleep(delay)

    def simulate_off_hours_login(self):
        """Simulate a suspicious login at 3 AM."""
        late_night = datetime.now().replace(hour=3, minute=14, second=0)
        log = make_auth_log_line(
            timestamp=late_night,
            status="Accepted",
            username="alice",
            ip="203.0.113.45"   # external IP
        )
        print(f"[Simulator] Off-hours login at 03:14 AM")
        self.producer.send_raw_log(log)

    def run_full_scenario(self):
        """Run a complete test scenario: normal + attack traffic."""
        print("=== Starting SIEM Test Scenario ===")
        self.simulate_normal_traffic(count=10, delay=0.2)
        time.sleep(1)
        self.simulate_brute_force(count=25)
        time.sleep(1)
        self.simulate_off_hours_login()
        self.simulate_normal_traffic(count=5, delay=0.3)
        print("=== Scenario complete ===")
