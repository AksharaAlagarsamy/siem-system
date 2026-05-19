import random
import time
from datetime import datetime
from pipeline import SIEMProducer

NORMAL_USERS = ["alice", "bob", "carol", "dave", "eve"]
NORMAL_IPS   = ["192.168.1.10", "192.168.1.20", "10.10.0.5"]

def _make_log_line(timestamp, status, username, ip):
    ts   = timestamp.strftime("%b %d %H:%M:%S")
    port = random.randint(40000, 65000)
    pid  = random.randint(1000, 9999)
    msg  = f"Accepted password for {username} from {ip} port {port} ssh2" \
           if status == "Accepted" else \
           f"Failed password for {username} from {ip} port {port} ssh2"
    return f"{ts} ubuntu-server sshd[{pid}]: {msg}"

class LogSimulator:
    def __init__(self):
        self.producer = SIEMProducer()

    def simulate_normal_traffic(self, count=20, delay=0.3):
        print(f"[Simulator] Sending {count} normal events...")
        for _ in range(count):
            line = _make_log_line(datetime.now(),
                random.choice(["Accepted","Accepted","Failed"]),
                random.choice(NORMAL_USERS), random.choice(NORMAL_IPS))
            self.producer.send_raw_log(line)
            time.sleep(delay)

    def simulate_brute_force(self, ip="192.168.100.55", count=25, delay=0.05):
        print(f"[Simulator] Brute force from {ip}...")
        for i in range(count):
            user = random.choice(NORMAL_USERS + ["root","admin","test"])
            line = _make_log_line(datetime.now(), "Failed", user, ip)
            self.producer.send_raw_log(line)
            print(f"  Attempt {i+1}/{count} — user: {user}")
            time.sleep(delay)

    def simulate_off_hours_login(self):
        late = datetime.now().replace(hour=3, minute=14, second=0)
        line = _make_log_line(late, "Accepted", "alice", "203.0.113.45")
        print("[Simulator] Off-hours login at 03:14 AM...")
        self.producer.send_raw_log(line)

    def run_full_scenario(self):
        print("\n=== Test Scenario Starting ===")
        self.simulate_normal_traffic(count=10, delay=0.2)
        time.sleep(0.5)
        self.simulate_brute_force(count=20)
        time.sleep(0.5)
        self.simulate_off_hours_login()
        self.simulate_normal_traffic(count=5, delay=0.2)
        print("=== Done — open localhost:8501 ===\n")
