import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest
from datetime import datetime
from detection.rule_engine import RuleEngine

def make_event(status="failed", username="bob", ip="192.168.1.5", hour=14):
    return {"status": status, "username": username, "ip": ip,
            "hour_of_day": hour, "timestamp": datetime.now().isoformat()}

class TestRuleEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine()

    def test_brute_force_triggers(self):
        for _ in range(6):
            labels = self.engine.evaluate(make_event(ip="10.0.0.1"))
        self.assertIn("BRUTE_FORCE", labels)

    def test_brute_force_below_threshold(self):
        labels = []
        for _ in range(4):
            labels = self.engine.evaluate(make_event(ip="10.0.0.2"))
        self.assertNotIn("BRUTE_FORCE", labels)

    def test_root_login_triggers(self):
        labels = self.engine.evaluate(make_event(username="root"))
        self.assertIn("ROOT_LOGIN_ATTEMPT", labels)

    def test_off_hours_triggers(self):
        labels = self.engine.evaluate(make_event(status="success", hour=3))
        self.assertIn("OFF_HOURS_LOGIN", labels)

    def test_off_hours_not_daytime(self):
        labels = self.engine.evaluate(make_event(status="success", hour=14))
        self.assertNotIn("OFF_HOURS_LOGIN", labels)

    def test_ip_cycling_triggers(self):
        self.engine.evaluate(make_event(username="alice", ip="10.0.0.1"))
        self.engine.evaluate(make_event(username="alice", ip="10.0.0.2"))
        labels = self.engine.evaluate(make_event(username="alice", ip="10.0.0.3"))
        self.assertIn("IP_CYCLING", labels)

    def test_credential_stuffing_triggers(self):
        labels = []
        for u in ["alice","bob","carol","dave","eve"]:
            labels = self.engine.evaluate(make_event(ip="10.99.0.1", username=u))
        self.assertIn("CREDENTIAL_STUFFING", labels)

    def test_empty_event_no_crash(self):
        try:
            labels = self.engine.evaluate({})
            self.assertIsInstance(labels, list)
        except Exception as e:
            self.fail(f"Raised {e} on empty event")

    def test_normal_login_no_alerts(self):
        labels = self.engine.evaluate(
            make_event(status="success", username="alice", ip="192.168.1.1", hour=10))
        self.assertNotIn("BRUTE_FORCE", labels)
        self.assertNotIn("ROOT_LOGIN_ATTEMPT", labels)
        self.assertNotIn("OFF_HOURS_LOGIN", labels)

if __name__ == "__main__":
    unittest.main(verbosity=2)
