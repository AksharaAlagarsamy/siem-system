import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest
from datetime import datetime
from detection.ml_engine import MLEngine

def make_event(status="failed", username="bob", ip="192.168.1.5", hour=14, port=22):
    return {"status": status, "username": username, "ip": ip, "port": port,
            "hour_of_day": hour, "timestamp": datetime.now().replace(hour=hour).isoformat()}

class TestMLEngine(unittest.TestCase):

    def setUp(self):
        for f in ["ml_model.pkl", "ml_scaler.pkl"]:
            if os.path.exists(f): os.rename(f, f + ".bak")
        self.engine = MLEngine(buffer_size=200, min_train=50)

    def tearDown(self):
        for f in ["ml_model.pkl", "ml_scaler.pkl"]:
            if os.path.exists(f + ".bak"): os.rename(f + ".bak", f)

    def test_score_returns_keys(self):
        result = self.engine.score(make_event())
        for key in ["score", "is_anomaly", "risk_bump", "norm_score"]:
            self.assertIn(key, result)

    def test_score_before_training(self):
        result = self.engine.score(make_event(status="success"))
        self.assertIsInstance(result["is_anomaly"], bool)
        self.assertIsInstance(result["score"], float)

    def test_brute_force_heuristic(self):
        result = None
        for _ in range(10):
            result = self.engine.score(make_event(status="failed", ip="10.99.0.55"))
        self.assertTrue(result["is_anomaly"])
        self.assertGreater(result["risk_bump"], 0)

    def test_trains_after_min_events(self):
        """Send 100 events to trigger retraining — min_train=50, retrain every 100."""
        for i in range(100):
            self.engine.score(make_event(
                status="success" if i % 3 != 0 else "failed",
                ip=f"192.168.1.{i % 50}"))
        self.assertTrue(self.engine.is_trained)

    def test_trained_model_scores(self):
        """After training, scored events return float scores."""
        for i in range(100):
            self.engine.score(make_event(status="success", hour=10,
                                         ip=f"192.168.1.{i % 20}"))
        result = self.engine.score(make_event(
            status="failed", username="root", ip="10.99.0.1", hour=3))
        self.assertIsNotNone(result["score"])
        self.assertIsInstance(result["is_anomaly"], bool)

    def test_empty_event_no_crash(self):
        try:
            result = self.engine.score({})
            self.assertIn("score", result)
        except Exception as e:
            self.fail(f"Raised {e} on empty event")

    def test_malformed_ip_no_crash(self):
        try:
            result = self.engine.score(make_event(ip="not.valid.ip"))
            self.assertIn("score", result)
        except Exception as e:
            self.fail(f"Raised {e} on malformed IP")

if __name__ == "__main__":
    unittest.main(verbosity=2)
