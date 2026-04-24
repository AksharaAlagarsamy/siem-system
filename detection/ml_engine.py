# detection/ml_engine.py
"""
Machine Learning anomaly detection using Isolation Forest.

Features used per event:
  - login_hour       : hour of day (0-23)
  - failed_flag      : 1 if failed, 0 if success
  - is_root          : 1 if username is root
  - ip_last_octet    : last octet of IP (rough proxy for IP range)
  - attempts_in_window: recent failed login count for this IP

The model trains on incoming data and periodically retrains.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import deque
from datetime import datetime
from typing import Dict, Any
from config.settings import ML_CONTAMINATION


class MLEngine:
    def __init__(self, buffer_size: int = 500, min_train: int = 50):
        """
        buffer_size : number of recent events kept for (re)training
        min_train   : minimum events before first training
        """
        self.buffer       = deque(maxlen=buffer_size)
        self.min_train    = min_train
        self.model        = None
        self.scaler       = StandardScaler()
        self.is_trained   = False
        self.train_count  = 0

        # Sliding window for per-IP failure count
        self._ip_fail_counts: Dict[str, int] = {}

    def _extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """
        Convert a log event into a fixed-size numeric feature vector.
        """
        # Hour of day (0–23)
        try:
            ts   = datetime.fromisoformat(event.get("timestamp", ""))
            hour = ts.hour
        except Exception:
            hour = event.get("hour_of_day", 12)

        # Failed login flag
        failed_flag = 1 if event.get("status") == "failed" else 0

        # Root user flag
        is_root = 1 if event.get("username") == "root" else 0

        # IP last octet (rough numeric representation)
        ip = event.get("ip", "0.0.0.0")
        try:
            ip_last = int(ip.split(".")[-1])
        except Exception:
            ip_last = 0

        # Recent failure count for this IP
        ip_key         = event.get("ip", "unknown")
        if failed_flag:
            self._ip_fail_counts[ip_key] = self._ip_fail_counts.get(ip_key, 0) + 1
        ip_fail_count  = self._ip_fail_counts.get(ip_key, 0)

        return np.array([hour, failed_flag, is_root, ip_last, ip_fail_count])

    def train(self):
        """Train (or retrain) the Isolation Forest on buffered events."""
        if len(self.buffer) < self.min_train:
            return

        X = np.array([self._extract_features(e) for e in self.buffer])
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            contamination=ML_CONTAMINATION,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        self.train_count += 1
        print(f"[MLEngine] Model trained on {len(X)} samples (run #{self.train_count})")

    def score(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score an event for anomaly likelihood.
        Returns:
          - score      : float, lower = more anomalous (-1.0 to 0.0+)
          - is_anomaly : bool
        """
        features = self._extract_features(event)
        self.buffer.append(event)

        # Retrain every 100 events once we have enough data
        if len(self.buffer) % 100 == 0:
            self.train()

        # If model not yet trained, use a heuristic fallback
        if not self.is_trained:
            heuristic_anomaly = (features[1] == 1 and features[4] > 3)
            return {
                "score":      -1.0 if heuristic_anomaly else 0.1,
                "is_anomaly": heuristic_anomaly,
            }

        X = self.scaler.transform([features])
        raw_score   = self.model.score_samples(X)[0]
        is_anomaly  = self.model.predict(X)[0] == -1   # -1 = anomaly in sklearn

        return {
            "score":      float(raw_score),
            "is_anomaly": bool(is_anomaly),
        }
