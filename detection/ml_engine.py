import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import deque
from datetime import datetime, timedelta
from typing import Dict, Any
from config.settings import ML_CONTAMINATION

MODEL_PATH  = "ml_model.pkl"
SCALER_PATH = "ml_scaler.pkl"

class MLEngine:
    def __init__(self, buffer_size: int = 1000, min_train: int = 50):
        self.buffer       = deque(maxlen=buffer_size)
        self.min_train    = min_train
        self.model        = None
        self.scaler       = StandardScaler()
        self.is_trained   = False
        self.train_count  = 0
        self._new_since_train = 0
        self._ip_failures: Dict[str, deque] = {}
        self._load_model()

    def _load_model(self):
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                self.model      = joblib.load(MODEL_PATH)
                self.scaler     = joblib.load(SCALER_PATH)
                self.is_trained = True
                print("[MLEngine] Loaded saved model from disk")
        except Exception as e:
            print(f"[MLEngine] Could not load model: {e}")

    def _save_model(self):
        try:
            joblib.dump(self.model,  MODEL_PATH)
            joblib.dump(self.scaler, SCALER_PATH)
        except Exception as e:
            print(f"[MLEngine] Could not save model: {e}")

    def _get_ip_failure_rate(self, ip: str, now: datetime, window_secs: int = 300) -> float:
        if ip not in self._ip_failures:
            self._ip_failures[ip] = deque()
        q      = self._ip_failures[ip]
        cutoff = now - timedelta(seconds=window_secs)
        while q and q[0] < cutoff:
            q.popleft()
        return sum(1.0 * (1 - (now - ts).total_seconds() / window_secs) for ts in q)

    def _extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        try:
            ts   = datetime.fromisoformat(event.get("timestamp", ""))
            hour = ts.hour
        except Exception:
            hour = event.get("hour_of_day", 12)
            ts   = datetime.now()
        hour_sin     = np.sin(2 * np.pi * hour / 24)
        hour_cos     = np.cos(2 * np.pi * hour / 24)
        failed_flag  = 1 if event.get("status") == "failed" else 0
        is_root      = 1 if event.get("username") == "root" else 0
        is_off_hours = 1 if (hour >= 23 or hour <= 5) else 0
        ip = event.get("ip", "0.0.0.0")
        try:
            ip_last = int(ip.split(".")[-1])
        except Exception:
            ip_last = 0
        if failed_flag and ip:
            if ip not in self._ip_failures:
                self._ip_failures[ip] = deque()
            self._ip_failures[ip].append(ts)
        ip_failure_rate = self._get_ip_failure_rate(ip, ts)
        port      = event.get("port", 22)
        port_risk = 0 if port in (22, 80, 443, 8080, 8443) else 1
        return np.array([hour_sin, hour_cos, failed_flag, is_root,
                         ip_last, ip_failure_rate, is_off_hours, port_risk])

    def train(self):
        if len(self.buffer) < self.min_train:
            return
        X        = np.array([self._extract_features(e) for e in self.buffer])
        X_scaled = self.scaler.fit_transform(X)
        self.model = IsolationForest(
            contamination=ML_CONTAMINATION, n_estimators=150,
            max_samples="auto", random_state=42, n_jobs=-1)
        self.model.fit(X_scaled)
        self.is_trained       = True
        self.train_count     += 1
        self._new_since_train = 0
        self._save_model()
        print(f"[MLEngine] Trained on {len(X)} samples (run #{self.train_count}) — saved")

    def score(self, event: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(event)
        self.buffer.append(event)
        self._new_since_train += 1
        if self._new_since_train >= 100:
            self.train()
        if not self.is_trained:
            bf = features[2] == 1 and features[5] > 3
            return {"score": -1.0 if bf else 0.1, "norm_score": 80 if bf else 10,
                    "is_anomaly": bool(bf), "risk_bump": 25 if bf else 0}
        X          = self.scaler.transform([features])
        raw_score  = float(self.model.score_samples(X)[0])
        is_anomaly = self.model.predict(X)[0] == -1
        norm_score = max(0, min(100, int((-raw_score + 0.1) / 0.7 * 100)))
        risk_bump  = int(norm_score * 0.30) if is_anomaly else 0
        return {"score": raw_score, "norm_score": norm_score,
                "is_anomaly": bool(is_anomaly), "risk_bump": risk_bump}
