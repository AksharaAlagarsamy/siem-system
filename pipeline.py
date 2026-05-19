import queue
from enrichments import enrich_event

_raw_log_queue = queue.Queue(maxsize=0)
_event_counter = 0

def get_event_count():
    return _event_counter

class SIEMProducer:
    def send_raw_log(self, raw_line: str):
        if raw_line and raw_line.strip():
            _raw_log_queue.put(raw_line.strip())
    def flush(self): pass
    def close(self): pass

class SIEMConsumer:
    def __init__(self):
        from parsers.auth_log_parser import parse_auth_log_line
        from parsers.normalizer       import normalize
        from detection.rule_engine    import RuleEngine
        from detection.ml_engine      import MLEngine
        from storage.sqlite_store     import init_db, insert_event, insert_alert
        from alerts.alert_manager     import AlertManager
        self.parse        = parse_auth_log_line
        self.normalize    = normalize
        self.rule_engine  = RuleEngine()
        self.ml_engine    = MLEngine()
        self.insert_event = insert_event
        self.insert_alert = insert_alert
        self.alert_mgr    = AlertManager()
        init_db()
        print("[Consumer] Ready — waiting for log events...")

    def _severity(self, score):
        if score >= 80: return "CRITICAL"
        if score >= 60: return "HIGH"
        if score >= 40: return "MEDIUM"
        return "LOW"

    def process(self, raw_line):
        global _event_counter
        event = self.parse(raw_line)
        if not event: return
        if event.get("event_type") == "unparsed": return
        event = self.normalize(event)
        labels = self.rule_engine.evaluate(event)
        if labels:
            event["labels"].extend(labels)
            event["risk_score"] = min(100, event["risk_score"] + min(50, len(labels) * 15))
        ml = self.ml_engine.score(event)
        event["ml_score"]      = ml["score"]
        event["ml_norm_score"] = ml.get("norm_score", 0)
        event["ml_anomaly"]    = ml["is_anomaly"]
        if ml["is_anomaly"]:
            event["labels"].append("ML_ANOMALY")
            event["risk_score"] = min(100, event["risk_score"] + ml["risk_bump"])
        event = enrich_event(event)
        event["severity"] = self._severity(event["risk_score"])
        self.insert_event(event)
        if event["risk_score"] >= 40 or event["labels"]:
            self.insert_alert(event, event["severity"])
        if event["risk_score"] >= 50 or event["labels"]:
            self.alert_mgr.dispatch(event)
        _event_counter += 1

    def run(self):
        while True:
            try:
                raw_line = _raw_log_queue.get(timeout=1)
                self.process(raw_line)
                _raw_log_queue.task_done()
            except queue.Empty:
                continue
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[Consumer] Error: {e}")
