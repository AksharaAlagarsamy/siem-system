# streaming/consumer.py
"""
Kafka consumer — reads from raw-logs, parses, detects, stores, and alerts.
This is the core processing pipeline.
"""

import json
from kafka import KafkaConsumer
from config.settings import (
    KAFKA_BOOTSTRAP_SERVERS, KAFKA_RAW_TOPIC, KAFKA_GROUP_ID
)
from parser.auth_log_parser import parse_auth_log_line
from parser.normalizer import normalize
from detection.rule_engine import RuleEngine
from detection.ml_engine import MLEngine
from storage.elastic_client import ElasticClient
from alerts.alert_manager import AlertManager


class SIEMConsumer:
    def __init__(self):
        self.consumer = KafkaConsumer(
            KAFKA_RAW_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id=KAFKA_GROUP_ID,
            auto_offset_reset="latest",          # Only process new messages
            enable_auto_commit=True,
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        )

        # Initialize all pipeline components
        self.rule_engine  = RuleEngine()
        self.ml_engine    = MLEngine()
        self.elastic      = ElasticClient()
        self.alert_mgr    = AlertManager()

        print(f"[Consumer] Listening on topic: {KAFKA_RAW_TOPIC}")

    def process_message(self, raw_message: dict):
        """
        Full processing pipeline for one log message:
          raw → parse → normalize → rule check → ML check → store → alert
        """
        raw_line = raw_message.get("raw", "")
        if not raw_line:
            return

        # Step 1: Parse the raw log line
        event = parse_auth_log_line(raw_line)
        if not event:
            return

        # Step 2: Normalize + add computed fields
        event = normalize(event)

        # Step 3: Rule-based detection
        rule_alerts = self.rule_engine.evaluate(event)
        if rule_alerts:
            event["labels"].extend(rule_alerts)
            event["risk_score"] = min(100, event["risk_score"] + 30)

        # Step 4: ML anomaly detection
        ml_result = self.ml_engine.score(event)
        event["ml_score"]    = ml_result["score"]
        event["ml_anomaly"]  = ml_result["is_anomaly"]
        if ml_result["is_anomaly"]:
            event["labels"].append("ML_ANOMALY")
            event["risk_score"] = min(100, event["risk_score"] + 25)

        # Step 5: Store to Elasticsearch
        self.elastic.index_log(event)

        # Step 6: Trigger alerts if high-risk
        if event["risk_score"] >= 50 or event["labels"]:
            self.alert_mgr.dispatch(event)

    def run(self):
        """Start consuming messages in a loop."""
        for msg in self.consumer:
            self.process_message(msg.value)
