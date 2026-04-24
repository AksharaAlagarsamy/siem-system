# streaming/producer.py
"""
Kafka producer — sends raw log lines to the 'raw-logs' topic.
Serializes as JSON for structured downstream processing.
"""

import json
from kafka import KafkaProducer
from config.settings import KAFKA_BOOTSTRAP_SERVERS, KAFKA_RAW_TOPIC


class SIEMProducer:
    def __init__(self):
        self.producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            # Serialize Python dicts to JSON bytes
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            # Retry up to 3 times on transient failures
            retries=3,
            # Wait for leader + all ISR replicas to acknowledge
            acks="all",
        )
        print(f"[Producer] Connected to Kafka: {KAFKA_BOOTSTRAP_SERVERS}")

    def send_raw_log(self, raw_line: str):
        """Send a raw log string to the raw-logs topic."""
        message = {"raw": raw_line}
        self.producer.send(KAFKA_RAW_TOPIC, value=message)

    def send_parsed_log(self, event: dict, topic: str = None):
        """Send a parsed/enriched event dict to a topic."""
        target = topic or KAFKA_RAW_TOPIC
        self.producer.send(target, value=event)

    def flush(self):
        """Block until all buffered messages are sent."""
        self.producer.flush()

    def close(self):
        self.flush()
        self.producer.close()
