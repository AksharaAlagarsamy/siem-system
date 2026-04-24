# storage/elastic_client.py
"""
Elasticsearch client — indexes parsed + enriched log events.
Creates index templates with proper field mappings on startup.
"""

from elasticsearch import Elasticsearch
from datetime import datetime
from config.settings import ES_HOST, ES_PORT, ES_LOG_INDEX, ES_ALERT_INDEX


# Index mapping for SIEM logs
LOG_INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "timestamp":     {"type": "date"},
            "hostname":      {"type": "keyword"},
            "service":       {"type": "keyword"},
            "username":      {"type": "keyword"},
            "ip":            {"type": "ip"},
            "port":          {"type": "integer"},
            "status":        {"type": "keyword"},
            "event_type":    {"type": "keyword"},
            "hour_of_day":   {"type": "integer"},
            "is_failed":     {"type": "boolean"},
            "is_root":       {"type": "boolean"},
            "is_off_hours":  {"type": "boolean"},
            "risk_score":    {"type": "float"},
            "ml_score":      {"type": "float"},
            "ml_anomaly":    {"type": "boolean"},
            "labels":        {"type": "keyword"},
            "raw":           {"type": "text"},
        }
    },
    "settings": {
        "number_of_shards":   1,
        "number_of_replicas": 0,    # Single-node dev setup
    }
}


class ElasticClient:
    def __init__(self):
        self.es = Elasticsearch(
            [{"host": ES_HOST, "port": ES_PORT, "scheme": "http"}]
        )
        self._ensure_indices()

    def _ensure_indices(self):
        """Create indices with mappings if they don't exist yet."""
        for index in [ES_LOG_INDEX, ES_ALERT_INDEX]:
            if not self.es.indices.exists(index=index):
                self.es.indices.create(index=index, body=LOG_INDEX_MAPPING)
                print(f"[Elastic] Created index: {index}")

    def index_log(self, event: dict):
        """Index a log event into Elasticsearch."""
        try:
            self.es.index(index=ES_LOG_INDEX, body=event)
        except Exception as e:
            print(f"[Elastic] Indexing error: {e}")

    def index_alert(self, alert: dict):
        """Index an alert event separately."""
        try:
            self.es.index(index=ES_ALERT_INDEX, body=alert)
        except Exception as e:
            print(f"[Elastic] Alert indexing error: {e}")

    def search_recent(self, minutes: int = 5, size: int = 100):
        """
        Search for log events from the last N minutes.
        Useful for dashboard widgets or quick status checks.
        """
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{minutes}m",
                        "lte": "now"
                    }
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": size,
        }
        result = self.es.search(index=ES_LOG_INDEX, body=query)
        return [hit["_source"] for hit in result["hits"]["hits"]]

    def get_top_ips(self, top_n: int = 10):
        """Aggregate top source IPs by event count."""
        query = {
            "size": 0,
            "aggs": {
                "top_ips": {
                    "terms": {"field": "ip", "size": top_n}
                }
            }
        }
        result = self.es.search(index=ES_LOG_INDEX, body=query)
        return result["aggregations"]["top_ips"]["buckets"]
