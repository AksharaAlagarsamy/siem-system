# config/settings.py
import os
from dotenv import load_dotenv

load_dotenv()

# ── Kafka ──────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_RAW_TOPIC         = "raw-logs"
KAFKA_PARSED_TOPIC      = "parsed-logs"
KAFKA_ALERT_TOPIC       = "alerts"
KAFKA_GROUP_ID          = "siem-consumer-group"

# ── Elasticsearch ──────────────────────────────────────────────────────────
ES_HOST        = os.getenv("ES_HOST", "localhost")
ES_PORT        = int(os.getenv("ES_PORT", 9200))
ES_LOG_INDEX   = "siem-logs"
ES_ALERT_INDEX = "siem-alerts"

# ── Detection ──────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = 5    # failed logins within window
BRUTE_FORCE_WINDOW_SECS = 60   # time window in seconds
ML_CONTAMINATION        = 0.05 # expected anomaly ratio (5%)
ML_RETRAIN_INTERVAL     = 3600 # retrain model every 1 hour

# ── Alerts ─────────────────────────────────────────────────────────────────
ALERT_EMAIL_ENABLED  = False
ALERT_EMAIL_TO       = os.getenv("ALERT_EMAIL_TO", "admin@lab.com")
ALERT_EMAIL_FROM     = os.getenv("ALERT_EMAIL_FROM", "siem@lab.com")
SMTP_HOST            = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT            = int(os.getenv("SMTP_PORT", 587))
SLACK_WEBHOOK_URL    = os.getenv("SLACK_WEBHOOK_URL", "")

# ── Logging ────────────────────────────────────────────────────────────────
LOG_FILE_PATH = "/var/log/auth.log"
