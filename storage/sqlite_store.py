# storage/sqlite_store.py
"""
STEP 1 OF 4 — The shared data bridge.
Pipeline WRITES here. Dashboard READS from here.
Replaces every random.randint() in dashboard.py.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "siem_data.db"


def get_connection():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables + indexes. Safe to call multiple times."""
    conn = get_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                ip           TEXT,
                username     TEXT,
                status       TEXT,
                event_type   TEXT,
                risk_score   REAL    DEFAULT 0,
                ml_score     REAL,
                ml_anomaly   INTEGER DEFAULT 0,
                labels       TEXT,
                hour_of_day  INTEGER,
                raw          TEXT,
                created_at   TEXT    DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                ip          TEXT,
                username    TEXT,
                severity    TEXT,
                labels      TEXT,
                risk_score  REAL,
                raw         TEXT,
                created_at  TEXT    DEFAULT (datetime('now'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts     ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip     ON events(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)")
    conn.close()
    print(f"[SQLiteStore] Ready at {DB_PATH}")


def insert_event(event: dict):
    conn = get_connection()
    with conn:
        conn.execute("""
            INSERT INTO events
                (timestamp,ip,username,status,event_type,
                 risk_score,ml_score,ml_anomaly,labels,hour_of_day,raw)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            event.get("timestamp", datetime.now().isoformat()),
            event.get("ip"),
            event.get("username"),
            event.get("status"),
            event.get("event_type"),
            float(event.get("risk_score", 0)),
            float(event["ml_score"]) if event.get("ml_score") is not None else None,
            1 if event.get("ml_anomaly") else 0,
            json.dumps(event.get("labels", [])),
            event.get("hour_of_day"),
            (event.get("raw") or "")[:500],
        ))
    conn.close()


def insert_alert(event: dict, severity: str):
    conn = get_connection()
    with conn:
        conn.execute("""
            INSERT INTO alerts (timestamp,ip,username,severity,labels,risk_score,raw)
            VALUES (?,?,?,?,?,?,?)
        """, (
            event.get("timestamp", datetime.now().isoformat()),
            event.get("ip"), event.get("username"), severity,
            json.dumps(event.get("labels", [])),
            float(event.get("risk_score", 0)),
            (event.get("raw") or "")[:500],
        ))
    conn.close()


def get_login_summary(hours: int = 24) -> dict:
    conn = get_connection()
    row = conn.execute("""
        SELECT
            COUNT(*)                                             AS total,
            SUM(CASE WHEN status='success' THEN 1 ELSE 0 END)   AS success,
            SUM(CASE WHEN status='failed'  THEN 1 ELSE 0 END)   AS failed,
            SUM(CASE WHEN ml_anomaly=1     THEN 1 ELSE 0 END)   AS anomalies
        FROM events
        WHERE timestamp >= datetime('now', ? || ' hours')
    """, (f"-{hours}",)).fetchone()
    conn.close()
    return dict(row) if row else {"total":0,"success":0,"failed":0,"anomalies":0}


def get_top_ips(limit: int = 10) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT ip,
               COUNT(*)                                             AS total,
               SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)    AS failures,
               ROUND(MAX(risk_score),1)                             AS max_risk
        FROM events WHERE ip IS NOT NULL
        GROUP BY ip ORDER BY total DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_events_by_hour() -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT strftime('%H:00',timestamp)                          AS hour,
               COUNT(*)                                             AS total,
               SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)    AS failed
        FROM events
        WHERE timestamp >= datetime('now','-24 hours')
        GROUP BY strftime('%H',timestamp) ORDER BY hour
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_alerts(limit: int = 20) -> list:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_high_risk_events(threshold: float = 60.0, limit: int = 50) -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM events WHERE risk_score >= ?
        ORDER BY timestamp DESC LIMIT ?
    """, (threshold, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_label_counts() -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT labels, COUNT(*) AS cnt FROM events
        WHERE labels != '[]' AND labels IS NOT NULL
        GROUP BY labels ORDER BY cnt DESC LIMIT 20
    """).fetchall()
    conn.close()
    counts: dict = {}
    for row in rows:
        try:
            for label in json.loads(row["labels"]):
                counts[label] = counts.get(label, 0) + row["cnt"]
        except Exception:
            pass
    return [{"label": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]

def get_mitre_summary() -> list:
    conn = get_connection()
    rows = conn.execute("""
        SELECT labels, COUNT(*) AS cnt FROM events
        WHERE labels != '[]' AND labels IS NOT NULL
        GROUP BY labels ORDER BY cnt DESC LIMIT 20
    """).fetchall()
    conn.close()
    from enrichments import MITRE_MAPPING
    import json
    counts = {}
    for row in rows:
        try:
            for label in json.loads(row["labels"]):
                mitre = MITRE_MAPPING.get(label, "")
                key = f"{label} ({mitre})" if mitre else label
                counts[key] = counts.get(key, 0) + row["cnt"]
        except Exception:
            pass
    return [{"label": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]
