from flask import Flask, jsonify
from flask_cors import CORS
from storage.sqlite_store import (
    init_db, get_login_summary, get_top_ips,
    get_events_by_hour, get_recent_alerts,
    get_label_counts, get_high_risk_events
)

app = Flask(__name__)
CORS(app)
init_db()

@app.route("/")
def index():
    return jsonify({"status": "SIEM API running"})

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/summary")
def summary():
    return jsonify(get_login_summary(hours=24))

@app.route("/api/top-ips")
def top_ips():
    return jsonify(get_top_ips(limit=10))

@app.route("/api/timeline")
def timeline():
    return jsonify(get_events_by_hour())

@app.route("/api/alerts")
def alerts():
    return jsonify(get_recent_alerts(limit=20))

@app.route("/api/threats")
def threats():
    return jsonify(get_label_counts())

@app.route("/api/high-risk")
def high_risk():
    return jsonify(get_high_risk_events(threshold=60.0, limit=50))

@app.route("/api/mitre")
def mitre():
    from storage.sqlite_store import get_mitre_summary
    return jsonify(get_mitre_summary())

@app.route("/api/geo")
def geo():
    import os
    import geoip2.database
    from storage.sqlite_store import get_connection
    conn = get_connection()
    rows = conn.execute("""
        SELECT ip, COUNT(*) as total FROM events
        WHERE ip IS NOT NULL
        GROUP BY ip ORDER BY total DESC LIMIT 20
    """).fetchall()
    conn.close()
    db_path = os.path.join(os.path.dirname(__file__), "GeoLite2-City.mmdb")
    if not os.path.exists(db_path):
        return jsonify({"error": "GeoLite2-City.mmdb not found"})
    results = []
    with geoip2.database.Reader(db_path) as reader:
        for row in rows:
            try:
                r = reader.city(row["ip"])
                results.append({
                    "ip":      row["ip"],
                    "total":   row["total"],
                    "country": r.country.name,
                    "city":    r.city.name or "Unknown",
                    "lat":     r.location.latitude,
                    "lon":     r.location.longitude,
                })
            except Exception:
                results.append({
                    "ip":      row["ip"],
                    "total":   row["total"],
                    "country": "Private/Unknown",
                    "city":    "",
                    "lat":     None,
                    "lon":     None,
                })
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
