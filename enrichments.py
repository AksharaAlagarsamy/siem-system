import requests

ABUSEIPDB_API_KEY = ""
MITRE_MAPPING = {
    "BRUTE_FORCE":        "T1110",
    "ROOT_LOGIN_ATTEMPT": "T1078",
    "OFF_HOURS_LOGIN":    "T1078",
    "IP_CYCLING":         "T1090",
    "ML_ANOMALY":         "T1078.004",
}

def enrich_with_geoip(event: dict) -> dict:
    ip = event.get("ip")
    if not ip:
        return event
    try:
        import geoip2.database
        with geoip2.database.Reader("GeoLite2-City.mmdb") as reader:
            r = reader.city(ip)
            event["geo"] = {
                "country":   r.country.name,
                "city":      r.city.name,
                "latitude":  r.location.latitude,
                "longitude": r.location.longitude,
            }
    except Exception:
        event["geo"] = {}
    return event

def check_threat_intel(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        data = resp.json().get("data", {})
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports":    data.get("totalReports", 0),
            "is_known_bad":     data.get("abuseConfidenceScore", 0) > 50,
        }
    except Exception:
        return {}

def tag_mitre(event: dict) -> dict:
    labels = event.get("labels", [])
    event["mitre_techniques"] = list(
        {MITRE_MAPPING[l] for l in labels if l in MITRE_MAPPING}
    )
    return event

def compute_final_risk_score(event: dict) -> float:
    score = 0.0
    score += min(50, len(event.get("labels", [])) * 10)
    ml_raw = event.get("ml_score", 0.0) or 0.0
    score += max(0, min(30, (-ml_raw) * 60))
    ti = event.get("threat_intel", {}).get("abuse_confidence", 0)
    score += (ti / 100) * 20
    return round(min(100, score), 2)

def enrich_event(event: dict) -> dict:
    event = enrich_with_geoip(event)
    event["threat_intel"] = check_threat_intel(event.get("ip", ""))
    event = tag_mitre(event)
    event["risk_score"] = compute_final_risk_score(event)
    return event
