import hashlib
from datetime import datetime
from typing import Dict, Any

_ip_seen_counts: Dict[str, int] = {}

def _is_private_ip(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        if parts[0] == 127: return True
    except Exception:
        pass
    return False

def _compute_base_risk(event: Dict[str, Any]) -> float:
    score = 0.0
    hour  = event.get("hour_of_day", 12)
    if event.get("status") == "failed": score += 20
    if event.get("username") == "root":  score += 40
    if hour >= 23 or hour <= 5:
        if 0 <= hour <= 3:   score += 20
        elif hour <= 5:      score += 12
        else:                score += 8
    ip = event.get("ip", "")
    if ip:
        _ip_seen_counts[ip] = _ip_seen_counts.get(ip, 0) + 1
        count = _ip_seen_counts[ip]
        if count > 20:   score += 15
        elif count > 10: score += 10
        elif count > 5:  score += 5
    if ip and not _is_private_ip(ip): score += 5
    return min(score, 75)

def _severity_label(score: float) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"

def normalize(event: Dict[str, Any]) -> Dict[str, Any]:
    raw      = event.get("raw", "")
    ts_str   = event.get("timestamp", datetime.now().isoformat())
    event_id = hashlib.md5(f"{ts_str}{raw}".encode()).hexdigest()
    is_failed    = event.get("status") == "failed"
    is_root      = event.get("username") == "root"
    hour         = event.get("hour_of_day", 12)
    is_off_hours = hour >= 23 or hour <= 5
    risk_score   = _compute_base_risk(event)
    event.update({
        "event_id":    event_id,
        "is_failed":   is_failed,
        "is_root":     is_root,
        "is_off_hours": is_off_hours,
        "is_external": not _is_private_ip(event.get("ip", "")),
        "risk_score":  risk_score,
        "severity":    _severity_label(risk_score),
        "labels":      [],
        "ml_score":    None,
        "ml_anomaly":  False,
    })
    return event
