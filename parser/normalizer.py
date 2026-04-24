# parser/normalizer.py
"""
Normalizes parsed log events into the common SIEM schema.
Adds computed fields useful for ML and detection.
"""

import hashlib
from datetime import datetime
from typing import Dict, Any


def normalize(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Takes a parsed event dict and enriches it with:
    - Unique event ID
    - Risk pre-score
    - Boolean flags for quick rule matching
    """
    # Generate a unique event ID from raw content + timestamp
    raw    = event.get("raw", "")
    ts_str = event.get("timestamp", datetime.now().isoformat())
    event_id = hashlib.md5(f"{ts_str}{raw}".encode()).hexdigest()

    # Compute boolean flags
    is_failed    = event.get("status") == "failed"
    is_root      = event.get("username") == "root"
    hour         = event.get("hour_of_day", 12)
    is_off_hours = hour >= 23 or hour <= 5

    # Base risk score (will be updated by detection engine)
    risk_score = 0
    if is_failed:    risk_score += 20
    if is_root:      risk_score += 40
    if is_off_hours: risk_score += 15

    event.update({
        "event_id":     event_id,
        "is_failed":    is_failed,
        "is_root":      is_root,
        "is_off_hours": is_off_hours,
        "risk_score":   risk_score,
        "labels":       [],     # detection labels added later
        "ml_score":     None,   # ML anomaly score added later
    })

    return event
