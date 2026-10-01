from datetime import datetime, timezone

def generate_threat_alert(record):
    if int(record["risk_score"]) >= 75 or (int(record["risk_score"]) >= 60 and int(record["confidence_score"]) >= 80):
        return {
            "alert_id": f"ALT-{record['threat_id']}",
            "threat_id": record["threat_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "alert_type": "HIGH_RISK_SYNTHETIC_OBSERVATION",
            "severity": record["severity"],
            "risk_score": int(record["risk_score"]),
            "confidence_score": int(record["confidence_score"]),
            "description": "Synthetic alert generated from local risk/confidence thresholds.",
            "status": "NEW"
        }
    return None
