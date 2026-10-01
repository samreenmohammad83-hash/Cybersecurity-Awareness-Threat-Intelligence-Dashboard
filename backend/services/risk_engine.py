from datetime import datetime, timezone

SEVERITY_SCORE = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 50, "HIGH": 70, "CRITICAL": 90}
RELIABILITY_SCORE = {"A": 100, "B": 80, "C": 60, "D": 40}

def calculate_threat_risk(severity, confidence, recency=50, observations=1,
                          source_reliability="C", context=50, related_alerts=0):
    severity_component = SEVERITY_SCORE.get(str(severity).upper(), 10)
    frequency_component = min(100, 20 + observations * 8)
    alert_component = min(100, related_alerts * 20)
    source_component = RELIABILITY_SCORE.get(str(source_reliability).upper(), 40)
    score = (
        severity_component * .30 +
        float(confidence) * .25 +
        float(recency) * .15 +
        frequency_component * .10 +
        source_component * .10 +
        ((float(context) + alert_component) / 2) * .10
    )
    return max(0, min(100, round(score)))

def classify_risk(score):
    score = float(score)
    if score <= 20: return "INFORMATIONAL"
    if score <= 40: return "LOW"
    if score <= 60: return "MEDIUM"
    if score <= 80: return "HIGH"
    return "CRITICAL"

def recency_score(last_seen):
    try:
        dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = max(0, (datetime.now(timezone.utc) - dt).days)
        return max(0, 100 - min(100, age * 2))
    except Exception:
        return 0

def calculate_confidence(source_reliability, validation_quality=100, observations=1, corroboration=0):
    base = RELIABILITY_SCORE.get(str(source_reliability).upper(), 40)
    observation_bonus = min(20, observations * 2)
    corroboration_bonus = min(20, corroboration * 4)
    return max(0, min(100, round(base * .55 + validation_quality * .25 + observation_bonus + corroboration_bonus)))
