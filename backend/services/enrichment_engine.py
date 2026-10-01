from .risk_engine import classify_risk

def enrich_indicator(db, indicator_value):
    rows = db.search_indicator(indicator_value)
    if not rows:
        return {"known_in_demo_dataset": False, "indicator": indicator_value, "related_records": []}
    categories = sorted({r["threat_category"] for r in rows})
    alerts = db.alerts_for_threats([r["threat_id"] for r in rows])
    return {
        "known_in_demo_dataset": True,
        "indicator": indicator_value,
        "indicator_type": rows[0]["indicator_type"],
        "first_seen": min(r["first_seen"] for r in rows),
        "last_seen": max(r["last_seen"] for r in rows),
        "associated_categories": categories,
        "confidence": max(int(r["confidence_score"]) for r in rows),
        "severity": max(rows, key=lambda r: {"INFORMATIONAL":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(r["severity"],0))["severity"],
        "risk_score": max(int(r["risk_score"]) for r in rows),
        "related_alerts": len(alerts),
        "related_indicators": sorted({r["indicator_value"] for r in rows})[:20],
        "mitre_mappings": sorted({(r["mitre_tactic_optional"], r["mitre_technique_optional"]) for r in rows if r["mitre_tactic_optional"]}),
        "analyst_notes": "Synthetic/local enrichment only. No external indicator was contacted.",
        "records": rows[:50]
    }
