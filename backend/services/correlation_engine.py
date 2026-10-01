from collections import defaultdict

def correlate_threats(records):
    clusters = defaultdict(list)
    for r in records:
        key = (r.get("threat_category"), r.get("first_seen", "")[:10])
        clusters[key].append(r)
    return [
        {"cluster_key": f"{k[0]}:{k[1]}", "relationship_basis": "same category + observation window",
         "records": v, "observation_count": len(v)}
        for k, v in clusters.items() if len(v) > 1
    ]

def correlate_alerts(alerts):
    groups = defaultdict(list)
    for a in alerts:
        key = (a["threat_id"], a["alert_type"], a["severity"])
        groups[key].append(a)
    return [
        {"threat_id": k[0], "alert_type": k[1], "severity": k[2],
         "observation_count": len(v), "alert_ids": [x["alert_id"] for x in v]}
        for k, v in groups.items()
    ]
