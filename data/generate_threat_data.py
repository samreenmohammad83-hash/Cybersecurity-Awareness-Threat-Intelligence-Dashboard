"""Generate safe, synthetic CTI records. No external network access is used."""
from __future__ import annotations
import csv, hashlib, random
from datetime import datetime, timedelta
from pathlib import Path

CATEGORIES = [
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS",
    "WEB THREATS", "NETWORK THREATS", "VULNERABILITY EXPOSURE",
    "SOCIAL ENGINEERING", "DATA EXPOSURE", "ACCOUNT SECURITY"
]
INDICATOR_TYPES = ["IP ADDRESS", "DOMAIN", "URL", "FILE HASH", "EMAIL/SENDER DOMAIN", "CVE ID"]
SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
SOURCES = [
    ("Internal SOC", "A"), ("Security Vendor", "A"),
    ("Public Threat Feed", "B"), ("Research Report", "B"),
    ("Community Submission", "C"), ("Unknown Source", "D")
]
TACTICS = [
    ("Initial Access", "T1566", "Phishing"),
    ("Credential Access", None, "Credential Access"),
    ("Discovery", None, "Discovery"),
    ("Command and Control", None, "Command and Control"),
    ("Impact", None, "Impact"),
]

DOC_IP_NETS = ["192.0.2.", "198.51.100.", "203.0.113."]
DEMO_DOMAINS = ["example.com", "example.org", "example.net", "demo.invalid"]

def synthetic_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()

def indicator(i: int, kind: str) -> str:
    if kind == "IP ADDRESS":
        base = DOC_IP_NETS[i % len(DOC_IP_NETS)]
        return f"{base}{(i % 250) + 1}"
    if kind == "DOMAIN":
        return DEMO_DOMAINS[i % len(DEMO_DOMAINS)]
    if kind == "URL":
        return f"https://demo.invalid/resource/{i:04d}"
    if kind == "FILE HASH":
        return synthetic_hash(f"demo-file-{i}")
    if kind == "EMAIL/SENDER DOMAIN":
        return f"sender{i % 20 + 1}@example.org"
    return f"CVE-2026-{1000 + (i % 9000):04d}"

def severity_for(cat, i):
    if cat in {"RANSOMWARE", "ACCOUNT SECURITY"}:
        return ["MEDIUM", "HIGH", "CRITICAL"][i % 3]
    if cat in {"PHISHING", "CREDENTIAL THREATS", "VULNERABILITY EXPOSURE"}:
        return ["LOW", "MEDIUM", "HIGH"][i % 3]
    return SEVERITIES[i % len(SEVERITIES)]

def generate(n=2000, out=None, seed=42):
    random.seed(seed)
    out = Path(out or Path(__file__).with_name("threat_intelligence_dataset.csv"))
    start = datetime(2026, 1, 1)
    fields = [
        "threat_id","timestamp","threat_name","threat_category","indicator_type",
        "indicator_value","source_name","confidence_score","severity","risk_score",
        "status","first_seen","last_seen","country_or_region_optional","description",
        "mitre_tactic_optional","mitre_technique_optional","cve_id_optional"
    ]
    rows = []
    for i in range(n):
        cat = CATEGORIES[i % len(CATEGORIES)]
        kind = INDICATOR_TYPES[i % len(INDICATOR_TYPES)]
        sev = severity_for(cat, i)
        ts = start + timedelta(hours=i * 3)
        first = ts - timedelta(days=i % 45)
        last = ts + timedelta(hours=i % 18)
        source, reliability = SOURCES[i % len(SOURCES)]
        confidence = 45 + ((i * 17) % 56)
        sev_base = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 50, "HIGH": 70, "CRITICAL": 90}[sev]
        risk = max(0, min(100, round(sev_base * 0.30 + confidence * 0.25 + (i % 16) * 0.8 + (i % 10) * 0.7 + {"A":10,"B":8,"C":5,"D":2}[reliability])))
        tactic, tech_id, tech_name = TACTICS[i % len(TACTICS)]
        if cat in {"PHISHING", "SOCIAL ENGINEERING"}:
            tactic, tech_id, tech_name = ("Initial Access", "T1566", "Phishing")
        elif cat in {"CREDENTIAL THREATS", "ACCOUNT SECURITY"}:
            tactic, tech_id, tech_name = ("Credential Access", None, "Credential Access")
        cve = indicator(i, "CVE ID") if kind == "CVE ID" or cat == "VULNERABILITY EXPOSURE" else ""
        rows.append({
            "threat_id": f"THR-2026-{i+1:04d}",
            "timestamp": ts.isoformat(timespec="seconds"),
            "threat_name": f"Synthetic {cat.title()} Observation {i+1:04d}",
            "threat_category": cat,
            "indicator_type": kind,
            "indicator_value": indicator(i, kind),
            "source_name": source,
            "confidence_score": confidence,
            "severity": sev,
            "risk_score": risk,
            "status": STATUSES[i % len(STATUSES)],
            "first_seen": first.isoformat(timespec="seconds"),
            "last_seen": last.isoformat(timespec="seconds"),
            "country_or_region_optional": ["Demo Region", "Synthetic Region", "N/A"][i % 3],
            "description": f"SYNTHETIC / DEMO ONLY: defensive observation associated with {cat.lower()}. No claim of real-world maliciousness.",
            "mitre_tactic_optional": tactic,
            "mitre_technique_optional": tech_name,
            "cve_id_optional": cve
        })
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return out

if __name__ == "__main__":
    path = generate()
    print(f"Generated {path} with 2000 synthetic records.")
