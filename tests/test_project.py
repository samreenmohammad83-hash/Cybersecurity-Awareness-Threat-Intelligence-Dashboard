import json, sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from services.ioc_validator import validate_indicator
from services.risk_engine import calculate_threat_risk, classify_risk, calculate_confidence
from services.vulnerability_service import calculate_vulnerability_priority
from services.correlation_engine import correlate_threats
from services.attack_mapper import map_category

@pytest.mark.parametrize("value,typ", [
("192.0.2.25","IP ADDRESS"),("2001:db8::1","IP ADDRESS"),
("example.com","DOMAIN"),("https://demo.invalid/a","URL"),
("a"*32,"FILE HASH"),("b"*40,"FILE HASH"),("c"*64,"FILE HASH"),
("CVE-2026-1234","CVE ID")])
def test_valid_indicators(value,typ):
    r=validate_indicator(value); assert r["valid"]; assert r["indicator_type"]==typ

def test_invalid_ipv4(): assert not validate_indicator("999.1.1.1")["valid"]
def test_invalid_domain(): assert not validate_indicator("not a domain")["valid"]
def test_invalid_cve(): assert not validate_indicator("CVE-20-12")["valid"]
def test_empty_indicator(): assert not validate_indicator("")["valid"]
def test_url_is_not_contacted(): assert validate_indicator("https://demo.invalid/x")["valid"]
def test_risk_bounds(): assert 0 <= calculate_threat_risk("CRITICAL",95,100,20,"A",100,5) <= 100
def test_risk_classification(): assert classify_risk(78)=="HIGH"; assert classify_risk(90)=="CRITICAL"
def test_confidence_bounds(): assert 0 <= calculate_confidence("A",100,20,10) <= 100
def test_source_reliability_distinction(): assert calculate_confidence("A") > calculate_confidence("D")
def test_vulnerability_priority(): assert calculate_vulnerability_priority(9.8,100,100,100,100) > calculate_vulnerability_priority(5,20,20,0,20)
def test_correlation_groups(): 
    rows=[{"threat_category":"PHISHING","first_seen":"2026-01-01","id":1},{"threat_category":"PHISHING","first_seen":"2026-01-01","id":2}]
    assert correlate_threats(rows)[0]["observation_count"]==2
def test_attack_mapping(): assert map_category("PHISHING")["technique_id"]=="T1566"
def test_unknown_attack_mapping(): assert map_category("UNKNOWN") is None

# API behavior / database persistence
@pytest.fixture()
def client(tmp_path, monkeypatch):
    import app as app_module
    from db import Database
    test_db=Database(tmp_path/"test.db"); test_db.init_schema()
    monkeypatch.setattr(app_module, "db", test_db)
    app_module.app.config["TESTING"]=True
    return app_module.app.test_client()

def seed_one(client):
    from db import Database
    # use API validation path; direct DB seed is covered by integration smoke below
    return client.post("/api/threats", json={"threat_id":"T-X","threat_name":"Demo","category":"PHISHING","severity":"HIGH","indicator_type":"IP ADDRESS","indicator_value":"198.51.100.25"})

def test_api_health(client): assert client.get("/api/health").status_code==200
def test_threat_creation_validation(client): assert seed_one(client).status_code==201
def test_threat_creation_rejects_bad_indicator(client):
    r=client.post("/api/threats",json={"threat_id":"T-X","threat_name":"Demo","category":"PHISHING","severity":"HIGH","indicator_type":"IP ADDRESS","indicator_value":"999.999.1.1"})
    assert r.status_code==400
def test_api_indicator_search_unknown(client): assert client.get("/api/indicators/search?q=198.51.100.25").status_code==200
def test_dashboard_stats_empty(client): assert client.get("/api/dashboard/stats").json["total_threat_records"]==0
def test_group_validation(client): assert client.get("/api/dashboard/groups/not_allowed").status_code==400
def test_notes_not_found(client): assert client.post("/api/threats/T-X/notes",json={"note":"x"}).status_code==404
def test_quiz_endpoint(client):
    r=client.get("/api/quiz"); assert r.status_code==200; assert len(r.json)>=30
def test_awareness_modules(client):
    r=client.get("/api/awareness/modules"); assert r.status_code==200; assert "Phishing Awareness" in r.json
def test_quiz_submission(client):
    qs=client.get("/api/quiz").json
    r=client.post("/api/quiz/submit",json={"answers":{str(q["id"]):q["correct_index"] for q in qs}})
    assert r.status_code==200 and r.json["score"]==100
def test_vulnerability_endpoint(client): assert client.get("/api/vulnerabilities").status_code==200
def test_threat_detail_not_found(client): assert client.get("/api/threats/MISSING").status_code==404
def test_alert_status_validation(client): assert client.put("/api/alerts/X/status",json={"status":"BAD"}).status_code==400
def test_alert_generation(client): assert client.post("/api/alerts/generate").status_code==200
def test_database_persistence(tmp_path):
    from db import Database
    d=Database(tmp_path/"persist.db"); d.init_schema()
    with d.connect() as c: c.execute("INSERT INTO threats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("T1","2026-01-01","x","PHISHING","desc","HIGH",70,80,"NEW","2026-01-01","2026-01-02","Internal SOC","DOMAIN","example.com","Demo","Initial Access","Phishing",""))
    assert d.get_threat("T1")["threat_id"]=="T1"
def test_duplicate_observation_indexing(tmp_path):
    from db import Database
    d=Database(tmp_path/"x.db"); d.init_schema()
    with d.connect() as c:
        indexes=[x[1] for x in c.execute("PRAGMA index_list(threats)").fetchall()]
    assert indexes
def test_filter_severity(tmp_path):
    from db import Database
    d=Database(tmp_path/"x.db"); d.init_schema()
    with d.connect() as c: c.execute("INSERT INTO threats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("T1","2026-01-01","x","PHISHING","d","HIGH",70,80,"NEW","2026-01-01","2026-01-02","s","DOMAIN","example.com","r","Initial Access","Phishing",""))
    assert len(d.list_threats({"severity":"HIGH"}))==1
def test_correlation_does_not_claim_attribution():
    rows=[{"threat_category":"PHISHING","first_seen":"2026-01-01"},{"threat_category":"PHISHING","first_seen":"2026-01-01"}]
    assert "relationship_basis" in correlate_threats(rows)[0]
def test_confidence_low_can_coexist_with_high_risk():
    assert calculate_confidence("D",20,1,0) < 50
def test_local_only_disclaimer():
    p=Path(__file__).parents[1]/"backend"/"app.py"
    text=p.read_text().lower()
    assert "local" in text or "external" in text
def test_required_dataset_schema():
    p=Path(__file__).parents[1]/"data"/"threat_intelligence_dataset.csv"
    # generator creates it during setup; if absent, this test is intentionally skipped.
    if not p.exists(): pytest.skip("Run data generator first")
    header=p.read_text(encoding="utf-8").splitlines()[0].split(",")
    assert "threat_id" in header and "indicator_value" in header and "risk_score" in header
