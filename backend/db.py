import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "instance" / "threat_dashboard.db"

class Database:
    def __init__(self, path=DB_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self):
        with self.connect() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                threat_id TEXT PRIMARY KEY, timestamp TEXT, threat_name TEXT, category TEXT,
                description TEXT, severity TEXT, risk_score INTEGER, confidence_score INTEGER,
                status TEXT, first_seen TEXT, last_seen TEXT, source_name TEXT,
                indicator_type TEXT, indicator_value TEXT, country_or_region TEXT,
                mitre_tactic TEXT, mitre_technique TEXT, cve_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_threat_category ON threats(category);
            CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity);
            CREATE INDEX IF NOT EXISTS idx_indicator_value ON threats(indicator_value);
            CREATE INDEX IF NOT EXISTS idx_threat_status ON threats(status);

            CREATE TABLE IF NOT EXISTS indicators (
                indicator_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT,
                indicator_type TEXT, indicator_value TEXT, first_seen TEXT, last_seen TEXT,
                FOREIGN KEY(threat_id) REFERENCES threats(threat_id)
            );
            CREATE INDEX IF NOT EXISTS idx_ind_value ON indicators(indicator_value);

            CREATE TABLE IF NOT EXISTS sources (
                source_id INTEGER PRIMARY KEY AUTOINCREMENT, source_name TEXT UNIQUE, reliability TEXT
            );
            CREATE TABLE IF NOT EXISTS attack_mappings (
                mapping_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT,
                tactic TEXT, technique TEXT, technique_id TEXT
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT, product_category TEXT,
                severity TEXT, cvss_score REAL, published_date TEXT, patch_available INTEGER,
                exploitation_status_demo TEXT, description TEXT, priority_score REAL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY, threat_id TEXT, timestamp TEXT, alert_type TEXT,
                severity TEXT, risk_score INTEGER, confidence_score INTEGER, description TEXT, status TEXT
            );
            CREATE TABLE IF NOT EXISTS analyst_notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, note TEXT, created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS quiz_results (
                result_id INTEGER PRIMARY KEY AUTOINCREMENT, anonymous_user_id TEXT,
                overall_score INTEGER, category_scores TEXT, created_at TEXT
            );
            """)

    def seed_from_csv(self, csv_path):
        import csv
        with self.connect() as c, open(csv_path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            for r in rows:
                c.execute("""INSERT OR REPLACE INTO threats VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    r["threat_id"],r["timestamp"],r["threat_name"],r["threat_category"],r["description"],
                    r["severity"],r["risk_score"],r["confidence_score"],r["status"],r["first_seen"],r["last_seen"],
                    r["source_name"],r["indicator_type"],r["indicator_value"],r["country_or_region_optional"],
                    r["mitre_tactic_optional"],r["mitre_technique_optional"],r["cve_id_optional"]
                ))
                c.execute("INSERT OR IGNORE INTO sources(source_name,reliability) VALUES(?,?)",
                          (r["source_name"], {"Internal SOC":"A","Security Vendor":"A","Public Threat Feed":"B","Research Report":"B","Community Submission":"C","Unknown Source":"D"}[r["source_name"]]))
                c.execute("DELETE FROM indicators WHERE threat_id=?", (r["threat_id"],))
                c.execute("INSERT INTO indicators(threat_id,indicator_type,indicator_value,first_seen,last_seen) VALUES(?,?,?,?,?)",
                          (r["threat_id"],r["indicator_type"],r["indicator_value"],r["first_seen"],r["last_seen"]))
                if r["mitre_tactic_optional"]:
                    c.execute("DELETE FROM attack_mappings WHERE threat_id=?", (r["threat_id"],))
                    c.execute("INSERT INTO attack_mappings(threat_id,tactic,technique,technique_id) VALUES(?,?,?,?)",
                              (r["threat_id"],r["mitre_tactic_optional"],r["mitre_technique_optional"],
                               {"Phishing":"T1566"}.get(r["mitre_technique_optional"])))
        return len(rows)

    def list_threats(self, filters=None, limit=100):
        filters = filters or {}
        clauses, args = [], []
        for field in ("severity","category","indicator_type","status"):
            if filters.get(field):
                clauses.append(f"{field}=?"); args.append(filters[field])
        if filters.get("min_risk") is not None:
            clauses.append("risk_score>=?"); args.append(int(filters["min_risk"]))
        if filters.get("min_confidence") is not None:
            clauses.append("confidence_score>=?"); args.append(int(filters["min_confidence"]))
        q = "SELECT * FROM threats"
        if clauses: q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY timestamp DESC LIMIT ?"; args.append(min(500, int(limit)))
        with self.connect() as c:
            return [dict(r) for r in c.execute(q, args).fetchall()]

    def get_threat(self, threat_id):
        with self.connect() as c:
            r = c.execute("SELECT * FROM threats WHERE threat_id=?", (threat_id,)).fetchone()
            if not r: return None
            d = dict(r)
            d["related_indicators"] = [dict(x) for x in c.execute("SELECT * FROM indicators WHERE threat_id=?", (threat_id,))]
            d["notes"] = [dict(x) for x in c.execute("SELECT * FROM analyst_notes WHERE threat_id=? ORDER BY created_at DESC", (threat_id,))]
            d["alerts"] = [dict(x) for x in c.execute("SELECT * FROM alerts WHERE threat_id=? ORDER BY timestamp DESC", (threat_id,))]
            d["attack_mapping"] = [dict(x) for x in c.execute("SELECT * FROM attack_mappings WHERE threat_id=?", (threat_id,))]
            return d

    def search_indicator(self, value):
        with self.connect() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM threats WHERE lower(indicator_value)=lower(?) ORDER BY timestamp DESC", (value.strip(),)
            ).fetchall()]

    def alerts_for_threats(self, ids):
        if not ids: return []
        placeholders = ",".join("?" for _ in ids)
        with self.connect() as c:
            return [dict(r) for r in c.execute(f"SELECT * FROM alerts WHERE threat_id IN ({placeholders})", ids)]

    def stats(self):
        with self.connect() as c:
            total = c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            def count(q): return c.execute(q).fetchone()[0]
            return {
                "total_threat_records": total,
                "critical_threats": count("SELECT COUNT(*) FROM threats WHERE severity='CRITICAL'"),
                "high_threats": count("SELECT COUNT(*) FROM threats WHERE severity='HIGH'"),
                "active_indicators": count("SELECT COUNT(DISTINCT indicator_value) FROM threats"),
                "open_investigations": count("SELECT COUNT(*) FROM threats WHERE status IN ('NEW','UNDER_REVIEW')"),
                "average_confidence": round(c.execute("SELECT COALESCE(AVG(confidence_score),0) FROM threats").fetchone()[0], 1),
                "vulnerabilities_tracked": count("SELECT COUNT(*) FROM vulnerabilities")
            }

    def group_counts(self, field):
        allowed = {"severity","category","indicator_type","status","mitre_tactic"}
        if field not in allowed: raise ValueError("Unsupported grouping")
        with self.connect() as c:
            return [dict(r) for r in c.execute(f"SELECT {field} AS label, COUNT(*) AS count FROM threats GROUP BY {field} ORDER BY count DESC").fetchall()]

    def trends(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute(
                "SELECT substr(timestamp,1,10) AS day, COUNT(*) AS count FROM threats GROUP BY day ORDER BY day"
            ).fetchall()]

    def add_note(self, threat_id, note):
        from datetime import datetime, timezone
        with self.connect() as c:
            c.execute("INSERT INTO analyst_notes(threat_id,note,created_at) VALUES(?,?,?)",
                      (threat_id, note.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds")))

    def list_alerts(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200").fetchall()]

    def update_alert_status(self, alert_id, status):
        with self.connect() as c:
            c.execute("UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id))

    def add_alert(self, alert):
        with self.connect() as c:
            c.execute("""INSERT OR REPLACE INTO alerts VALUES(?,?,?,?,?,?,?,?,?)""", (
                alert["alert_id"],alert["threat_id"],alert["timestamp"],alert["alert_type"],
                alert["severity"],alert["risk_score"],alert["confidence_score"],alert["description"],alert["status"]
            ))

    def list_vulnerabilities(self):
        with self.connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM vulnerabilities ORDER BY priority_score DESC").fetchall()]

    def seed_vulnerabilities(self):
        rows = [
            ("CVE-DEMO-001","Web Application","CRITICAL",9.8,"2026-03-01",1,"DEMO_NOT_REAL","Synthetic critical vulnerability record for prioritization practice.",92.0),
            ("CVE-DEMO-002","Identity Service","HIGH",8.8,"2026-04-12",0,"DEMO_NOT_REAL","Synthetic high-severity identity exposure record.",84.0),
            ("CVE-DEMO-003","Endpoint Software","MEDIUM",6.5,"2026-05-20",1,"DEMO_NOT_REAL","Synthetic endpoint patch-awareness record.",61.0),
            ("CVE-DEMO-004","Database","HIGH",8.1,"2026-06-18",0,"DEMO_NOT_REAL","Synthetic database prioritization record.",79.0),
            ("CVE-DEMO-005","Cloud Service","LOW",3.7,"2026-07-03",1,"DEMO_NOT_REAL","Synthetic cloud configuration awareness record.",38.0),
        ]
        with self.connect() as c:
            c.execute("DELETE FROM vulnerabilities")
            c.executemany("""INSERT INTO vulnerabilities(cve_id,product_category,severity,cvss_score,published_date,patch_available,exploitation_status_demo,description,priority_score)
                             VALUES(?,?,?,?,?,?,?,?,?)""", rows)

    def save_quiz_result(self, score, category_scores):
        import json
        from datetime import datetime, timezone
        with self.connect() as c:
            c.execute("INSERT INTO quiz_results(anonymous_user_id,overall_score,category_scores,created_at) VALUES(?,?,?,?)",
                      ("anonymous-demo", int(score), json.dumps(category_scores), datetime.now(timezone.utc).isoformat(timespec="seconds")))
