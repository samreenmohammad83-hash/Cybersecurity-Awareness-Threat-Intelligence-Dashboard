from flask import Flask, jsonify, request, send_from_directory, render_template
from pathlib import Path
import json

from db import Database
from services.ioc_validator import validate_indicator
from services.enrichment_engine import enrich_indicator
from services.alert_engine import generate_threat_alert
from services.awareness_service import generate_learning_recommendations

BASE = Path(__file__).resolve().parent.parent
FRONTEND = BASE / "frontend"
AWARENESS = BASE / "awareness"
DATA = BASE / "data"

app = Flask(__name__, static_folder=str(FRONTEND), static_url_path="/static")
db = Database()

def json_error(message, code=400):
    return jsonify({"error": message}), code

@app.get("/")
def home():
    return send_from_directory(FRONTEND, "index.html")

@app.get("/dashboard")
def dashboard():
    return send_from_directory(FRONTEND, "threat-dashboard.html")

@app.get("/threat/<threat_id>")
def threat_page(threat_id):
    return send_from_directory(FRONTEND, "threat-details.html")

@app.get("/awareness")
def awareness_page():
    return send_from_directory(FRONTEND, "awareness.html")

@app.get("/quiz")
def quiz_page():
    return send_from_directory(FRONTEND, "quiz.html")

@app.get("/api/health")
def health():
    return jsonify({"status":"ok","mode":"synthetic-local-only"})

@app.get("/api/threats")
def threats():
    return jsonify(db.list_threats({
        "severity": request.args.get("severity"),
        "category": request.args.get("category"),
        "indicator_type": request.args.get("indicator_type"),
        "status": request.args.get("status"),
        "min_risk": request.args.get("min_risk"),
        "min_confidence": request.args.get("min_confidence")
    }, request.args.get("limit", 100)))

@app.get("/api/threats/<threat_id>")
def threat_detail(threat_id):
    item = db.get_threat(threat_id)
    return jsonify(item) if item else json_error("Threat not found.", 404)

@app.post("/api/threats")
def create_threat():
    data = request.get_json(silent=True) or {}
    required = ["threat_id","threat_name","category","severity","indicator_type","indicator_value"]
    missing = [x for x in required if not str(data.get(x,"")).strip()]
    if missing: return json_error(f"Missing fields: {', '.join(missing)}")
    validation = validate_indicator(data["indicator_value"])
    if not validation["valid"]: return json_error("Indicator syntax is invalid.")
    return jsonify({"message":"Validated threat payload. Use the local ingestion layer to persist it.","validation":validation}), 201

@app.put("/api/threats/<threat_id>")
def update_threat(threat_id):
    data = request.get_json(silent=True) or {}
    if not db.get_threat(threat_id): return json_error("Threat not found.",404)
    allowed = {"status","severity","risk_score","confidence_score"}
    updates = {k:v for k,v in data.items() if k in allowed}
    if not updates: return json_error("No supported fields supplied.")
    sets = ", ".join(f"{k}=?" for k in updates)
    with db.connect() as c:
        c.execute(f"UPDATE threats SET {sets} WHERE threat_id=?", [*updates.values(), threat_id])
    return jsonify(db.get_threat(threat_id))

@app.get("/api/indicators/search")
def indicator_search():
    value = request.args.get("q","").strip()
    validation = validate_indicator(value)
    if not validation["valid"]: return jsonify({"validation":validation,"known_in_demo_dataset":False,"records":[]})
    return jsonify({"validation":validation, **enrich_indicator(db, validation["normalized_value"])})

@app.get("/api/dashboard/stats")
def dashboard_stats():
    return jsonify(db.stats())

@app.get("/api/dashboard/trends")
def dashboard_trends():
    return jsonify(db.trends())

@app.get("/api/dashboard/groups/<field>")
def dashboard_group(field):
    try: return jsonify(db.group_counts(field))
    except ValueError as e: return json_error(str(e),400)

@app.get("/api/alerts")
def alerts():
    return jsonify(db.list_alerts())

@app.put("/api/alerts/<alert_id>/status")
def alert_status(alert_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in {"NEW","INVESTIGATING","MONITORING","RESOLVED","FALSE_POSITIVE"}:
        return json_error("Invalid alert status.")
    db.update_alert_status(alert_id,status)
    return jsonify({"alert_id":alert_id,"status":status})

@app.post("/api/threats/<threat_id>/notes")
def add_note(threat_id):
    if not db.get_threat(threat_id): return json_error("Threat not found.",404)
    note = (request.get_json(silent=True) or {}).get("note","").strip()
    if not note or len(note) > 2000: return json_error("Note must be 1-2000 characters.")
    db.add_note(threat_id,note)
    return jsonify({"message":"Note saved."}),201

@app.get("/api/vulnerabilities")
def vulnerabilities():
    return jsonify(db.list_vulnerabilities())

@app.get("/api/awareness/modules")
def modules():
    return jsonify(json.loads((AWARENESS/"modules.json").read_text(encoding="utf-8")))

@app.get("/api/quiz")
def quiz():
    return jsonify(json.loads((AWARENESS/"quiz_questions.json").read_text(encoding="utf-8")))

@app.post("/api/quiz/submit")
def quiz_submit():
    payload = request.get_json(silent=True) or {}
    answers = payload.get("answers", {})
    questions = json.loads((AWARENESS/"quiz_questions.json").read_text(encoding="utf-8"))
    correct = 0
    cats = {}
    for q in questions:
        answer = answers.get(str(q["id"]))
        ok = answer is not None and int(answer) == q["correct_index"]
        correct += int(ok)
        cats.setdefault(q["category"], [0,0])
        cats[q["category"]][1] += 1
        cats[q["category"]][0] += int(ok)
    score = round(correct / len(questions) * 100) if questions else 0
    category_scores = {k: round(v[0]/v[1]*100) for k,v in cats.items()}
    db.save_quiz_result(score, category_scores)
    label = "Needs Improvement" if score <= 40 else "Basic Awareness" if score <= 60 else "Good Awareness" if score <= 80 else "Strong Awareness"
    return jsonify({"score":score,"label":label,"category_scores":category_scores,
                    "recommendations":generate_learning_recommendations(category_scores)})

@app.post("/api/alerts/generate")
def alerts_generate():
    records = db.list_threats({"min_risk":60,"limit":500})
    created = 0
    for r in records:
        a = generate_threat_alert(r)
        if a:
            db.add_alert(a); created += 1
    return jsonify({"created_or_refreshed":created})

if __name__ == "__main__":
    db.init_schema()
    app.run(host="127.0.0.1", port=5000, debug=True)
