# Cybersecurity Awareness & Threat Intelligence Dashboard

A defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.

> **Safety:** This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.

## Overview
The application is intentionally local-first. It uses synthetic data so it remains useful without internet access or external API keys.

## Problem Statement
Threat indicators require context. A suspicious-looking artifact is not automatically proof of compromise. This project separates observation, indicator, alert, threat, and incident concepts.

## Objectives
- Synthetic CTI ingestion
- IOC validation and search
- Local enrichment
- Risk vs confidence scoring
- Threat correlation
- MITRE ATT&CK-aware mapping
- Vulnerability prioritization
- SOC investigation workflow
- Awareness learning center
- 30-question awareness quiz
- Executive-friendly summaries
- Automated tests

## Architecture
Synthetic Data → Ingestion → Normalization → IOC Validation → Enrichment → Risk/Confidence → Correlation → DB/Alerts/ATT&CK → SOC Dashboard.

Awareness Data → Learning Modules → Quiz → Awareness Score → Recommendations.

## Technology Stack
- Python 3.11+
- Flask
- SQLite
- Pandas (available for future analytics extensions)
- HTML/CSS/JavaScript
- Pytest

## Threat Intelligence Types
- Strategic: long-term business/leadership context
- Tactical: adversary behaviors and defensive patterns
- Operational: campaign/activity context
- Technical: indicators and technical artifacts

This student project focuses mainly on technical, tactical, and awareness-oriented intelligence.

## IOC Analysis
Supported demo indicator types:
IP, domain, URL, file hash, sender domain, CVE ID.

Validation means syntactic validity, not maliciousness.

## Risk Scoring
Educational weighting:
- Severity 30%
- Confidence 25%
- Recency 15%
- Observation frequency 10%
- Source reliability 10%
- Context/correlation 10%

High risk does not mean confirmed compromise.

## Confidence Scoring
Confidence describes the quality/strength of the available intelligence. Risk and confidence are intentionally displayed separately.

## Threat Correlation
Records can be grouped using shared category and observation window. Correlation indicates a relationship in the available data; it does not prove attribution.

## MITRE ATT&CK
The dashboard uses conservative mappings. Current MITRE ATT&CK terminology was checked against the official ATT&CK site; phishing is T1566 under Initial Access. See the project documentation for details.

## Vulnerability Awareness
Synthetic CVE-style records demonstrate:
CVSS + asset criticality + exposure + exploitation evidence + business context.

## SOC Workflow
Threat Feed → IOC → Validation → Enrichment → Risk/Confidence → Alert → SOC Queue → Triage → Correlation → Investigation → Monitor/Resolve/False Positive → Documentation.

## Awareness Center
Includes phishing, password security, MFA, social engineering, safe browsing, Wi-Fi, software updates, ransomware, USB safety, privacy, mobile, remote work, cloud account security, incident reporting, and AI-enabled scam awareness.

## Installation — Windows PowerShell

```powershell
cd C:\path\to\Cybersecurity-Awareness-Threat-Intelligence-Dashboard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python data\generate_threat_data.py
python backend\init_db.py
python backend\app.py
```

Open:
- http://127.0.0.1:5000/
- http://127.0.0.1:5000/dashboard
- http://127.0.0.1:5000/awareness
- http://127.0.0.1:5000/quiz

## Useful demo IOC
`198.51.100.25`

This is a documentation-range IP and is used only as synthetic data. The application performs a database lookup and does not contact it.

## Testing
```powershell
pytest -q
```

## Project Structure
```text
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
├── backend/
│   ├── app.py
│   ├── db.py
│   ├── init_db.py
│   └── services/
├── frontend/
├── awareness/
├── data/
├── tests/
├── reports/
├── docs/
├── requirements.txt
├── .env.example
└── README.md
```

## API
- GET `/api/threats`
- GET `/api/threats/{id}`
- POST `/api/threats`
- PUT `/api/threats/{id}`
- GET `/api/indicators/search?q=...`
- GET `/api/dashboard/stats`
- GET `/api/dashboard/trends`
- GET `/api/alerts`
- PUT `/api/alerts/{id}/status`
- POST `/api/threats/{id}/notes`
- GET `/api/vulnerabilities`
- GET `/api/awareness/modules`
- GET `/api/quiz`
- POST `/api/quiz/submit`

## Security & Privacy
- Never automatically visit suspicious URLs.
- Never execute files based on hashes.
- Never contact suspicious IPs.
- Sanitize displayed threat content.
- Validate API input.
- Use authentication/RBAC before production deployment.
- Rate-limit APIs before internet exposure.
- Keep secrets in environment variables.
- Use HTTPS in production.
- Audit administrative changes.
- Minimize unnecessary personal data.

## Limitations
The dataset is synthetic, risk scoring is educational, and correlation is not attribution.

## Future Improvements
Authorized live threat-feed integration, STIX/TAXII, SIEM/SOAR, CVE/KEV feeds, indicator expiry, advanced clustering, ATT&CK Navigator, email/endpoint/cloud telemetry, Docker, CI/CD, and centralized logging.

## Ethical Disclaimer
This is a defensive educational project. Do not use it to attack, scan, probe, exploit, or interact with systems you do not own or have explicit authorization to test.

## Author
Student cybersecurity course project.
