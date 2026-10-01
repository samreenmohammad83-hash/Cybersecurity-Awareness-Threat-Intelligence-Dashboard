Write-Host "Cybersecurity Awareness & Threat Intelligence Dashboard"
if (!(Test-Path ".venv")) { python -m venv .venv }
& ".\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
pip install -r requirements.txt
python data\generate_threat_data.py
python backend\init_db.py
python backend\app.py
