from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from db import Database
db=Database(); db.init_schema()
csv_path=Path(__file__).resolve().parent.parent/"data"/"threat_intelligence_dataset.csv"
if not csv_path.exists():
    sys.path.insert(0,str(csv_path.parent))
    from generate_threat_data import generate
    generate(out=csv_path)
count=db.seed_from_csv(csv_path)
db.seed_vulnerabilities()
print(f"Database initialized and seeded with {count} synthetic threat records.")
