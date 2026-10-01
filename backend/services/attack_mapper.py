# Only mappings supported by current MITRE ATT&CK terminology are used.
# Technique IDs are intentionally omitted where the demo lacks sufficient context.
ATTACK_MAP = {
    "PHISHING": {"tactic": "Initial Access", "technique": "Phishing", "technique_id": "T1566"},
    "SOCIAL ENGINEERING": {"tactic": "Initial Access", "technique": "Phishing", "technique_id": "T1566"},
    "CREDENTIAL THREATS": {"tactic": "Credential Access", "technique": "Credential Access", "technique_id": None},
    "ACCOUNT SECURITY": {"tactic": "Credential Access", "technique": "Credential Access", "technique_id": None},
}

def map_category(category):
    return ATTACK_MAP.get(str(category).upper())
