import ipaddress, re
from urllib.parse import urlparse

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
HASH_PATTERNS = {"MD5": re.compile(r"^[0-9a-fA-F]{32}$"), "SHA-1": re.compile(r"^[0-9a-fA-F]{40}$"), "SHA-256": re.compile(r"^[0-9a-fA-F]{64}$")}

def validate_indicator(value: str) -> dict:
    raw = (value or "").strip()
    if not raw:
        return {"valid": False, "indicator_type": None, "normalized_value": "", "validation_notes": "Empty indicator."}
    try:
        ipaddress.ip_address(raw)
        return {"valid": True, "indicator_type": "IP ADDRESS", "normalized_value": raw, "validation_notes": "Syntactically valid IP address."}
    except ValueError:
        pass
    if CVE_RE.fullmatch(raw):
        return {"valid": True, "indicator_type": "CVE ID", "normalized_value": raw.upper(), "validation_notes": "Syntactically valid CVE identifier."}
    for name, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(raw):
            return {"valid": True, "indicator_type": "FILE HASH", "normalized_value": raw.lower(), "validation_notes": f"Syntactically valid {name}-format hash."}
    parsed = urlparse(raw)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return {"valid": True, "indicator_type": "URL", "normalized_value": raw, "validation_notes": "Syntactically valid URL. It was not contacted."}
    if DOMAIN_RE.fullmatch(raw.lower()):
        return {"valid": True, "indicator_type": "DOMAIN", "normalized_value": raw.lower(), "validation_notes": "Syntactically valid domain. It was not resolved or contacted."}
    return {"valid": False, "indicator_type": None, "normalized_value": raw, "validation_notes": "Unsupported or invalid indicator syntax."}
