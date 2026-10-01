# System Architecture

Synthetic/Public Defensive Threat Data → Data Ingestion → Normalization → IOC Validation/Extraction → Threat Enrichment → Risk + Confidence Engine → Correlation Engine → Threat DB / Alert Engine / ATT&CK Mapping → SOC Dashboard → Analyst.

Parallel awareness path: Awareness Content → Learning Modules → Quiz Engine → Awareness Score → Recommendations.

## Core distinctions
- Observation: a recorded event or data point.
- Indicator: an artifact such as an IP, domain, URL, hash, or CVE.
- Alert: a detection/notification generated from rules or thresholds.
- Threat: a contextualized security concern.
- Incident: a confirmed or formally declared security event requiring response.

The application deliberately does not label every indicator as a confirmed attack.
