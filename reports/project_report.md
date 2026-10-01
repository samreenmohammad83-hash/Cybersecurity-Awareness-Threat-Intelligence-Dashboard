# Cybersecurity Awareness & Threat Intelligence Dashboard — Project Report

## Abstract
This project presents a defensive cybersecurity dashboard combining synthetic cyber threat intelligence with security awareness education. The platform validates and enriches indicators, scores risk and confidence, groups related observations, presents alerts, maps justified records to MITRE ATT&CK concepts, tracks synthetic vulnerability records, and provides awareness modules and a 30-question quiz.

## Introduction
Security teams need to transform raw observations into useful defensive context while people need practical guidance for recognizing security risks. This project combines both perspectives in one local application.

## Problem Statement
Raw threat indicators can be difficult for beginners to interpret. A defensive platform should distinguish observations, indicators, alerts, threats, and incidents instead of treating every suspicious artifact as confirmed compromise.

## Objectives
- Analyze synthetic IOCs safely.
- Normalize and validate indicator syntax.
- Enrich records from local data.
- Score risk and confidence separately.
- Correlate related observations.
- Provide ATT&CK-aware defensive context.
- Prioritize synthetic vulnerabilities.
- Support SOC-style investigation.
- Teach cybersecurity awareness.
- Measure educational quiz performance.

## Proposed System
The system uses a Flask API, SQLite database, HTML/CSS/JavaScript frontend, synthetic CSV data, local JSON awareness content, and automated tests.

## Synthetic Dataset
The generator creates 2,000 records using documentation IP ranges, example domains, fictional URLs, synthetic SHA-256 strings, and synthetic CVE-style identifiers. Records are clearly marked as demo-only.

## IOC Validation
Validation checks syntax for IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256 formats, and CVE identifiers. It does not determine maliciousness.

## Risk and Confidence
Risk combines severity, confidence, recency, observation frequency, source reliability, and contextual correlation. Confidence is separately influenced by source reliability, validation quality, observations, and corroboration.

## MITRE ATT&CK
Synthetic phishing observations may be mapped to the current MITRE ATT&CK Phishing technique where context is sufficient. Other categories use tactic-level context when a technique ID is not justified.

## Vulnerability Awareness
Synthetic vulnerability records demonstrate CVSS and contextual prioritization. CVSS alone is not treated as the complete patch-priority decision.

## Alert Management
The alert engine creates local alerts from risk/confidence thresholds and can refresh correlated alerts rather than creating unlimited duplicates.

## Awareness Center
Modules cover phishing, passwords, MFA, social engineering, safe browsing, Wi-Fi, updates, ransomware, removable media, privacy, mobile, remote work, cloud security, incident reporting, and AI-enabled scams.

## Quiz System
Thirty questions produce an educational score from 0–100, category scores, and learning recommendations.

## Security and Privacy
The project does not contact suspicious indicators, execute files, attack systems, or store unnecessary personal information.

## Limitations
- Data is synthetic and cannot represent live threat prevalence.
- Risk weights are educational.
- ATT&CK mappings are intentionally conservative.
- No live reputation APIs are used.
- No attribution is inferred from correlation.

## Future Scope
Authorized STIX/TAXII feeds, SIEM/SOAR integration, CVE/KEV feeds, stronger deduplication, indicator expiry, role-based dashboards, Docker, CI/CD, centralized logging, and approved endpoint/email telemetry can be added defensively.

## Conclusion
The project demonstrates a complete defensive workflow from synthetic threat data through validation, enrichment, scoring, correlation, alerting, investigation, awareness training, and testing.
