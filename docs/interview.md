# Interview Preparation — 10 Questions + 10 Answers

## 1. Explain your project.
**Answer:** I built a defensive Cybersecurity Awareness and Threat Intelligence Dashboard using Flask, SQLite, HTML, CSS, and JavaScript. It uses synthetic data so there is no interaction with suspicious infrastructure. I implemented IOC validation, local enrichment, separate risk and confidence scoring, correlation, alerts, ATT&CK-aware mapping, vulnerability prioritization, a SOC investigation view, and an awareness quiz.

## 2. What is threat intelligence?
**Answer:** Threat intelligence is analyzed information about threats that helps defenders make better security decisions. In my project I mainly focused on technical and tactical intelligence using synthetic indicators and contextual fields.

## 3. What is an IOC?
**Answer:** An IOC is an Indicator of Compromise, such as an IP address, domain, URL, file hash, or other artifact that may be relevant to an investigation. I treat an IOC as evidence to analyze, not as automatic proof of compromise.

## 4. Why separate risk and confidence?
**Answer:** Risk describes how concerning an item may be, while confidence describes how strong the available evidence is. For example, an item can have high potential impact but weak evidence, so showing both values prevents overconfidence.

## 5. What is threat enrichment?
**Answer:** Enrichment adds context to an indicator, such as type, first and last seen, category, confidence, severity, related alerts, related indicators, and ATT&CK context. My demo performs enrichment only from the local synthetic database.

## 6. How did you use MITRE ATT&CK?
**Answer:** I used ATT&CK to describe adversary behavior at a high level. For example, synthetic phishing records can be mapped to the Phishing technique under Initial Access when the context supports it. I avoid inventing technique IDs when context is insufficient.

## 7. How did you prioritize vulnerabilities?
**Answer:** I did not rely on CVSS alone. The educational model also considers asset criticality, exposure, known exploitation evidence, and business context. This demonstrates why contextual prioritization can differ from simply sorting by CVSS.

## 8. How does threat correlation work?
**Answer:** The demo groups synthetic observations using shared context such as category and observation window. The result is a related threat cluster. I explicitly do not treat correlation as proof of attribution.

## 9. Explain the SOC workflow in your project.
**Answer:** The workflow is threat feed, IOC detection, validation, enrichment, risk and confidence scoring, alerting, SOC queue, triage, correlation, investigation, and then monitor, resolve, or mark false positive, followed by documentation.

## 10. How did you handle false positives?
**Answer:** I included a FALSE_POSITIVE status and explained that IPs, domains, cloud infrastructure, and threat feeds can be ambiguous or stale. The dashboard supports analyst review instead of automatically declaring every suspicious indicator malicious.
