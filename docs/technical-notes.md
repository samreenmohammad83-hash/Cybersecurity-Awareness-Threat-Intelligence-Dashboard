# Technical Notes

## IOC lifecycle
Observed → Validated → Enriched → Scored → Investigated → Monitored → Expired/Closed.

Validation answers “is the syntax valid?”, not “is it malicious?”

## Risk vs confidence
Risk estimates how concerning an item may be. Confidence estimates the strength/quality of the available intelligence. A high-risk item can have low confidence.

## Risk model
Severity 30%, confidence 25%, recency 15%, observation frequency 10%, source reliability 10%, context/correlation 10%. This is an educational model and should not be treated as a production risk standard.

## Vulnerability prioritization
CVSS is only one input. Asset criticality, exposure, known exploitation evidence, and business context are also considered.

## Threat correlation
Correlation groups synthetic observations by shared context. Correlation does not prove attribution.

## Security
No URL resolution, DNS lookup, HTTP request, socket connection, file execution, exploit, malware, or phishing page is included.
