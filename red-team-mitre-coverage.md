# Red Team Program — MITRE ATT&CK Coverage

Latent Archon operates an internal red team program with automated attack execution against staging infrastructure. All attacks are mapped to the [MITRE ATT&CK framework](https://attack.mitre.org/) and executed monthly via Cloud Build.

## Coverage Summary

| Suite | Attacks | Focus |
|-------|---------|-------|
| **Auth Bypass** | 21 | JWT forgery, token replay, cross-pool escalation, SAML manipulation, session hijacking |
| **Privilege Escalation** | 12 | IAM abuse, service account impersonation, Cloud SQL privilege escalation, metadata exploitation |
| **Data Exfiltration** | 15 | GCS bucket enumeration, vector store extraction, cross-tenant data leakage, backup theft |
| **Web Application** | 28 | OWASP Top 10, RLS bypass, IDOR, injection, rate limiting, CORS, SSRF |
| **Lateral Movement & Persistence** | 15 | Resource hijacking, DNS manipulation, key theft, infrastructure persistence |
| **Manual Scenarios** | 2 | Custom attack playbooks for emerging threats |
| **Total** | **93+** | |

## MITRE ATT&CK Technique Coverage

| Tactic | Techniques |
|--------|-----------|
| **Initial Access** | T1189, T1190, T1204.002 |
| **Execution** | T1059, T1059.007, T1059.009 |
| **Persistence** | T1098 |
| **Privilege Escalation** | T1078, T1078.001, T1078.004, T1548.002 |
| **Defense Evasion** | T1027, T1550, T1550.001, T1556.006 |
| **Credential Access** | T1110.001, T1552, T1552.001, T1552.004 |
| **Discovery** | T1046, T1083, T1087 |
| **Lateral Movement** | T1563 |
| **Collection** | T1530 |
| **Command & Control** | T1090 |
| **Impact** | T1496, T1499, T1499.003, T1499.004, T1565 |
| **Reconnaissance** | T1583, T1589, T1590, T1592, T1592.004, T1595 |

## Execution Model

- **Frequency**: Monthly automated runs against staging; ad-hoc after security-relevant changes
- **Infrastructure**: Isolated GCP project (`archon-red-*`) with dedicated service accounts
- **Reporting**: JSON + Markdown reports with pass/fail per attack, evidence capture, remediation guidance
- **Integration**: Results archived to GCS evidence bucket; failures generate POA&M entries automatically

## What We Test

1. **Can a valid user in Org A read Org B's data?** (cross-tenant isolation)
2. **Can a compromised app-pool JWT authenticate to the admin API?** (pool isolation)
3. **Can an attacker enumerate or access GCS buckets without authorization?** (storage controls)
4. **Can SQL injection bypass Row-Level Security?** (database controls)
5. **Can a stolen service account key escalate beyond its intended scope?** (IAM controls)
6. **Can an attacker persist in the environment after credential rotation?** (persistence controls)
