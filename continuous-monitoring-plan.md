# Continuous Monitoring (ConMon) Plan

> **Document ID**: CONMON-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md, Appendix G)
> **Version**: 1.1 — DRAFT
> **Date**: March 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Plan Owner**: Andrew Hendel, CEO

---

## 1. Introduction

### 1.1 Purpose

This Continuous Monitoring (ConMon) Plan defines the ongoing monitoring strategy for the Latent Archon platform to maintain security authorization and ensure continued compliance with FedRAMP High and DoD IL5 requirements. It implements NIST SP 800-137 guidance and FedRAMP ConMon requirements. The system operates within GCP IL5 Assured Workloads, with non-IL5 services (Identity Platform, Cloud Scheduler) in dedicated FedRAMP High projects.

### 1.2 Scope

This plan covers monitoring of all security controls within the authorization boundary, vulnerability management, configuration management, incident response, and reporting obligations.

---

## 2. Monitoring Strategy

### 2.1 Control Monitoring Frequency

| Monitoring Activity | Frequency | Method |
|--------------------|-----------|--------|
| Automated vulnerability scanning | Continuous (per-build) | CI/CD pipeline (Trivy, GoSec, govulncheck, Semgrep) |
| Dependency vulnerability alerts | Daily | Dependabot |
| Infrastructure drift detection | Weekly | `terragrunt plan` comparison |
| Operating system patching | Inherited (CSP) | Managed container infrastructure (Cloud Run / ECS Fargate / Container Apps) |
| KSI evidence collection | Weekly | Go CLI (`cmd/ksi-evidence`) queries cloud APIs per provider; SHA-256 manifest |
| SCN classification | Per-PR | Go CLI (`cmd/classify-scn`) analyzes diffs; posts PR comment |
| OSCAL SSP validation | Per-PR | CI generates OSCAL v1.1.3 JSON and validates schema |
| Configuration compliance check | Weekly | Drata automated monitoring sync |
| Access review (IAM/RBAC) | Monthly | CEO review assisted by automated drift checker |
| Security control assessment | Annual | 3PAO assessment (POA-1) |
| Penetration testing | Annual | 3PAO or qualified assessor (POA-1) |
| Red team exercises | Monthly | Automated red team suite (99 attacks, 6 suites) — no human initiation required |
| POA&M review | Monthly | CEO review and Drata sync |
| SSP update | Annual + on significant change | CEO review |
| Contingency plan test | Monthly | Automated contingency-test CLI (backup/PITR/health checks) |

### 2.2 Automated Monitoring Tools

| Tool | What It Monitors | Alert Mechanism |
|------|-----------------|----------------|
| **Cloud Monitoring** | CPU, memory, latency, error rates, database metrics | Alert policies → notification channels |
| **Cloudflare WAF Analytics** | Edge WAF rule matches, rate-limit actions, threat score challenges, firewall rule blocks, Zero Trust Access decisions | Cloudflare dashboard + Logpush to GCS |
| **Cloud Armor Analytics** | Origin WAF rule matches, DDoS events, blocked requests, bot traffic | Dashboard + alert policies |
| **Cloud Audit Logs** | All cloud resource changes, data access events | Log-based alerts |
| **Application Audit Logger** | Authentication, authorization, data access, role changes, SCIM events | WARN-level events → email notifications |
| **Dependabot** | Dependency vulnerabilities across all repositories | GitHub alerts + automated PRs |
| **Drata** | Control implementation status, evidence freshness, personnel compliance | Dashboard + weekly sync report |
| **CI/CD Security Pipeline** | SAST findings, container vulnerabilities, secret exposure, image signing (Cosign) | Build failure + PR blocking |
| **DLP** (Cloud DLP) | PII, credentials, and financial data in uploaded documents (pre-RAG scanning) | DLP findings logged; optional redaction via de-identify template |
<!-- MULTI-CLOUD: Original monitoring tools also referenced CloudWatch, Azure Monitor, WAFv2, Front Door WAF, Comprehend, AI Language. -->
| **Security Alert Policies** | Cloud Armor WAF block spikes, 5xx error rate, database auth failures, IAM privilege escalation, KMS key lifecycle, secret access | Cloud monitoring alert → notification channels |
| **KSI Evidence Collector** | Network firewall rules, container services, Cloud Armor WAF policies, KMS rotation, log sinks, container images, DB backups, storage versioning | Weekly CI artifact (365-day retention) |
| **SCN Classifier** | Security-critical file changes in PRs (30+ patterns) | PR comment (advisory, non-blocking) |
| **OSCAL Validator** | SSP structural conformance to OSCAL v1.1.3 schema | PR check (advisory, non-blocking) |

> **Automation-first note**: All automated monitoring runs independently without human initiation. Monthly manual reviews (access review, POA&M, vulnerability triage) are directed by the CEO. As the team scales (POA-15), these duties will transfer to dedicated personnel. See SOD-LA-001 §5 for the automation-first security architecture.

---

## 3. Vulnerability Management

### 3.1 Scanning Schedule

All vulnerability scanning runs on **Google Cloud Build** (not GitHub Actions). Scheduled scans are triggered by Cloud Scheduler (FedRAMP High management project) via Pub/Sub push into the IL5 boundary.

| Scanner | Target | Frequency | Platform | Coverage |
|---------|--------|-----------|----------|----------|
| **Trivy** | Container images | Every build + daily | Cloud Build | CVE database (NVD, vendor advisories) |
| **GoSec** | Go source code | Every build + daily | Cloud Build | Go-specific security patterns |
| **Semgrep** | All source code | Daily | Cloud Build | Multi-language vulnerability patterns |
| **govulncheck** | Go dependencies | Every build + daily | Cloud Build | Go vulnerability database |
| **Gitleaks** | Git history | Every build + daily | Cloud Build | Credential/secret patterns |
| **Dependabot** | All dependencies | Daily | GitHub | GitHub Advisory Database |
| **Red Team Suite** | Deployed system | Monthly | Cloud Build (Cloud Run Job) | 99 attacks across 6 suites (auth bypass, escalation, exfiltration, leftfield, webapp, manual tools) |

**Daily scan pipeline** (`cloudbuild-security.yaml`): GoSec + Semgrep + Trivy FS + govulncheck + Gitleaks run in parallel at 6am ET via Cloud Scheduler (FedRAMP High mgmt project). SARIF results are uploaded to the build artifacts GCS bucket with date-partitioned paths.

### 3.2 Remediation SLAs

Per FedRAMP ConMon requirements (tightened to High-baseline timelines):

| Severity | CVSS Score | Remediation Deadline | Escalation |
|----------|-----------|---------------------|------------|
| **Critical** | 9.0 - 10.0 | 15 days | CEO notified immediately; expedited patch within 72 hours if actively exploited |
| **High** | 7.0 - 8.9 | 30 days | CEO / ISSO notified within 24 hours |
| **Medium** | 4.0 - 6.9 | 90 days | Tracked in POA&M |
| **Low** | 0.1 - 3.9 | 180 days | Tracked in POA&M |

### 3.3 Vulnerability Reporting

- **Monthly**: Vulnerability scan summary included in ConMon report
- **Unique Vulnerabilities**: Each new finding logged as POA&M item with owner, target date, and remediation plan
- **False Positives**: Documented with justification and approved by CEO / ISSO
- **Deviation Requests**: Submitted to FedRAMP PMO for vulnerabilities that cannot meet SLA

---

## 4. Configuration Management Monitoring

Refer to the Configuration Management Plan (CMP-LA-001) for detailed procedures.

Key monitoring activities:
- **Weekly**: Terraform drift detection via `terragrunt plan`
- **Weekly**: KSI evidence collection — Go CLI queries cloud API endpoints per provider and writes JSON evidence with SHA-256 checksum manifest
- **Per-PR**: Automated SCN classifier flags changes to security-critical paths (auth, crypto, network, IAM, SSP) as SIGNIFICANT or ROUTINE
- **Per-deploy**: Configuration baseline comparison
- **Continuous**: GitHub branch protection enforcement
- **Monthly**: IAM role and service account review

---

## 5. Incident Monitoring

Refer to the Incident Response Policy (POL-IR-001) for detailed procedures.

### 5.1 Real-Time Security Event Monitoring

| Event Category | Detection Source | Response |
|---------------|-----------------|----------|
| Authentication failures (threshold exceeded) | Application audit logger | Email notification to org admin |
| Cross-org access attempts | Auth interceptor WARN log | Immediate investigation |
| Role escalation events | Application audit logger | Email notification + audit review |
| Cloud Armor WAF blocks (high volume) | Cloud Armor analytics | DDoS assessment |
| Unexpected GCP resource changes | Cloud Audit Logs | Unauthorized change investigation |
| SCIM token creation/revocation | Application audit logger | Notification to org admin |
| ClamAV malware detection | Upload handler | File quarantine + investigation |
| DLP findings (PII/credentials in uploads) | Cloud DLP inspect template | Logged findings; optional redaction; review for data handling |
| Cloud Armor WAF block spike | Cloud Monitoring alert (Cloud Armor DENY events) | Active attack assessment; WAF rule review |
| 5xx error rate spike | Cloud Monitoring MQL alert (ratio > threshold) | Service health investigation; rollback assessment |
| Cloud SQL auth failures | Cloud Monitoring alert (FATAL/password failures) | Brute force assessment; SA credential review |
| IAM privilege escalation | Cloud Monitoring alert (SetIamPolicy/CreateRole/UpdateRole) | Unauthorized change investigation; revert if unapproved |
| KMS key lifecycle event | Cloud Monitoring alert (key disable/destroy/version change) | Verify authorized operation; escalate if unauthorized |
| Secret access | Cloud Monitoring alert (AccessSecretVersion) | Verify authorized access; investigate unexpected callers |
| Break-glass secret access (db-postgres-password) | Cloud Monitoring log-based metric + CRITICAL alert | Immediate investigation; verify authorized break-glass operation; rotate password if unauthorized |
| Database DDL/role changes | pgAudit (`ddl,role,write`) via Cloud SQL flags | Review for unauthorized schema modifications |
| Slow queries (>1s) | `log_min_duration_statement=1000` Cloud SQL flag | Performance investigation; potential abuse detection |
| BinAuthz admission denial | Cloud Monitoring alert (Binary Authorization deny event) | Unauthorized image deployment investigation; verify attestation pipeline |
| BinAuthz break-glass override | Cloud Monitoring alert (break-glass annotation on deploy) | Verify authorized emergency operation; audit break-glass justification |

### 5.2 Incident Reporting

- **Internal**: All security events logged and reviewed monthly
- **FedRAMP PMO**: Significant incidents reported per FedRAMP Incident Communications Procedures
- **US-CERT**: Reported within required timelines per CISA guidance
- **Customer Agencies**: Notified of incidents affecting their data within 1 hour

---

## 6. Reporting

### 6.1 Monthly ConMon Deliverables

| Deliverable | Content | Audience |
|------------|---------|----------|
| **Vulnerability Scan Report** | New findings, open findings, remediated findings, false positives | FedRAMP PMO, Agency AO |
| **POA&M Update** | Status of all open items, new items, closed items | FedRAMP PMO, Agency AO |
| **Inventory Update** | Changes to system components, new services, decommissioned services | FedRAMP PMO |

### 6.2 Annual ConMon Deliverables

| Deliverable | Content | Audience |
|------------|---------|----------|
| **3PAO Assessment Report (SAR)** | Annual security control assessment results | FedRAMP PMO, Agency AO |
| **Updated SSP** | Reflect all system changes during the year | FedRAMP PMO, Agency AO |
| **Updated PIA** | Privacy impact reassessment | FedRAMP PMO |
| **Contingency Plan Test Report** | Results of annual CP test | FedRAMP PMO, Agency AO |
| **Penetration Test Report** | Annual penetration test findings | FedRAMP PMO, Agency AO |

### 6.3 Significant Change Reporting

Significant changes that trigger SSP update and notification:
- New external services or integrations
- Architecture changes (new container services, new cloud environments)
- Changes to authorization boundary
- New data types or PII categories
- Changes to cryptographic implementations
- Changes to authentication mechanisms

The automated SCN classifier (`cmd/classify-scn`) runs on every PR and classifies changes against 30+ security-critical path patterns. When a change is classified SIGNIFICANT, the CI posts a PR comment directing the team to file an SCN with the FedRAMP PMO before merging. This classification is currently advisory (non-blocking) and will be promoted to a required status check prior to authorization.

---

## 7. Evidence Collection

### 7.1 Automated Evidence via Drata

The Drata sync CLI (`drata-sync`) automatically uploads the following evidence weekly:

| Evidence Type | Source | Drata Mapping |
|--------------|--------|---------------|
| 13 security policies | compliance/policies/ | Policy evidence library |
| SSP document | compliance/fedramp-ssp.md | SSP evidence |
| Security whitepaper | compliance/security-whitepaper.md | Architecture evidence |
| SBOM artifacts | CI/CD pipeline | Software composition evidence |
| Red team reports | redteam CI/CD | Penetration test evidence |
| Vendor registry | drata-sync vendors | Vendor management evidence |
| Risk register | drata-sync risks | Risk assessment evidence |
| Asset inventory | drata-sync assets | Asset management evidence |

### 7.2 Automated KSI Evidence via CI

The KSI evidence collector (`cmd/ksi-evidence`) runs weekly via GitHub Actions and collects machine-readable evidence from cloud APIs. The collector auto-detects the target cloud provider and queries the appropriate APIs:

| KSI Theme | Evidence File | GCP API |
|-----------|--------------|--------|
| IAM: Non-user authentication | `ksi-iam-sa-keys.json` | IAM Credentials |
| IAM: Least privilege | `ksi-iam-bindings.json` | Resource Manager |
| CNA: Network restrictions | `ksi-cna-firewall.json` | Compute Firewalls |
| CNA: Attack surface | `ksi-cna-services.json` | Cloud Run Services |
| CNA: DDoS protection | `ksi-cna-armor.json` | Compute Security Policies |
| SVC: Cryptographic modules | `ksi-svc-kms.json` | Cloud KMS |
| MLA: SIEM integration | `ksi-mla-sinks.json` | Cloud Logging Config |
| VDR: Vulnerability scanning | `ksi-vdr-images.json` | Artifact Registry |
| REC: Recovery capabilities | `ksi-rec-db-backup.json` | Cloud SQL Admin |
| REC: Storage versioning | `ksi-rec-storage-versioning.json` | Cloud Storage |

<!-- MULTI-CLOUD: Original table included AWS API (IAM Access Keys, IAM Policies, Security Groups, ECS Services, WAFv2 Web ACLs, AWS KMS, CloudWatch Log Groups, ECR, RDS Snapshots, S3 Versioning) and Azure API (Azure AD App Credentials, RBAC Role Assignments, NSG Rules, Container Apps, Front Door WAF Policies, Key Vault, Azure Monitor Diagnostics, Container Registry, PostgreSQL Flex Backups, Blob Versioning) columns. -->

Each collection run produces a `manifest.json` with SHA-256 checksums and byte counts for every evidence file. Evidence artifacts are uploaded to GitHub Actions with 365-day retention.

### 7.3 Manual Evidence

| Evidence | Collection Method | Frequency |
|----------|------------------|-----------|
| Access review records | Screenshot of IAM review | Monthly |
| Training completion records | HR records | Annual |
| Contingency plan test results | Test report document | Annual |
| Background check records | HR records | Per-hire + 5-year renewal |
| Incident response records | Incident reports | Per-incident |

---

## 8. Plan Maintenance

- **Annual Review**: Full ConMon plan review aligned with SSP annual review
- **Change-Triggered Update**: Updated when monitoring tools, frequencies, or reporting requirements change
- **FedRAMP Guidance Updates**: Plan updated to reflect new FedRAMP ConMon guidance within 60 days of issuance
- **Training**: All operations personnel trained on ConMon procedures during onboarding and annually

---

_End of Continuous Monitoring Plan_
