# Separation of Duties Matrix

> **Document ID**: SOD-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md)
> **Version**: 1.1
> **Date**: April 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Owner**: Andrew Hendel, CEO / ISSO
> **NIST 800-53 Controls**: AC-5, CM-3, CM-5, SA-10

---

## 1. Purpose

This matrix documents the separation of duties controls within the Latent Archon platform, ensuring that no single individual can independently complete a critical action without oversight. It satisfies NIST SP 800-53 AC-5 (Separation of Duties) and supports CM-3 (Configuration Change Control), CM-5 (Access Restrictions for Change), and SA-10 (Developer Configuration Management).

---

## 2. Role Definitions

### 2.1 Founder-Led Organization

Latent Archon operates as a founder-led, automation-first security organization. The founding team directs strategy, architecture, and compliance while an integrated automation workforce independently executes security scanning, deployment, monitoring, and evidence collection. This model delivers continuous, machine-verified security coverage that exceeds what manual processes alone can achieve.

| Role | Description | Personnel | Status |
|------|-------------|-----------|--------|
| **CEO / ISSO** | System owner, ISSO, engineering, operations, and security leadership | Andrew Hendel | Active |
| **Automation Workforce** | Independent automated security scanning (6 tools), deployment, drift detection, evidence collection, adversarial testing — acts as independent second actor | GitHub Actions / Cloud Build / Cloud Monitoring | Active |
| **Customer Admin** | Manages users within their organization | Per-customer agency | Active (post-onboarding) |

<details>
<summary> Growth Plan: Organizational Scaling (revenue-triggered)</summary>

| Role | Description | Hire Trigger |
|------|-------------|--------------|
| **Security Lead** | Dedicated incident response, vulnerability management, access reviews, forensics | First federal customer or 3PAO engagement |
| **Engineering Lead** | Dedicated code review, infrastructure deployment, technical implementation | Scaling milestone |
| **Developer(s)** | Additional code authoring, testing, documentation capacity | Revenue supports headcount |

As the team grows, duties currently handled by the CEO will transfer to dedicated personnel. The automation-first architecture remains the foundation regardless of team size.

</details>

---

## 3. Separation of Duties Matrix

### 3.1 Code and Infrastructure Changes

| Action | CEO / ISSO | Automation Workforce | Enforced By |
|--------|---------------|-------------|-------------|
| Author code changes | **Perform** | — | Git commit (signed) |
| Submit PR | **Perform** | — | GitHub |
| Run security scans (SAST, SCA, secrets) | — | **Perform (independent)** | CI/CD pipeline (automatic, cannot be bypassed) |
| Merge to protected branch | **Perform** (only after CI passes) | **Gate** | GitHub branch protection (CI checks required) |
| Deploy to staging | — | **Perform (automatic)** | Cloud Build trigger (automatic on merge) |
| Promote to production | **Authorize** | **Perform** | Manual promotion workflow |
| Apply Terraform changes | **Author** | **Plan + Apply** | `terragrunt apply` via CI (not local) |

> **Compensating control**: The CEO cannot merge code that fails security scans. The CI/CD system independently evaluates every change for SAST findings (GoSec), dependency vulnerabilities (govulncheck), secret exposure (Gitleaks), container CVEs (Trivy), and policy patterns (Semgrep). These gates cannot be disabled without a code change that itself goes through CI.

### 3.2 Access Management

| Action | CEO / ISSO | Automation Workforce | Customer Admin | Enforced By |
|--------|---------------|-------------|---------------|-------------|
| Grant GCP IAM roles | **Author** (IaC only) | **Apply** | — | Terraform (console changes blocked by org policy) |
| Create service accounts | **Author** (IaC only) | **Apply** | — | Terraform (SA key creation blocked by org policy) |
| Assign application roles (internal) | **Perform** | — | — | Admin API + audit log |
| Assign application roles (customer) | — | — | **Perform** | Admin portal (scoped to own org) |
| Create/revoke SCIM tokens | — | — | **Perform** | Admin portal (scoped to own org) |
| Configure SSO/SAML | **Approve** | — | **Request** | Admin API + Identity Platform |
| Review IAM access (monthly) | **Perform** | **Assist** (drift checker) | — | SOP-03 + automated SSP-IaC drift checker |
| Revoke terminated user access | **Perform** | — | Perform (own org) | Admin API + audit log |

> **Compensating control**: IAM changes are impossible via GCP Console (org policy `iam.disableServiceAccountKeyCreation` + IaC-only workflow). The `check-ssp-iac-drift` CLI detects unauthorized IAM bindings weekly.

### 3.3 Security Operations

| Action | CEO / ISSO | Automation Workforce | Customer Admin | Enforced By |
|--------|---------------|-------------|---------------|-------------|
| Triage vulnerability findings | **Perform** | **Detect** (continuous scanning) | — | SOP-01 + Dependabot + CI scanners |
| Approve false positive determination | **Perform + Document** | — | — | POA&M process (justification required) |
| Submit deviation request to FedRAMP | **Perform** | — | — | FedRAMP PMO portal |
| Activate incident response | **Authorize + Execute** | **Detect** (alerts) | — | IR Policy (POL-IR-001) |
| Conduct forensic investigation | **Perform** | **Preserve** (immutable audit logs) | — | Cloud Audit Logs (WORM, 7yr retention) |
| File US-CERT/CISA report | **Perform** | — | — | IR Policy |
| Approve DLP quarantine override (PII) | — | — | **Perform** (own org) | Admin portal + DLP audit log |
| Approve DLP quarantine override (credentials) | **Perform** (org admin required) | — | — | Admin API + elevated audit log |
| Review audit logs | **Perform** | **Collect** (automated KSI evidence) | — | SOP-03 + weekly KSI collection |

> **Compensating control**: Vulnerability detection is fully automated and continuous — findings appear without human initiation. Audit logs are immutable (WORM bucket, 7-year retention) and cannot be tampered with by any human actor including the CEO.

### 3.4 Cryptographic Operations

| Action | CEO / ISSO | Automation / Cloud Platform | Enforced By |
|--------|---------------|----------------------|-------------|
| Create KMS keys | **Author** (IaC only) | **Apply** | Terraform (IaC-only) |
| Rotate KMS keys | — | **Automatic** (90-day) | Cloud KMS auto-rotation |
| Destroy KMS keys | **Authorize** | **24-hour hold** | Cloud KMS (24-hour pending period — allows cancellation) |
| Manage TLS certificates | — | **Automatic** | GCP Managed Certs / ACM / App Service |
| Enable BoringCrypto (FIPS) | **Author** | **Verify** (CI scan) | Dockerfile + CI scan |

> **Compensating control**: Key rotation is fully automated (no human action required). Key destruction has a mandatory 24-hour pending period enforced by the cloud platform, providing a window for detection and cancellation. Cloud Monitoring alerts fire on any KMS lifecycle event.

### 3.5 Data Operations

| Action | CEO / ISSO | Automation Workforce | Customer Admin | Enforced By |
|--------|---------------|-------------|---------------|-------------|
| Access production database | **Break-glass only** | — | — | Secret Manager + CRITICAL alert policy |
| Modify database schema | **Author** | **Validate + Apply** (Atlas migrations) | — | Migration PR + CI + Atlas checksums |
| Delete customer data | **Authorize** | — | **Request** | Admin API + audit log |
| Export customer data | **Authorize** | — | **Request** | Admin API + audit log |
| Restore from backup | **Authorize + Execute** | — | — | ISCP procedures |

> **Compensating control**: Database access is impossible in normal operations — all services use IAM auth (no passwords). The `db-postgres-password` secret access triggers a CRITICAL Cloud Monitoring alert. Schema changes are validated by Atlas checksum verification and cannot be applied out of order. pgAudit logs all DDL, role changes, and write operations.

---

## 4. Conflict Detection and Automation-First Mitigations

In a founder-led organization, traditional two-person conflict detection is replaced by human-vs-automation separation:

| Traditional Conflict | Founder-Led Reality | Automation-First Control |
|---------------------|----------------------|---------------------|
| Same person authors AND approves code | CEO authors; automation reviews | Automation workforce independently gates all merges: SAST, SCA, secrets scan, container scan must pass. CEO cannot bypass CI. |
| Same person deploys AND approves deployment | CEO authors; automation deploys | Deployment is fully automated — CEO cannot deploy manually. Production requires explicit promotion step. |
| Same person manages IAM AND reviews IAM | CEO authors IaC; automation applies | Org policy blocks console IAM changes. Weekly `check-ssp-iac-drift` detects any unauthorized bindings. Immutable audit logs. |
| Same person creates AND approves vulnerability exception | CEO triages machine-generated findings | All findings are machine-generated (not self-reported). FP determinations require written justification in POA&M. Drata tracks evidence. |
| Same person authors AND reviews compliance docs | CEO authors; automation validates | OSCAL validator checks SSP structure. `check-ssp-iac-drift` validates 26+ claims against live infrastructure. 3PAO provides independent review at assessment. |

---

## 5. Automation-First Security Architecture

Latent Archon’s security architecture is built on the principle that **machines should independently enforce what other organizations rely on humans to do**. The automation workforce operates as a fully independent second actor — it cannot be overridden, bypassed, or silenced by any human, including the CEO.

### 5.1 Automation Workforce Capabilities

| Traditional Control | Compensating Control | Verification |
|--------------------|---------------------|-------------|
| Separate development and operations teams | CI/CD pipeline handles all deployment; operator cannot deploy manually or skip scanning | Cloud Build audit logs |
| Dedicated security team for reviews | 6 automated scanners (GoSec, Semgrep, govulncheck, Trivy, Gitleaks, Dependabot) run independently on every change | CI logs, Drata evidence |
| Separate database administrator | Zero direct database access in normal operations; all schema changes via Atlas migrations with checksum verification; IAM-only auth | pgAudit logs, Cloud SQL audit logs |
| Separate network administrator | All network/firewall config via Terraform; console changes blocked by org policy; weekly drift detection | Terraform state, drift detection logs |
| Change Advisory Board (multi-person) | Automated security checks act as independent review; significant changes flagged by SCN classifier; 3PAO provides external review at assessment | SCN classifier PR comments, CI logs |
| Independent security assessments | Monthly automated red team (44 attacks), weekly KSI evidence collection, weekly drift detection | Red team reports, KSI artifacts |
| Segregated audit log review | Audit logs written to WORM storage; operator cannot modify or delete; automated KSI evidence collector independently verifies log sink configuration | Cloud Audit Logs, WORM bucket |

### 5.2 Growth-Dependent Controls

The following controls will be enhanced as the team scales:

| Control Area | NIST Control | Current Implementation | Enhancement at Scale |
|-------------|-------------|----------------------|---------------------|
| Code review | SA-11, CM-3 | 6 independent automated security scanners review every change | Add dedicated human reviewer |
| Incident investigation | IR-4, IR-5 | Immutable audit logs provide complete forensic record; 3PAO provides annual independent review | Add dedicated Security Lead |
| Two-person integrity | CM-5(1) | Cloud platform enforces 24-hr KMS destroy hold; break-glass access triggers CRITICAL alerts | Add second authorized signatory |
| Adversarial personnel testing | AT-2(1) | Continuous automated adversarial testing (44-attack red team suite, monthly) | Add phishing simulation program |
| Multi-participant exercises | IR-3, CP-4 | Automated contingency testing (monthly CLI) + documented scenario walkthroughs | Add facilitated multi-person tabletop |

---

## 6. Audit Trail

All actions in the matrix above produce audit records. Critically, **no human — including the CEO — can modify or delete any audit record**. All logs flow to immutable (WORM) storage with 7-year retention.

| System | Audit Source | Retention | Tamper-Proof |
|--------|-------------|----------|-------------|
| GitHub | PR reviews, merge events, branch protection logs | Indefinite (GitHub) | GitHub-managed |
| Cloud Build | Build logs, deployment records | 400 days (Cloud Logging) | Cloud Logging WORM sink |
| GCP Cloud Audit Logs | IAM changes, resource creation, data access | 7 years (WORM bucket) | Bucket Lock retention policy |
| Application Audit Logger | Authentication, authorization, data access, role changes | 7 years (WORM bucket) | Bucket Lock retention policy |
| Cloud KMS | Key creation, rotation, destruction events | 7 years (WORM bucket) | Bucket Lock retention policy |
| Secret Manager | Secret access events | 7 years (WORM bucket) | Bucket Lock retention policy |
| pgAudit | Database DDL, role changes, write operations | 7 years (via Cloud Logging sink) | Cloud Logging WORM sink |

---

## 7. Document Revision History

| Version | Date | Change |
|---------|------|--------|
| 1.0 | March 2026 | Initial draft with projected team structure |
| 1.1 | April 2026 | Rewritten to reflect founder-led, automation-first organizational model. Automation workforce documented as independent second actor. Growth-dependent controls identified. |

---

_End of Separation of Duties Matrix — SOD-LA-001_
