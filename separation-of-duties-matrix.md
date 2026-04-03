# Separation of Duties Matrix

> **Document ID**: SOD-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md)
> **Version**: 1.0
> **Date**: April 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Owner**: Andrew Hendel, CEO / ISSO
> **NIST 800-53 Controls**: AC-5, CM-3, CM-5, SA-10

---

## 1. Purpose

This matrix documents the separation of duties controls within the Latent Archon platform, ensuring that no single individual can independently complete a critical action without oversight. It satisfies NIST SP 800-53 AC-5 (Separation of Duties) and supports CM-3 (Configuration Change Control), CM-5 (Access Restrictions for Change), and SA-10 (Developer Configuration Management).

---

## 2. Role Definitions

| Role | Description | Personnel |
|------|-------------|-----------|
| **CEO / ISSO** | System owner, authorizes significant changes, manages POA&M, ISSO duties | Andrew Hendel |
| **Security Lead** | Incident response lead, vulnerability management, access reviews, forensics | _TBD (POA-6)_ |
| **Engineering Lead** | Technical implementation, code review, infrastructure deployment | _TBD_ |
| **Developer** | Code authoring, testing, documentation | Engineering team |
| **CI/CD System** | Automated testing, scanning, building, deploying | GitHub Actions / Cloud Build |
| **Customer Admin** | Manages users within their organization | Per-customer agency |

---

## 3. Separation of Duties Matrix

### 3.1 Code and Infrastructure Changes

| Action | Developer | Engineering Lead | CEO / ISSO | CI/CD | Enforced By |
|--------|-----------|-----------------|------------|-------|-------------|
| Author code changes | **Perform** | Perform | — | — | Git commit |
| Submit PR | **Perform** | Perform | — | — | GitHub |
| Approve PR (code review) | — | **Approve** | Approve | — | GitHub branch protection (≥1 reviewer) |
| Run security scans (SAST, SCA, secrets) | — | — | — | **Perform** | CI/CD pipeline (automatic) |
| Merge to protected branch | — | **Perform** | Perform | — | GitHub branch protection |
| Deploy to staging | — | — | — | **Perform** | Cloud Build trigger (automatic on merge) |
| Promote to production | — | **Request** | **Approve** | Perform | Manual promotion workflow |
| Apply Terraform changes | — | **Request** | **Approve** | Perform | `terragrunt apply` via CI (not local) |

### 3.2 Access Management

| Action | Developer | Engineering Lead | CEO / ISSO | Customer Admin | Enforced By |
|--------|-----------|-----------------|------------|---------------|-------------|
| Grant GCP IAM roles | — | — | **Approve + Perform** | — | Terraform (IaC-only policy) |
| Create service accounts | — | — | **Approve + Perform** | — | Terraform (IaC-only policy) |
| Assign application roles (internal) | — | — | **Perform** | — | Admin API |
| Assign application roles (customer) | — | — | — | **Perform** | Admin portal (scoped to own org) |
| Create/revoke SCIM tokens | — | — | — | **Perform** | Admin portal (scoped to own org) |
| Configure SSO/SAML | — | — | **Approve** | **Request** | Admin API + Identity Platform |
| Review IAM access (monthly) | — | — | **Perform** | — | SOP-03 (ConMon SOPs) |
| Revoke terminated user access | — | — | **Perform** | Perform (own org) | HR process + Admin API |

### 3.3 Security Operations

| Action | Developer | Security Lead | CEO / ISSO | CI/CD | Enforced By |
|--------|-----------|--------------|------------|-------|-------------|
| Triage vulnerability findings | — | **Perform** | Review | — | SOP-01 (ConMon SOPs) |
| Approve false positive determination | — | **Perform** | **Approve** | — | POA&M process |
| Submit deviation request to FedRAMP | — | — | **Perform** | — | FedRAMP PMO portal |
| Activate incident response | — | **Recommend** | **Authorize** | — | IR Policy (POL-IR-001) |
| Conduct forensic investigation | — | **Perform** | — | — | IR Policy |
| File US-CERT/CISA report | — | — | **Perform** | — | IR Policy |
| Approve DLP quarantine override | — | — | — | — | Org Admin (**Perform**) |
| Review audit logs | — | **Perform** | Review | — | SOP-03 (ConMon SOPs) |

### 3.4 Cryptographic Operations

| Action | Developer | Engineering Lead | CEO / ISSO | CI/CD | Enforced By |
|--------|-----------|-----------------|------------|-------|-------------|
| Create KMS keys | — | **Request** | **Approve** | — | Terraform (IaC-only) |
| Rotate KMS keys | — | — | — | **Automatic** | Cloud KMS (90-day auto-rotation) |
| Destroy KMS keys | — | — | **Authorize** | — | Cloud KMS (24-hour pending period) |
| Manage TLS certificates | — | — | — | **Automatic** | GCP Managed Certs / ACM / App Service |
| Enable BoringCrypto (FIPS) | — | **Perform** | **Approve** | Verify | Dockerfile + CI scan |

### 3.5 Data Operations

| Action | Developer | Engineering Lead | CEO / ISSO | Customer Admin | Enforced By |
|--------|-----------|-----------------|------------|---------------|-------------|
| Access production database | — | — | **Break-glass only** | — | Secret Manager + alert policy |
| Modify database schema | **Author** | **Approve** | — | — | Migration PR + CI |
| Delete customer data | — | — | **Authorize** | **Request** | Admin API + audit log |
| Export customer data | — | — | **Authorize** | **Request** | Admin API + audit log |
| Restore from backup | — | **Perform** | **Authorize** | — | ISCP procedures |

---

## 4. Conflict Detection

The following role combinations are prohibited (conflict of interest):

| Conflict | Reason | Mitigation |
|----------|--------|------------|
| Same person authors AND approves code | No independent review | GitHub branch protection: author cannot approve own PR |
| Same person deploys AND approves deployment | No deployment oversight | CI/CD auto-deploys; production requires separate approval |
| Same person manages IAM AND reviews IAM | Self-review ineffective | IAM review (SOP-03) performed by ISSO; IAM changes via Terraform by Engineering |
| Same person creates AND approves vulnerability exception | Self-exception | Security Lead triages; CEO approves exceptions |

---

## 5. Compensating Controls (Small Team)

As a small startup, some separation of duties is achieved through automation rather than additional personnel:

| Traditional Control | Compensating Control |
|--------------------|---------------------|
| Separate development and operations teams | CI/CD pipeline handles all deployment; developers cannot deploy manually |
| Dedicated security team for reviews | Automated SAST/SCA/secrets scanning in CI; manual review by ISSO monthly |
| Separate database administrator | No direct database access; all schema changes via version-controlled migrations |
| Separate network administrator | All network configuration via Terraform; no console access for network changes |
| Change Advisory Board (multi-person) | PR review + automated security checks + CEO approval for significant changes |

---

## 6. Audit Trail

All actions in the matrix above produce audit records:

| System | Audit Source | Retention |
|--------|-------------|-----------|
| GitHub | PR reviews, merge events, branch protection logs | Indefinite (GitHub) |
| Cloud Build | Build logs, deployment records | 400 days (Cloud Logging) |
| GCP Cloud Audit Logs | IAM changes, resource creation, data access | 7 years (WORM bucket) |
| Application Audit Logger | Authentication, authorization, data access, role changes | 7 years (WORM bucket) |
| Cloud KMS | Key creation, rotation, destruction events | 7 years (WORM bucket) |
| Secret Manager | Secret access events | 7 years (WORM bucket) |
| pgAudit | Database DDL, role changes, write operations | 7 years (via Cloud Logging sink) |

---

_End of Separation of Duties Matrix — SOD-LA-001_
