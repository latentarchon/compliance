# Privacy Impact Assessment (PIA)

> **Document ID**: PIA-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md)
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Prepared By**: Andrew Hendel, CEO

---

## 1. System Overview

### 1.1 System Description

Latent Archon is a multi-tenant SaaS document intelligence platform that enables government agencies to securely upload, process, search, and interact with documents using AI-powered retrieval-augmented generation (RAG). The system is hosted on Google Cloud Platform (FedRAMP High authorized).

### 1.2 Purpose of the PIA

This PIA identifies and evaluates privacy risks associated with the collection, use, storage, and sharing of personally identifiable information (PII) within the Latent Archon platform. It satisfies requirements under the E-Government Act of 2002 (Section 208), OMB M-03-22, and NIST SP 800-122.

---

## 2. PII Inventory

### 2.1 PII Collected Directly

| PII Element | Source | Purpose | Retention |
|------------|--------|---------|-----------|
| **Email address** | User registration / SAML SSO / SCIM | Account identification, notifications, audit | Duration of account + 90 days |
| **Display name** | User registration / SAML SSO / SCIM | UI display, audit attribution | Duration of account + 90 days |
| **IP address** | HTTP request headers | Audit logging, Cloud Armor security, IP allowlisting | 365 days (audit log) |
| **User agent string** | HTTP request headers | Audit logging, anomaly detection | 365 days (audit log) |
| **TOTP MFA seed** | MFA enrollment (Identity Platform) | Second-factor authentication | Duration of account (managed by Identity Platform) |
| **Firebase UID** | Identity Platform token | Session management, RBAC | Duration of account |
| **IdP external ID** | SAML assertion / SCIM | Federated identity mapping | Duration of account |

### 2.2 PII in Customer Documents

Customer agencies upload documents that may contain any category of PII depending on agency mission. Latent Archon does not parse or extract PII from documents — documents are processed for text extraction (Document AI OCR) and semantic embedding (Vertex AI) only. The system treats all document content as CUI.

| PII Category | System Awareness | Protection |
|-------------|-----------------|------------|
| **Names, SSNs, financial data** | System is unaware of content semantics | RLS, CMEK encryption, workspace isolation |
| **Health information** | System is unaware of content semantics | RLS, CMEK encryption, workspace isolation |
| **Law enforcement records** | System is unaware of content semantics | RLS, CMEK encryption, workspace isolation |

---

## 3. Data Flow Analysis

### 3.1 PII Collection Points

1. **Account Registration**: Email and display name collected via Identity Platform sign-up flow (chat or admin app)
2. **SAML SSO**: Email, name, and IdP-assigned attributes received in SAML assertion
3. **SCIM Provisioning**: Email, name, external ID, and group memberships pushed by customer IdP
4. **HTTP Requests**: IP address and user agent captured automatically by Cloud Armor and application audit logger
5. **Document Upload**: Customer-uploaded documents may contain arbitrary PII

### 3.2 PII Storage Locations

| Location | PII Stored | Encryption | Access Control |
|----------|-----------|------------|----------------|
| **Cloud SQL (PostgreSQL)** | Email, name, Firebase UID, external ID, audit events (IP, UA) | CMEK AES-256 (FIPS 140-2 L3 HSM) | RLS + DB role separation |
| **Identity Platform** | Email, name, MFA seed, password hash | Google-managed encryption | Firebase Admin SDK (SA-scoped) |
| **Cloud Storage** | Document files (may contain PII) | CMEK AES-256 | Workspace-scoped object paths + IAM |
| **Vertex AI** | Document text embeddings (may encode PII semantics) | Google-managed encryption | Workspace-scoped vector tokens |
| **Cloud Logging** | IP addresses, user agents, request metadata | Google-managed encryption | IAM (logging.viewer) |

### 3.3 PII Sharing

| Recipient | PII Shared | Purpose | Mechanism |
|-----------|-----------|---------|-----------|
| **Google Cloud Platform** | All stored PII (as infrastructure provider) | Infrastructure hosting | GCP Data Processing Terms |
| **Customer Agency Admins** | Member emails, names, audit events | Organization management | Admin API (RBAC-gated) |
| **Customer SIEM** | Audit events (IP, UA, email) | Security monitoring | Pub/Sub export (opt-in) |

PII is **never** shared with: marketing platforms, analytics services, third-party AI providers (Vertex AI is first-party GCP), or other customer organizations.

---

## 4. Privacy Risk Assessment

### 4.1 Risk: Unauthorized Access to PII

- **Likelihood**: Low
- **Impact**: High
- **Mitigations**:
  - 5-layer organization isolation (IDP pool, header match, org membership, subdomain validation, cross-org check)
  - PostgreSQL Row-Level Security (fail-closed)
  - RBAC with least privilege
  - MFA required for all users
  - Per-org session timeouts (configurable)
  - Per-org IP allowlisting via Cloud Armor
- **Residual Risk**: Low

### 4.2 Risk: PII Exposure via AI/Search

- **Likelihood**: Low
- **Impact**: High
- **Mitigations**:
  - Vector search results scoped by workspace tokens (cross-workspace leakage prevented)
  - LLM responses grounded only in workspace-accessible documents
  - No cross-organization vector search possible
  - Embeddings do not contain raw PII (numerical vectors only)
- **Residual Risk**: Low

### 4.3 Risk: PII in Audit Logs Retained Beyond Necessity

- **Likelihood**: Medium
- **Impact**: Low
- **Mitigations**:
  - Audit log retention: 365 days in Cloud SQL (configurable), 30 days in Cloud Logging
  - Automated log rotation and deletion via Cloud Scheduler
  - Customer agencies can configure shorter retention periods
- **Residual Risk**: Low

### 4.4 Risk: PII Exposure via Backup/Recovery

- **Likelihood**: Low
- **Impact**: Medium
- **Mitigations**:
  - All backups encrypted with CMEK (same keys as primary data)
  - Cloud SQL PITR backups retained 30 days then auto-deleted
  - GCS object versions retained 365 days then auto-deleted
  - Cryptographic erasure available via CMEK key rotation
- **Residual Risk**: Low

### 4.5 Risk: Insider Threat — Unauthorized PII Access by CSP Personnel

- **Likelihood**: Low
- **Impact**: High
- **Mitigations**:
  - No standing production database access for any personnel
  - Break-glass access requires CEO approval and is audit-logged
  - All GCP IAM actions logged in Cloud Audit Logs
  - Background screening for all personnel
  - Personnel sanctions for policy violations
- **Residual Risk**: Low

### 4.6 Risk: PII Retained After Account Closure

- **Likelihood**: Low
- **Impact**: Medium
- **Mitigations**:
  - Account closure (`CloseAccount` RPC) triggers automated data purge
  - Step-up MFA required for account closure (prevents accidental deletion)
  - User PII purged within 90 days of account closure
  - Document data purged per organization retention policy
  - Cryptographic erasure available via CMEK key rotation
- **Residual Risk**: Low

---

## 5. Privacy Controls

### 5.1 Notice

- Privacy notice provided during account registration
- Terms of Service describe data processing activities
- Organization-level Data Processing Agreements available for agency customers

### 5.2 Consent

- Users consent via Terms of Service acceptance during registration
- Organization admins consent on behalf of their users via service agreements
- Users can withdraw consent by closing their account

### 5.3 Data Minimization

- Only email and display name collected for account operation
- IP and user agent collected only for security audit purposes
- No behavioral analytics, tracking pixels, or advertising data collected
- Document content is processed for search only — no content mining or profiling

### 5.4 Purpose Limitation

PII is used exclusively for:
1. Authentication and session management
2. RBAC and organization membership
3. Security audit logging
4. Service delivery (document processing and search)
5. Account communication (invitations, security notifications)

### 5.5 Data Subject Rights

| Right | Implementation |
|-------|---------------|
| **Access** | Users can view their profile information via the application |
| **Correction** | Users can update their display name; email changes require re-verification |
| **Deletion** | `CloseAccount` RPC triggers automated purge (90-day window for recovery) |
| **Portability** | Document export available via admin API |
| **Restriction** | Organization admins can disable user accounts |

---

## 6. Determination

Based on this assessment, the Latent Archon platform processes PII with appropriate privacy protections. Key findings:

- **PII collection is minimized** to what is necessary for service operation
- **Technical controls** (RLS, encryption, isolation, MFA) provide strong protection
- **Data retention** is bounded and configurable
- **Data subject rights** are implemented via application features
- **No PII is shared** with unauthorized third parties

### 6.1 Recommendations

1. Publish a public-facing privacy policy on the marketing site
2. Implement automated PII detection in uploaded documents (optional, for customer awareness)
3. Conduct annual PIA refresh aligned with SSP review
4. Engage 3PAO to validate privacy controls during FedRAMP assessment

---

## 7. Document Maintenance

- **Annual Review**: PIA reviewed and updated annually, aligned with SSP review
- **Change-Triggered Update**: Updated when new PII categories are collected or new data flows are established
- **Approval**: CEO approves all PIA revisions

---

_End of Privacy Impact Assessment_
