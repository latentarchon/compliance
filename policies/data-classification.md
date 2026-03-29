# Latent Archon — Data Classification & Retention Policy

> **Policy ID**: POL-DC-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Security Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: RA-2, MP-1, MP-6, SI-12, AU-11

---

## 1. Purpose

This policy defines data classification levels, handling requirements, retention periods, and disposal procedures for all data processed by the Latent Archon platform. Proper classification ensures data receives protection commensurate with its sensitivity and regulatory requirements.

---

## 2. Scope

This policy applies to all data created, received, processed, stored, or transmitted by Latent Archon, including:

- Customer-uploaded documents and generated content
- Conversation messages and AI-generated responses
- User account and authentication data
- Audit logs and system telemetry
- Source code and infrastructure configuration
- Business records and compliance documentation

---

## 3. Data Classification Levels

| Level | Label | Definition | Examples |
|-------|-------|-----------|----------|
| **1** | **CUI / Restricted** | Controlled Unclassified Information or data subject to regulatory protection. Unauthorized disclosure could cause serious harm. | Customer documents (may contain CUI), document embeddings, conversation messages referencing CUI |
| **2** | **Confidential** | Internal business data not intended for public disclosure. Unauthorized disclosure could cause moderate harm. | User credentials (hashed), API keys, SCIM tokens, audit event details, source code, infrastructure configs |
| **3** | **Internal** | Operational data for internal use. Unauthorized disclosure would cause limited harm. | System logs, performance metrics, deployment records, internal documentation |
| **4** | **Public** | Information approved for public disclosure. | Marketing website content, published security whitepaper (redacted), public API documentation |

---

## 4. Data Inventory

### 4.1 Customer Data (CUI / Restricted)

| Data Type | Storage | Encryption | Isolation | Retention |
|-----------|---------|-----------|-----------|-----------|
| Uploaded documents | Object storage (CMEK) | AES-256 at rest, TLS in transit | Per-workspace bucket prefix | Customer-controlled (purge on account deletion) |
| Document chunks & metadata | PostgreSQL (CMEK) | AES-256 at rest, TLS in transit | PostgreSQL RLS (FORCE) | Customer-controlled |
| Document embeddings | Vector search (CMEK) | AES-256 at rest (CMEK via cloud KMS, HSM-backed, 90-day rotation), TLS via private endpoint | Workspace-scoped token restrictions | Customer-controlled |
| Conversation messages | PostgreSQL (CMEK) | AES-256 at rest, TLS in transit | PostgreSQL RLS (FORCE) | Customer-controlled |
| AI-generated images | Object storage (CMEK) | AES-256 at rest, TLS in transit | Per-workspace path | Customer-controlled |

### 4.2 Account Data (Confidential)

| Data Type | Storage | Encryption | Retention |
|-----------|---------|-----------|-----------|
| User profiles (email, name) | PostgreSQL (CMEK) | AES-256 | Account lifetime + 30 days |
| Auth credentials | Identity provider | Provider-managed encryption | Account lifetime |
| TOTP MFA secrets | Identity provider | Provider-managed encryption | Account lifetime |
| SCIM tokens (SHA-256 hash only) | PostgreSQL (CMEK) | AES-256 | Until revoked |
| SSO configurations | PostgreSQL (CMEK) | AES-256 | Organization lifetime |
| Organization/workspace metadata | PostgreSQL (CMEK) | AES-256 | Account lifetime |

### 4.3 Operational Data (Internal)

| Data Type | Storage | Retention |
|-----------|---------|-----------|
| Application audit events | PostgreSQL | Indefinite (compliance requirement) |
| Audit dataset | Analytics storage (CMEK) | Indefinite (no expiration) |
| WORM audit bucket | Object storage (locked retention, versioned, CMEK) | 2-year locked retention (production), 1-year (staging) |
| Cloud Audit Logs (Admin Activity) | Cloud logging | Always on, indefinite |
| Cloud Audit Logs (Data Access) | Cloud logging | Enabled for database, container, KMS, IAM, storage services |
| Container access logs | Cloud logging | 30 days (default) |
| Terraform state | Cloud storage (versioned, CMEK) | Indefinite |
| CI/CD build logs | GitHub Actions | 90 days |
| Container images | Container registry (CMEK) | Current + 5 previous versions |
| Red team attack logs | Object storage (versioned) | 365 days |

---

## 5. Data Handling Requirements

### 5.1 By Classification Level

| Requirement | CUI/Restricted | Confidential | Internal | Public |
|-------------|---------------|-------------|----------|--------|
| Encryption at rest | Required (CMEK) | Required (CMEK or Google-managed) | Required (Google-managed) | Optional |
| Encryption in transit | Required (TLS 1.2+) | Required (TLS 1.2+) | Required (TLS 1.2+) | HTTPS preferred |
| Access control | RBAC + RLS + MFA | RBAC + MFA | Role-based | Open |
| Audit logging | Full (all operations) | Full (all modifications) | Standard | None required |
| Tenant isolation | Required (5-layer) | N/A | N/A | N/A |
| Backup | Required (PITR) | Required | Required | Optional |
| Sharing | Prohibited without authorization | Need-to-know | Internal only | Unrestricted |

### 5.2 Prohibited Handling

- CUI/Restricted data must **never** be stored on personal devices, personal email, or unapproved cloud services
- Confidential data must **never** be committed to source code repositories
- No data of any classification may be transmitted over unencrypted channels
- Customer data must **never** be used for training AI models or shared across tenant boundaries

---

## 6. Retention Schedule

### 6.1 Retention Periods

| Data Category | Minimum Retention | Maximum Retention | Basis |
|---------------|-------------------|-------------------|-------|
| Customer documents & messages | Customer-controlled | Indefinite (WORM retention: 2yr locked production, 1yr staging) | Customer agreement + WORM policy |
| Application audit events | Indefinite | Indefinite | NIST AU-11, CJIS §5.4, zero-deletion policy |
| BigQuery audit dataset | Indefinite | Indefinite (no table/partition expiration, CMEK) | NIST AU-11, zero-deletion policy |
| GCS WORM audit logs | 2 years (locked) | Indefinite (tiered to COLDLINE, never deleted) | NIST AU-9, CJIS §5.4 |
| Cloud Audit Logs | 365 days | 365 days (configurable) | CSP default + policy |
| Infrastructure state (Terraform) | Indefinite | Indefinite | Operational need |
| Source code | Indefinite | Indefinite | Business record |
| CI/CD artifacts (SBOMs, scan reports) | 90 days | 1 year | Compliance evidence |
| Red team reports | 1 year | 3 years | Security assessment |
| Employee records | Employment + 3 years | Employment + 7 years | Legal requirement |
| Vendor records | Contract term + 3 years | Contract term + 7 years | Legal requirement |
| Incident reports | 3 years | Indefinite | Compliance |

### 6.2 Retention Holds

- **Litigation hold**: All normal retention/deletion suspended for data subject to legal hold
- **Forensic preservation**: SEV-1/SEV-2 incidents trigger forensic preservation hold (per Incident Response Policy §7.3)
- **Regulatory hold**: Data subject to regulatory investigation retained until clearance

---

## 7. Data Disposal

### 7.1 Disposal Methods

| Data Type | Disposal Method | Verification |
|-----------|----------------|-------------|
| PostgreSQL records | `DELETE` with cascading constraints; PITR logs expire per backup retention | Query verification |
| Object storage objects | Object deletion after WORM retention period expires; no auto-delete lifecycle rules; versions tier to cold storage but never auto-delete; soft-delete recovery window | Lifecycle policy audit + retention policy verification |
| Vector embeddings | Index removal via cloud API | API confirmation |
| Identity provider accounts | Admin SDK / API deletion | Admin console verification |
| Local copies | Secure erase (overwrite) | N/A |

### 7.2 Account Deletion / Data Purge

When a customer account is deleted (organization purge):

1. All workspace data (documents, messages, embeddings) deleted from PostgreSQL
2. All storage objects in workspace prefix deleted
3. All vector embeddings for workspace removed from vector search index
4. User accounts disassociated (not deleted — may belong to other orgs)
5. Audit events preserved (exempt from purge — compliance requirement)
6. Purge operation itself logged as audit event

### 7.3 Cryptographic Erasure

For CMEK-encrypted data, key destruction renders all encrypted data unrecoverable. This is used as a supplementary disposal method when:

- A customer requests verifiable data destruction
- Regulatory requirement mandates cryptographic erasure
- Key is scheduled for destruction with 24-hour delay for confirmation

---

## 8. Data Sovereignty

- All customer data is stored and processed within the United States (US regions only, regardless of cloud provider)
- Per-tenant data residency: `organizations.data_region` column enables per-tenant regional data isolation for agencies requiring specific region constraints
- No cross-border data transfers for customer data
- CSP Data Processing Addendum governs data location obligations
- All AI/embedding API calls route to US regions only

---

## 9. Monitoring and Compliance

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Data inventory review | Annual | Security Lead |
| Retention compliance audit | Semi-annual | Security Lead |
| Storage lifecycle policy review | Quarterly | Engineering |
| Database backup verification | Monthly | Engineering |
| Data classification review | Annual | Security Lead |
| Disposal verification | On occurrence | Engineering |

---

## 10. Enforcement

- Unauthorized data handling (wrong classification, improper storage, retention violation) is a policy violation
- Data breaches resulting from improper classification trigger incident response
- Failure to dispose of data per retention schedule is tracked as a compliance finding
- All data handling decisions are auditable

---

*Next review date: March 2027*
