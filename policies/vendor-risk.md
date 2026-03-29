# Latent Archon — Vendor Risk Management Policy

> **Policy ID**: POL-VR-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Security Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: SA-1, SA-4, SA-9, SA-12, SR-1, SR-2, SR-3

---

## 1. Purpose

This policy establishes requirements for assessing, approving, monitoring, and managing risks associated with third-party vendors, service providers, and open-source dependencies used in the Latent Archon platform. As a provider of CUI-grade document intelligence services to government agencies, Latent Archon must ensure its supply chain meets equivalent security standards.

---

## 2. Scope

This policy applies to:

- Cloud infrastructure providers (GCP)
- SaaS/PaaS service dependencies
- Open-source software libraries and frameworks
- Contractor and consulting engagements with system access
- Any third party that processes, stores, transmits, or has access to Latent Archon or customer data

---

## 3. Vendor Classification

### 3.1 Risk Tiers

| Tier | Criteria | Examples | Review Frequency |
|------|----------|---------|-----------------|
| **Critical** | Processes or stores customer data; single point of failure | GCP (Cloud Run, Cloud SQL, GCS, Vertex AI, Identity Platform) | Continuous + Annual deep review |
| **High** | Has access to production systems or code; integral to operations | GitHub (source control, CI/CD), Microsoft (Graph API), Go/Node runtime | Semi-annual |
| **Medium** | Supports development or has indirect data access | Dependabot, development tooling, monitoring integrations | Annual |
| **Low** | No data access; easily replaceable | Documentation tools, design tools, project management | Biennial |

### 3.2 Current Critical Vendor: Google Cloud Platform

GCP is Latent Archon's sole infrastructure provider. Risk is managed through:

| Control | Implementation |
|---------|---------------|
| **FedRAMP Authorization** | GCP holds FedRAMP High authorization (IL4 capable) |
| **SOC 2 Type II** | Annual audit reports reviewed |
| **ISO 27001/27017/27018** | Certifications maintained |
| **BAA** | Available for HIPAA-regulated workloads |
| **Data Processing Terms** | Google Cloud Data Processing Addendum in effect |
| **Vendor Lock-in Mitigation** | PostgreSQL (portable), standard container images, Terraform IaC (multi-cloud capable), Connect-RPC (protocol-agnostic) |

### 3.3 High Tier Vendor: Microsoft (Graph API / Entra ID)

Microsoft Graph API and Microsoft Entra ID (Azure AD) are used for SharePoint/OneDrive document ingestion via OAuth2 authorization code grant. Risk is managed through:

| Control | Implementation |
|---------|---------------|
| **FedRAMP Authorization** | Microsoft Azure holds FedRAMP High authorization |
| **SOC 2 Type II** | Annual audit reports reviewed |
| **Permissions Scope** | Read-only delegated permissions only (`Files.Read.All`, `Sites.Read.All`) — no write access to customer Microsoft 365 data |
| **Token Security** | OAuth refresh tokens encrypted via Cloud KMS (AES-256-GCM, HSM-backed) before database storage; client secret injected as runtime env var only |
| **Data Residency** | Documents downloaded from Microsoft 365 are stored exclusively in US GCP regions; no Microsoft-side data persistence by the integration |
| **Network Isolation** | `graph.microsoft.com` and `login.microsoftonline.com` added to FQDN egress firewall allowlist; all other egress blocked |
| **Vendor Lock-in Mitigation** | Integration is optional per-org; documents enter standard pipeline after download; no proprietary format dependencies |

---

## 4. Vendor Assessment Process

### 4.1 Pre-Engagement Assessment

Before engaging any new Critical or High tier vendor:

1. **Security Questionnaire**: Vendor completes security assessment covering:
   - Data handling practices
   - Encryption (at rest and in transit)
   - Access control and authentication
   - Incident response capabilities
   - Business continuity and DR
   - Compliance certifications (FedRAMP, SOC 2, ISO 27001)
   - Subprocessor disclosure

2. **Compliance Verification**:
   - FedRAMP authorization status (required for Critical tier handling CUI)
   - SOC 2 Type II report review (required for Critical and High tiers)
   - Penetration test results or summary (if available)

3. **Data Flow Analysis**: Document what data the vendor will access, process, or store

4. **Contract Review**: Ensure contracts include:
   - Data protection obligations
   - Breach notification requirements (< 72 hours)
   - Right to audit
   - Data return/deletion on termination
   - Compliance maintenance obligations
   - Indemnification for security failures

### 4.2 Approval Authority

| Vendor Tier | Approval Required |
|-------------|------------------|
| Critical | CEO + Security Lead |
| High | CTO + Security Lead |
| Medium | Engineering Lead |
| Low | Any team lead |

---

## 5. Ongoing Monitoring

### 5.1 Continuous Monitoring

| Activity | Frequency | Applies To |
|----------|-----------|-----------|
| FedRAMP marketplace status check | Quarterly | Critical (GCP) |
| SOC 2 report review | Annual (on issuance) | Critical, High |
| Security advisory monitoring | Continuous | All tiers |
| Dependency vulnerability scanning (Dependabot) | Continuous (automated) | Open-source deps |
| Vendor incident notification review | On occurrence | Critical, High |
| Contract renewal review | On renewal | All tiers |

### 5.2 Annual Vendor Review

Critical and High tier vendors undergo an annual review covering:

- Changes to security posture or certifications
- Incident history (breaches, outages)
- Compliance status changes
- Subprocessor changes
- Contract term compliance
- Performance against SLAs

---

## 6. Open-Source Dependency Management

### 6.1 Dependency Governance

Open-source dependencies are managed as a supply chain risk:

| Control | Implementation |
|---------|---------------|
| **Automated Scanning** | Dependabot configured on all repositories (Go, npm, GitHub Actions, Terraform) |
| **Vulnerability Alerting** | GitHub security advisories + Dependabot alerts |
| **License Compliance** | Only OSI-approved licenses (MIT, Apache 2.0, BSD) without copyleft restrictions |
| **Integrity Verification** | `go.sum` (cryptographic checksums), `pnpm-lock.yaml`, `.terraform.lock.hcl` |
| **Pinned Versions** | All dependencies pinned to specific versions (no floating ranges in production) |
| **Minimal Dependencies** | Prefer standard library; evaluate necessity before adding new dependencies |

### 6.2 Vulnerability Response

| Severity | Response Time | Action |
|----------|--------------|--------|
| Critical (CVSS ≥ 9.0) | < 24 hours | Emergency change process; patch or mitigate |
| High (CVSS 7.0–8.9) | < 72 hours | Normal change process; prioritize patch |
| Medium (CVSS 4.0–6.9) | < 2 weeks | Standard change process |
| Low (CVSS < 4.0) | Next release cycle | Standard change process |

### 6.3 Current Dependency Inventory

#### Backend (Go)

| Category | Key Dependencies |
|----------|-----------------|
| Database | `github.com/jackc/pgx/v5`, `cloud.google.com/go/cloudsqlconn` |
| Auth | `firebase.google.com/go/v4` |
| AI/ML | `cloud.google.com/go/aiplatform` |
| Protobuf | `connectrpc.com/connect`, `google.golang.org/protobuf` |
| Observability | `go.opentelemetry.io/otel` |
| Crypto | Go standard library (`crypto/sha256`, `crypto/hmac`) |

#### Frontend (TypeScript)

| Category | Key Dependencies |
|----------|-----------------|
| Framework | React 18, TypeScript |
| Auth | Firebase JS SDK |
| Build | Vite |
| Styling | TailwindCSS |

---

## 7. Subprocessor Management

### 7.1 Current Subprocessors

| Subprocessor | Service | Data Access | FedRAMP |
|-------------|---------|-------------|---------|
| Google Cloud Platform | Infrastructure (compute, storage, AI, identity) | Customer documents, messages, embeddings | High |
| Microsoft | Graph API (SharePoint/OneDrive sync), Entra ID (OAuth2) | Read-only access to customer Microsoft 365 documents (downloaded and stored in GCP) | High |
| GitHub | Source control, CI/CD | Source code (no customer data) | SOC 2 |

### 7.2 Subprocessor Changes

- New subprocessors processing customer data require the same assessment as Critical tier vendors
- Customers are notified of subprocessor changes with 30 days advance notice
- Customers may object to new subprocessors; objections are addressed before proceeding

---

## 8. Vendor Incident Response

When a vendor reports a security incident:

1. **Assess impact** on Latent Archon and customer data (< 4 hours)
2. **Activate** Latent Archon incident response if customer data is affected
3. **Request** vendor incident report and remediation timeline
4. **Notify** affected customers per incident response policy timelines
5. **Verify** vendor remediation before restoring normal operations
6. **Document** in vendor risk register

---

## 9. Vendor Offboarding

When a vendor relationship ends:

1. **Revoke** all access (API keys, IAM grants, repository access)
2. **Request** data deletion confirmation (in writing)
3. **Verify** no residual access via audit log review
4. **Update** vendor inventory and dependency manifests
5. **Migrate** to replacement vendor (if applicable) before termination

---

## 10. Risk Register

A vendor risk register is maintained with:

| Field | Description |
|-------|-------------|
| Vendor name | Legal entity name |
| Tier | Critical / High / Medium / Low |
| Service provided | What the vendor does |
| Data access | What data the vendor can access |
| Compliance status | FedRAMP, SOC 2, ISO 27001 |
| Contract expiration | Renewal date |
| Last review date | Most recent assessment |
| Open risks | Known risks with mitigation status |
| Owner | Latent Archon point of contact |

---

## 11. Exceptions

Exceptions to this policy require:

- Written justification including business need
- Risk assessment with compensating controls
- CEO/CTO approval for Critical/High tier exceptions
- Maximum 90-day exception period (renewable)
- Documented in vendor risk register

---

## 12. Enforcement

- Unauthorized vendor engagements (especially those involving customer data) are a serious policy violation
- Vendors found non-compliant with contractual obligations will be placed on remediation plans
- Persistent non-compliance results in vendor offboarding
- All vendor risk decisions are documented and auditable

---

*Next review date: March 2027*
