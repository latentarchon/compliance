# Latent Archon — FedRAMP System Security Plan (SSP)

> **Document ID**: SSP-LA-001  
> **Version**: 2.0 — DRAFT  
> **Date**: April 2026  
> **Baseline**: NIST SP 800-53 Rev. 5 — High Impact  
> **System Name**: Latent Archon Document Intelligence Platform  
> **System Owner**: Latent Archon, LLC  
> **Contact**: ajhendel@latentarchon.com  
> **FIPS 199 Category**: High (Confidentiality: High, Integrity: High, Availability: Moderate)

> **IL5 Assured Workloads**: The GCP deployment runs within IL5 Assured Workloads folders, which enforce data residency (US-only regions), service restrictions (only IL5-approved GCP services), US-person personnel controls, and CMEK encryption requirements. Services not yet IL5-approved (Identity Platform, Cloud Scheduler, Certificate Manager) operate in dedicated FedRAMP High Assured Workloads projects outside the IL5 boundary, communicating with the data plane via JWT validation and Pub/Sub push. The system satisfies DFARS 252.204-7012 and NIST SP 800-171 requirements for CUI protection at DoD Impact Level 5.

---

## Table of Contents

1. [System Identification](#1-system-identification)
2. [System Description](#2-system-description)
3. [System Environment](#3-system-environment)
4. [System Interconnections](#4-system-interconnections)
5. [Laws, Regulations, Standards](#5-applicable-laws-regulations-and-standards)
6. [Information Types](#6-information-types-and-categorization)
7. [Users and Access](#7-users-and-access)
8. [Architecture and Data Flows](#8-illustrated-architecture-and-narratives)
9. [Ports, Protocols, Services](#9-ports-protocols-and-services)
10. [Cryptographic Modules](#10-cryptographic-modules)
11. [Security Control Implementations (Appendix A)](#appendix-a-security-control-implementations)
12. [Appendix B: Acronyms](#appendix-b-acronyms)
13. [Appendix C: Policies and Procedures](#appendix-c-security-policies-and-procedures)
14. [Appendix D: Contingency Plan (ISCP)](#appendix-d-contingency-plan)
15. [Appendix E: Configuration Management Plan](#appendix-e-configuration-management-plan)
16. [Appendix F: Incident Response Plan](#appendix-f-incident-response-plan)
17. [Appendix G: Continuous Monitoring Plan](#appendix-g-continuous-monitoring-plan)
18. [Appendix H: Supply Chain Risk Management Plan](#appendix-h-supply-chain-risk-management-plan)
19. [Appendix I: POA&M](#appendix-i-poam)

---

## 1. System Identification

| Field | Value |
|-------|-------|
| **System Name** | Latent Archon Document Intelligence Platform |
| **System Abbreviation** | LA-DIP |
| **Version/Release** | 1.0 |
| **Unique Identifier** | LA-DIP-HIGH-IL5-2026 |
| **System Owner Organization** | Latent Archon, LLC |
| **System Owner Name** | Andrew Hendel |
| **System Owner Title** | Chief Executive Officer |
| **System Owner Email** | ajhendel@latentarchon.com |
| **Authorizing Official** | _[Agency AO — TBD upon sponsor engagement]_ |
| **Information System Security Officer (ISSO)** | Andrew Hendel, CEO (self-appointed per ISSO-APPT-001; see Appendix C) |
| **Cloud Service Model** | Software as a Service (SaaS) |
| **Cloud Deployment Model** | Public Cloud |
| **Underlying CSP** | Google Cloud Platform (GCP) — FedRAMP High Authorized |
| **GCP Authorization ID** | FR1805181233 |
| **Deployment Model** | GCP deployment — IL5 Assured Workloads |

<!-- MULTI-CLOUD: Original listed AWS (FR1603057795) and Azure (FR1601018498) as additional underlying CSPs with single-cloud per customer deployment model. -->
| **FIPS 199 Categorization** | High |
| **DoD Impact Level** | IL5 |
| **Authorization Type** | FedRAMP High + DoD IL5 Agency Authorization |
| **Authorization Status** | Pre-Authorization (DRAFT) |

### 1.1 System Status

This system is in **pre-authorization** status. Infrastructure-as-code has been developed and validated in staging. Production deployment is pending authorization boundary finalization and 3PAO engagement.

---

## 2. System Description

### 2.1 System Function and Purpose

Latent Archon is a multi-tenant document intelligence platform purpose-built for U.S. government agencies handling Controlled Unclassified Information (CUI). The platform provides:

- **Document Management**: Secure upload, storage, and lifecycle management of government documents with malware scanning (ClamAV, fail-closed in production), magic-byte validation, and file type allowlisting.
- **AI-Powered Search**: Retrieval-Augmented Generation (RAG) using vector embeddings for semantic document search across workspace-scoped document collections.
- **Interactive Conversation**: Conversational interface over uploaded documents using Vertex AI (Gemini), with citations and source attribution.
<!-- MULTI-CLOUD: Original also listed Claude (AWS Bedrock) and GPT-4o (Azure OpenAI). -->
- **Workspace Isolation**: Logical data isolation at the workspace level enforced through PostgreSQL Row-Level Security (RLS), vector store token restrictions, and application-layer access controls.
- **Enterprise SSO/SCIM**: SAML 2.0 federation with customer Identity Providers and SCIM 2.0 automated user lifecycle management.

### 2.2 System Scope

The authorization boundary encompasses all components required to deliver the Latent Archon SaaS offering, including:

- Application code (Go backend, React SPAs)
- Cloud infrastructure (GCP — see [Cloud Environment Supplements](cloud/) for service details)
- CI/CD pipelines (GitHub Actions with Workload Identity Federation)
- Administrative interfaces (admin SPA, ops service)
- Supporting services (ClamAV malware scanning, document extraction/OCR)

Each customer deployment runs on a **single cloud provider** selected at onboarding time.

**Excluded from boundary** (but documented as external services):
- Customer Identity Providers (Okta, Azure AD, etc.) — customer-operated
- Customer end-user devices — customer responsibility
- Underlying CSP FedRAMP High infrastructure controls — inherited from cloud provider authorization

### 2.3 Leveraged Authorizations

| CSP/Service | Authorization | Impact Level | Authorization ID |
|-------------|---------------|--------------|------------------|
| Google Cloud Platform | FedRAMP High P-ATO | High (IL5 Assured Workloads) | FR1805181233 |
| Cloudflare DNS | FedRAMP Moderate | Moderate | — |

<!-- MULTI-CLOUD: Original also included:
| Amazon Web Services | FedRAMP High P-ATO | High | FR1603057795 |
| Microsoft Azure | FedRAMP High P-ATO | High | FR1601018498 | -->

#### 2.3.1 IL5 Assured Workloads Architecture

Data-plane projects (admin, ops, app, kms) operate within an **IL5 Assured Workloads** folder. The IL5 folder enforces org policies automatically: data residency (US-only regions), service restrictions (only IL5-approved services), US-person personnel controls for support, and CMEK encryption requirements.

Services not yet approved for IL5 (Identity Platform, Cloud Scheduler, Certificate Manager) are isolated into dedicated **FedRAMP High Assured Workloads** projects:

| Boundary | Projects | Compliance Regime | Services |
|----------|----------|-------------------|----------|
| IL5 data plane | `archon-fed-admin-*`, `archon-fed-ops-*`, `archon-fed-app-*`, `archon-fed-kms-*` | IL5 | Cloud Run, Cloud SQL, GCS, Vertex AI, Cloud Armor, Cloud KMS, Cloud Tasks, Cloud Logging, Artifact Registry, Cloud DLP |
| FedRAMP High auth | `archon-fed-auth-admin-*`, `archon-fed-auth-app-*` | FedRAMP High | Identity Platform (Firebase Auth), Firebase Hosting |
| FedRAMP High management | `archon-mgmt-scheduler-*` | FedRAMP High | Cloud Scheduler, Pub/Sub |

The auth projects communicate with the data plane via JWT public key validation only — no direct service-to-service calls cross the IL5 boundary. The backend validates JWTs offline using JWKS public keys fetched from the auth projects. Cloud Scheduler delivers cron events via cross-project Pub/Sub push subscriptions into the IL5 boundary.

### 2.4 Service Layers

```
┌─────────────────────────────────────────────────────────┐
│                   Latent Archon SaaS                     │
│  (Application Logic, RBAC, RLS, Audit, MFA, SSO/SCIM)  │
│  Go binary + React SPAs                                  │
├─────────────────────────────────────────────────────────┤
│         Google Cloud Platform (GCP) — IL5 AW             │
│  Cloud Run, Cloud SQL, GCS, Vertex AI, Cloud Armor,      │
│  Cloud KMS, Cloud Tasks, Cloud DLP, Artifact Registry    │
├─────────────────────────────────────────────────────────┤
│       GCP — FedRAMP High AW (non-IL5 services)           │
│  Identity Platform (auth projects), Cloud Scheduler      │
│  (mgmt project), Pub/Sub (cross-project bridge)          │
├─────────────────────────────────────────────────────────┤
│          CSP Physical Infrastructure (Inherited)          │
│  Data Centers, Network, Power, HVAC, Physical Security   │
└─────────────────────────────────────────────────────────┘
```

<!-- MULTI-CLOUD: Original service layers diagram also included:
  AWS:   ECS Fargate, RDS, S3, Bedrock, WAFv2, IAM (SAML), KMS, SQS
  Azure: Container Apps, PostgreSQL Flex, Blob, Azure OpenAI, Front Door WAF, Azure AD, Key Vault -->

---

## 3. System Environment

### 3.1 Authorization Boundary Components

| Component | GCP Service | IL5 Boundary | Description |
|-----------|-------------|---------------|-------------|
| App API | Cloud Run (`archon-app`) | IL5 | User-facing API: conversation, search, auth, streaming |
| Admin API | Cloud Run (`archon-admin`) | IL5 | Admin API: org management, document ingestion, settings |
| Ops Service | Cloud Run (`archon-ops`) | IL5 | Background processing: embeddings, cron, document processing |
| App SPA | Cloud Run (nginx) | IL5 | React single-page application for end users |
| Admin SPA | Cloud Run (nginx) | IL5 | React single-page application for administrators |
| Database | Cloud SQL PostgreSQL 15 | IL5 | Primary data store with RLS, encrypted at rest (CMEK) |
| Object Storage | Cloud Storage | IL5 | Document file storage, versioning (365-day retention) |
| Vector Search | Vertex AI Vector Search | IL5 | Semantic search index (private endpoint) |
| Text Generation | Vertex AI (Gemini) | IL5 | LLM for RAG conversation responses |
| Identity | Identity Platform | FedRAMP High (auth projects) | Auth pools for multi-tenant isolation; JWTs validated offline in IL5 boundary |
| WAF | Cloud Armor | IL5 | DDoS protection, OWASP CRS, bot blocking, IP allowlisting |
| Load Balancing | Global HTTPS LB | IL5 | TLS termination, routing, health checks |
| Key Management | Cloud KMS | IL5 | CMEK for database and storage encryption |
| Task Queue | Cloud Tasks | IL5 | Async document processing and embedding queues |
| Cron Scheduling | Cloud Scheduler + Pub/Sub | FedRAMP High (mgmt project) | Cron triggers via cross-project Pub/Sub push into IL5 boundary |
| Malware Scanner | Cloud Run (ClamAV) | IL5 | Internal-only ClamAV REST service for upload scanning |
| Logging | Cloud Logging + Monitoring | IL5 | Centralized logging, metrics, alerting |
| Container Registry | Artifact Registry | IL5 | Docker image storage for all services |
| DNS/TLS | Certificate Manager | FedRAMP High | TLS certificates with DNS authorization |
| DNS | Cloudflare | FedRAMP Moderate | Authoritative DNS with DNSSEC enabled |

<!-- MULTI-CLOUD: Original table included AWS Service (ECS Fargate, RDS, S3, OpenSearch Serverless, Bedrock Claude, Textract, SAML IdP, WAFv2, ALB, AWS KMS, SQS, CloudWatch, ECR, ACM) and Azure Service (Container Apps, PostgreSQL Flexible Server, Blob Storage, Azure AI Search, Azure OpenAI GPT-4o, Document Intelligence, Azure AD, Front Door WAF, Front Door, Key Vault, Service Bus, Azure Monitor, Container Registry, Front Door managed) columns. -->

For detailed GCP service configurations and project structure, see the [Cloud Environment Supplements](cloud/).

### 3.2 Multi-Project Architecture (IL5 + FedRAMP High)

Latent Archon uses a **multi-project architecture** with IL5 Assured Workloads for data-plane isolation and dedicated FedRAMP High projects for services not yet IL5-approved:

<!-- MULTI-CLOUD: Original also referenced AWS accounts and Azure subscriptions. -->

#### IL5 Data-Plane Projects

- **App Environment** (`archon-fed-app-*`): Contains the user-facing app API and SPA, WAF policy, and load balancer. The app service identity has **read-only** database access (`app_ro` PostgreSQL role) via cross-environment database IAM grants to the ops environment.

- **Ops Environment** (`archon-fed-ops-*`): Contains the entire data tier — database (PostgreSQL), object storage, key management, vector search, LLM inference, DLP/PII scanning, task queue, malware scanning (ClamAV), and the ops background-processing service. Has no public ingress — all access is cross-environment via IAM grants. The ops service identity has `ops_rw` database access. Receives cron events via Pub/Sub push subscriptions from the management project.

- **Admin Environment** (`archon-fed-admin-*`): Contains the admin API and SPA, WAF policy, and load balancer. The admin service identity has `admin_rw` database access via cross-environment database IAM grants to the ops environment.

- **KMS Environment** (`archon-fed-kms-*`): Dedicated project for Cloud KMS CMEK keys, isolating key management from data-plane services.

#### FedRAMP High Projects (outside IL5 boundary)

- **Auth Admin** (`archon-fed-auth-admin-*`): Identity Platform (Firebase Auth) for the admin tenant pool. Runs under a FedRAMP High Assured Workloads folder because Identity Platform is not IL5-supported. The IL5 data-plane validates admin JWTs offline via JWKS public keys — no direct service calls cross the boundary.

- **Auth App** (`archon-fed-auth-app-*`): Identity Platform (Firebase Auth) for the app tenant pool. Same FedRAMP High AW isolation as auth-admin. JWT validation is offline via JWKS.

- **Management Scheduler** (`archon-mgmt-scheduler-*`): Cloud Scheduler for cron jobs. Cloud Scheduler is not IL5-supported, so cron triggers are published to a Pub/Sub topic in this project. Push subscriptions in the ops project (within the IL5 boundary) deliver messages to the ops Cloud Run service, satisfying Cloud Run's `ingress = "internal"` policy.

**Cross-pool identity bridging is explicitly prohibited.** Users who exist in both pools (admin and app) are treated as separate identities. Workspace access across pools uses an explicit invite flow only (see `docs/POOL_ISOLATION.md`).

### 3.3 Environments

| Environment | Purpose | IL5 Projects | FedRAMP High Projects | Access |
|-------------|---------|--------------|----------------------|--------|
| Production | Live customer data | `archon-fed-admin-prod`, `archon-fed-ops-prod`, `archon-fed-app-prod`, `archon-fed-kms-prod` | `archon-fed-auth-admin-prod`, `archon-fed-auth-app-prod`, `archon-mgmt-scheduler-prod` | Restricted to CI/CD + emergency break-glass |
| Staging | Pre-production validation | `archon-fed-admin-staging`, `archon-fed-ops-staging`, `archon-fed-app-staging`, `archon-fed-kms-staging` | `archon-fed-auth-admin-stg`, `archon-fed-auth-app-stg`, `archon-mgmt-scheduler-stg` | Engineering team |
| Development | Local development | N/A (local Docker Compose) | N/A | Individual developers |

All environments are managed via Terraform/Terragrunt. No manual cloud console changes are permitted in staging or production.

---

## 4. System Interconnections

| External System | Direction | Protocol | Port | Purpose | Authorization |
|-----------------|-----------|----------|------|---------|---------------|
| Customer IdP (Okta, Azure AD) | Inbound | SAML 2.0 / HTTPS | 443 | SSO authentication | Customer-operated |
| Customer IdP (SCIM) | Inbound | HTTPS REST | 443 | Automated user provisioning | Customer-operated |
| Customer Browser | Inbound | HTTPS | 443 | SPA access | N/A |
| Microsoft Graph API | Outbound | HTTPS REST | 443 | SharePoint/OneDrive document sync (delta queries, file download) | Microsoft FedRAMP High |
| Microsoft Entra ID (Azure AD) | Outbound | HTTPS (OAuth2) | 443 | OAuth2 authorization code grant for Graph API token exchange | Microsoft FedRAMP High |
| Cloudflare DNS | Outbound | DNS/HTTPS | 53/443 | Authoritative DNS with DNSSEC | FedRAMP Moderate |
| Cloud Provider APIs | Outbound | HTTPS | 443 | All cloud service APIs (via egress firewall allowlist) | FedRAMP High (inherited) |
| GitHub | Outbound | HTTPS | 443 | CI/CD source code, Dependabot | N/A |

### 4.1 Egress Firewall Policy

All outbound traffic from VPC is **denied by default**. Egress controls explicitly allow only:

- Cloud provider APIs (`*.googleapis.com`)
- Container registry (`*.gcr.io`, `*.pkg.dev`)

<!-- MULTI-CLOUD: Original also included AWS VPC Endpoints, ECR endpoints; Azure Private Endpoints, ACR endpoints. -->
- `graph.microsoft.com` — Microsoft Graph API (SharePoint/OneDrive document sync)
- `login.microsoftonline.com` — Microsoft Entra ID (OAuth2 token exchange)
- Cloudflare DNS endpoints

All other egress is blocked. Microsoft Graph API egress is only active when the integration is configured (`MSGRAPH_CLIENT_ID` present). This is enforced via Terraform-managed firewall rules.

---

## 5. Applicable Laws, Regulations, and Standards

| Law/Regulation/Standard | Applicability |
|------------------------|---------------|
| FISMA (Federal Information Security Modernization Act) | Governs federal information systems security |
| NIST SP 800-53 Rev. 5 | FedRAMP High baseline control catalog |
| NIST SP 800-37 Rev. 2 | Risk Management Framework |
| NIST SP 800-171 Rev. 2 | CUI protection requirements (DoD IL5) |
| DFARS 252.204-7012 | Safeguarding Covered Defense Information — requires NIST 800-171 compliance for DoD CUI |
| DoD CC SRG (Cloud Computing Security Requirements Guide) | IL5 requirements for DoD mission data in commercial cloud |
| NIST FIPS 199 | Security categorization |
| NIST FIPS 200 | Minimum security requirements |
| NIST FIPS 140-2 | Cryptographic module validation (BoringCrypto) |
| FedRAMP Authorization Act (2022) | FedRAMP program authorization |
| Privacy Act of 1974 | PII protection |
| E-Government Act of 2002 | Privacy impact assessments |
| OMB Circular A-130 | Managing information as a strategic resource |
| Executive Order 14028 | Improving the Nation's Cybersecurity (SBOM requirements) |

---

## 6. Information Types and Categorization

### 6.1 FIPS 199 Categorization

| Security Objective | Impact Level | Justification |
|-------------------|--------------|---------------|
| **Confidentiality** | High | System processes CUI and DoD mission data; unauthorized disclosure could cause severe or catastrophic adverse effect to national defense operations |
| **Integrity** | High | Unauthorized modification of documents or AI responses supporting DoD mission decisions could cause severe adverse effect |
| **Availability** | Moderate | Extended unavailability could cause serious adverse effect to agency mission operations |

**Overall Categorization: HIGH**

> **DoD IL5**: The system operates within GCP IL5 Assured Workloads, satisfying DoD Cloud Computing SRG requirements for Impact Level 5 workloads. IL5 covers CUI and National Security Systems (unclassified) data. The IL5 Assured Workloads folder enforces data residency, service restrictions, US-person personnel controls, and CMEK encryption requirements at the organizational policy layer.

### 6.2 Information Types

| Information Type | NIST SP 800-60 Category | Confidentiality | Integrity | Availability |
|-----------------|------------------------|-----------------|-----------|--------------|
| Customer Documents (CUI) | D.14 — General Information | Moderate | Moderate | Moderate |
| Messages / AI Responses | D.14 — General Information | Moderate | Moderate | Low |
| User Account Data (PII) | D.8 — Personal Identity and Authentication | Moderate | Moderate | Low |
| Audit Logs | D.3.5 — Internal Risk Mgmt | Moderate | Moderate | Low |
| System Configuration | D.3 — Administrative Mgmt | Low | Moderate | Moderate |
| Workspace Metadata | D.14 — General Information | Moderate | Moderate | Low |

### 6.3 Data Classification Levels

| Level | Description | Examples |
|-------|-------------|---------|
| **CUI / Restricted** | Controlled Unclassified Information per 32 CFR 2002 | Customer documents, workspace content, conversation messages |
| **Confidential** | Internal business data requiring protection | Audit logs, user PII, API keys, system credentials |
| **Internal** | Internal use data not for external distribution | Architecture docs, runbooks, non-sensitive config |
| **Public** | Approved for public distribution | Marketing materials, published documentation |

---

## 7. Users and Access

### 7.1 User Categories

| User Type | Description | Auth Method | Privileges | Count |
|-----------|-------------|-------------|------------|-------|
| **Customer End User** | Agency staff using app search/conversation | Magic link + MFA | viewer, editor roles within assigned workspaces | Variable per customer |
| **Customer Org Admin** | Agency administrator | SSO preferred + MFA | master_admin or admin role; org management, user lifecycle, settings | 1-5 per customer org |
| **Latent Archon Founder / ISSO** | CEO — directs engineering, operations, and security; automation workforce handles execution (see SOD-LA-001) | GitHub SSO + cloud IAM (WIF/OIDC) | CI/CD deployment via automation; break-glass DB access (emergency only) | 1 |
| **Automated CI/CD** | GitHub Actions runners | Workload Identity Federation / OIDC (keyless) | Deploy containers, run migrations; no static keys | N/A |
| **Ops Service (Machine)** | Background processing | Cloud IAM (service-to-service) | Document processing, embeddings, cron; OIDC-authenticated task dispatch | N/A |

### 7.2 Authentication Requirements

| Requirement | Implementation |
|-------------|----------------|
| **Multi-Factor Authentication** | TOTP-based MFA enforced on all data endpoints via auth interceptor; step-up MFA for sensitive operations. |
| **Session Management** | Global idle timeout: 25 min (default). Global absolute timeout: 12 hr (default). Per-org configurable: idle 5-480 min, absolute 60-1440 min. Enforced server-side via JWT `auth_time` and `iat` claims. |
| **Password Policy** | Managed by Identity Platform; magic link (passwordless) preferred. SSO/SAML available with password policy delegated to customer IdP. |
| **Account Lockout** | Identity provider built-in brute-force protection. Application-level rate limiting at IP + per-user levels. |

### 7.3 Role-Based Access Control (RBAC)

#### Organization Roles

| Role | Capabilities |
|------|-------------|
| `master_admin` | Full organization management; promote/demote admins; configure org settings (session timeouts, IP allowlists); manage SSO/SCIM |
| `admin` | Workspace management; invite/remove members; upload/delete documents; view audit logs |
| `editor` | Document upload and metadata editing within assigned workspaces |
| `viewer` | Read-only access to documents and conversations within assigned workspaces |

#### Database Roles (Separation of Duties)

Default `PUBLIC` privileges are revoked on all tables and sequences. Only the three named roles below have any access.

| DB Role | Service | Auth Method | Privileges |
|---------|---------|-------------|------------|
| `archon_app_ro` | archon-app | IAM-based (keyless) | SELECT on reference tables; SELECT + INSERT on messages, rag_searches, generations; INSERT on audit_events; SELECT + INSERT + UPDATE on users (profile upsert) |
| `archon_admin_rw` | archon-admin | IAM-based (keyless) | ALL on all tables and sequences (full CRUD) |
| `archon_ops_rw` | archon-ops | IAM-based (keyless) | SELECT + INSERT + UPDATE on documents, document_versions, DLQ; SELECT + INSERT + UPDATE + DELETE on chunks; INSERT on audit_events and generations; SELECT on reference tables |

**Migration user** (`archon_migrator` role via IAM): The Atlas migration job authenticates using Cloud SQL IAM auth via the admin service identity, then assumes the `archon_migrator` PostgreSQL role using `SET ROLE`.

<!-- MULTI-CLOUD: Original also referenced RDS IAM (AWS) and Azure AD auth (Azure). --> This role owns all tables in the public schema and has DDL privileges (CREATE/ALTER/DROP). No static credentials are used in the normal migration path. A `postgres` superuser password exists in secrets management as a break-glass mechanism, accessible only to human security administrators — it is not mounted on any container service or job by default.

All database roles operate under PostgreSQL Row-Level Security (RLS). RLS policies scope queries to the authenticated user's organization and workspace. RLS is **fail-closed**: if `app.organization_id` or `app.workspace_id` session variables are not set, queries return zero rows (not all rows). Roles are granted to IAM service accounts dynamically by naming convention (`archon-app@*`, `archon-admin@*`, `archon-ops@*`), ensuring environment-agnostic enforcement across staging and production.

---

## 8. Illustrated Architecture and Narratives

### 8.1 Authorization Boundary Diagram

```
┌─ Authorization Boundary ─────────────────────────────────────────────────┐
│                                                                          │
│  ┌─ IL5 Assured Workloads ─────────────────────────────────────────┐   │
│  │                                                                   │   │
│  │  ┌─ App Project (archon-fed-app-*) ──────────────────────┐   │   │
│  │  │  WAF → Load Balancer → App SPA (container)               │   │   │
│  │  │                       → App API (container)               │   │   │
│  │  │  Logging + Monitoring │ Container Registry                 │   │   │
│  │  └───────────────────────────────────────────────────────────┘   │   │
│  │          │ Cross-project: database IAM grant (read-only)          │   │
│  │  ┌─ Ops Project (archon-fed-ops-*) ──────────────────────┐   │   │
│  │  │  Ops Service (container) ←── no public ingress              │   │   │
│  │  │  ClamAV (container) ←── internal only                       │   │   │
│  │  │  PostgreSQL 15 ←── RLS enforced                            │   │   │
│  │  │  Object Storage (Documents) ←── AES-256 + CMEK             │   │   │
│  │  │  Vector Search + LLM ←── private endpoint                   │   │   │
│  │  │  Task Queue │ DLP │ Pub/Sub push subs (from scheduler)     │   │   │
│  │  │  Logging + Monitoring │ Container Registry                   │   │   │
│  │  └───────────────────────────────────────────────────────────┘   │   │
│  │          │ Cross-project: database IAM grant (read-write)         │   │
│  │  ┌─ Admin Project (archon-fed-admin-*) ───────────────────┐   │   │
│  │  │  WAF → Load Balancer → Admin SPA (container)              │   │   │
│  │  │                       → Admin API (container)              │   │   │
│  │  │  Logging + Monitoring │ Container Registry                  │   │   │
│  │  └───────────────────────────────────────────────────────────┘   │   │
│  │                                                                   │   │
│  │  ┌─ KMS Project (archon-fed-kms-*) ──────────────────────┐   │   │
│  │  │  Cloud KMS CMEK keys (HSM-backed)                         │   │   │
│  │  └───────────────────────────────────────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─ FedRAMP High AW (non-IL5 services) ────────────────────────────┐   │
│  │  Auth Admin (archon-fed-auth-admin-*): Identity Platform          │   │
│  │  Auth App (archon-fed-auth-app-*): Identity Platform              │   │
│  │  ── JWT public keys fetched by IL5 data plane (offline validation)│   │
│  │                                                                    │   │
│  │  Mgmt Scheduler (archon-mgmt-scheduler-*):                        │   │
│  │    Cloud Scheduler → Pub/Sub topic → push subs in ops project     │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─ CI/CD ──────────────────────────────────────────────────────────┐   │
│  │  Cloud Build → Artifact Registry → Container Deploy               │   │
│  │  GitHub Actions → WIF/OIDC (keyless) → PR checks                 │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

External (outside boundary):
  • Customer IdP (Okta/Azure AD) — SAML 2.0 inbound
  • Microsoft Graph API — SharePoint/OneDrive document sync (outbound HTTPS)
  • Microsoft Entra ID — OAuth2 token exchange (outbound HTTPS)
  • Cloudflare DNS — DNSSEC-signed authoritative DNS
  • Customer browsers — HTTPS only
  • CSP FedRAMP High infrastructure — inherited controls (GCP)
```

### 8.2 Data Flow Diagram — Document Upload

```
Customer Browser (HTTPS/TLS 1.2+)
    │
    ▼
WAF (Cloud Armor — OWASP CRS, rate limiting, bot blocking)
    │
    ▼
Load Balancer (managed TLS cert, HSTS 2yr)
    │
    ▼
Admin API (container) — Auth Interceptor:
    1. JWT verification (Firebase ID token / SAML assertion)
    2. IDP pool enforcement
    3. X-IDP-Pool-ID header match
    4. MFA enforcement (TOTP / delegated to IdP)
    5. Session timeout check (idle + absolute)
    6. Org membership gate
    7. Subdomain→org DB validation
    8. RBAC check (admin or editor role)
    │
    ├─► Size check (50 MB limit)
    ├─► File type allowlist validation
    ├─► Magic-byte validation (content-type verification)
    ├─► ClamAV malware scan (fail-closed in production)
    │
    ▼
Object Storage (AES-256-GCM + CMEK, workspace-scoped path)
    │
    ▼
Task Queue → Ops Service (container):
    ├─► Document text extraction (native Go parsing)
    ├─► Text chunking
    ├─► Embedding generation
    ├─► Vector index upsert (workspace-scoped)
    │
    ▼
Audit event logged (user_id, org_id, workspace_id, action,
                    ip_address, user_agent, metadata JSONB)
```

### 8.2.1 Data Flow Diagram — Microsoft Graph Document Sync

```
Admin Console (HTTPS/TLS 1.2+)
    │
    ▼
Admin API — Org Admin authorization check
    │
    ├─► Generate HMAC-signed OAuth state token (nonce:timestamp:orgID:tenantID:hmac)
    │   (SHA-256 derived key, 10-minute TTL)
    │
    ▼
Redirect → Microsoft Entra ID (login.microsoftonline.com)
    │   OAuth2 authorization code grant, admin consent
    │
    ▼
Callback → Admin API:
    ├─► Verify HMAC state signature + TTL
    ├─► Exchange authorization code for tokens (graph.microsoft.com)
    ├─► Encrypt refresh token via KMS (app_secrets key, AES-256-GCM, HSM-backed)
    ├─► Store in graph_connections (org-scoped, RLS-protected)
    ├─► Store client_id for connection identification
    │
    ▼
Sync Trigger (manual via Admin API):
    ├─► Org admin or workspace admin authorization check
    ├─► Decrypt refresh token (KMS)
    ├─► Obtain access token from Microsoft Entra ID
    ├─► Microsoft Graph delta query (only new/changed files)
    ├─► File download → Standard ingestion pipeline
    │   (malware scan → DLP → OCR → chunking → embedding)
    ├─► SHA-256 dedup prevents re-ingesting unchanged files
    │
    ▼
Sync log persisted (graph_sync_log table)
Audit event logged
```

### 8.3 Data Flow Diagram — App / RAG Query

```
Customer Browser (HTTPS/TLS 1.2+)
    │
    ▼
WAF → Load Balancer
    │
    ▼
App API (container) — Auth Interceptor (same 7-layer chain)
    │
    ├─► Workspace access check (explicit membership OR master_admin)
    │
    ▼
Vector Search Query (private endpoint):
    ├─► Workspace-scoped filter/token restriction
    ├─► Top-K semantic similarity search
    │
    ▼
Context Assembly + LLM Request (Vertex AI Gemini):
    ├─► Retrieved document chunks as context
    ├─► System prompt with safety guardrails
    ├─► Streaming response to client
    │
    ▼
Message persisted (PostgreSQL, RLS-scoped)
Audit event logged
```

### 8.4 Network Architecture

```
Internet
    │
    ▼
Cloudflare DNS (DNSSEC enabled)
    │
    ▼
WAF (Cloud Armor / WAFv2 / Front Door WAF — per environment):
    ├─► OWASP CRS v3.3 (SQLi, XSS, LFI, RFI, RCE, Scanner)
    ├─► HTTP method enforcement (GET, POST, OPTIONS only)
    ├─► Origin header restriction
    ├─► Bot/scanner blocking (User-Agent rules)
    ├─► Per-org IP allowlisting
    ├─► Rate limiting
    │
    ▼
Load Balancer:
    ├─► TLS 1.2+ termination (managed cert)
    ├─► HSTS (max-age=63072000, includeSubDomains, preload)
    │
    ▼
Private Network (VPC — no public IPs on any service):
    ├─► Container services
    ├─► PostgreSQL (private IP only)
    ├─► AI services (private endpoint)
    │
    ├─► Egress Controls:
    │   ├─► DEFAULT: DENY ALL
    │   ├─► ALLOW: Cloud provider APIs only
    │   └─► All other egress BLOCKED
    │
    ▼
Logging (structured JSON → cloud-native logging → optional SIEM export)
```

---

## 9. Ports, Protocols, and Services

| Service | Ports | Protocol | Direction | Purpose | Encrypted |
|---------|-------|----------|-----------|---------|-----------|
| Customer HTTPS | 443 | TCP/TLS 1.2+ | Inbound | SPA and API access | Yes |
| SAML SSO | 443 | TCP/TLS 1.2+ | Inbound | Enterprise SSO federation | Yes |
| SCIM Provisioning | 443 | TCP/TLS 1.2+ | Inbound | Automated user lifecycle | Yes |
| Cloud Provider APIs | 443 | TCP/TLS 1.2+ | Outbound | All cloud service communication | Yes |
| DNS | 53, 443 | UDP/TCP, HTTPS | Outbound | Cloudflare DNS (DNSSEC) | Yes (DoH) |
| PostgreSQL | 5432 | TCP/TLS | Internal VPC/VNet | Database connections | Yes |
| ClamAV REST | 8080 | TCP/TLS | Internal VPC/VNet | Malware scanning (internal-only container) | Yes |
| AI Services | 443 | TCP/TLS | Internal VPC/VNet | Vector search and LLM via private endpoint | Yes |
| Microsoft Graph API | 443 | TCP/TLS 1.2+ | Outbound | SharePoint/OneDrive document sync (`graph.microsoft.com`) | Yes |
| Microsoft Entra ID | 443 | TCP/TLS 1.2+ | Outbound | OAuth2 token exchange (`login.microsoftonline.com`) | Yes |

**All inbound traffic flows through WAF and load balancer. No services have public IP addresses. All internal communication uses TLS.**

---

## 10. Cryptographic Modules

| Module | Standard | Usage | Key Size | Notes |
|--------|----------|-------|----------|-------|
| Go BoringCrypto | FIPS 140-2 Level 1 (Cert #4407) | All Go application cryptography | AES-256, SHA-256/384/512 | Enabled via `GOEXPERIMENT=boringcrypto` build flag |
| Cloud KMS | FIPS 140-2 Level 3 | CMEK for database and object storage | AES-256 | HSM-backed, automatic key rotation |
| Cloud KMS (`app_secrets`) | FIPS 140-2 Level 3 | Encryption of Microsoft Graph OAuth refresh tokens | AES-256-GCM | HSM-backed, 90-day rotation |

<!-- MULTI-CLOUD: Original also listed AWS KMS and Azure Key Vault as equivalent cryptographic modules. -->
| Load Balancer TLS | FIPS 140-2 Level 1 | TLS termination at load balancer | TLS 1.2+, ECDHE, AES-256-GCM | Cloud-managed certificates |
| Database Encryption | FIPS 140-2 Level 1 | Data at rest encryption | AES-256 | CMEK enforced |
| Object Storage Encryption | FIPS 140-2 Level 1 | Object encryption at rest | AES-256-GCM | CMEK enforced |

### 10.1 Prohibited Algorithms

The following algorithms are explicitly prohibited per NIST SP 800-131A:
- DES, 3DES, RC4, MD5 (for cryptographic purposes)
- TLS 1.0, TLS 1.1, SSL 2.0, SSL 3.0
- RSA keys < 2048 bits
- SHA-1 (for digital signatures)

---

## Appendices

| Appendix | Title | Document |
|----------|-------|----------|
| **A** | Security Control Implementations | `fedramp-ssp-appendix-a-controls.md` |
| **B** | Acronyms and Glossary | _See below_ |
| **C** | Policies and Procedures | `policies/` directory (13 documents) |
| **D** | Information System Contingency Plan (ISCP) | `contingency-plan.md` |
| **E** | Configuration Management Plan (CMP) | `configuration-management-plan.md` |
| **F** | Incident Response Plan (IRP) | `policies/incident-response.md` (POL-IR-001) |
| **G** | Continuous Monitoring (ConMon) Plan | `continuous-monitoring-plan.md` |
| **H** | Supply Chain Risk Management Plan (SCRMP) | `supply-chain-risk-management-plan.md` |
| **I** | Plan of Action and Milestones (POA&M) | _See below_ |
| **J** | Privacy Impact Assessment (PIA) | `privacy-impact-assessment.md` |
| **K** | Continuous Monitoring SOPs | `conmon-sops.md` |
| **L** | Incident Response Tabletop Exercise | `incident-response-tabletop-exercise.md` |
| **M** | Red Team Deployment Guide | `red-team-deployment-guide.md` |
| **N** | Rules of Behavior | `rules-of-behavior.md` |
| **O** | Separation of Duties Matrix | `separation-of-duties-matrix.md` |

---

### Appendix B: Acronyms and Glossary

| Acronym | Definition |
|---------|-----------|
| 3PAO | Third Party Assessment Organization |
| AO | Authorizing Official |
| ATO | Authority to Operate |
| CAB | Change Advisory Board |
| CMP | Configuration Management Plan |
| CMEK | Customer-Managed Encryption Keys |
| ConMon | Continuous Monitoring |
| CSP | Cloud Service Provider |
| CUI | Controlled Unclassified Information |
| DNSSEC | Domain Name System Security Extensions |
| FIPS | Federal Information Processing Standards |
| GCS | Google Cloud Storage |
| GCP | Google Cloud Platform |
| HSTS | HTTP Strict Transport Security |
| IaC | Infrastructure as Code |
| IDP | Identity Provider |
| IRP | Incident Response Plan |
| ISCP | Information System Contingency Plan |
| ISSO | Information System Security Officer |
| JIT | Just-In-Time (provisioning) |
| KMS | Key Management Service |
| KSI | Key Security Indicator (FedRAMP 20x) |
| LLM | Large Language Model |
| MFA | Multi-Factor Authentication |
| NIST | National Institute of Standards and Technology |
| OSCAL | Open Security Controls Assessment Language |
| OWASP | Open Worldwide Application Security Project |
| PIA | Privacy Impact Assessment |
| PII | Personally Identifiable Information |
| PITR | Point-In-Time Recovery |
| POA&M | Plan of Action and Milestones |
| PSC | Private Service Connect |
| RAG | Retrieval-Augmented Generation |
| RBAC | Role-Based Access Control |
| RLS | Row-Level Security |
| RPO | Recovery Point Objective |
| RTO | Recovery Time Objective |
| SAML | Security Assertion Markup Language |
| SAR | Security Assessment Report |
| SAST | Static Application Security Testing |
| SBOM | Software Bill of Materials |
| SCIM | System for Cross-domain Identity Management |
| SCN | Significant Change Notification |
| SCRMP | Supply Chain Risk Management Plan |
| SLA | Service Level Agreement |
| SORN | System of Records Notice |
| SSO | Single Sign-On |
| SSP | System Security Plan |
| TLS | Transport Layer Security |
| TOTP | Time-Based One-Time Password |
| VPC | Virtual Private Cloud |
| WAF | Web Application Firewall |
| WIF | Workload Identity Federation |

---

### Appendix I: Plan of Action and Milestones (POA&M)

| ID | Finding | Severity | Control | Owner | Target Date | Status |
|----|---------|----------|---------|-------|-------------|--------|
| POA-1 | Complete 3PAO readiness assessment | High | CA-2 | CEO | Q3 2026 | Open |
| POA-2 | Conduct first contingency plan tabletop exercise | Medium | CP-4 | CEO / ISSO | Q2 2026 | Remediated — Automated monthly CP-4 test via `contingency-test` CLI + GitHub Actions cron (1st of month). Checks: Cloud SQL backup/PITR, GCS versioning, Cloud Run health, KMS keys, Artifact Registry. Reports uploaded to Drata. |
| POA-3 | Implement automated session concurrency limiting | Low | AC-10 | Engineering | Q2 2026 | Remediated — DB-backed session tracking (`user_sessions` table), interceptor enforcement with `MAX_CONCURRENT_SESSIONS` (default 3), configurable per env. Migration 20260403190000. |
| POA-4 | Identify and engage FedRAMP agency sponsor | High | PM-10 | CEO | Q3 2026 | Open |
| POA-5 | Complete first annual incident response exercise | Medium | IR-3 | CEO / ISSO | Q2 2026 | Remediated — Monthly IR-3 red team exercise via GitHub Actions cron (1st of month). 99 automated attacks across 6 suites (auth bypass, escalation, exfiltration, leftfield, webapp, manual tools). MITRE ATT&CK mapped. Reports uploaded to Drata. |
| POA-6 | Establish formal ISSO appointment letter | Low | PM-2 | CEO | Q2 2026 | Remediated — Formal ISSO appointment letter created (`isso-appointment-letter.md`, ISSO-APPT-001). CEO self-appointed as ISSO per startup exception. |
| POA-7 | Finalize PIA with 3PAO input | Medium | PT-5 | CEO | Q3 2026 | Open |
| POA-8 | Cross-project Cloud Armor IAM for IP allowlisting | Medium | SC-7 | Engineering | Q2 2026 | Open |
| POA-9 | Implement periodic Cloud Armor reconciliation job | Low | SC-7 | Engineering | Q3 2026 | Open |
| POA-10 | Admin UI for IP allowlist management | Low | AC-3 | Engineering | Q3 2026 | Open |
| POA-11 | Deploy red team infrastructure via Terraform (red-infra/) | Low | CA-8 | Engineering | Q3 2026 | Open |
| POA-12 | Promote SCN classifier from advisory to required CI check | Low | CM-3 | Engineering | Q2 2026 | Remediated — All 7 repo SCN workflows now include "Enforce SCN acknowledgment" step. PRs with SIGNIFICANT classification are blocked unless `scn-acknowledged` label is present. |
| POA-13 | Enable App Check enforcement in Firebase (currently unenforced) | Medium | IA-9 | Engineering | Q2 2026 | Open |
| POA-14 | Implement session concurrency limiting (AC-10 max sessions per user) | Low | AC-10 | Engineering | Q2 2026 | Remediated — See POA-3. Session concurrency enforced in auth interceptor via `user_sessions` table + `CountActiveUserSessions` query. |
| POA-15 | Hire dedicated Security Lead for independent incident investigation and two-person integrity | Medium | AC-5, SA-11, IR-4 | CEO | Post-first-customer | Open — Currently addressed by automation-first architecture (see SOD-LA-001 §5). Hire planned as organization scales. |
| POA-16 | Hire dedicated Engineering Lead for independent PR review and expanded development capacity | Medium | AC-5, CM-3 | CEO | Post-revenue | Open — Currently addressed by 6 independent automated security scanners that review every change (see SOD-LA-001 §5). |
| POA-17 | Implement phishing simulation program (AT-2(1)) | Low | AT-2(1) | CEO | Post-first-hire | Open — Adversarial personnel testing will be added as team grows. Currently, continuous automated adversarial testing (44-attack red team suite) validates security posture monthly. |

---

_End of System Security Plan — SSP-LA-001_
