# Latent Archon — FedRAMP System Security Plan (SSP)

> **Document ID**: SSP-LA-001  
> **Version**: 1.0 — DRAFT  
> **Date**: March 2026  
> **Baseline**: NIST SP 800-53 Rev. 5 — Moderate Impact  
> **System Name**: Latent Archon Document Intelligence Platform  
> **System Owner**: Latent Archon, LLC  
> **Contact**: ajhendel@latentarchon.com  
> **FIPS 199 Category**: Moderate (Confidentiality: Moderate, Integrity: Moderate, Availability: Moderate)

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
| **Unique Identifier** | LA-DIP-MODERATE-2026 |
| **System Owner Organization** | Latent Archon, LLC |
| **System Owner Name** | Andrew Hendel |
| **System Owner Title** | Chief Executive Officer |
| **System Owner Email** | ajhendel@latentarchon.com |
| **Authorizing Official** | _[Agency AO — TBD upon sponsor engagement]_ |
| **Information System Security Officer (ISSO)** | _[TBD — to be appointed]_ |
| **Cloud Service Model** | Software as a Service (SaaS) |
| **Cloud Deployment Model** | Public Cloud |
| **Underlying CSP** | Google Cloud Platform (GCP) — FedRAMP High Authorized |
| **GCP Authorization ID** | FR1805181233 |
| **FIPS 199 Categorization** | Moderate |
| **Authorization Type** | FedRAMP Agency Authorization |
| **Authorization Status** | Pre-Authorization (DRAFT) |

### 1.1 System Status

This system is in **pre-authorization** status. Infrastructure-as-code has been developed and validated in staging. Production deployment is pending authorization boundary finalization and 3PAO engagement.

---

## 2. System Description

### 2.1 System Function and Purpose

Latent Archon is a multi-tenant document intelligence platform purpose-built for U.S. government agencies handling Controlled Unclassified Information (CUI). The platform provides:

- **Document Management**: Secure upload, storage, and lifecycle management of government documents with malware scanning (ClamAV, fail-closed in production), magic-byte validation, and file type allowlisting.
- **AI-Powered Search**: Retrieval-Augmented Generation (RAG) using vector embeddings (Vertex AI) for semantic document search across workspace-scoped document collections.
- **Interactive Conversation**: Conversational interface over uploaded documents using Google Gemini large language models, with citations and source attribution.
- **Workspace Isolation**: Logical data isolation at the workspace level enforced through PostgreSQL Row-Level Security (RLS), vector store token restrictions, and application-layer access controls.
- **Enterprise SSO/SCIM**: SAML 2.0 federation with customer Identity Providers and SCIM 2.0 automated user lifecycle management.

### 2.2 System Scope

The authorization boundary encompasses all components required to deliver the Latent Archon SaaS offering, including:

- Application code (Go backend, React SPAs)
- GCP infrastructure (Cloud Run, Cloud SQL, Cloud Storage, Vertex AI, Cloud Armor, Cloud KMS, Identity Platform)
- CI/CD pipelines (GitHub Actions with Workload Identity Federation)
- Administrative interfaces (admin SPA, ops service)
- Supporting services (ClamAV malware scanning, Document AI OCR processing)

**Excluded from boundary** (but documented as external services):
- Customer Identity Providers (Okta, Azure AD, etc.) — customer-operated
- Customer end-user devices — customer responsibility
- GCP FedRAMP High infrastructure controls — inherited from GCP authorization

### 2.3 Leveraged Authorizations

| CSP/Service | Authorization | Impact Level | Authorization ID |
|-------------|---------------|--------------|------------------|
| Google Cloud Platform | FedRAMP High P-ATO | High | FR1805181233 |
| Cloudflare DNS | FedRAMP Moderate | Moderate | — |

### 2.4 Service Layers

```
┌─────────────────────────────────────────────────────────┐
│                   Latent Archon SaaS                     │
│  (Application Logic, RBAC, RLS, Audit, MFA, SSO/SCIM)  │
├─────────────────────────────────────────────────────────┤
│              Google Cloud Platform (PaaS/IaaS)           │
│  Cloud Run, Cloud SQL, GCS, Vertex AI, Cloud Armor,     │
│  Identity Platform, Cloud KMS, Cloud Tasks, Cloud        │
│  Logging, Cloud Monitoring, Artifact Registry            │
├─────────────────────────────────────────────────────────┤
│              GCP Physical Infrastructure                  │
│  Data Centers, Network, Power, HVAC, Physical Security   │
└─────────────────────────────────────────────────────────┘
```

---

## 3. System Environment

### 3.1 Authorization Boundary Components

| Component | GCP Service | Project | Description |
|-----------|-------------|---------|-------------|
| App API | Cloud Run (`archon-app`) | `latentarchon-app-prod` | User-facing API: conversation, search, auth, streaming |
| Admin API | Cloud Run (`archon-admin`) | `latentarchon-admin-prod` | Admin API: org management, document ingestion, settings |
| Ops Service | Cloud Run (`archon-ops`) | `latentarchon-admin-prod` | Background processing: embeddings, cron, document processing |
| App SPA | Cloud Run (nginx) | `latentarchon-app-prod` | React single-page application for end users |
| Admin SPA | Cloud Run (nginx) | `latentarchon-admin-prod` | React single-page application for administrators |
| Database | Cloud SQL PostgreSQL 15 | `latentarchon-admin-prod` | Primary data store with RLS, encrypted at rest (CMEK) |
| Object Storage | Cloud Storage | `latentarchon-admin-prod` | Document file storage, GCS versioning (365-day retention) |
| Vector Search | Vertex AI Vector Search | `latentarchon-admin-prod` | Semantic search index with PSC endpoint |
| Text Generation | Vertex AI (Gemini) | `latentarchon-admin-prod` | LLM for RAG conversation responses |
| Document Processing | Document AI | `latentarchon-admin-prod` | OCR and document parsing |
| Identity | Identity Platform | Both projects | Firebase Auth with IDP pools for multi-tenant isolation |
| WAF | Cloud Armor | Both projects | DDoS protection, OWASP CRS, bot blocking, IP allowlisting |
| Load Balancing | Global HTTPS LB | Both projects | TLS termination, routing, health checks |
| Key Management | Cloud KMS | `latentarchon-admin-prod` | CMEK for Cloud SQL and GCS encryption |
| Task Queue | Cloud Tasks | `latentarchon-admin-prod` | Async document processing and embedding queues |
| Malware Scanner | Cloud Run (ClamAV) | `latentarchon-admin-prod` | Internal-only ClamAV REST service for upload scanning |
| Logging | Cloud Logging + Monitoring | Both projects | Centralized logging, metrics, alerting |
| Container Registry | Artifact Registry | Both projects | Docker image storage for all services |
| DNS/TLS | Certificate Manager | Both projects | Google-managed TLS certificates with DNS authorization |
| DNS | Cloudflare | External | Authoritative DNS with DNSSEC enabled |

### 3.2 Two-Project Architecture

Latent Archon uses a **two-project architecture** for blast-radius isolation:

- **App Project** (`latentarchon-app-prod`): Contains the user-facing app API and SPA. Has its own Identity Platform user pool, Cloud Armor policy, and load balancer. The app service account has **read-only** database access (`app_ro` PostgreSQL role) and cross-project `cloudsql.client` + `cloudsql.instanceUser` IAM grants.

- **Admin Project** (`latentarchon-admin-prod`): Contains the admin API, ops service, database, object storage, vector search, and all backend processing. Has its own Identity Platform admin pool. The admin service account has `admin_rw` database access. The ops service account has `ops_rw` access.

**Cross-pool identity bridging is explicitly prohibited.** Users who exist in both pools (admin and app) are treated as separate identities. Workspace access across pools uses an explicit invite flow only (see `docs/POOL_ISOLATION.md`).

### 3.3 Environments

| Environment | Purpose | GCP Projects | Access |
|-------------|---------|--------------|--------|
| Production | Live customer data | `latentarchon-app-prod`, `latentarchon-admin-prod` | Restricted to CI/CD + emergency break-glass |
| Staging | Pre-production validation | `latentarchon-app-staging`, `latentarchon-admin-staging` | Engineering team |
| Development | Local development | N/A (local Docker Compose) | Individual developers |

All environments are managed via Terraform/Terragrunt. No manual GCP console changes are permitted in staging or production (enforced by gcloud guardrail wrapper).

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
| GCP APIs | Outbound | HTTPS | 443 | All GCP service APIs (via FQDN egress firewall allowlist) | FedRAMP High (inherited) |
| GitHub | Outbound | HTTPS | 443 | CI/CD source code, Dependabot | N/A |

### 4.1 Egress Firewall Policy

All outbound traffic from VPC is **denied by default**. An FQDN-based egress firewall explicitly allows only:

- `*.googleapis.com` — GCP API access
- `*.gcr.io`, `*.pkg.dev` — Container registry
- `*.cloudfunctions.net` — Cloud Functions (if needed)
- `graph.microsoft.com` — Microsoft Graph API (SharePoint/OneDrive document sync)
- `login.microsoftonline.com` — Microsoft Entra ID (OAuth2 token exchange)
- Cloudflare DNS endpoints

All other egress is blocked. Microsoft Graph API egress is only active when the integration is configured (`MSGRAPH_CLIENT_ID` present). This is enforced via Terraform-managed firewall rules.

---

## 5. Applicable Laws, Regulations, and Standards

| Law/Regulation/Standard | Applicability |
|------------------------|---------------|
| FISMA (Federal Information Security Modernization Act) | Governs federal information systems security |
| NIST SP 800-53 Rev. 5 | FedRAMP Moderate baseline control catalog |
| NIST SP 800-37 Rev. 2 | Risk Management Framework |
| NIST SP 800-171 Rev. 2 | CUI protection requirements |
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
| **Confidentiality** | Moderate | System processes CUI documents; unauthorized disclosure could cause serious adverse effect |
| **Integrity** | Moderate | Unauthorized modification of documents or AI responses could cause serious adverse effect |
| **Availability** | Moderate | Extended unavailability could cause serious adverse effect to agency mission operations |

**Overall Categorization: MODERATE**

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
| **Customer End User** | Agency staff using app search/conversation | Firebase Auth (magic link or SSO) + MFA | viewer, editor roles within assigned workspaces | Variable per customer |
| **Customer Org Admin** | Agency administrator | Firebase Auth (SSO preferred) + MFA | master_admin or admin role; org management, user lifecycle, settings | 1-5 per customer org |
| **Latent Archon Engineer** | Platform developer | GitHub SSO + GCP IAM (WIF) | CI/CD deployment; no direct production data access | < 10 |
| **Latent Archon Operations** | Platform operations | GCP IAM (break-glass only) | Emergency access via IAM Conditions; time-limited | 1-2 |
| **Automated CI/CD** | GitHub Actions runners | Workload Identity Federation (keyless) | Deploy containers, run migrations; no SA keys | N/A |
| **Ops Service (Machine)** | Background processing | GCP IAM (service-to-service) | Document processing, embeddings, cron; OIDC-authenticated Cloud Tasks | N/A |

### 7.2 Authentication Requirements

| Requirement | Implementation |
|-------------|----------------|
| **Multi-Factor Authentication** | TOTP-based MFA enforced on all data endpoints via auth interceptor. Step-up MFA required for sensitive operations (member invite/remove, document delete, role changes). |
| **Session Management** | Global idle timeout: 25 min (default). Global absolute timeout: 12 hr (default). Per-org configurable: idle 5-480 min, absolute 60-1440 min. Enforced server-side via JWT `auth_time` and `iat` claims. |
| **Password Policy** | Managed by Identity Platform. Magic link (passwordless) preferred. SSO federation eliminates password management for enterprise customers. |
| **Account Lockout** | Identity Platform built-in brute-force protection. Application-level rate limiting at IP + per-user levels. |

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
| `archon_app_ro` | archon-app | Cloud SQL IAM (keyless) | SELECT on reference tables; SELECT + INSERT on messages, rag_searches, generations; INSERT on audit_events; SELECT + INSERT + UPDATE on users (profile upsert) |
| `archon_admin_rw` | archon-admin | Cloud SQL IAM (keyless) | ALL on all tables and sequences (full CRUD) |
| `archon_ops_rw` | archon-ops | Cloud SQL IAM (keyless) | SELECT + INSERT + UPDATE on documents, document_versions, DLQ; SELECT + INSERT + UPDATE + DELETE on chunks; INSERT on audit_events and generations; SELECT on reference tables |

**Migration user** (`archon_migrator` role via IAM): The Atlas migration job (Cloud Run Job) authenticates using Cloud SQL IAM auth (keyless) via the `archon-admin` service account, then assumes the `archon_migrator` PostgreSQL role using `SET ROLE`. This role owns all tables in the public schema and has DDL privileges (CREATE/ALTER/DROP). No static credentials are used in the normal migration path. A `postgres` superuser password exists in Secret Manager as a break-glass mechanism, accessible only to human security administrators — it is not mounted on any Cloud Run service or job by default.

All database roles operate under PostgreSQL Row-Level Security (RLS). RLS policies scope queries to the authenticated user's organization and workspace. RLS is **fail-closed**: if `app.organization_id` or `app.workspace_id` session variables are not set, queries return zero rows (not all rows). Roles are granted to IAM service accounts dynamically by naming convention (`archon-app@*`, `archon-admin@*`, `archon-ops@*`), ensuring environment-agnostic enforcement across staging and production.

---

## 8. Illustrated Architecture and Narratives

### 8.1 Authorization Boundary Diagram

```
┌─ Authorization Boundary ─────────────────────────────────────────────────┐
│                                                                          │
│  ┌─ App Project (latentarchon-app-prod) ──────────────────────────┐   │
│  │  Cloud Armor (WAF) → Global HTTPS LB → App SPA (Cloud Run)     │   │
│  │                                       → App API (Cloud Run)     │   │
│  │  Identity Platform (App User Pool)                              │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│           │ Cross-project: cloudsql.client IAM                          │
│  ┌─ Admin Project (latentarchon-admin-prod) ────────────────────────┐   │
│  │  Cloud Armor (WAF) → Global HTTPS LB → Admin SPA (Cloud Run)    │   │
│  │                                       → Admin API (Cloud Run)    │   │
│  │                                       → Ops Service (Cloud Run)  │   │
│  │  Identity Platform (Admin User Pool)                             │   │
│  │  Cloud SQL (PostgreSQL 15) ←── RLS enforced                     │   │
│  │  Cloud Storage (Documents) ←── AES-256 + CMEK                   │   │
│  │  Vertex AI (Vector Search + Gemini) ←── PSC endpoint            │   │
│  │  Document AI (OCR) │ Cloud Tasks │ Cloud KMS │ ClamAV           │   │
│  │  Cloud Logging + Monitoring │ Artifact Registry                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌─ CI/CD ──────────────────────────────────────────────────────────┐   │
│  │  GitHub Actions → Workload Identity Federation (keyless) →       │   │
│  │  Artifact Registry → Cloud Run Deploy                            │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

External (outside boundary):
  • Customer IdP (Okta/Azure AD) — SAML 2.0 inbound
  • Microsoft Graph API — SharePoint/OneDrive document sync (outbound HTTPS)
  • Microsoft Entra ID — OAuth2 token exchange (outbound HTTPS)
  • Cloudflare DNS — DNSSEC-signed authoritative DNS
  • Customer browsers — HTTPS only
  • GCP FedRAMP High infrastructure — inherited controls
```

### 8.2 Data Flow Diagram — Document Upload

```
Customer Browser (HTTPS/TLS 1.2+)
    │
    ▼
Cloud Armor WAF (OWASP CRS, rate limiting, bot blocking)
    │
    ▼
Global HTTPS Load Balancer (Google-managed TLS cert, HSTS 2yr)
    │
    ▼
Admin API (Cloud Run) — Auth Interceptor:
    1. JWT verification (Firebase ID token)
    2. IDP pool enforcement (REQUIRE_IDP_POOL)
    3. X-IDP-Pool-ID header match
    4. MFA enforcement (TOTP required)
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
Cloud Storage (AES-256-GCM + CMEK, workspace-scoped path)
    │
    ▼
Cloud Tasks queue → Ops Service (Cloud Run):
    ├─► Document AI OCR extraction
    ├─► Text chunking
    ├─► Vertex AI embedding generation
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
    ├─► Encrypt refresh token via Cloud KMS (app_secrets key, AES-256-GCM)
    ├─► Store in graph_connections (org-scoped, RLS-protected)
    ├─► Store client_id for connection identification
    │
    ▼
Sync Trigger (manual via Admin API):
    ├─► Org admin or workspace admin authorization check
    ├─► Decrypt refresh token (Cloud KMS)
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
Cloud Armor WAF → Global HTTPS LB
    │
    ▼
App API (Cloud Run) — Auth Interceptor (same 7-layer chain)
    │
    ├─► Workspace access check (explicit membership OR master_admin)
    │
    ▼
Vector Search Query (Vertex AI, PSC endpoint):
    ├─► Workspace-scoped token restriction
    ├─► Top-K semantic similarity search
    │
    ▼
Context Assembly + Gemini LLM Request (Vertex AI):
    ├─► Retrieved document chunks as context
    ├─► System prompt with safety guardrails
    ├─► Streaming response to client
    │
    ▼
Message persisted (Cloud SQL, RLS-scoped)
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
Google Cloud Armor (WAF policies per project):
    ├─► OWASP CRS v3.3 (SQLi, XSS, LFI, RFI, RCE, Scanner)
    ├─► HTTP method enforcement (GET, POST, OPTIONS only)
    ├─► Origin header restriction
    ├─► Bot/scanner blocking (User-Agent rules)
    ├─► Per-org IP allowlisting (CEL expressions)
    ├─► Rate limiting
    │
    ▼
Global HTTPS Load Balancer:
    ├─► TLS 1.2+ termination (Google-managed cert)
    ├─► HSTS (max-age=63072000, includeSubDomains, preload)
    │
    ▼
VPC (Private IP only — no public IPs on any service):
    ├─► Cloud Run services (serverless containers)
    ├─► Cloud SQL (private IP, VPC peering)
    ├─► Vertex AI (Private Service Connect endpoint)
    │
    ├─► Egress Firewall (FQDN-based):
    │   ├─► DEFAULT: DENY ALL
    │   ├─► ALLOW: *.googleapis.com
    │   ├─► ALLOW: *.gcr.io, *.pkg.dev
    │   └─► All other egress BLOCKED
    │
    ▼
Cloud Logging (structured JSON → Cloud Logging → optional SIEM export via Pub/Sub)
```

---

## 9. Ports, Protocols, and Services

| Service | Ports | Protocol | Direction | Purpose | Encrypted |
|---------|-------|----------|-----------|---------|-----------|
| Customer HTTPS | 443 | TCP/TLS 1.2+ | Inbound | SPA and API access | Yes |
| SAML SSO | 443 | TCP/TLS 1.2+ | Inbound | Enterprise SSO federation | Yes |
| SCIM Provisioning | 443 | TCP/TLS 1.2+ | Inbound | Automated user lifecycle | Yes |
| GCP APIs | 443 | TCP/TLS 1.2+ | Outbound | All GCP service communication | Yes |
| DNS | 53, 443 | UDP/TCP, HTTPS | Outbound | Cloudflare DNS (DNSSEC) | Yes (DoH) |
| Cloud SQL | 5432 | TCP/TLS | Internal VPC | Database connections | Yes |
| ClamAV REST | 8080 | TCP/TLS | Internal VPC | Malware scanning (internal-only Cloud Run) | Yes |
| Vertex AI PSC | 443 | TCP/TLS | Internal VPC | Vector search and LLM via Private Service Connect | Yes |
| Microsoft Graph API | 443 | TCP/TLS 1.2+ | Outbound | SharePoint/OneDrive document sync (`graph.microsoft.com`) | Yes |
| Microsoft Entra ID | 443 | TCP/TLS 1.2+ | Outbound | OAuth2 token exchange (`login.microsoftonline.com`) | Yes |

**All inbound traffic flows through Cloud Armor WAF and Global HTTPS Load Balancer. No services have public IP addresses. All internal communication uses TLS.**

---

## 10. Cryptographic Modules

| Module | Standard | Usage | Key Size | Notes |
|--------|----------|-------|----------|-------|
| Google BoringCrypto (Go) | FIPS 140-2 Level 1 (Cert #4407) | All Go application cryptography | AES-256, SHA-256/384/512 | Enabled via `GOEXPERIMENT=boringcrypto` build flag |
| Google Cloud KMS | FIPS 140-2 Level 3 | CMEK for Cloud SQL and GCS | AES-256 | Automatic key rotation (365 days) |
| Google Cloud KMS (`app_secrets`) | FIPS 140-2 Level 3 | Encryption of Microsoft Graph OAuth refresh tokens | AES-256-GCM | HSM-backed, 90-day rotation |
| Google Front End (GFE) | FIPS 140-2 Level 1 | TLS termination at load balancer | TLS 1.2+, ECDHE, AES-256-GCM | Google-managed certificates |
| Cloud SQL Encryption | FIPS 140-2 Level 1 | Data at rest encryption | AES-256 | Google-managed or CMEK |
| Cloud Storage Encryption | FIPS 140-2 Level 1 | Object encryption at rest | AES-256-GCM | Google-managed or CMEK |

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
| POA-2 | Conduct first contingency plan tabletop exercise | Medium | CP-4 | Security Lead | Q2 2026 | Remediated — Automated monthly CP-4 test via `contingency-test` CLI + GitHub Actions cron (1st of month). Checks: Cloud SQL backup/PITR, GCS versioning, Cloud Run health, KMS keys, Artifact Registry. Reports uploaded to Drata. |
| POA-3 | Implement automated session concurrency limiting | Low | AC-10 | Engineering | Q4 2026 | Open |
| POA-4 | Identify and engage FedRAMP agency sponsor | High | PM-10 | CEO | Q3 2026 | Open |
| POA-5 | Complete first annual incident response exercise | Medium | IR-3 | Security Lead | Q2 2026 | Remediated — Monthly IR-3 red team exercise via GitHub Actions cron (1st of month). 44 automated attacks across 3 suites (auth bypass, escalation, exfiltration). MITRE ATT&CK mapped. Reports uploaded to Drata. |
| POA-6 | Establish formal ISSO appointment letter | Low | PM-2 | CEO | Q2 2026 | Open |
| POA-7 | Finalize PIA with 3PAO input | Medium | PT-5 | CEO | Q3 2026 | Open |
| POA-8 | Cross-project Cloud Armor IAM for IP allowlisting | Medium | SC-7 | Engineering | Q2 2026 | Open |
| POA-9 | Implement periodic Cloud Armor reconciliation job | Low | SC-7 | Engineering | Q3 2026 | Open |
| POA-10 | Admin UI for IP allowlist management | Low | AC-3 | Engineering | Q3 2026 | Open |

---

_End of System Security Plan — SSP-LA-001_
