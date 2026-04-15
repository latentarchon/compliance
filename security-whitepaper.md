# Latent Archon — Security Architecture Whitepaper

> **Classification**: Company Confidential — Approved for Government Prospect Distribution  
> **Version**: 2.0  
> **Date**: March 2026  
> **Contact**: ajhendel@latentarchon.com

---

## Executive Summary

Latent Archon is a multi-tenant document intelligence platform purpose-built for government agencies handling Controlled Unclassified Information (CUI) and DoD mission data. The platform enables Retrieval-Augmented Generation (RAG) conversation over uploaded documents with workspace-level data isolation, deployable on **Google Cloud Platform (GCP)** within **IL5 Assured Workloads** — satisfying FedRAMP High and DoD Impact Level 5 requirements.

<!-- MULTI-CLOUD: AWS/Azure deployment options removed to focus on GCP-only strategy. Restore when multi-cloud support is reactivated.
Original: deployable on **Google Cloud Platform (GCP)**, **Amazon Web Services (AWS)**, or **Microsoft Azure** — all FedRAMP High authorized infrastructure.
The application binary, database schema, and security controls are **identical across all three clouds**. Only the underlying infrastructure services differ (e.g., Cloud Run vs. ECS Fargate vs. Container Apps). This whitepaper describes the platform's cloud-agnostic security architecture. For cloud-specific implementation details, see the [Cloud Environment Supplements](cloud/). -->

This whitepaper describes the platform's security architecture across authentication, data isolation, data flow, encryption, logging, disaster recovery, infrastructure governance, and network security.

---

## 1. Authentication & Identity

### Multi-Pool Auth Isolation

Authentication is handled by dedicated **FedRAMP High Assured Workloads** projects (Identity Platform is not IL5-supported). Each auth project hosts an independent identity pool. The IL5 data-plane projects validate JWTs offline via JWKS public keys — no direct service calls cross the IL5 boundary:

| Pool | GCP Project | Users | Domain |
|------|-------------|-------|--------|
| App (End Users) | `archon-fed-auth-app-*` (FedRAMP High AW) | Agency analysts, viewers | `app.latentarchon.com` |
| Admin (Org Admins) | `archon-fed-auth-admin-*` (FedRAMP High AW) | Org administrators, workspace managers | `admin.latentarchon.com` |

<!-- MULTI-CLOUD: AWS/Azure auth columns removed. Original included:
| Pool | AWS | Azure |
| App | SAML IdP providers | Azure AD federation |
| Admin | SAML IdP providers | Azure AD federation | -->

This architecture provides **complete auth pool isolation** — a valid app-pool JWT cannot authenticate against the admin API, and vice versa. Credential compromise in one pool cannot escalate to the other. The IL5 data-plane projects (admin, ops, app, kms) have no identity pools — auth projects exist in a separate FedRAMP High Assured Workloads boundary. The ops project is a pure data tier with no public ingress.

> **Auth model**: GCP deployments support self-service registration (magic link + TOTP MFA) and SAML 2.0 SSO with SCIM 2.0 provisioning.

<!-- MULTI-CLOUD: Original included AWS/Azure auth models:
> AWS and Azure deployments use **SSO/SAML exclusively** — no self-service registration, no magic links. MFA is delegated to the customer's Identity Provider. All three clouds support SAML 2.0 SSO and SCIM 2.0 provisioning. -->

### Cross-Pool Identity Prohibition

Because Firebase UIDs are project-scoped, the same person has different UIDs in the admin and app pools. **Cross-pool identity bridging is explicitly prohibited** — the system never copies memberships between pools by matching on email. This would create a lateral escalation path (compromise one pool → gain the other pool's permissions).

Instead, workspace access across pools uses the **explicit invite flow**:

1. Admin creates workspace → admin UID stored in `workspace_members` (admin app)
2. System auto-creates a pending invite for the creator's email
3. Creator receives email with sign-in link to the app
4. Creator authenticates in the app → app UID
5. Creator accepts invite → app UID stored in `workspace_members` (app)

Each pool's membership is created through that pool's own authentication, with an auditable invite record bridging the two. See `docs/POOL_ISOLATION.md` for the full architectural decision record.

### Multi-Tenant Organization Routing

Each customer organization receives its own Identity Platform **IDP pool** in both projects and a unique **DNS-safe slug** (RFC 1123 label) used for subdomain routing. Organization isolation is enforced at five independent layers in the auth interceptor chain:

1. **IDP Pool Presence**: Firebase ID token must contain a `firebase.tenant` claim (when `REQUIRE_IDP_POOL=true`)
2. **Header Match**: `X-IDP-Pool-ID` request header must exactly match the token's `firebase.tenant` claim
3. **Org Membership Gate**: After token verification, the user's organization membership is resolved from the database (`organization_members` by Firebase UID). Users without any org membership are **rejected** on all non-AuthService RPCs (`PermissionDenied: "organization membership required"`)
4. **Subdomain→Org DB Validation**: If the Host header contains a non-reserved subdomain (i.e., not `www`, `api`, `app`, `admin`, `staging`, `localhost`), the subdomain is resolved against the `organizations` table by slug via `GetOrgIDBySlug`. **Unknown subdomains are rejected** (`PermissionDenied: "unknown organization"`)
5. **Cross-Org Check**: If the subdomain resolves to an org that differs from the user's resolved org, the request is rejected (`PermissionDenied: "organization mismatch"`)

If any check fails, the request is rejected with `PermissionDenied`. This five-layer enforcement prevents orgless users, unknown org subdomains, and cross-org request routing.

> **Note**: `organization_id` (PostgreSQL UUID) is the business identifier. `idp_pool_id` (Identity Platform tenant string) is the auth isolation implementation detail. They are never interchangeable. See `docs/TENANT_CONFIGURATION.md` for the full terminology guide.

### Organization Slug Enforcement

Organization slugs are validated at creation time against a DNS-safe regex (`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`) and a reserved-slug blocklist. Slugs must be 3–63 characters, lowercase alphanumeric with hyphens, and cannot collide with infrastructure subdomains. The `organizations.slug` column is `NOT NULL UNIQUE` in the database schema.

### Multi-Factor Authentication (MFA)

TOTP-based MFA is enforced at the API interceptor level on all data endpoints. MFA status is verified via the `sign_in_second_factor` Firebase JWT claim. High-risk operations (member invite/remove, document delete) require **step-up MFA** with recent re-authentication.

Admin MFA management (reset, unenroll) is restricted to org admins, with self-reset explicitly blocked and all actions audit-logged.

### Session Management (NIST 800-53 AC-12 / SC-10)

| Control | Global Default | Per-Org Range | Enforcement |
|---------|---------------|---------------|-------------|
| Idle timeout | 30 minutes | 5–480 min | `iat` JWT claim comparison |
| Absolute timeout | 12 hours | 60–1440 min | `auth_time` JWT claim comparison |

Session timeouts are enforced server-side in the auth interceptor chain at two levels:

1. **Global defaults** — configured via `SESSION_IDLE_TIMEOUT_MIN` and `SESSION_ABSOLUTE_TIMEOUT_MIN` environment variables
2. **Per-org overrides** — agency administrators can set stricter timeouts via `UpdateOrganizationSettings` RPC (stored in org settings JSONB, enforced after global checks)

Per-org timeouts can only be **stricter** than the global defaults — the interceptor applies the more restrictive of the two. This allows agencies with heightened security requirements (e.g., 15-minute idle timeout) to enforce their own policies.

### SSO & SCIM

Enterprise SSO is supported via SAML 2.0 integration with Identity Platform tenants. Each organization can configure its own IdP (Okta, Azure AD, etc.) with:

- Just-In-Time (JIT) user provisioning on first federated login
- IdP group-to-role mapping (IdP groups → org roles + workspace memberships)
- Full SCIM 2.0 server (RFC 7643/7644) for automated user lifecycle management

---

## 2. Row-Level Security & Data Isolation

### Workspace-Scoped RLS

All data tables (documents, chunks, messages, RAG searches) are protected by PostgreSQL Row-Level Security with **FORCE** enabled — even table owners are subject to RLS policies.

The application uses PostgreSQL GUC (Grand Unified Configuration) variables to scope every query:

```
SET LOCAL app.workspace_ids = '<uuid>,<uuid>'
```

If no workspace IDs are set, **zero rows are returned** (fail-closed design).

### Three Database Access Wrappers

| Wrapper | GUC Setting | Used By |
|---------|-------------|---------|
| `WorkspaceScopedDBTX()` | `app.workspace_ids` | All user-facing queries |
| `AdminScopedDBTX()` | `app.rls_bypass = 'on'` | System operations, cron jobs |
| `UnscopedDBTX()` | None | Non-workspace tables (users, org_members) |

### Least-Privilege Database Roles

Default `PUBLIC` privileges are revoked on all tables and sequences. Only named roles have access.

| Role | Service | Auth | Permissions |
|------|---------|------|-------------|
| `archon_app_ro` | App API | IAM-based (keyless) | SELECT on reference tables; SELECT + INSERT on messages/searches/generations; INSERT on audit_events; SELECT + INSERT + UPDATE on users (profile upsert) |
| `archon_admin_rw` | Admin API | IAM-based (keyless) | ALL on all tables and sequences |
| `archon_ops_rw` | Ops service | IAM-based (keyless) | SELECT/INSERT/UPDATE on documents, versions, DLQ; full CRUD on chunks; INSERT on audit_events + generations; SELECT on reference tables |
| `archon_migrator` (migration only) | Atlas migration job | IAM-based (keyless, SET ROLE) | DDL privileges for schema migrations. Owns all public tables. No static credentials in normal path. `postgres` password exists in secrets management as break-glass only (human admin access). |

Database IAM auth is implemented via Cloud SQL IAM. The PostgreSQL role model is consistent across all environments.

<!-- MULTI-CLOUD: Original: Database IAM auth is implemented via Cloud SQL IAM (GCP), RDS IAM (AWS), or Azure AD auth (Azure). The PostgreSQL role model is identical across all clouds. -->

The app role **cannot** create, modify, or delete organizations, workspaces, documents, or members. Even if the app service is fully compromised, the attacker cannot ALTER tables, CREATE functions/triggers (no backdoor), or DELETE any data. Roles are granted to IAM service accounts dynamically by naming convention, ensuring environment-agnostic enforcement. Enforced via migration `20260328120000_enforce_least_privilege_db_roles.sql`.

### Vector Store Isolation

Vector search results are scoped to authorized workspace IDs via token restrictions (Vertex AI Vector Search). Each stored embedding carries `workspace_id` and `document_id` namespace restrictions, preventing cross-workspace data leakage at the vector database level.

<!-- MULTI-CLOUD: Original also included: filter queries (AWS: OpenSearch Serverless), or security filters (Azure: AI Search). -->

---

## 3. Data Flow

### Request Path

```
Client (SPA)
  → WAF (Cloud Armor — OWASP CRS)
  → Load Balancer (TLS termination, DDoS protection)
  → Container Runtime (Cloud Run)
    → CORS Middleware
    → Security Headers Middleware
    → IP Rate Limiter (pre-auth)
    → Connect-RPC Interceptor Chain:
      1. Recovery (panic → CodeInternal, never leaks stack traces)
      2. Trace (OpenTelemetry span injection)
      3. Auth:
         a. Token verify (Firebase JWT / SAML assertion)
         b. IDP pool isolation (header + Host subdomain vs token pool)
         c. MFA enforcement (TOTP required / delegated to IdP)
         d. Session timeouts (idle 25 min, absolute 12 hr)
         e. JIT provisioning (federated users)
         f. Org membership gate (reject orgless users)
         g. Subdomain→org DB validation (reject unknown/mismatched orgs)
      4. Per-User Rate Limiter
      5. Logging Interceptor
    → Handler (authorization check, business logic)
    → RLS-scoped Database Query (PostgreSQL, private network)
```

### Document Ingestion Pipeline

```
[Manual Upload]  Upload → Size Check (50 MB) → Type Allowlist → Magic-Byte Validation
[Graph Sync]     Microsoft Graph Delta Query → File Download → Type/Size Check
       ↓
  → ClamAV Malware Scan → SHA-256 Dedup → Object Storage Upload (workspace-scoped path)
  → DB Insert → Task Queue → DLP/PII Inspection
  → Document Extraction (OCR) → Chunking (800-token segments) → Embedding
  → Vector Search Index (workspace-scoped)
```

The pipeline uses the following GCP services:

| Step | GCP Service |
|------|-------------|
| Object storage | GCS |
| Task queue | Cloud Tasks |
| DLP/PII | Cloud DLP |
| Text extraction | Native Go parsing (in-process) |
| Embedding | Vertex AI (Gemini Embedding) |
| Vector search | Vertex AI Vector Search |

<!-- MULTI-CLOUD: Original table included AWS (S3, SQS, Comprehend, Textract, Bedrock Titan Embed, OpenSearch Serverless) and Azure (Blob Storage, Service Bus, AI Language, Document Intelligence, Azure OpenAI text-embedding-3, Azure AI Search) columns. -->

Documents from Microsoft 365 (SharePoint, OneDrive) enter the same pipeline as manual uploads. The Graph sync path downloads files via Microsoft Graph API delta queries, then feeds them through the identical malware scan → DLP → embed pipeline. Content-hash deduplication prevents re-ingesting unchanged files.

### RAG Conversation Flow

```
User Message → Workspace Access Verification → Query Embedding
  → Vector Search (workspace-filtered) → Chunk Hydration (from PostgreSQL)
  → Prompt Construction (server-controlled system prompt + context + history)
  → LLM Streaming Response → SSE to Client
  → Async: Message Persistence + Audit Event
```

| Step | GCP Service |
|------|-------------|
| LLM | Vertex AI (Gemini 2.5 Pro) |

<!-- MULTI-CLOUD: Original included AWS (Claude 3.5 Sonnet via Bedrock) and Azure (GPT-4o via Azure OpenAI). -->

### Microsoft Graph Sync Flow

```
Admin Console → Initiate OAuth2 (Microsoft Entra ID)
  → HMAC-signed CSRF state token (10-min TTL)
  → Admin consent → Authorization code callback
  → Token exchange → Refresh token encrypted via KMS (HSM-backed)
  → Stored in graph_connections (org-scoped, RLS-protected)

Sync Trigger (manual or scheduled):
  → Decrypt refresh token (KMS) → Obtain access token
  → Microsoft Graph Delta Query (only new/changed files)
  → File download → Standard ingestion pipeline
  → Sync audit log (graph_sync_log table)
```

OAuth tokens are encrypted at rest using Cloud KMS (HSM-backed).

<!-- MULTI-CLOUD: Original: cloud-native KMS service (Cloud KMS / AWS KMS / Key Vault). -->

### Cross-Environment Data Flow

Two narrow IAM grants cross environment boundaries — both targeting the ops environment which owns the entire data tier:

**App → Ops (read-only database access)**:
- `roles/cloudsql.client` + `roles/cloudsql.instanceUser` for the app SA on the ops project

**Admin → Ops (read-write database access)**:
- `roles/cloudsql.client` + `roles/cloudsql.instanceUser` for the admin SA on the ops project

<!-- MULTI-CLOUD: Original also included:
- AWS: Cross-account IAM role assumption for RDS access
- Azure: Cross-subscription managed identity delegation for PostgreSQL access -->

Additionally, the admin SA holds `compute.securityAdmin` on the app environment for Cloud Armor IP allowlist sync.

All data-tier services (database, object storage, KMS, vector search, LLM, document extraction, DLP, task queue, ClamAV) are isolated within the ops environment. The app and admin environments contain only their respective APIs, SPAs, identity pools, and WAF/LB infrastructure.

---

## 4. Encryption

### Data at Rest

| Layer | Mechanism | GCP Key Management |
|-------|-----------|-------------------|
| PostgreSQL | AES-256 | CMEK via Cloud KMS |
| OAuth Tokens | AES-256-GCM | Cloud KMS `app_secrets` key |
| Object Storage | AES-256 | CMEK via Cloud KMS (GCS) |
| Vector Index | AES-256 | CMEK via Cloud KMS (Vertex AI) |
| Container Images | AES-256 | CMEK via Cloud KMS (AR) |
| Audit Logs | AES-256 | CMEK via Cloud KMS (BigQuery + Cloud Logging) |

<!-- MULTI-CLOUD: Original table included AWS Key Management (CMEK via KMS/RDS, SSE-KMS/S3, etc.) and Azure Key Management (CMEK via Key Vault/TDE, etc.) columns. -->

All data-at-rest encryption uses Customer-Managed Encryption Keys (CMEK) backed by HSMs (FIPS 140-2 Level 3). Keys rotate automatically every 90 days. Each service has a dedicated CMEK key, with IAM grants scoped to minimum required permissions. Key lifecycle events (disable, destroy, version state changes) trigger monitoring alerts. Per-tenant CMEK anchor: `organizations.kms_key_name` column stores the KMS key resource name for each tenant, enabling future per-tenant encryption key isolation.

### Data in Transit

| Path | Protocol | GCP |
|------|----------|-----|
| Client → Load Balancer | TLS 1.2+ | Certificate Manager (DNS auth) |
| LB → Container | TLS 1.2+ | Google-managed |
| Container → Database | TLS 1.2+ | Cloud SQL Connector (IAM, private VPC) |
| Container → AI Services | TLS 1.2+ | PSC (no public internet) |
| Container → Object Storage | TLS 1.2+ | Google-managed |
| Container → Microsoft Graph | TLS 1.2+ | Microsoft-managed |

<!-- MULTI-CLOUD: Original table included AWS (ACM, ALB→ECS, RDS TLS, VPC endpoints) and Azure (Front Door managed certs, Front Door→Container Apps, Azure AD auth, Private endpoints) columns. -->

HSTS is enforced with `max-age=63072000; includeSubDomains; preload` (2-year pinning).

### Secrets Management

- **Zero secrets in container images**: All configuration via environment variables at runtime
- **No static database passwords**: IAM-based database authentication only (Cloud SQL IAM). The `postgres` superuser password exists in secrets management as break-glass only, accessible to security administrators — not mounted on any service or job by default. A monitoring alert (CRITICAL severity) fires on any access to this secret.
- **No service account keys**: Workload Identity Federation (GCP WIF) for CI/CD — zero stored credentials
- **Org policy enforcement**: GCP org policies block SA key creation/import.

<!-- MULTI-CLOUD: Original also included:
- IAM-based auth: RDS IAM (AWS), Azure AD auth (Azure)
- WIF: AWS OIDC, Azure Workload Identity
- Org policies: AWS SCPs restrict IAM key creation. Azure policies enforce managed identity usage. -->
- **Secret rotation**: All secrets have a 90-day automatic rotation schedule configured via Terraform
- **Secret access alerting**: Monitoring alert policies fire on any secret access, enabling detection of unauthorized or unexpected access
- **CI guardrail**: The infra CI pipeline (`iam-auth-guardrail` job) rejects PRs that introduce `DB_USER` or `DB_PASSWORD` into atlas-migrate configs, preventing regressions to password-based auth.

### PostgreSQL Database Audit Flags

PostgreSQL database-level auditing is enforced via Terraform-managed Cloud SQL database flags:

| Flag | Value | Purpose |
|------|-------|---------|
| `cloudsql.enable_pgaudit` | `on` | Enables the pgAudit extension for detailed SQL audit logging |
| `pgaudit.log` | `ddl,role,write` | Logs DDL statements, role changes, and write operations |
| `log_statement` | `ddl` | Logs all DDL statements (CREATE, ALTER, DROP) |
| `log_connections` | `on` | Logs all connection attempts (successful and failed) |
| `log_disconnections` | `on` | Logs session termination with duration |
| `log_lock_waits` | `on` | Logs lock waits exceeding `deadlock_timeout` |
| `log_min_duration_statement` | `1000` | Logs queries taking longer than 1 second (slow query detection) |
| `cloudsql.iam_authentication` | `on` | Enables IAM-based authentication (required for keyless auth) |

These flags are defined in the Cloud SQL module (`infra/gcp/modules/cloud-sql/`) and applied uniformly across staging and production.

<!-- MULTI-CLOUD: Original referenced infra/{gcp,aws,azure}/modules/ and RDS parameter groups / Azure Flexible Server parameters. -->

### Schema future-proofing (no behavioral change today)

- `organizations.kms_key_name` — Per-tenant CMEK anchor for future customer-managed key isolation.
- `organizations.data_region` — Default `us-east4`; enables future per-tenant data residency constraints.
- `audit_events.session_id` and `audit_events.mfa_method` — Additional audit information per AU-3(1) for session correlation and MFA method tracking.

---

## 5. Logging & Audit

### Audit Event System

All security-relevant operations are persisted to the `audit_events` database table with:

| Field | Purpose |
|-------|---------|
| `user_id` | Actor identification (Firebase UID) |
| `organization_id` / `workspace_id` | Scope |
| `action` | Operation type (e.g., `document.upload`, `org.invite_member`) |
| `status` | `started`, `success`, `failure` |
| `resource_type` / `resource_id` | Affected resource |
| `ip_address` (INET) | Client IP |
| `user_agent` | Client identification |
| `metadata` (JSONB) | request_id, idp_pool_id, trace_id, span_id, error_code, duration_ms, platform |
| `correlation_id` | Cross-event linking |
| `session_id` | Session identification for cross-event correlation |
| `mfa_method` | MFA method used for the action (e.g., TOTP) — supports AU-3(1) additional audit information |

### Audited Operations

- **Auth**: login, login_failed, mfa_challenge, session_timeout
- **Organization**: create, invite_member, remove_member, reset_member_mfa
- **Workspace**: create, invite_member, remove_member
- **Document**: upload, delete, metadata_update
- **Admin**: bootstrap, role_escalation
- **SCIM**: user_create, user_replace, user_patch, user_deactivate, group_member_add, group_member_remove
- **Graph**: connection_initiated, connection_completed, connection_revoked, sync_source_added, sync_source_removed, sync_triggered

### SIEM Integration

- All audit events emit structured JSON logs to Cloud Logging
- Security-critical events (failures, auth, member changes, deletions) logged at WARN level
- OpenTelemetry trace correlation (trace_id, span_id) for end-to-end request tracing
- **SIEM Export Pipeline**: Per-customer Pub/Sub topic + subscription for agency SIEM integration (Splunk, Chronicle). Supports both pull and push delivery. Enabled per-customer via Terraform variable.
- Long-term audit log sink for analytics and compliance reporting (BigQuery)

<!-- MULTI-CLOUD: Original included CloudWatch/Azure Monitor logging, SNS+SQS/Event Hub SIEM options, S3/Blob Storage audit sinks, and Sentinel as SIEM target. -->

### Observability

- **Distributed Tracing**: OpenTelemetry with OTLP/gRPC export (Cloud Trace)

<!-- MULTI-CLOUD: Original included X-Ray (AWS) and Application Insights (Azure). -->
- **Structured Logging**: Go `slog` with JSON output to cloud-native logging
- **Metrics**: Database queries, slow queries, HTTP request count/duration/status, rate limit violations
- **Sampling**: 1% production, 10% staging, 100% development

---

## 6. Security Email Notifications

The platform includes a **real-time security notification service** that alerts organization administrators when security-critical events occur. Notifications are sent asynchronously to avoid blocking request processing.

### Notifiable Events

| Event | Severity | Trigger |
|-------|----------|---------|
| `admin.role_escalation` | CRITICAL | Privilege escalation attempt or successful elevation |
| `admin.bootstrap` | CRITICAL | Initial admin bootstrap of a new organization |
| `auth.login_failed` | HIGH | Failed authentication attempt |
| `member.remove` / `org.member_remove` | HIGH | Member removed from workspace or organization |
| `member.role_change` | MEDIUM | Member role changed within organization |
| `document.delete` | MEDIUM | Document permanently deleted from workspace |
| `scim.user_deactivate` | HIGH | User deactivated via SCIM directory sync |
| `scim.user_create` / `scim.user_patch` | MEDIUM | User provisioned or modified via SCIM |

### Safeguards

- **Deduplication window** — prevents alert storms (default 5 min per org+action, configurable)
- **Panic recovery** — notification goroutine catches panics, never crashes the server
- **Timeout protection** — 10s recipient resolution + 30s SMTP send timeout
- **Fallback recipient** — configurable default alert email when no org admins can be resolved
- **Bypasses EMAIL_ALLOWLIST** — security notifications always deliver, even in staging

---

## 7. Account Lifecycle & Data Purge

### Account Closure

| Capability | Detail |
|-----------|--------|
| Self-service closure | Users can close their own account via the `CloseAccount` RPC |
| Admin closure | Organization admins can close member accounts with audit trail |
| Token revocation | All Firebase tokens are revoked immediately on closure |
| Audit logging | Closure event logged with admin ID, target user ID, and org context |
| Step-up MFA | Account closure requires recent MFA verification (within 15 minutes) |

### Data Purge (Privacy Policy §5)

A **daily cron job** (Cloud Scheduler → Pub/Sub push → ops Cloud Run) permanently deletes all data for accounts closed more than 90 days ago. This includes user records, org memberships, workspace memberships, documents, conversation messages, and audit events. Cloud Scheduler runs in a dedicated FedRAMP High management project outside the IL5 boundary; messages are delivered via cross-project Pub/Sub push subscriptions into the IL5 ops project. The purge is irreversible and fully logged.

### Forensic Preservation (Security Addendum §7.4)

On **P1/P2 security incidents**, a forensic preservation endpoint captures a complete database snapshot and audit trail for the affected scope. This ensures evidence is preserved before any automated purge or account lifecycle action can destroy relevant data. Forensic endpoints are restricted to the ops service with OIDC authentication.

---

## 8. Document Integrity

### Semantic Deduplication

Beyond SHA-256 content hash deduplication (exact duplicate detection), the platform implements **vector similarity near-duplicate detection**:

- After embedding, new document chunks are compared against existing workspace chunks using cosine similarity
- Documents exceeding a **0.97 similarity threshold** are flagged as semantic near-duplicates
- Near-duplicate status is recorded in document metadata and surfaced in the admin UI
- Deduplication is workspace-scoped — cross-workspace duplicates are not flagged (by design)

### Document Versioning

Documents support **immutable version history**:

- Each upload creates a new version with an incrementing version number
- Previous versions are retained in object storage with workspace-scoped paths
- Version metadata (uploader, timestamp, size, content hash) is stored in the database
- Versions are immutable once created — no in-place modification

---

## 9. Multimodal AI (Image Generation)

The app API supports **inline image generation** within streaming conversations:

| Step | Detail |
|------|--------|
| Model | Gemini 2.0 Flash (Vertex AI) |
| Streaming | Images generated inline during server-streaming conversation responses |
| Storage | Generated images uploaded to object storage with workspace-scoped paths |
| Proxy | Images served via authenticated proxy endpoint — no direct storage URLs exposed |
| Rate Limiting | Max 4 images per response, 10 MB total image payload per response |
| Audit | Image generation events logged with image count, total bytes, and correlation ID |

All generated images inherit the workspace scope of the conversation and are never directly accessible via object storage URLs.

---

## 10. Data Export (FOIA Compliance)

A dedicated **Export Service** supports bulk data export for FOIA requests, government record-keeping requirements, and data portability obligations:

| Capability | Detail |
|-----------|--------|
| Scope | Organization-level or workspace-level data export |
| Data Included | Documents (originals + metadata), conversation messages, audit events, user records, workspace configurations |
| Format | Structured export package with manifest and chain-of-custody metadata |
| Access Control | Export restricted to organization `master_admin` role with step-up MFA |
| Audit Trail | Every export request is audit-logged with requestor ID, scope, and completion status |
| Processing | Large exports processed via task queue (Cloud Tasks) with progress tracking |

Export manifests include chain-of-custody metadata (who exported, when, what scope) to satisfy federal record-keeping requirements.

---

## 11. Usage Analytics & Cost Attribution

The platform includes an **Analytics Service** providing per-organization usage metrics and cost attribution:

| Capability | Detail |
|-----------|--------|
| Usage Metrics | Conversation messages, document uploads, vector searches, and API calls tracked per org and workspace |
| Cost Attribution | AI services, document processing, object storage, and compute costs attributed to org/workspace |
| Dashboard | Admin-facing usage dashboard with time-series charts and per-workspace breakdowns |
| Access Control | Analytics endpoints restricted to organization admin role; data org-scoped |
| Export | Analytics data exportable as CSV/JSON for agency reporting systems |

---

## 12. Operational Resilience

### Dead Letter Queue (DLQ) Management

Documents that fail processing after task queue retry exhaustion are captured in a **Dead Letter Queue**:

- Admin endpoint lists all DLQ items with failure reason, attempt count, and timestamps
- Admin endpoint requeues individual or batch DLQ items for reprocessing
- DLQ endpoints restricted to ops service with OIDC authentication
- DLQ depth integrated with cloud monitoring for threshold-based alerting

### Deep Readiness Probes (`/readyz`)

Beyond basic liveness checks (`/health`), the platform implements **mode-aware deep readiness probes**:

| Dependency | Check | Mode-Aware |
|-----------|-------|-----------|
| PostgreSQL | Connection pool ping with timeout | All modes |
| Vector Store | Index endpoint reachability | public + ops |
| Object Storage | Bucket/container accessibility verification | admin + ops |
| Task Queue | Queue accessibility check | admin + ops |
| LLM Service | Model endpoint reachability | public |

Readiness checks are scoped to the server mode to prevent cascading failures across unrelated service boundaries.

### Per-Organization Cloud Armor IP Allowlisting

Organization administrators can configure **self-service IP allowlists** via the admin API:

- CIDR-based IP allowlists stored in organization settings (JSONB)
- Allowlists synced to WAF rules via Cloud Armor API
- Per-org enforcement matches org hostname + IP range
- Sync failure is non-fatal (logged + audit event; database is source of truth)
- Periodic reconciliation cron catches WAF drift

### Data Loss Prevention (DLP)

DLP/PII inspect templates are deployed via Terraform to scan uploaded documents for sensitive data before they enter the RAG pipeline using Cloud DLP:

<!-- MULTI-CLOUD: Original also referenced Amazon Comprehend PII detection (AWS) and AI Language PII detection (Azure). -->

| Detector Category | Info Types |
|-------------------|-----------|
| **PII** | `PERSON_NAME`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SOCIAL_SECURITY_NUMBER`, `US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER`, `DATE_OF_BIRTH`, `STREET_ADDRESS` |
| **Credentials** | `AUTH_TOKEN`, `AWS_CREDENTIALS`, `GCP_API_KEY`, `GCP_CREDENTIALS`, `PASSWORD`, `ENCRYPTION_KEY` |
| **Financial** | `CREDIT_CARD_NUMBER`, `US_BANK_ROUTING_MICR`, `IBAN_CODE`, `SWIFT_CODE` |
| **Custom regex** | Configurable per-deployment (e.g., internal case numbers, badge IDs) |

DLP scanning is integrated into the document ingestion pipeline. Findings are logged with minimum likelihood thresholds and finding limits configurable via Terraform variables. An optional de-identification template can redact detected PII/credentials before RAG indexing.

IAM access is scoped to minimum required permissions for scan execution and template management on each cloud platform.

### Microsoft Graph Integration (SharePoint / OneDrive Sync)

Organization administrators can connect Microsoft 365 tenants to ingest documents from SharePoint sites and OneDrive drives directly into Archon workspaces:

| Capability | Implementation |
|-----------|---------------|
| **OAuth2 Flow** | Authorization code grant with Microsoft Entra ID (Azure AD). Admin consent required — delegated permissions only (`Files.Read.All`, `Sites.Read.All`). |
| **CSRF Protection** | OAuth state token is HMAC-signed (SHA-256) with a derived key and 10-minute TTL. Format: `nonce:timestamp:orgID:msTenantID:hmac`. Prevents forgery and replay. |
| **Token Storage** | Refresh tokens encrypted at rest via cloud-native KMS (AES-256-GCM, HSM-backed). Stored in `graph_connections` table with org-scoped RLS. |
| **Token Refresh** | Access tokens obtained on-demand using stored refresh token. No long-lived access tokens persisted. |
| **Delta Sync** | Microsoft Graph delta queries fetch only new/changed files since last sync. Content-hash deduplication prevents re-ingesting unchanged files. |
| **Authorization** | Connection management (create, list, revoke) restricted to org admins. Sync source configuration requires workspace admin permission. Source-level history queries require workspace document-edit permission. |
| **Ingestion Pipeline** | Downloaded files enter the standard pipeline: malware scan → DLP inspection → OCR → chunking → embedding → vector index. No bypass path. |
| **Audit Trail** | All Graph operations logged: `connection_initiated`, `connection_completed`, `connection_revoked`, `sync_source_added`, `sync_source_removed`, `sync_triggered`. |
| **Credential Isolation** | `MSGRAPH_CLIENT_ID` and `MSGRAPH_CLIENT_SECRET` are environment variables injected at runtime. The client secret is never stored in the database — only the encrypted refresh token. |
| **Network Egress** | `graph.microsoft.com` and `login.microsoftonline.com` added to the FQDN egress firewall allowlist only when Graph integration is configured. |

### Security Monitoring Alerts

Automated alert policies are deployed via Terraform across all cloud environments:

| Alert | Trigger | Severity | Purpose |
|-------|---------|----------|---------|
| WAF Block Spike | Elevated WAF DENY events | HIGH | Active attack or misconfigured WAF rule detection |
| 5xx Error Rate | 5xx/total request ratio exceeds threshold | HIGH | Service degradation or deployment regression |
| Database Auth Failure | Failed authentication attempts in database logs | HIGH | Brute force attempt or misconfigured identity detection |
| IAM Privilege Escalation | IAM policy changes on sensitive resources | CRITICAL | Unauthorized IAM changes detection |
| KMS Key Lifecycle | Key disable, destroy, or version state changes | CRITICAL | Unauthorized key operations detection |
| Secret Access | Secret read operations on managed secrets | CRITICAL | Unexpected secret access detection |
| Break-Glass Secret Access | Access to database superuser password secret | CRITICAL | Emergency credential usage tracking |
| BinAuthz Admission Denial | Binary Authorization rejects a Cloud Run deploy (missing/invalid attestation) | CRITICAL | Unauthorized or untrusted image deployment detection |
| BinAuthz Break-Glass Override | Deploy bypasses Binary Authorization via break-glass annotation | CRITICAL | Emergency attestation bypass tracking |

All alerts route to configured notification channels with rate limiting to prevent alert fatigue. Staging and production environments share identical alert configurations to ensure security parity.

---

## 13. Data Retention & Immutability

All data stores enforce a **zero-deletion policy** — no object storage lifecycle deletion, audit log expiration, or automated process permanently deletes any data. This ensures government records, audit trails, and documents remain available for compliance, investigation, and FOIA requests indefinitely.

### Immutability Controls

| Control | GCP | Scope |
|---------|-----|-------|
| WORM Retention | GCS retention policy (locked) | Audit + document storage |
| Soft-Delete | 90-day GCS soft-delete | All storage |
| Object Versioning | GCS versioning | All storage |
| Audit Log No-Expiration | BigQuery (no expiration) | Audit datasets |
| Terraform `prevent_destroy` | Lifecycle rule on buckets + KMS | All stateful resources |
| Force-destroy protection | `force_destroy = false` | All storage |

<!-- MULTI-CLOUD: Original table included AWS (S3 Object Lock, S3 versioning + MFA delete, etc.) and Azure (Blob immutability policy, Blob soft-delete, etc.) columns. -->

### Storage Tiering (Cost Optimization Without Deletion)

Old data tiers down for cost savings but is **never deleted**:

| Age | Storage Class | Cost Reduction |
|-----|--------------|----------------|
| 0–90 days | STANDARD | Baseline |
| 90–365 days | NEARLINE | ~50% |
| 365+ days | COLDLINE | ~75% |

### Data Access Audit Logging

DATA_READ and DATA_WRITE audit logs are enabled for all critical services (NIST AU-3/AU-12, CJIS 5.4):

| Capability | GCP |
|-----------|-----|
| Database access logging | Cloud SQL audit logs |
| Storage access logging | GCS data access logs |
| Container access logging | Cloud Run audit logs |
| KMS access logging | Cloud KMS audit logs |
| IAM change logging | IAM audit logs |
| API call logging | Cloud Audit Logs |

<!-- MULTI-CLOUD: Original table included AWS (RDS audit logs, S3 access logs + CloudTrail, ECS + CloudTrail, KMS + CloudTrail, CloudTrail, CloudTrail) and Azure (PostgreSQL audit logs, Blob Storage diagnostic logs, Container Apps audit logs, Key Vault diagnostic logs, Activity Log, Activity Log) columns. -->

These logs capture who accessed which data and when, providing the forensic trail required for incident investigation and compliance audits.

### Document Retention Policy

| Environment | Retention Period | Locked |
|-------------|-----------------|--------|
| Staging | 1 year (365 days) | No (for testing flexibility) |
| Production | 2 years (730 days) | Yes (irreversible) |

Retention policies prevent object deletion before the minimum period expires. Production retention is **locked** — it cannot be shortened or removed, even by project owners.

---

## 14. Supply Chain Security

### Software Bill of Materials (SBOM)

SBOMs are generated automatically in CI/CD for every component:

| Component | Tool | Format | Trigger |
|-----------|------|--------|--------|
| Backend (Go modules) | Syft + anchore/sbom-action | CycloneDX JSON + SPDX JSON | Every push to main + weekly |
| Backend container image | anchore/sbom-action | SPDX JSON | Every container build |
| Admin SPA (npm) | anchore/sbom-action | SPDX JSON | Every push to main |
| App SPA (npm) | anchore/sbom-action | SPDX JSON | Every push to main |

SBOM artifacts are retained for 90 days and attached to each workflow run.

### Static Analysis & Vulnerability Scanning

| Scanner | What It Checks | Trigger |
|---------|---------------|--------|
| GoSec | Go SAST (OWASP patterns) | PRs + weekly |
| govulncheck | Go dependency CVEs (Go advisory DB) | PRs + every deploy |
| Semgrep | SAST + secrets + OWASP Top 10 (Go rulesets) | PRs + weekly |
| Trivy (filesystem) | Dependency CVEs in source tree | PRs + weekly |
| Trivy (container) | OS + app CVEs in built image (hard fail gate: CRITICAL/HIGH block deploy) | Every container build |
| npm audit | npm dependency CVEs (high/critical) | Every SPA build |
| Gitleaks | Secret scanning across git history | PRs + push to main + weekly |

Critical findings on the main branch trigger a notification job. SARIF results are uploaded to GitHub Code Scanning for centralized triage.

### Container Hardening

- **Distroless base image**: `gcr.io/distroless/base-debian12` — no shell, no package manager; includes glibc for BoringSSL dynamic linkage. Same image used across all clouds.
- **FIPS 140-2 Go binary**: `CGO_ENABLED=1` with BoringCrypto (`GOEXPERIMENT=boringcrypto`) for FIPS 140-2 validated cryptography (BoringSSL cert #4407)
- **nginx-unprivileged**: SPA containers run as non-root with read-only filesystem
- **Pinned dependencies**: `go.sum`, `pnpm-lock.yaml`, `.terraform.lock.hcl` for reproducible builds
- **Pinned CI/CD builder images**: All Cloud Build builder images (cloud-sdk, kaniko, trivy, syft, gitleaks, atlas) pinned by version substitution variable — no `:latest` tags
- **Immutable tags**: Container registry repositories have immutable tags enabled (`immutable_tags = true` on Artifact Registry), preventing tag overwrites (tag-squatting attacks)

### Image Signing & Verification (Cosign)

All container images are cryptographically signed using **Cosign keyless signing** (Sigstore OIDC):

| Step | Action | Enforcement |
|------|--------|------------|
| Build | Image pushed to container registry with SHA commit tag | CI/CD |
| Sign | `cosign sign --yes` with Sigstore OIDC identity (GitHub Actions OIDC token) | Automated in build job |
| Verify | `cosign verify` checks certificate identity (`github.com/latentarchon/*`) and OIDC issuer (`token.actions.githubusercontent.com`) | Required before every deploy |
| Deploy | Container deploy uses `image@sha256:digest` (digest-pinned, not tag-based) | CI/CD |

This ensures:
- **Provenance**: Every deployed image is cryptographically tied to a specific GitHub Actions workflow run
- **Tamper detection**: Any image modification after signing invalidates the signature
- **No tag mutability risk**: Digest pinning + immutable tags prevent tag-squatting attacks
- **Supply chain attestation**: Sigstore transparency log provides a public, append-only record of all signing events

### Binary Authorization Enforcement

Cloud Run enforces a Binary Authorization policy that **rejects images without a valid attestation**:

| Control | Detail |
|---------|--------|
| Attestor | Cloud Build attestor with KMS-backed signing key |
| Policy | `ALWAYS_DENY` default; only images signed by the Cloud Build attestor are admitted |
| Break-Glass | Annotation-based override for emergency deploys — triggers CRITICAL monitoring alert |
| Monitoring | Admission denials and break-glass overrides both fire alert policies routed to notification channels |

This provides a second layer of supply chain enforcement beyond Cosign — even if a malicious image is pushed to Artifact Registry, it cannot be deployed without a valid attestation from the authorized Cloud Build pipeline.

### CI/CD Security

- **Keyless authentication**: Workload Identity Federation (GCP WIF) — zero stored secrets
- **Org policy enforcement**: GCP org policies block static credential creation

<!-- MULTI-CLOUD: Original included AWS OIDC, Azure Workload Identity, and cross-cloud org policy enforcement. -->
- **OIDC provider lock**: Federation providers locked to `latentarchon` GitHub org via attribute condition
- **Production gates**: All app repos require manual approval for production deployment
- **Terraform safety**: Plans posted as PR comments, never auto-applied
- **Digest-pinned deploys**: Container services deployed by image digest (`@sha256:...`), not by mutable tag

---

## 15. Security Headers

### SPA (nginx)

Both admin and app SPAs enforce comprehensive security headers:

| Header | Value |
|--------|-------|
| Content-Security-Policy | Strict allowlist: `default-src 'self'`, no `unsafe-eval`, scoped `connect-src` to `*.latentarchon.com` + Firebase/reCAPTCHA domains |
| Strict-Transport-Security | `max-age=63072000; includeSubDomains; preload` (2-year HSTS) |
| Cross-Origin-Opener-Policy | `same-origin-allow-popups` (required for Firebase Auth popups) |
| Cross-Origin-Resource-Policy | `same-origin` |
| Cross-Origin-Embedder-Policy | `credentialless` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |

### API (Go backend)

The backend applies an even stricter policy to all API responses:

- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- `Cache-Control: no-store` (prevents caching of authenticated responses)
- All headers from the SPA table above, plus `Cross-Origin-Opener-Policy: same-origin` (stricter than SPA)

---

## 16. Disaster Recovery & Business Continuity

### Recovery Objectives

| Metric | Target | Mechanism |
|--------|--------|-----------|
| **RPO** (Recovery Point Objective) | < 5 minutes | PostgreSQL continuous backup + point-in-time recovery |
| **RTO** (Recovery Time Objective) | < 1 hour | Container auto-scaling + infrastructure-as-code |

### Backup Strategy

| Component | Backup Method | Retention |
|-----------|--------------|----------|
| PostgreSQL | Automated daily backups + continuous WAL archiving (PITR) | 30 days |
| Object Storage (Documents) | Versioning + WORM retention policy + soft-delete | Indefinite (never auto-deleted) |
| Vector Search Index | Reconstructible from source chunks | N/A (rebuildable) |
| Audit Logs | CMEK-encrypted long-term storage, no expiration | Indefinite (never auto-deleted) |
| WORM Audit Storage | Immutable retention-locked storage + versioning | 2 years production (locked), 1 year staging |
| Migration Job Logs | Encrypted storage with tiering | Indefinite (never auto-deleted) |
| Infrastructure Config | Git (Terragrunt/Terraform IaC) | Indefinite |

### High Availability

| Capability | GCP |
|-----------|-----|
| Container HA | Cloud Run multi-zone (0–N) |
| Database HA | Cloud SQL Regional HA (auto failover) |
| Load Balancer | Global anycast + health checks |
| Object Storage | Multi-region class available |

<!-- MULTI-CLOUD: Original table included AWS (ECS Fargate multi-AZ, RDS Multi-AZ, ALB multi-AZ, Cross-region replication) and Azure (Container Apps zone-redundant, Flexible Server zone-redundant, Front Door global, GRS/RA-GRS) columns. -->

### Infrastructure as Code

All infrastructure is defined in Terragrunt/Terraform with:
- Full state stored in GCS backend with versioning and locking
- CI/CD pipeline validates plans on every PR (never auto-applies)
- Production deployments require manual approval gates
- Drift detection on main branch pushes

### Incident Response Integration

- Cloud Armor provides DDoS protection and OWASP rule enforcement
- Rate limiting at both IP and per-user levels prevents abuse
- Graceful shutdown with in-flight request completion (30-second drain)
- Kill-on-breach capability in red team tooling for immediate containment

---

## 17. Organization Governance

### Cloud Resource Hierarchy

The platform uses an isolated **three-environment architecture** on each cloud, providing hard IAM boundaries, separate billing, independent audit trails, data-plane compartmentalization, and blast-radius containment:

| Concept | GCP |
|---------|-----|
| **Top-level** | Organization |
| **Environment boundary** | Project |
| **App environment** | `archon-fed-app-*` |
| **Ops environment** | `archon-fed-ops-*` |
| **Admin environment** | `archon-fed-admin-*` |
| **Network isolation** | VPC per project |
| **KMS isolation** | KMS keyring in ops project |
| **Centralized logging** | Org-level log sink → central project |

<!-- MULTI-CLOUD: Original table included AWS (AWS Organizations, Account, VPC per account, KMS per account, CloudTrail org trail → S3) and Azure (Azure AD Tenant, Subscription, VNet per subscription, Key Vault per subscription, Activity Log → central Log Analytics) columns. -->

### Organization-Level Security Policies

Preventive guardrails are enforced at the GCP organization level:

| Security Objective | GCP Org Policy |
|---|---|
| Block public storage | `storage.publicAccessPrevention` |
| Block static credentials | `iam.disableServiceAccountKeyCreation` |
| Enforce encryption | `gcp.restrictNonCmekServices` |
| Restrict public endpoints | `sql.restrictPublicIp`, `run.allowedIngress` |
| Enforce network isolation | `compute.skipDefaultNetworkCreation` |
| Restrict egress | FQDN-based firewall policy |

GCP enforces 15+ org policies. All are defined in Terraform.

<!-- MULTI-CLOUD: Original table included AWS SCP (s3:PutBucketPolicy deny, iam:CreateAccessKey deny, etc.) and Azure Policy (Deny public blob access, Deny password-based auth, etc.) columns. AWS uses SCPs and Azure uses Azure Policy assignments. -->

### CMEK Enforcement

Customer-Managed Encryption Keys (CMEK) are enforced:

- **GCP**: Autokey with dedicated KMS projects; `gcp.restrictNonCmekServices` blocks Google-managed keys

<!-- MULTI-CLOUD: Original also included:
- AWS: KMS CMKs required for S3, RDS, and ECS; S3 bucket policies deny unencrypted uploads
- Azure: Key Vault Premium (HSM-backed) keys required for all storage and database encryption -->

All keys are HSM-backed with automatic rotation and lifecycle event alerting.

### Centralized Network Governance

| Capability | GCP |
|-----------|-----|
| Network isolation | Shared VPC (host + service projects) |
| Flow logging | VPC Flow Logs (50% sampling) |
| Egress control | FQDN-based firewall policy |
| Cross-env access | Shared VPC service project attachment |

<!-- MULTI-CLOUD: Original table included AWS (VPC per account with VPC endpoints, VPC Flow Logs, VPC endpoints + NAT, Cross-account IAM assume-role) and Azure (VNet per subscription with private endpoints, NSG Flow Logs, Private endpoints + NAT, Cross-subscription managed identity) columns. -->

### Centralized Logging & Monitoring

- Organization-level log sinks capture all admin activity, data access, and system events across all environments
- Logs routed to centralized storage with CMEK encryption
- Unified monitoring dashboards and cross-environment alerting
- All managed via Terraform

### IAM Groups

IAM is managed via Google Workspace identity groups for role-based access. All groups are managed via Terraform.

<!-- MULTI-CLOUD: Original also referenced AWS IAM Identity Center groups and Azure AD groups. -->

---

## 18. Network Security

### VPC / VNet Architecture

| Capability | GCP |
|-----------|-----|
| Network type | Custom VPC (no default subnets) |
| Routing | Regional |
| Private API access | Private Google Access |
| Private AI access | Private Service Connect (PSC) |

<!-- MULTI-CLOUD: Original table included AWS (VPC no default, Regional multi-AZ, VPC Endpoints, VPC Endpoint Bedrock/OpenSearch) and Azure (VNet no default, Regional multi-zone, Private Endpoints, Private Endpoint OpenAI/AI Search) columns. -->

### Egress Firewall (Zero Trust Network)

All clouds implement deny-by-default egress with explicit allowlists:

| Priority | Rule | GCP |
|----------|------|-----|
| 1 | Cloud APIs | FQDN firewall → `*.googleapis.com` |
| 2 | Microsoft Graph | FQDN → `graph.microsoft.com`, `login.microsoftonline.com` |
| 3 | Internal APIs | FQDN → `*.latentarchon.com` |
| Default | DENY ALL | `0.0.0.0/0` blocked |

<!-- MULTI-CLOUD: Original table included AWS (VPC Endpoints, Security group → Microsoft FQDNs, Security group → ALB, Default SG deny) and Azure (Private Endpoints, NSG → Microsoft FQDNs, NSG → Front Door, Default NSG deny) columns. -->

**The platform cannot exfiltrate data to arbitrary external endpoints.** Only explicitly allowlisted cloud APIs, Microsoft Graph API (for SharePoint/OneDrive document sync), and internal services are reachable. Microsoft Graph API egress is only enabled when the Graph integration is configured.

### Ingress Controls

- **Database**: Only accessible from container runtime services via private network (no public endpoints)
- **Task queue**: Cloud-native service integration (no public dispatch endpoints)
- **Internal network**: East-west communication within VPC/VNet subnets only
- **No public SSH/RDP** — VMs (if any) require IAP tunneling

### NAT / Egress Gateway

| Capability | GCP |
|-----------|-----|
| NAT type | Cloud NAT |
| Container egress | Direct VPC egress (private subnet IPs) |
| Logging | Cloud NAT logging |

<!-- MULTI-CLOUD: Original table included AWS (NAT Gateway per-AZ, Private subnets via NAT, NAT Gateway flow logs) and Azure (NAT Gateway, VNet-integrated via NAT, NAT Gateway metrics) columns. -->

---

## 19. Web Application Firewall

Cloud Armor WAF is deployed in front of all load-balanced services:

### OWASP Top 10 Protection

| Rule | Priority | Protection |
|------|----------|------------|
| XSS (v33-stable) | 300 | Cross-Site Scripting |
| SQLi (v33-stable) | 301 | SQL Injection |
| LFI (v33-stable) | 302 | Local File Inclusion |
| RFI (v33-stable) | 303 | Remote File Inclusion |
| RCE (v33-stable) | 304 | Remote Code Execution |
| Protocol Attack (v33-stable) | 305 | HTTP Request Smuggling, Response Splitting |
| Session Fixation (v33-stable) | 306 | Session Fixation |
| Scanner Detection (v33-stable) | 307 | Automated Vulnerability Scanners |
| JSON SQLi (canary) | 308 | JSON-based SQL Injection (Connect-RPC payloads) |

### Adaptive / Intelligent Protection

ML-based L7 DDoS detection is enabled on all WAF policies:
- **GCP**: Cloud Armor Adaptive Protection

<!-- MULTI-CLOUD: Original also included:
- AWS: WAFv2 intelligent threat mitigation + Shield Advanced
- Azure: Front Door WAF bot protection + DDoS Protection -->

Adaptive protection uses machine learning to detect and alert on anomalous traffic patterns that may indicate application-layer DDoS attacks, automatically generating suggested rules for mitigation.

### Tiered Rate Limiting

| Tier | Path Pattern | Limit | Ban Duration | Purpose |
|------|-------------|-------|-------------|--------|
| SCIM provisioning | `/scim/v2/*` | 30 req/60s | 10 min | IdP provisioning is low-volume |
| Auth endpoints | `/api/auth/*` | 20 req/60s | 10 min | Brute force / credential stuffing prevention |
| Login / magic link | `/api/auth/login`, `/api/auth/magic-link`, `/api/auth/verify-otp` | 10 req/60s | 15 min | Account takeover prevention |
| Global | All paths | 100 req/60s | 5 min | General abuse prevention |

All rate limits use `rate_based_ban` with automatic IP banning on exceedance.

### Geographic Restriction (OFAC Compliance)

Traffic from OFAC-embargoed countries is blocked at the WAF layer when geo-restriction is enabled:

- **Denied regions**: Cuba (CU), Iran (IR), North Korea (KP), Syria (SY), Russia (RU)
- GCP: Cloud Armor CEL expression matching `origin.region_code`
- Configurable per-policy via Terraform variables

<!-- MULTI-CLOUD: Original also included AWS WAFv2 geographic match statement and Azure Front Door geo-filtering rule. -->

### Additional WAF Controls

- **HTTP Method Enforcement**: Only GET, POST, OPTIONS allowed; TRACE, DELETE, PATCH blocked at WAF
- **Origin Header Restriction**: Requests with disallowed `Origin` headers denied
- **Bot Blocking**: Empty/missing `User-Agent` denied; known scanner/attack tools (curl, wget, sqlmap, nikto, nmap, nuclei, etc.) blocked
- **IP Allowlisting**: Configurable for government/VPN IP ranges (plus per-org self-service allowlisting)

---

## 20. Frontend Security

### Authentication Flow

Both SPAs implement authentication models appropriate to the cloud deployment:

**GCP (magic link + MFA)**:
```
User enters email → Magic link sent via Firebase → User clicks link →
  ├── If MFA enrolled: TOTP challenge → Authenticated
  └── If MFA not enrolled: Forced TOTP enrollment (QR scan) → Verified → Authenticated
```

<!-- MULTI-CLOUD: Original also included AWS/Azure SSO/SAML-only auth flow:
User clicks "Sign In" → Redirect to organization IdP (Okta, Entra ID, etc.) →
  IdP authenticates (MFA delegated to IdP) → SAML assertion → Authenticated -->

The `AuthGate` component enforces a strict state machine — the application does not render protected routes until authentication and MFA is complete and verified.

### Content Security Policy

The CSP is tightly scoped:

- **`default-src 'self'`** — Block all resources not explicitly allowed
- **`script-src 'self'`** — Only same-origin scripts (no CDN, no inline, no `eval()`)
- **`connect-src`** — Explicitly allowlisted Firebase Auth, Identity Toolkit, and Secure Token endpoints
- **`frame-src https://accounts.google.com`** — Only Google OAuth popups allowed
- **`object-src 'none'`** — No plugins
- **`frame-ancestors 'none'`** — Cannot be embedded in any frame
- **`upgrade-insecure-requests`** — Force HTTPS for all subresources

### Container Security

- **Non-root execution**: `nginxinc/nginx-unprivileged` runs as UID 101
- **Alpine Linux**: Minimal base image (~5 MB)
- **Multi-stage build**: Build tools and source code not present in production image
- **No install scripts**: `npm ci --ignore-scripts` prevents supply chain attacks via lifecycle scripts

### Dependency Posture

All production dependencies use permissive open-source licenses (MIT, Apache 2.0, ISC) compatible with government procurement. Key dependencies include React 19, Firebase Auth 11, Connect-RPC (buf.build), and TailwindCSS — all actively maintained with strong security track records.

---

## Appendix A: CORS Governance

CORS is enforced via a config-driven origin allowlist derived from deployment environment:

- **Production**: Exact-match origins for `app.latentarchon.com`, `admin.latentarchon.com`, `api.latentarchon.com`
- **Staging**: Exact-match + tight suffix patterns (`*.app.staging.latentarchon.com`, `*.admin.staging.latentarchon.com`) — only one label depth allowed (no deep nesting)
- **Development**: Localhost origins (`http://localhost:3000`, `:3001`, `:5173`, `:8080`) added only when `ENVIRONMENT=development`
- **Domain cross-validation**: Config validates that `APP_DOMAIN`, `ADMIN_DOMAIN`, `API_DOMAIN` suffixes match the `ENVIRONMENT` setting — prevents env mismatch
- Disallowed origins receive no CORS headers (no `Access-Control-Allow-Origin`, no credentials)

CORS is tested with unit tests and e2e tests covering allowed origins, blocked origins, subdomain patterns, and deep-nesting attacks.

---

## Appendix B: FedRAMP Authorization (GCP) — IL5 Assured Workloads

Latent Archon is deployed on GCP within **IL5 Assured Workloads** folders. Data-plane services run in IL5-approved GCP services. Services not yet IL5-approved operate in dedicated FedRAMP High Assured Workloads projects outside the IL5 boundary:

| Capability | GCP Service | Compliance Boundary |
|-----------|------------|---------------------|
| Container compute | Cloud Run | IL5 |
| Database | Cloud SQL (PostgreSQL) | IL5 |
| Object storage | Cloud Storage | IL5 |
| Load balancer | Cloud Load Balancing | IL5 |
| WAF / DDoS | Cloud Armor | IL5 |
| KMS | Cloud KMS | IL5 |
| Logging / monitoring | Cloud Logging + Monitoring | IL5 |
| LLM | Vertex AI (Gemini) | IL5 |
| Vector search | Vertex AI Vector Search | IL5 |
| Container registry | Artifact Registry | IL5 |
| Task queue | Cloud Tasks | IL5 |
| DLP / PII | Cloud DLP | IL5 |
| Pub/Sub (push subs) | Cloud Pub/Sub | IL5 (subscriptions in ops project) |
| Identity | Identity Platform | FedRAMP High (auth projects) |
| Cron scheduling | Cloud Scheduler | FedRAMP High (mgmt project) |
| TLS certificates | Certificate Manager | FedRAMP High |

<!-- MULTI-CLOUD: Original table included AWS Service (ECS Fargate, RDS PostgreSQL, S3, ALB, WAFv2, AWS KMS, CloudWatch, IAM SAML, Bedrock Claude, Textract, ECR, SQS, ACM, Comprehend) and Azure Service (Container Apps, PostgreSQL Flexible Server, Blob Storage, Front Door, Front Door WAF, Key Vault, Azure Monitor, Azure AD, Azure OpenAI GPT-4o, Document Intelligence, Container Registry, Service Bus, Front Door managed, AI Language) columns. -->

The IL5 Assured Workloads folder enforces org policies at the GCP organizational layer: data residency (US-only regions), service restrictions (only IL5-approved services may be enabled), US-person personnel controls for GCP support, and CMEK encryption requirements. By deploying on IL5-authorized infrastructure, Latent Archon inherits a substantial portion of NIST 800-53 and NIST 800-171 controls at the physical, environmental, and platform layers.

---

## Appendix C: Red Team Validation

Latent Archon maintains an internal red team program with 99 automated attacks across 6 suites:

| Suite | Attacks | Coverage |
|-------|---------|----------|
| Auth Bypass | 17 attacks | No auth, forged JWT, wrong audience, MFA bypass, TOTP replay, alg:none, session fixation, CORS bypass, HTTP method override |
| Privilege Escalation | 12 attacks | Database, object storage, task queue, KMS, admin API, IAM escalation, identity impersonation |
| Data Exfiltration | 15 attacks | SQL injection, IDOR, prompt injection, vector store access, path traversal, UUID enumeration |
| Left-Field & Cloud-Native | 15 attacks | SSRF, timing side-channel, embedding inversion, prompt cache poisoning, DNS rebinding, Cloud Tasks queue poisoning, TOCTOU race, JWT key confusion (JKU), streaming resource exhaustion, GCS compose, KMS key version confusion, Firebase email enumeration, org invite typosquatting, WAF bypass |
| OWASP Web Application | 28 attacks | SQLi (workspace/search/document/chat), XSS (stored + reflected), XXE (document upload, billion laughs), SSRF (document import, Graph sync, profile image → GCE metadata), command injection, IDOR, role escalation, debug endpoint probes, default credentials, malformed protobuf, file upload bypass (size/type/path traversal), business logic abuse (negative quantity, mass assignment) |
| External Tool Assessment | 12 attacks | nmap service scan, nikto web scan, nuclei vulnerability + CVE scan, ffuf directory/API/parameter fuzzing, sqlmap SQL injection probes, SSL cipher audit, security header audit |

Red team attack suites are organized under `attacks/gcp/` with a shared cloud-agnostic framework.

<!-- MULTI-CLOUD: Original also referenced attacks/aws/ and attacks/azure/ directories. -->

All attacks include MITRE ATT&CK technique mapping and NIST 800-53 control correlation. The external tool assessment suite shells out to industry-standard penetration testing tools (nuclei, nikto, sqlmap, ffuf, nmap) and captures their output as structured log entries. Results are published as structured Markdown reports with executive summaries and remediation recommendations.

---

*This document is maintained alongside the codebase and updated with each security-relevant release.*
