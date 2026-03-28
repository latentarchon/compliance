# Latent Archon — Security Architecture Whitepaper

> **Classification**: Company Confidential — Approved for Government Prospect Distribution  
> **Version**: 1.0  
> **Date**: March 2026  
> **Contact**: ajhendel@latentarchon.com

---

## Executive Summary

Latent Archon is a multi-tenant document intelligence platform purpose-built for government agencies handling Controlled Unclassified Information (CUI). The platform enables Retrieval-Augmented Generation (RAG) chat over uploaded documents with workspace-level data isolation, operating entirely on Google Cloud Platform (GCP) FedRAMP-authorized infrastructure.

This whitepaper describes the platform's security architecture across authentication, data isolation, data flow, encryption, logging, disaster recovery, infrastructure governance, and network security.

---

## 1. Authentication & Identity

### Multi-Pool Auth Isolation

Authentication is split across two GCP projects with independent Firebase Auth / Identity Platform pools:

| Pool | Project | Users | Domain |
|------|---------|-------|--------|
| Chat (End Users) | `latentarchon-chat-prod` | Agency analysts, viewers | `app.latentarchon.com` |
| Admin (Org Admins) | `latentarchon-admin-prod` | Org administrators, workspace managers | `admin.latentarchon.com` |

This two-project split provides **complete auth pool isolation** — a valid chat-pool JWT cannot authenticate against the admin API, and vice versa. Credential compromise in one pool cannot escalate to the other.

### Cross-Pool Identity Prohibition

Because Firebase UIDs are project-scoped, the same person has different UIDs in the admin and chat pools. **Cross-pool identity bridging is explicitly prohibited** — the system never copies memberships between pools by matching on email. This would create a lateral escalation path (compromise one pool → gain the other pool's permissions).

Instead, workspace access across pools uses the **explicit invite flow**:

1. Admin creates workspace → admin UID stored in `workspace_members` (admin app)
2. System auto-creates a pending invite for the creator's email
3. Creator receives email with sign-in link to the chat app
4. Creator authenticates in the chat app → chat UID
5. Creator accepts invite → chat UID stored in `workspace_members` (chat app)

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

| Role | Cloud Run Service | Auth | Permissions |
|------|-------------------|------|-------------|
| `archon_chat_ro` | Chat API | Cloud SQL IAM (keyless) | SELECT on reference tables; SELECT + INSERT on messages/searches/generations; INSERT on audit_events; SELECT + INSERT + UPDATE on users (profile upsert) |
| `archon_admin_rw` | Admin API | Cloud SQL IAM (keyless) | ALL on all tables and sequences |
| `archon_ops_rw` | Ops service | Cloud SQL IAM (keyless) | SELECT/INSERT/UPDATE on documents, versions, DLQ; full CRUD on chunks; INSERT on audit_events + generations; SELECT on reference tables |
| `postgres` (migration only) | Atlas job (Cloud Run Job) | Password (Secret Manager) | Superuser — DDL privileges for schema migrations only. Not accessible to any runtime service. |

The chat role **cannot** create, modify, or delete organizations, workspaces, documents, or members. Even if the chat service is fully compromised, the attacker cannot ALTER tables, CREATE functions/triggers (no backdoor), or DELETE any data. Roles are granted to IAM service accounts dynamically by naming convention, ensuring environment-agnostic enforcement. Enforced via migration `20260328120000_enforce_least_privilege_db_roles.sql`.

### Vector Store Isolation

Vertex AI Vector Search results are scoped to authorized workspace IDs via token restrictions. Each stored embedding carries `workspace_id` and `document_id` namespace restrictions, preventing cross-workspace data leakage at the vector database level.

---

## 3. Data Flow

### Request Path

```
Client (SPA)
  → Cloud Armor (WAF + OWASP CRS)
  → Global Load Balancer (TLS termination, DDoS protection)
  → Cloud Run (serverless container)
    → CORS Middleware
    → Security Headers Middleware
    → IP Rate Limiter (pre-auth)
    → Connect-RPC Interceptor Chain:
      1. Recovery (panic → CodeInternal, never leaks stack traces)
      2. Trace (OpenTelemetry span injection)
      3. Auth:
         a. Token verify (Firebase JWT)
         b. IDP pool isolation (header + Host subdomain vs token pool)
         c. MFA enforcement (TOTP required, step-up for sensitive RPCs)
         d. Session timeouts (idle 30 min, absolute 12 hr)
         e. JIT provisioning (federated users)
         f. Org membership gate (reject orgless users)
         g. Subdomain→org DB validation (reject unknown/mismatched orgs)
      4. Per-User Rate Limiter
      5. Logging Interceptor
    → Handler (authorization check, business logic)
    → RLS-scoped Database Query (Cloud SQL, private VPC)
```

### Document Ingestion Pipeline

```
Upload → Size Check (50 MB) → Type Allowlist → Magic-Byte Validation
  → ClamAV Malware Scan → SHA-256 Dedup → GCS Upload (workspace-scoped path)
  → DB Insert → Cloud Tasks Queue → Document AI OCR
  → Chunking (800-token segments) → Embedding (Vertex AI)
  → Vector Search Index (workspace-scoped)
```

### RAG Chat Flow

```
User Message → Workspace Access Verification → Query Embedding
  → Vector Search (workspace-filtered) → Chunk Hydration (from Cloud SQL)
  → Prompt Construction (server-controlled system prompt + context + history)
  → Gemini Streaming Response → SSE to Client
  → Async: Message Persistence + Audit Event
```

### Cross-Project Data Flow

Only one narrow IAM grant crosses the project boundary:
- `roles/cloudsql.client` + `roles/cloudsql.instanceUser` for the chat SA on the admin project
- This enables chat API read access to documents and workspace data from Cloud SQL
- All other services are project-isolated

---

## 4. Encryption

### Data at Rest

| Layer | Mechanism | Key Management |
|-------|-----------|---------------|
| Cloud SQL (PostgreSQL) | AES-256 | Google-managed + optional CMEK via Cloud KMS |
| Cloud Storage (GCS) | AES-256 | Google-managed + optional CMEK via Cloud KMS |
| Vertex AI Vector Search | AES-256 | Google-managed |
| Audit Logs | AES-256 | Google-managed |

Cloud KMS is provisioned in the infrastructure for customer-managed encryption key (CMEK) support. Key rotation is automated.

### Data in Transit

| Path | Protocol | Certificate |
|------|----------|------------|
| Client → Load Balancer | TLS 1.2+ | Certificate Manager with DNS authorization |
| Load Balancer → Cloud Run | TLS 1.2+ (mTLS capable) | Google-managed |
| Cloud Run → Cloud SQL | TLS via Cloud SQL Connector | IAM-authenticated, private VPC |
| Cloud Run → Vertex AI | TLS 1.2+ via PSC | Private Service Connect (no public internet) |
| Cloud Run → GCS | TLS 1.2+ | Google-managed |
| Cloud Run → Document AI | TLS 1.2+ | Regional, Google-managed |

HSTS is enforced with `max-age=63072000; includeSubDomains; preload` (2-year pinning).

### Secrets Management

- **Zero secrets in container images**: All configuration via environment variables at runtime
- **No static database passwords**: Cloud SQL IAM authentication only
- **No service account keys**: Workload Identity Federation (WIF) with OIDC for CI/CD
- **Org policy enforcement**: `iam.disableServiceAccountKeyCreation` blocks SA key creation org-wide

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

### Audited Operations

- **Auth**: login, login_failed, mfa_challenge, session_timeout
- **Organization**: create, invite_member, remove_member, reset_member_mfa
- **Workspace**: create, invite_member, remove_member
- **Document**: upload, delete, metadata_update
- **Admin**: bootstrap, role_escalation
- **SCIM**: user_create, user_replace, user_patch, user_deactivate, group_member_add, group_member_remove

### SIEM Integration

- All audit events emit structured JSON logs to Cloud Logging
- Security-critical events (failures, auth, member changes, deletions) logged at WARN level
- OpenTelemetry trace correlation (trace_id, span_id) for end-to-end request tracing
- **Pub/Sub SIEM Export Pipeline**: Per-customer Pub/Sub topic + subscription for agency SIEM integration (Splunk, Sentinel, Chronicle). Supports both pull (gRPC) and push (webhook) delivery. Agency service accounts granted subscriber IAM access. Enabled per-customer via `enable_siem_export` Terraform variable.
- BigQuery audit log sink for long-term analytics and compliance reporting

### Observability

- **Distributed Tracing**: OpenTelemetry with OTLP/gRPC export to Cloud Trace
- **Structured Logging**: Go `slog` with JSON output for Cloud Logging
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

A **Cloud Scheduler-triggered daily job** permanently deletes all data for accounts closed more than 90 days ago. This includes user records, org memberships, workspace memberships, documents, chat messages, and audit events. The purge is irreversible and fully logged.

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
- Previous versions are retained in GCS with workspace-scoped paths
- Version metadata (uploader, timestamp, size, content hash) is stored in the database
- Versions are immutable once created — no in-place modification

---

## 9. Multimodal AI (Image Generation)

The chat API supports **inline image generation** within streaming conversations:

| Step | Detail |
|------|--------|
| Model | Gemini 2.0 Flash with ResponseModalities image output via Vertex AI |
| Streaming | Images generated inline during server-streaming chat responses |
| Storage | Generated images uploaded to GCS with workspace-scoped paths |
| Proxy | Images served via authenticated proxy endpoint — no direct GCS URLs exposed |
| Rate Limiting | Max 4 images per response, 10 MB total image payload per response |
| Audit | Image generation events logged with image count, total bytes, and correlation ID |

All generated images inherit the workspace scope of the conversation and are never directly accessible via GCS URLs.

---

## 10. Data Export (FOIA Compliance)

A dedicated **Export Service** supports bulk data export for FOIA requests, government record-keeping requirements, and data portability obligations:

| Capability | Detail |
|-----------|--------|
| Scope | Organization-level or workspace-level data export |
| Data Included | Documents (originals + metadata), chat messages, audit events, user records, workspace configurations |
| Format | Structured export package with manifest and chain-of-custody metadata |
| Access Control | Export restricted to organization `master_admin` role with step-up MFA |
| Audit Trail | Every export request is audit-logged with requestor ID, scope, and completion status |
| Processing | Large exports processed via Cloud Tasks with progress tracking |

Export manifests include chain-of-custody metadata (who exported, when, what scope) to satisfy federal record-keeping requirements.

---

## 11. Usage Analytics & Cost Attribution

The platform includes an **Analytics Service** providing per-organization usage metrics and cost attribution:

| Capability | Detail |
|-----------|--------|
| Usage Metrics | Chat messages, document uploads, vector searches, and API calls tracked per org and workspace |
| Cost Attribution | Vertex AI, Document AI, Cloud Storage, and compute costs attributed to org/workspace |
| Dashboard | Admin-facing usage dashboard with time-series charts and per-workspace breakdowns |
| Access Control | Analytics endpoints restricted to organization admin role; data org-scoped |
| Export | Analytics data exportable as CSV/JSON for agency reporting systems |

---

## 12. Operational Resilience

### Dead Letter Queue (DLQ) Management

Documents that fail processing after Cloud Tasks retry exhaustion are captured in a **Dead Letter Queue**:

- Admin endpoint lists all DLQ items with failure reason, attempt count, and timestamps
- Admin endpoint requeues individual or batch DLQ items for reprocessing
- DLQ endpoints restricted to ops service with OIDC authentication
- DLQ depth integrated with Cloud Monitoring for threshold-based alerting

### Deep Readiness Probes (`/readyz`)

Beyond basic liveness checks (`/health`), the platform implements **mode-aware deep readiness probes**:

| Dependency | Check | Mode-Aware |
|-----------|-------|-----------|
| Cloud SQL | Connection pool ping with timeout | All modes |
| Vector Store (Vertex AI) | Index endpoint reachability | public + ops |
| Document Service (GCS) | Bucket accessibility verification | admin + ops |
| Cloud Tasks | Queue accessibility check | admin + ops |
| GenText (Gemini) | Model endpoint reachability | public |

Readiness checks are scoped to the server mode to prevent cascading failures across unrelated service boundaries.

### Per-Organization Cloud Armor IP Allowlisting

Organization administrators can configure **self-service IP allowlists** via the admin API:

- CIDR-based IP allowlists stored in organization settings (JSONB)
- Allowlists synced to Cloud Armor WAF rules via the Cloud Armor API
- CEL expressions match org hostname (`request.headers['host'].startsWith('<slug>.')`) + IP range for per-org enforcement
- Sync failure is non-fatal (logged + audit event; database is source of truth)
- Periodic reconciliation cron catches Cloud Armor drift

---

## 13. Supply Chain Security

### Software Bill of Materials (SBOM)

SBOMs are generated automatically in CI/CD for every component:

| Component | Tool | Format | Trigger |
|-----------|------|--------|--------|
| Backend (Go modules) | Syft + anchore/sbom-action | CycloneDX JSON + SPDX JSON | Every push to main + weekly |
| Backend container image | anchore/sbom-action | SPDX JSON | Every container build |
| Admin SPA (npm) | anchore/sbom-action | SPDX JSON | Every push to main |
| Chat SPA (npm) | anchore/sbom-action | SPDX JSON | Every push to main |

SBOM artifacts are retained for 90 days and attached to each workflow run.

### Static Analysis & Vulnerability Scanning

| Scanner | What It Checks | Trigger |
|---------|---------------|--------|
| GoSec | Go SAST (OWASP patterns) | PRs + weekly |
| govulncheck | Go dependency CVEs (Go advisory DB) | PRs + every deploy |
| Semgrep | SAST + secrets + OWASP Top 10 (Go rulesets) | PRs + weekly |
| Trivy (filesystem) | Dependency CVEs in source tree | PRs + weekly |
| Trivy (container) | OS + app CVEs in built image | Every container build |
| npm audit | npm dependency CVEs (high/critical) | Every SPA build |
| Gitleaks | Secret scanning across git history | PRs + push to main + weekly |

Critical findings on the main branch trigger a notification job. SARIF results are uploaded to GitHub Code Scanning for centralized triage.

### Container Hardening

- **Distroless base image**: `gcr.io/distroless/base-debian12` — no shell, no package manager; includes glibc for BoringSSL dynamic linkage
- **FIPS 140-2 Go binary**: `CGO_ENABLED=1` with BoringCrypto (`GOEXPERIMENT=boringcrypto`) for FIPS 140-2 validated cryptography (BoringSSL cert #4407)
- **nginx-unprivileged**: SPA containers run as non-root with read-only filesystem
- **Pinned dependencies**: `go.sum`, `pnpm-lock.yaml`, `.terraform.lock.hcl` for reproducible builds

### CI/CD Security

- **Keyless authentication**: Workload Identity Federation (WIF) — zero stored secrets
- **Org policy enforcement**: `iam.disableServiceAccountKeyCreation` blocks SA key creation
- **OIDC provider lock**: WIF providers locked to `latentarchon` GitHub org via attribute condition
- **Production gates**: All app repos require manual approval for production deployment
- **Terraform safety**: Plans posted as PR comments, never auto-applied

---

## 14. Security Headers

### SPA (nginx)

Both admin and chat SPAs enforce comprehensive security headers:

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

## 15. Disaster Recovery & Business Continuity

### Recovery Objectives

| Metric | Target | Mechanism |
|--------|--------|-----------|
| **RPO** (Recovery Point Objective) | < 5 minutes | Cloud SQL continuous backup + point-in-time recovery |
| **RTO** (Recovery Time Objective) | < 1 hour | Cloud Run auto-scaling + infrastructure-as-code |

### Backup Strategy

| Component | Backup Method | Retention |
|-----------|--------------|-----------|
| Cloud SQL (PostgreSQL) | Automated daily backups + continuous WAL archiving | 30 days |
| GCS (Documents) | Object versioning + lifecycle policies | 365 days |
| Vector Search Index | Reconstructible from source chunks | N/A (rebuildable) |
| Audit Logs | Cloud Logging export to GCS | 365 days |
| Infrastructure Config | Git (Terragrunt/Terraform IaC) | Indefinite |

### High Availability

- **Cloud Run**: Multi-zone deployment with auto-scaling (0 to N instances)
- **Cloud SQL**: Regional HA configuration with automatic failover
- **Load Balancer**: Global anycast with health checks and automatic backend failover
- **GCS**: Multi-region storage class available for critical documents

### Infrastructure as Code

All infrastructure is defined in Terragrunt/Terraform with:
- Full state stored in GCS with versioning and locking
- CI/CD pipeline validates plans on every PR (never auto-applies)
- Production deployments require manual approval gates
- Drift detection on main branch pushes

### Incident Response Integration

- Cloud Armor WAF provides DDoS protection and OWASP rule enforcement
- Rate limiting at both IP and per-user levels prevents abuse
- Graceful shutdown with in-flight request completion (30-second drain)
- Kill-on-breach capability in red team tooling for immediate containment

---

## 16. Organization Governance

### GCP Resource Hierarchy

The platform uses a **multi-project GCP architecture** based on the Google Cloud Foundation Blueprint:

```
Organization (latentarchon.com)
├── Common/
│   ├── prod-vpc-latentarchon     (Shared VPC Host — Production)
│   ├── staging-vpc-latentarchon  (Shared VPC Host — Staging)
│   └── central-log-latentarchon  (Centralized Logging & Monitoring)
├── Production/
│   ├── latentarchon-chat-prod    (Chat API + SPA)
│   ├── latentarchon-admin-prod   (Admin API + Ops + Data)
│   └── kms-proj-*                (KMS Autokey)
├── Non-Production/
│   ├── latentarchon-chat-staging
│   ├── latentarchon-admin-staging
│   └── kms-proj-*
└── Development/
    └── kms-proj-*
```

Separate GCP projects provide hard IAM boundaries, separate billing, independent audit trails, and blast-radius containment.

### Organization Policies (Enforced)

Ten organization-wide policies are enforced across all projects:

| Policy | Effect |
|--------|--------|
| `storage.publicAccessPrevention` | All GCS buckets prevented from being made public |
| `compute.requireOsLogin` | SSH access requires IAM-based OS Login (no SSH keys) |
| `compute.vmExternalIpAccess` | VMs cannot have external IPs |
| `compute.disableNestedVirtualization` | Prevents VM escape attack vector |
| `compute.disableSerialPortAccess` | No serial console access to VMs |
| `sql.restrictAuthorizedNetworks` | Cloud SQL cannot use authorized networks |
| `sql.restrictPublicIp` | Cloud SQL instances cannot have public IPs |
| `compute.restrictXpnProjectLienRemoval` | Shared VPC liens cannot be removed |
| `compute.skipDefaultNetworkCreation` | No default VPC in new projects |
| `compute.disableVpcExternalIpv6` | No external IPv6 addresses |

### CMEK Autokey Encryption

Customer-Managed Encryption Keys (CMEK) are enforced at the folder level via **Autokey**:

- Dedicated KMS projects per environment folder (Production, Non-Production, Development)
- `gcp.restrictNonCmekServices` org policy denies 35+ GCP services from using Google-managed keys
- `gcp.restrictCmekCryptoKeyProjects` limits which projects can host KMS keys
- HSM-backed keys with 90-day rotation, destroy-scheduled protection, and lifecycle event alerting

### Shared VPC

Both production and staging environments use **Shared VPC** for centralized network governance:

- VPC host projects in the `Common` folder manage all network policies
- Service projects (app, admin) are attached as Shared VPC service projects
- Network policies are managed centrally; service project teams cannot modify firewall rules
- Subnets have **VPC Flow Logs enabled** at 50% sampling with full metadata for network forensics

### Centralized Logging & Monitoring

- Organization-level log sink captures all Admin Activity, System Events, Data Access, and Access Transparency logs across every project
- Logs routed to a centralized log bucket in `central-log-latentarchon`
- All projects enrolled in a single metrics scoping project for single-pane-of-glass monitoring
- Cross-project alerting and unified dashboards

### IAM Groups

IAM is managed via Google Workspace security groups for role-based access at folder/project scopes. All groups are managed via Terraform.

---

## 17. Network Security

### VPC Architecture

- **Custom VPC** — `auto_create_subnetworks = false` (no default subnets)
- **Regional routing** — traffic stays within-region
- **Private Google Access** enabled on all subnets — services access Google APIs without public internet
- **Private Service Connect (PSC)** — Vertex AI Vector Search accessed via deterministic internal IP (`10.10.0.5`) within the VPC

### FQDN-Based Egress Firewall (Zero Trust Network)

A **network firewall policy** implements FQDN-based egress control — effectively a network-level allowlist:

| Priority | Rule | Targets |
|----------|------|----------|
| 100 | Google APIs (ALLOW) | `googleapis.com`, `aiplatform.googleapis.com`, `sqladmin.googleapis.com`, `storage.googleapis.com`, `identitytoolkit.googleapis.com`, `securetoken.googleapis.com`, `firebaseappcheck.googleapis.com`, and others |
| 200 | Internal APIs (ALLOW) | `app.latentarchon.com`, `admin.latentarchon.com` (prod + staging) |
| 65534 | Default DENY ALL | `0.0.0.0/0` — all protocols blocked |

**The platform cannot exfiltrate data to any external endpoint.** Only explicitly allowlisted Google APIs and internal services are reachable. Email is sent via Identity Platform's server-side `sendOobCode` API, eliminating the need for external email provider egress.

### Ingress Controls

- **Cloud SQL**: Only accessible from Cloud Shell admin ranges and Direct VPC Cloud Run services
- **Cloud Tasks**: Google service IP ranges for task dispatch
- **Internal VPC**: East-west communication within subnet and VPC Connector range
- **No public SSH/RDP** — VMs (if any) require IAP tunneling

### Cloud NAT

- Cloud Router + Cloud NAT provides outbound connectivity for private-IP Cloud Run services
- All Cloud Run services use **Direct VPC egress** (private subnet IPs, not public IPs)
- NAT logging enabled for troubleshooting

---

## 18. Web Application Firewall (Cloud Armor)

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

### Additional WAF Controls

- **Rate Limiting**: Configurable requests-per-interval threshold with automatic IP ban on exceedance
- **HTTP Method Enforcement**: Only GET, POST, OPTIONS allowed; TRACE, DELETE, PATCH blocked at WAF
- **Origin Header Restriction**: Requests with disallowed `Origin` headers denied
- **Bot Blocking**: Empty/missing `User-Agent` denied; known scanner/attack tools (curl, wget, sqlmap, nikto, nmap, nuclei, etc.) blocked
- **IP Allowlisting**: Configurable for government/VPN IP ranges (plus per-org self-service allowlisting)

---

## 19. Frontend Security

### Authentication Flow

Both SPAs implement a **zero-password authentication model** with mandatory MFA:

```
User enters email → Magic link sent via Firebase → User clicks link →
  ├── If MFA enrolled: TOTP challenge → Authenticated
  └── If MFA not enrolled: Forced TOTP enrollment (QR scan) → Verified → Authenticated
```

The `AuthGate` component enforces a strict state machine — the application does not render protected routes until MFA is complete and verified. There is no way to bypass MFA enrollment.

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
- **Domain cross-validation**: Config validates that `CHAT_DOMAIN`, `ADMIN_DOMAIN`, `API_DOMAIN` suffixes match the `ENVIRONMENT` setting — prevents env mismatch
- Disallowed origins receive no CORS headers (no `Access-Control-Allow-Origin`, no credentials)

CORS is tested with unit tests and e2e tests covering allowed origins, blocked origins, subdomain patterns, and deep-nesting attacks.

---

## Appendix B: GCP FedRAMP Authorization

Latent Archon is deployed exclusively on Google Cloud Platform services that hold **FedRAMP High** authorization (IL4 capable):

| Service | FedRAMP Status |
|---------|---------------|
| Cloud Run | FedRAMP High |
| Cloud SQL (PostgreSQL) | FedRAMP High |
| Cloud Storage | FedRAMP High |
| Cloud Load Balancing | FedRAMP High |
| Cloud Armor | FedRAMP High |
| Cloud KMS | FedRAMP High |
| Cloud Logging / Monitoring | FedRAMP High |
| Identity Platform | FedRAMP High |
| Vertex AI | FedRAMP High |
| Document AI | FedRAMP High |
| Artifact Registry | FedRAMP High |
| Cloud Tasks | FedRAMP High |
| Certificate Manager | FedRAMP High |

By deploying on FedRAMP-authorized infrastructure, Latent Archon inherits a substantial portion of NIST 800-53 controls at the physical, environmental, and platform layers.

---

## Appendix C: Red Team Validation

Latent Archon maintains an internal red team program with automated attack suites:

| Suite | Attacks | Coverage |
|-------|---------|----------|
| Auth Bypass | 17 attacks | No auth, forged JWT, wrong audience, MFA bypass, TOTP replay, alg:none, session fixation |
| Privilege Escalation | 12 attacks | Cloud SQL, GCS, Cloud Tasks, KMS, admin API, IAM escalation, SA impersonation |
| Data Exfiltration | 15 attacks | SQL injection, IDOR, prompt injection, vector store access, path traversal, UUID enumeration |

All attacks include MITRE ATT&CK technique mapping and NIST 800-53 control correlation. Results are published as structured Markdown reports with executive summaries and remediation recommendations.

---

*This document is maintained alongside the codebase and updated with each security-relevant release.*
