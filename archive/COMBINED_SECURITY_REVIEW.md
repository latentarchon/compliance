# Latent Archon — Combined Security Review Documentation

> Straight concatenation of all security review documents across all repositories.
> Includes both Claude (Cascade) and ChatGPT reviews. Redundancy is intentional.
>
> **Generated**: March 22, 2026

---

# SECTION 1: CLAUDE — Backend Security Review

> Source: `backend/docs/security/CLAUDE_Backend_Security_Review.md`

---

# Latent Archon — Backend Security Architecture

> **Document Purpose**: Comprehensive security review of the Latent Archon backend, suitable for government application sales processes and compliance assessments. This document details all implemented security controls, architectural decisions, and compliance posture across the entire backend codebase.
>
> **Last Updated**: 2026-03-22  
> **Scope**: `backend/` repository — Go backend serving Connect-RPC APIs for the Archon document intelligence platform

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Authentication & Identity](#3-authentication--identity)
4. [Authorization & Access Control](#4-authorization--access-control)
5. [Multi-Factor Authentication (MFA)](#5-multi-factor-authentication-mfa)
6. [Session Management (NIST 800-171 AC-12)](#6-session-management-nist-800-171-ac-12)
7. [Multi-Tenancy & Tenant Isolation](#7-multi-tenancy--tenant-isolation)
8. [Database Security](#8-database-security)
9. [Row-Level Security (RLS)](#9-row-level-security-rls)
10. [API Security](#10-api-security)
11. [Transport Security](#11-transport-security)
12. [Rate Limiting & Abuse Prevention](#12-rate-limiting--abuse-prevention)
13. [Document Upload Security](#13-document-upload-security)
14. [Malware Scanning](#14-malware-scanning)
15. [Vector Store & AI Pipeline Security](#15-vector-store--ai-pipeline-security)
16. [Audit Logging & Compliance](#16-audit-logging--compliance)
17. [Observability & Monitoring](#17-observability--monitoring)
18. [Infrastructure Security](#18-infrastructure-security)
19. [Container & Build Security](#19-container--build-security)
20. [Configuration & Secrets Management](#20-configuration--secrets-management)
21. [Internal Service-to-Service Authentication](#21-internal-service-to-service-authentication)
22. [Error Handling & Information Disclosure Prevention](#22-error-handling--information-disclosure-prevention)
23. [Graceful Shutdown & Data Integrity](#23-graceful-shutdown--data-integrity)
24. [NIST 800-171 Control Mapping](#24-nist-800-171-control-mapping)
25. [Red Team Testing](#25-red-team-testing)

---

## 1. Executive Summary

Latent Archon is a CUI-compliant RAG (Retrieval-Augmented Generation) chatbot platform for government document intelligence. The backend is a Go monolith deployed on Google Cloud Run, designed with defense-in-depth security principles aligned with **NIST 800-171** controls for protecting Controlled Unclassified Information (CUI).

### Key Security Highlights

| Category | Implementation |
|---|---|
| **Authentication** | Firebase Auth with JWT verification, token caching (SHA-256 hashed keys), Firebase App Check |
| **MFA** | TOTP-based multi-factor authentication enforced on all data endpoints; step-up MFA for sensitive operations |
| **Session Management** | NIST 800-171 AC-12 compliant idle (30 min) and absolute (12 hr) timeouts |
| **Multi-Tenancy** | Two-project auth isolation (separate Firebase pools), tenant ID enforcement at interceptor + host + header levels |
| **Data Isolation** | PostgreSQL Row-Level Security (RLS) with fail-closed workspace scoping on all data tables |
| **Database Roles** | Three least-privilege Postgres roles: read-only (app), read-write (admin), ops (processing) |
| **API Protocol** | Connect-RPC with typed interceptor chain (auth → MFA → rate limit → logging) |
| **Rate Limiting** | Two-tier: IP-based HTTP middleware + per-user Connect-RPC interceptor with service-specific tiers |
| **Upload Security** | File type allowlist, magic-byte validation, size limits, filename sanitization, SHA-256 deduplication |
| **Malware Scanning** | ClamAV integration via REST API for pre-persistence file scanning |
| **Audit Trail** | Database-persisted audit events with IP, user agent, trace IDs, and Cloud Logging SIEM integration |
| **Observability** | OpenTelemetry distributed tracing, structured logging (slog), Prometheus-compatible metrics |
| **Container** | Distroless base image, static binary, no shell, non-root, CGO disabled |
| **Internal Auth** | Google OIDC JWT verification with service account allowlisting for Cloud Tasks/Scheduler |
| **CORS** | Strict origin allowlist with environment-gated localhost access |

---

## 2. Architecture Overview

### Deployment Model

The system is deployed as three isolated Cloud Run services, each operating in a distinct **server mode**:

| Service | Mode | Purpose | Auth Model |
|---|---|---|---|
| `archon-app` | `public` | User-facing app API, streaming, search | Firebase Auth (app pool) |
| `archon-admin` | `admin` | Admin API: org/workspace/document management | Firebase Auth (admin pool) |
| `archon-ops` | `ops` | Internal: document processing, cron jobs | Google OIDC (service accounts) |

### Two-Project Auth Isolation

Authentication is split across two GCP projects to provide **complete auth pool isolation**:

- **`latentarchon-app`**: Firebase Auth user pool for app users
- **`latentarchon-admin`**: Firebase Auth pool for admin users

This prevents cross-pool authentication attacks — a valid app user token cannot authenticate against the admin API, and vice versa.

### Request Flow

```
Client → Cloud Armor (WAF) → Load Balancer → Cloud Run
  → CORS Middleware
  → Security Headers Middleware
  → IP Rate Limiter
  → Connect-RPC Interceptor Chain:
    1. Auth Interceptor (token verify, tenant check, MFA, session timeout)
    2. Per-User Rate Limiter
    3. Logging Interceptor
  → Handler (authorization check, business logic)
  → RLS-scoped Database Query
```

---

## 3. Authentication & Identity

### Firebase Auth Token Verification

**Implementation**: `shared-go/auth/auth.go`

All API requests are authenticated via Firebase ID tokens (JWTs) verified server-side:

- **Token Extraction**: Bearer token from `Authorization` header
- **Verification**: Firebase Admin SDK `VerifyIDToken()` with full cryptographic validation (signature, issuer, audience, expiration)
- **Token Caching**: Verified tokens are cached in-memory with SHA-256 hashed keys to avoid re-verification on every request. Cache keys use `crypto/sha256` to prevent token leakage in memory dumps.
- **Verification Timeout**: 10-second deadline prevents hanging on Firebase API issues
- **User Object**: Verified tokens produce an `auth.User` struct containing:
  - Firebase UID
  - Email
  - Display name
  - Tenant ID (for multi-tenant isolation)
  - MFA verification status (`sign_in_second_factor` claim)
  - Authentication timestamp (`auth_time`)
  - Token issued-at timestamp (`iat`)

### Firebase App Check

**Implementation**: `shared-go/auth/auth.go` → `verifyWithFirebase()`

Firebase App Check verifies client integrity (device attestation):

- App Check token extracted from `X-Firebase-AppCheck` header
- Verified via Firebase App Check Admin SDK
- When `FIREBASE_APPCHECK_ENABLED=true`, requests without valid App Check tokens are rejected
- Prevents automated attacks from non-legitimate clients

### Early Configuration Validation

`validateFirebaseConfig()` performs startup-time validation of all Firebase configuration to prevent silent authentication failures in production. Missing or invalid configuration causes a hard startup failure rather than runtime errors.

---

## 4. Authorization & Access Control

### Role-Based Access Control (RBAC)

The system implements a hierarchical RBAC model:

#### Organization Roles
| Role | Permissions |
|---|---|
| `master_admin` | God-mode: implicit access to all workspaces in the org, can invite other master_admins, can reset member MFA |
| `admin` | Org-level admin: can create workspaces (auto-added as workspace admin), invite members, remove members |

#### Workspace Roles
| Role | Permissions |
|---|---|
| `admin` | Full workspace management: invite/remove members, upload/delete documents |
| `editor` | Document upload and metadata editing |
| `viewer` | Read-only access to documents and conversations |

#### Access Tier (CUI Segmentation)
| Tier | Purpose |
|---|---|
| `standard` | Default access level |
| `premium` | Reserved for CUI segmentation within a workspace |

### Authorization Enforcement Points

Every RPC handler performs explicit authorization checks:

1. **Organization operations**: `IsOrgAdmin()` / `IsMasterAdmin()` checks
2. **Workspace operations**: `CanUserAccessWorkspace()` checks (explicit membership OR master_admin of parent org)
3. **Document operations**: Workspace access verified before any document CRUD
4. **App/Search**: Workspace access verified for every workspace ID in the request
5. **Member management**: Only admins can invite/remove; only master_admins can invite other master_admins
6. **MFA reset**: Admin-only, with self-reset prevention (`cannot reset your own MFA via admin endpoint`)
7. **Last-admin guard**: Both org and workspace member removal prevent removing the last admin

### Privilege Escalation Prevention

- Only `master_admin` can promote others to `master_admin` (checked in `InviteMember`)
- Self-MFA-reset is blocked to prevent session manipulation
- Org member removal atomically removes all workspace memberships under that org (transactional)
- Last-admin guard prevents lockout scenarios at both org and workspace levels

---

## 5. Multi-Factor Authentication (MFA)

### MFA Enforcement

**Implementation**: `cmd/server/connect_interceptors.go` → `extractAndVerify()`

TOTP-based MFA is enforced at the Connect-RPC interceptor level:

- **Verification**: Checks `sign_in_second_factor` claim in Firebase JWT (set by Firebase when user completes TOTP challenge)
- **Enforcement Scope**: All RPCs **except** explicitly exempt procedures
- **MFA-Exempt Procedures**: Only `AuthService` RPCs are exempt (login/verification flows that occur before MFA is possible)

### Step-Up MFA for Sensitive Operations

High-risk operations require **recent MFA verification** (step-up authentication):

| Sensitive RPC | Service |
|---|---|
| `InviteMember` | OrganizationService |
| `RemoveMember` | OrganizationService |
| `InviteMember` | WorkspaceService |
| `RemoveMember` | WorkspaceService |
| `DeleteDocument` | DocumentService |

Step-up MFA is enforced unless the server is in development mode (`ENVIRONMENT=development`).

### Admin MFA Management

Organization admins can reset member MFA via `ResetMemberMFA` RPC:
- Unenrolls all MFA factors via Firebase Admin SDK
- Revokes all active sessions
- Audit logged with admin ID, target user ID, and org context
- Self-reset is explicitly blocked

### SSO & SCIM (Enterprise Identity Federation)

**Implementation**: `internal/sso/service.go`, `internal/sso/scim_handler.go`, `internal/sso/admin_handler.go`

Enterprise SSO is supported via SAML 2.0 integration with Identity Platform tenants:

- **Per-org SSO configuration**: Each organization can configure its own SAML IdP (Okta, Azure AD, etc.) via admin REST endpoints
- **JIT provisioning**: Federated users are automatically provisioned on first login — the auth interceptor creates user records and org memberships transparently
- **IdP group-to-role mapping**: IdP group assertions map to organization roles and workspace memberships, enabling automated access management
- **SCIM 2.0 server**: Full RFC 7643/7644 compliant SCIM endpoint for automated user provisioning and deprovisioning:
  - Users CRUD (list/get/create/replace/patch/delete)
  - Groups (list/get/patch) mapped to workspaces
  - Bearer token auth with SHA-256 hashed tokens stored in database
  - ServiceProviderConfig, Schemas, and ResourceTypes discovery endpoints
- **Admin management**: REST endpoints for SSO config CRUD and SCIM token lifecycle (create/list/revoke)
- **External identity mapping**: `external_identities` table maps IdP users to Archon users with SCIM/JIT tracking

### Per-Tenant IP Allowlisting

**Implementation**: `internal/cloudarmor/service.go`

Organization admins can configure CIDR-based IP allowlists enforced at the WAF layer:

- **Self-service configuration**: Org admins set IP allowlists via `UpdateOrganizationSettings` RPC with CIDR validation
- **Cloud Armor integration**: Backend syncs per-tenant deny rules (priority 50–99) via the GCP Compute API
- **CEL expressions**: Rules match on `request.headers['host'].startsWith('<slug>.')` combined with `inIpRange()` for tenant-scoped enforcement
- **Full reconciliation**: Add/update/remove logic ensures Cloud Armor rules stay in sync with database state
- **Non-fatal sync**: Cloud Armor sync failure is logged and audit-recorded but does not block the settings update — database is source of truth

---

## 6. Session Management (NIST 800-171 AC-12)

**Implementation**: `cmd/server/connect_interceptors.go` → `extractAndVerify()`

Session management complies with **NIST 800-171 AC-12** (Session Termination):

### Idle Session Timeout
- **Default**: 30 minutes (configurable via `SESSION_IDLE_TIMEOUT_MIN`)
- **Enforcement**: Compares current time against `auth_time` claim
- **Error**: `CodeUnauthenticated` with message "session idle timeout exceeded"

### Absolute Session Timeout
- **Default**: 720 minutes / 12 hours (configurable via `SESSION_ABSOLUTE_TIMEOUT_MIN`)
- **Enforcement**: Compares current time against `iat` (issued-at) claim
- **Error**: `CodeUnauthenticated` with message "session absolute timeout exceeded"

### Session Timeout Logging

Both timeout configurations are logged at startup:
```
Session timeouts configured: idle=25m0s absolute=12h0m0s
```

Session timeouts are **not enforced in development mode** to facilitate local development.

---

## 7. Multi-Tenancy & Tenant Isolation

### Three-Layer Tenant Verification

**Implementation**: `cmd/server/connect_interceptors.go` → `extractAndVerify()`

Every authenticated request undergoes three independent tenant isolation checks:

1. **Token Tenant ID**: Firebase JWT must contain a tenant ID (when `requireTenant=true`)
2. **Header Match**: `X-Tenant-ID` request header must match the token's tenant ID
3. **Host Subdomain Match**: The request's hostname subdomain must match the tenant ID (prevents cross-tenant request forwarding)

If any check fails, the request is rejected with `CodePermissionDenied`.

### Database-Level Isolation

All workspace-scoped data is isolated via PostgreSQL Row-Level Security (see [Section 9](#9-row-level-security-rls)).

### Vector Store Isolation

Vector search results are scoped to specific workspace IDs via Vertex AI token restrictions:
- Each stored vector carries a `workspace_id` namespace restriction
- Search queries include workspace ID filters
- Cross-workspace data leakage is prevented at the vector database level

---

## 8. Database Security

### Cloud SQL Connector (Private VPC)

**Implementation**: `shared-go/postgres/pgx.go` → `attemptPoolConnection()`

Database connections use the **Google Cloud SQL Connector** with IAM authentication:

- **IAM Authentication**: `cloudsqlconn.WithIAMAuthN()` — no static passwords
- **Private IP**: `cloudsqlconn.WithPrivateIP()` — connections traverse VPC only, never public internet
- **SSL Required**: DSN includes `sslmode=require`
- **Lazy Refresh**: `cloudsqlconn.WithLazyRefresh()` — credentials refreshed on demand

### Connection Pool Security

Pool settings are tuned for security and resource management:

| Parameter | Value | Purpose |
|---|---|---|
| `MaxConns` | 8 | Prevent connection exhaustion |
| `MinConns` | 2 | Warm connections for availability |
| `MaxConnLifetime` | 10 min | Force credential rotation |
| `MaxConnIdleTime` | 3 min | Close stale connections |
| `HealthCheckPeriod` | 30 sec | Detect failed connections |

### Least-Privilege Database Roles

**Implementation**: `shared-go/postgres/roles.sql`

Three Postgres roles enforce least-privilege access:

| Role | Used By | Permissions |
|---|---|---|
| `archon_app_ro` | App API (`archon-app`) | SELECT on reference tables; SELECT + INSERT on messages, rag_searches, generations |
| `archon_admin_rw` | Admin API (`archon-admin`) | ALL on all tables and sequences |
| `archon_ops_rw` | Ops service (`archon-ops`) | SELECT/INSERT/UPDATE on documents + chunks; INSERT on audit_events + generations; SELECT on reference tables |

Key restrictions:
- App role **cannot** create, modify, or delete organizations, workspaces, documents, or members
- App role **cannot** delete any data
- Ops role **cannot** modify organizations, workspaces, or members
- Roles are mapped to GCP IAM service accounts via Cloud SQL IAM authentication

### Slow Query Detection

All database operations include timing instrumentation. Queries exceeding 1 second are logged as warnings with the query text for investigation.

---

## 9. Row-Level Security (RLS)

**Implementation**: `shared-go/postgres/schema.sql` + `shared-go/postgres/rls.go`

### RLS-Protected Tables

| Table | RLS Policy | Scope |
|---|---|---|
| `documents` | workspace_id match | Workspace |
| `chunks` | workspace_id match | Workspace |
| `messages` | workspace_ids overlap | Multi-workspace |
| `rag_searches` | workspace_ids overlap | Multi-workspace |

### Fail-Closed Design

RLS is **FORCE-enabled** on all data tables:
```sql
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
```

This means even the table owner is subject to RLS policies. If no workspace IDs are set in the session, **zero rows are returned** (fail-closed).

### RLS Implementation Mechanism

The application uses PostgreSQL GUC (Grand Unified Configuration) variables to pass workspace scope:

1. **Workspace-scoped queries**: `SET LOCAL app.workspace_ids = '<uuid>,<uuid>'`
2. **Admin bypass**: `SET LOCAL app.rls_bypass = 'on'`

Each query is wrapped in its own mini-transaction with `SET LOCAL` to ensure the GUC is scoped correctly:

```go
// workspaceScopedDBTX wraps every query in a transaction with SET LOCAL
tx, _ := pool.BeginTx(ctx, pgx.TxOptions{})
tx.Exec(ctx, "SELECT set_config('app.workspace_ids', $1, true)", wsIDs)
result, _ := tx.Query(ctx, sql, args...)
tx.Commit(ctx)
```

### Three DBTX Wrappers

| Wrapper | GUC Set | Use Case |
|---|---|---|
| `WorkspaceScopedDBTX()` | `app.workspace_ids` | User-facing queries (default) |
| `AdminScopedDBTX()` | `app.rls_bypass = 'on'` | System operations, cron jobs |
| `UnscopedDBTX()` | None | Tables without RLS (users, org_members) |

### Transaction Helpers

- `WithWorkspaceTx()`: Runs a function in a workspace-scoped transaction
- `WithAdminTx()`: Runs a function with RLS bypass (admin operations only)
- `BeginTx()`: Auto-sets workspace scope from context if available

---

## 10. API Security

### Connect-RPC Protocol

The API uses **Connect-RPC** (connectrpc.com), a modern RPC protocol that:

- Provides strongly-typed request/response contracts via Protocol Buffers
- Supports both unary and server-streaming RPCs
- Works natively in browsers via `connect-web`
- Includes built-in error codes for consistent error handling

### Interceptor Chain

All Connect-RPC calls pass through a layered interceptor chain:

1. **Auth Interceptor** (`connect_interceptors.go`): Token verification, tenant isolation, MFA enforcement, session timeouts
2. **Per-User Rate Limiter** (`connect_ratelimit.go`): Service-tier rate limiting by authenticated user ID
3. **Logging Interceptor** (`connect_interceptors.go`): Request/response logging with user ID, tenant ID, duration, error codes

### Input Validation

Every RPC handler validates inputs before processing:
- Required fields checked (empty string, nil checks)
- Length limits enforced (e.g., organization name ≤ 255 chars, message ≤ 10,000 chars)
- Pagination bounds enforced (page size max 100, offset ≥ 0)
- Enum values validated and mapped with safe defaults
- UUID parsing with validation

### Recovery Interceptor

A `RecoveryInterceptor` catches panics in RPC handlers:
- Logs the panic with user context and procedure name
- Returns a generic `CodeInternal` error (no internal details leaked)
- Prevents process crashes from propagating

---

## 11. Transport Security

### Security Headers

**Implementation**: `cmd/server/main.go` → `securityHeadersMiddleware()` + `shared-go/transport/http.go` → `addSecurityHeaders()`

All HTTP responses include hardened security headers:

| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Strictest CSP (API-only, no scripts/styles) |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disables sensitive browser APIs |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Enforces HTTPS (2-year HSTS) |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates browsing context |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevents cross-origin resource loading |
| `Cache-Control` | `no-store` | Prevents caching of API responses |

### CORS Policy

**Implementation**: `cmd/server/main.go` → `corsMiddleware()` + `shared-go/transport/http.go` → `ConnectCORSMiddleware()`

CORS is enforced with a strict origin allowlist:

- **Production origins**: `https://app.latentarchon.com`, `https://admin.latentarchon.com`, etc.
- **Staging origins**: `https://staging.app.latentarchon.com`, etc.
- **Localhost**: Only allowed when `ENVIRONMENT=development` (environment-gated)
- **Credentials**: `Access-Control-Allow-Credentials: true` only for allowed origins
- **Max-Age**: 86400 seconds (24-hour preflight cache)
- **Vary headers**: `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers` set for correct cache behavior
- **Non-allowlisted origins**: No CORS headers set (silent rejection), logged as warning

### Request ID Tracking

**Implementation**: `cmd/server/main.go` → `requestIDMiddleware()`

Every request receives a unique request ID:
- Uses incoming `X-Request-ID` header if present (from load balancer)
- Generates a new UUID v4 if absent
- Injected into context for correlation across logs, traces, and audit events

---

## 12. Rate Limiting & Abuse Prevention

### Two-Tier Rate Limiting

#### Tier 1: IP-Based HTTP Rate Limiter

**Implementation**: `cmd/server/ratelimit.go`

Applied as HTTP middleware **before** authentication:

- **Key**: Client IP from `X-Forwarded-For` (Cloud Run) or `RemoteAddr`
- **Algorithm**: Token bucket with periodic refill
- **Response**: `429 Too Many Requests` with `Retry-After: 60` header
- **Exemptions**: Health checks (`/health`) and OPTIONS preflight
- **Memory Management**: Stale buckets evicted every 5 minutes (10-minute inactivity threshold)

#### Tier 2: Per-User Connect-RPC Rate Limiter

**Implementation**: `cmd/server/connect_ratelimit.go`

Applied as a Connect-RPC interceptor **after** authentication:

| Service Tier | Rate | Burst | Interval |
|---|---|---|---|
| App (ConversationService) | 20 req/min | 30 | 1 minute |
| Upload (DocumentService) | 15 req/min | 20 | 1 minute |
| Default (all other RPCs) | 60 req/min | 80 | 1 minute |

- **Key**: Authenticated user ID (from Firebase token)
- **Response**: Connect `CodeResourceExhausted` error
- **Logging**: Rate limit violations logged with user ID and procedure name

### Invite Rate Limiting

Organization and workspace invite endpoints have additional per-user rate limiters to prevent invitation spam abuse.

---

## 13. Document Upload Security

**Implementation**: `internal/document/service.go` → `Upload()`

Document uploads undergo multiple security validations:

### File Size Enforcement
- **Max Upload Size**: 50 MB (`MaxUploadSize = 50 * 1024 * 1024`)
- Server-side enforcement via `io.LimitReader(reader, MaxUploadSize+1)`
- HTTP handler adds 1 MB overhead for multipart form data

### File Type Allowlist
Only approved MIME types are accepted:
- `application/pdf`
- `text/plain`, `text/markdown`, `text/csv`
- `image/png`, `image/jpeg`, `image/tiff`, `image/gif`, `image/bmp`, `image/webp`
- `application/vnd.openxmlformats-officedocument.wordprocessingml.document` (.docx)

### Magic-Byte Validation

**Implementation**: `internal/document/service.go` → `validateMagicBytes()`

Prevents MIME-type spoofing by verifying actual file content matches the claimed type:

| Claimed Type | Magic Bytes Checked |
|---|---|
| PDF | `%PDF` (first 4 bytes) |
| PNG | `\x89PNG` signature |
| JPEG | `\xFF\xD8\xFF` signature |
| GIF | `GIF87a` or `GIF89a` |
| TIFF | `II\x2A\x00` (LE) or `MM\x00\x2A` (BE) |
| BMP | `BM` prefix |
| WebP | `RIFF....WEBP` structure |
| DOCX | `PK\x03\x04` (ZIP archive) |
| Text/CSV/MD | `http.DetectContentType()` must return `text/*` or `application/octet-stream` |

### Filename Sanitization

**Implementation**: `internal/document/service.go` → `sanitizeFilename()`

- Path traversal prevention: strips `/` and `\` path components
- Control character removal: filters characters ≤ 31 and DEL (127)
- Length limit: truncated to 255 characters
- Whitespace trimming

### Content Hash Deduplication

- SHA-256 hash computed over entire file content
- Duplicate check against existing documents in the same workspace
- Prevents re-upload of identical content

### GCS Storage Path

Documents are stored at workspace-scoped paths:
```
workspaces/{workspace_id}/documents/{document_id}/{sanitized_filename}
```

---

## 14. Malware Scanning

**Implementation**: `internal/malware/clamav.go`

### ClamAV Integration

Optional malware scanning via a ClamAV REST service (`benzino77/clamav-rest`):

- **Scan Point**: Before file persistence (pre-GCS upload)
- **Protocol**: POST multipart form to `/api/v1/scan`
- **Timeout**: 60-second HTTP client timeout
- **Response Handling**: Parses `is_infected` and `viruses` fields
- **Rejection**: Infected files are rejected with error before any persistence
- **Response Size Limit**: 1 MB limit on scan response body
- **Logging**: Infections logged at WARN level with filename and virus names

### Scan Flow

```
Upload → Size Check → Type Check → Magic Bytes → Malware Scan → Hash Check → GCS Upload → DB Insert
```

If any step fails, the upload is rejected and no data is persisted.

---

## 15. Vector Store & AI Pipeline Security

### Vertex AI Vector Search

**Implementation**: `internal/vectorstore/client.go`

- **Authentication**: Uses GCP Application Default Credentials (IAM-based, no API keys)
- **Endpoint**: Regional `{region}-aiplatform.googleapis.com:443` (TLS)
- **Workspace Scoping**: Every stored vector includes `workspace_id` token restriction
- **Search Scoping**: Every search query includes workspace ID filter
- **Document Scoping**: Vectors also carry `document_id` restriction for granular filtering

### RAG Pipeline Security

**Implementation**: `cmd/server/connect_conversation.go` → `SendMessage()`

1. **Input Validation**: Message length ≤ 10,000 characters; workspace IDs required
2. **Workspace Access**: Every workspace ID verified via `CanUserAccessWorkspace()` before processing
3. **Context Isolation**: Vector search results are scoped to authorized workspaces only
4. **Prompt Construction**: System prompt is server-controlled (not user-modifiable)
5. **Message Persistence**: Async with WaitGroup tracking for graceful shutdown
6. **Correlation IDs**: Every conversation flow gets a unique correlation ID for audit trail

### Document Processing Pipeline

**Implementation**: `internal/document/service.go` → `Process()`

- Processing runs in isolated context with 10-minute timeout
- Failed processing marks document as `error` with error message
- Dead Letter Queue (DLQ) captures documents that fail after retries
- Document AI processing uses `SkipHumanReview: true` to prevent data exposure to human reviewers

---

## 16. Audit Logging & Compliance

### Audit Event System

**Implementation**: `internal/audit/logger.go`

All security-relevant operations are recorded in the `audit_events` database table:

#### Recorded Fields
| Field | Source | Purpose |
|---|---|---|
| `user_id` | Firebase UID | Actor identification |
| `organization_id` | Context | Org scoping |
| `workspace_id` | Context | Workspace scoping |
| `action` | Handler code | Operation type (e.g., `document.upload`, `org.invite_member`) |
| `status` | Handler code | `started`, `success`, `failure` |
| `resource_type` | Handler code | Affected resource type |
| `resource_id` | Handler code | Affected resource ID |
| `error_message` | Error | Failure details |
| `metadata` | JSONB | Structured context (request_id, tenant_id, trace_id, span_id, error_code, duration_ms, platform) |
| `correlation_id` | Context | Cross-event linking |
| `ip_address` | Context (INET) | Client IP |
| `user_agent` | Context | Client user agent |

#### Audited Operations
- Organization: create, invite_member, remove_member, reset_member_mfa
- Workspace: create, invite_member, remove_member
- Document: upload, delete, metadata_update
- Auth: login, login_failed, mfa_challenge
- Admin: bootstrap, role_escalation

### Cloud Logging SIEM Integration

Every audit event emits a structured log entry for Cloud Logging:
- **Security-critical events** (failures, auth events, member changes, deletions) logged at `WARN` level
- **Normal operations** logged at `INFO` level
- Format: `AUDIT_EVENT` prefix with structured fields for SIEM alert policies
- Cloud Run automatically forwards stdout JSON to Cloud Logging

### OpenTelemetry Trace Correlation

Audit events are enriched with `trace_id` and `span_id` from the active OpenTelemetry span context, enabling end-to-end request tracing from audit event to distributed trace.

### Best-Effort Design

Audit logging is **best-effort**: insert failures are logged and ignored, never blocking the request path. This prevents audit system failures from causing service outages while maintaining a structured log trail.

### Async Audit Logging

`EventAsync()` runs audit inserts in a background goroutine with `context.WithoutCancel()` to ensure events are persisted even after the request handler returns.

---

## 17. Observability & Monitoring

### OpenTelemetry Distributed Tracing

**Implementation**: `internal/telemetry/otel.go`

- **Production**: OTLP/gRPC exporter to Cloud Trace (1% sampling)
- **Staging**: OTLP/gRPC exporter (10% sampling)
- **Development**: stdout or no-op exporter (100% sampling)
- **Resource Attributes**: Service name, version, environment, server mode, project ID
- **Propagation**: W3C TraceContext + Baggage propagation

### Structured Logging

All logging uses Go's `slog` structured logging:
- JSON output for Cloud Logging ingestion
- Consistent field naming across all services
- Context-enriched log entries (request ID, user ID, tenant ID)
- Slow query detection and logging (> 1 second threshold)

### Metrics

- Database metrics: queries total, slow queries, transactions started/committed/rolled back, execs total
- HTTP metrics: request count, duration, status codes
- Rate limit violations tracked and logged

### Connect-RPC Logging Interceptor

**Implementation**: `cmd/server/connect_interceptors.go` → `loggingInterceptor`

Every RPC call is logged with:
- Procedure name, duration, user ID, tenant ID
- Request ID for correlation
- Error code (on failure)
- Structured format for Cloud Logging search

---

## 18. Infrastructure Security

### Google Cloud Platform

| Component | Security Feature |
|---|---|
| **Cloud Run** | Serverless, auto-scaling, no persistent compute surface |
| **Cloud SQL** | Private VPC networking, IAM authentication, encrypted at rest |
| **Cloud Armor** | WAF with OWASP rules, IP allowlisting |
| **Load Balancer** | TLS termination, DDoS protection |
| **Cloud Storage** | Server-side encryption, IAM-controlled access |
| **Cloud Tasks** | OIDC-authenticated task delivery |
| **Vertex AI** | PSC-enabled endpoint (Private Service Connect), VPC-isolated |
| **Document AI** | Regional processing, no human review |
| **KMS** | Customer-managed encryption keys |
| **VPC** | Private networking, no public IP on services |

### Cross-Project Security

Only one narrow IAM grant crosses the project boundary:
- `roles/cloudsql.client` + `roles/cloudsql.instanceUser` for the app service account on the admin project
- This enables the app API to read documents and workspace data from Cloud SQL

---

## 19. Container & Build Security

**Implementation**: `Dockerfile`

### Multi-Stage Build

```dockerfile
# Builder stage: golang:1.25.0 with BoringCrypto (FIPS 140-2)
FROM golang:1.25.0 AS builder
ENV GOEXPERIMENT=boringcrypto

# Runtime stage: distroless with glibc (required by BoringSSL dynamic linkage)
FROM gcr.io/distroless/base-debian12
```

### Security Hardening

| Measure | Implementation |
|---|---|
| **Distroless base** | `gcr.io/distroless/base-debian12` — no shell, no package manager, minimal attack surface; includes glibc for BoringSSL |
| **FIPS 140-2 cryptography** | `GOEXPERIMENT=boringcrypto` with `CGO_ENABLED=1` — uses BoringSSL (FIPS 140-2 validated, cert #4407) for all TLS and crypto operations |
| **Stripped binary** | `-ldflags="-w -s"` — no debug symbols |
| **Trimmed paths** | `-trimpath` — no local filesystem paths in binary |
| **Build tags** | `osusergo` — pure Go user/group lookup |
| **CA Certificates** | Explicitly copied from builder (only external dependency) |
| **No secrets in image** | All configuration via environment variables at runtime |

---

## 20. Configuration & Secrets Management

### Environment-Based Configuration

**Implementation**: `shared-go/config/config.go`

All configuration is loaded from environment variables at startup — no config files, no embedded secrets:

- **Environment Validation**: `ENVIRONMENT` must be explicitly `development`, `staging`, or `production`
- **Server Mode Validation**: `SERVER_MODE` must be `public`, `admin`, or `ops`
- **Domain Cross-Validation**: Domains are validated against their environment (e.g., production domains must end with `latentarchon.com`, staging with `staging.latentarchon.com`, development with `localhost`)
- **Session Timeouts**: Configurable via `SESSION_IDLE_TIMEOUT_MIN` and `SESSION_ABSOLUTE_TIMEOUT_MIN` with secure defaults

### Domain Mismatch Prevention

```go
allowedDomainSuffixes := map[string][]string{
    "development": {"localhost"},
    "staging":     {"staging.latentarchon.com"},
    "production":  {"latentarchon.com"},
}
```

This prevents configuration errors such as pointing a production deployment at staging domains.

---

## 21. Internal Service-to-Service Authentication

**Implementation**: `shared-go/transport/http.go` → `GoogleOIDCAuthMiddleware()`

### Google OIDC Verification

Internal endpoints (ops service) are protected by Google OIDC JWT verification:

1. **Signature Verification**: Uses Google's public JWKS (automatically cached)
2. **Issuer Validation**: Must be `accounts.google.com`
3. **Audience Validation**: Must match configured API domain or incoming request host
4. **Service Account Allowlist**: Only specific service accounts are authorized:
   - `cloud-tasks@{project}.iam.gserviceaccount.com`
   - `cloud-scheduler@{project}.iam.gserviceaccount.com`
   - `archon-admin@{project}.iam.gserviceaccount.com`

### Singleton Validator

The OIDC validator is a thread-safe singleton that caches Google's public keys, avoiding repeated key fetches.

---

## 22. Error Handling & Information Disclosure Prevention

### Generic Error Responses

All RPC handlers return generic errors to clients:

```go
func internalErr() error {
    return connect.NewError(connect.CodeInternal, fmt.Errorf("internal error"))
}
```

Internal details (database errors, stack traces, etc.) are **never** exposed to clients. Detailed errors are logged server-side only.

### Structured Error Classification

The document upload handler classifies errors for proper HTTP status codes:

| Classification | HTTP Status | Example |
|---|---|---|
| Client error | 400 | Missing fields, invalid file type |
| Auth error | 401 | Missing/invalid token |
| Permission error | 403 | No workspace access |
| Rate limit | 429 | Too many requests |
| Server error | 500 | Database failure |

### Recovery from Panics

The `RecoveryInterceptor` catches all panics in Connect-RPC handlers, logs the panic with context, and returns a generic internal error instead of crashing the process.

---

## 23. Graceful Shutdown & Data Integrity

**Implementation**: `cmd/server/main.go` → `Close()` + signal handling

### Shutdown Sequence

1. **Signal Handling**: Catches `SIGINT` and `SIGTERM`
2. **HTTP Server Drain**: 15-second graceful shutdown for in-flight requests
3. **WaitGroup**: Waits for async operations (message persistence) to complete
4. **Rate Limiter Cleanup**: Stops all background eviction goroutines
5. **OpenTelemetry Flush**: Flushes pending traces
6. **Database Close**: Closes connection pool and Cloud SQL dialer
7. **Service Cleanup**: Closes GCS clients, Document AI clients, vector store clients

### Async Operation Tracking

Message persistence uses a `sync.WaitGroup` to ensure all in-flight writes complete before shutdown:

```go
if h.wg != nil {
    h.wg.Add(1)
}
go func() {
    if h.wg != nil {
        defer h.wg.Done()
    }
    // Persist messages...
}()
```

---

## 24. NIST 800-171 Control Mapping

| NIST Control | Description | Implementation |
|---|---|---|
| **AC-2** | Account Management | Firebase Auth user management, org/workspace member CRUD, invite system with expiring tokens |
| **AC-3** | Access Enforcement | RBAC (master_admin/admin/editor/viewer), workspace access checks, RLS |
| **AC-4** | Information Flow Enforcement | RLS workspace scoping, vector search token restrictions, two-project auth isolation |
| **AC-5** | Separation of Duties | Three database roles (app_ro, admin_rw, ops_rw), three server modes |
| **AC-6** | Least Privilege | Database roles, IAM service accounts, per-service permissions |
| **AC-7** | Unsuccessful Login Attempts | Firebase Auth built-in lockout; rate limiting on auth endpoints |
| **AC-8** | System Use Notification | Configurable at frontend level |
| **AC-11** | Session Lock | Idle session timeout (25 min) enforced at interceptor level |
| **AC-12** | Session Termination | Absolute session timeout (12 hr); configurable idle and absolute timeouts |
| **AC-17** | Remote Access | TLS-only (HSTS preload), VPC networking, Cloud Armor WAF |
| **AU-2** | Audit Events | Comprehensive audit_events table with 15+ event types |
| **AU-3** | Content of Audit Records | User ID, action, status, resource, IP, user agent, timestamps, trace IDs, correlation IDs |
| **AU-6** | Audit Review | Cloud Logging SIEM integration, structured JSON logs, WARN-level security events |
| **AU-8** | Time Stamps | `TIMESTAMPTZ` on all records, server-generated timestamps |
| **AU-9** | Protection of Audit Information | Audit table uses admin-scoped DBTX; app role has SELECT-only on audit_events |
| **AU-12** | Audit Generation | Audit events generated at handler level for all security-relevant operations |
| **IA-2** | Identification and Authentication | Firebase Auth JWT verification with MFA; SAML 2.0 SSO federation with customer IdPs |
| **IA-4** | Identifier Management | SCIM 2.0 automated user provisioning/deprovisioning; external identity mapping |
| **IA-5** | Authenticator Management | Firebase Auth manages credentials; TOTP MFA; admin MFA reset capability; SCIM token lifecycle |
| **IA-8** | Identification (Non-Organizational) | Firebase App Check for client integrity verification; SAML federation for external IdPs |
| **AC-22** | Publicly Accessible Content | Per-tenant IP allowlisting via Cloud Armor; CEL-based host/IP enforcement |
| **MP-2** | Media Access | GCS IAM controls, workspace-scoped storage paths |
| **SC-8** | Transmission Confidentiality | TLS 1.2+ (HSTS), Cloud SQL SSL, VPC private networking |
| **SC-12** | Cryptographic Key Management | GCP KMS for encryption keys; Firebase manages auth keys |
| **SC-13** | Cryptographic Protection | SHA-256 for content hashing and token cache keys; TLS for all transport |
| **SC-28** | Protection of Information at Rest | Cloud SQL encryption at rest; GCS server-side encryption; KMS |
| **SI-3** | Malicious Code Protection | ClamAV malware scanning on document uploads |
| **SI-4** | System Monitoring | OpenTelemetry tracing, structured logging, Cloud Logging, audit trail |
| **SI-10** | Information Input Validation | File type allowlist, magic-byte validation, filename sanitization, input length limits |

---

## 25. Red Team Testing

The project includes a purpose-built red team testing suite (`redteam/` repository) with 44 automated attacks across three categories:

### Attack Suites

| Suite | Attacks | Focus |
|---|---|---|
| **Auth Bypass** (AB-001–AB-017) | 17 | No auth, empty bearer, malformed JWT, expired JWT, forged JWT, wrong audience, modified claims, cross-pool auth, MFA bypass, TOTP replay, brute force, alg:none, alg confusion, session fixation, CORS bypass, HTTP method override |
| **Privilege Escalation** (CPE-001–CPE-012) | 12 | Cloud SQL, GCS, Cloud Tasks, KMS, admin API, ops endpoints, IAM escalation, SA impersonation |
| **Data Exfiltration** (EX-001–EX-015) | 15 | SQL injection (search, path params, headers), workspace ID manipulation, UUID enumeration, IDOR (docs, messages), prompt injection (direct, system override, encoded), vector store direct access, pagination abuse, direct GCS, parameter pollution, path traversal |

### Red Team Infrastructure

- Isolated GCP project (`latentarchon-redteam`) with zero permissions on target projects
- Attack logs stored in versioned GCS bucket with 365-day retention
- Monitoring dashboard for attack requests, IAM denials, auth failures, WAF blocks
- Safety controls: staging-only lock, rate limiting, dry-run mode, kill-on-breach switch

### MITRE ATT&CK Mapping

Each attack is tagged with relevant MITRE ATT&CK technique IDs and NIST 800-171 controls for compliance reporting.

---

## Appendix: File Reference

| File | Security Controls |
|---|---|
| `cmd/server/main.go` | Server startup, CORS, security headers, rate limiting, graceful shutdown, document upload handler |
| `cmd/server/connect_interceptors.go` | Auth interceptor, MFA enforcement, tenant isolation, session timeouts, logging interceptor |
| `cmd/server/connect_ratelimit.go` | Per-user rate limiting with service tiers |
| `cmd/server/ratelimit.go` | IP-based token bucket rate limiter |
| `cmd/server/connect_organization.go` | Org RBAC, invite rate limiting, master_admin escalation prevention |
| `cmd/server/connect_workspace.go` | Workspace RBAC, access tier, invite rate limiting |
| `cmd/server/connect_document.go` | Document CRUD with workspace access verification |
| `cmd/server/connect_conversation.go` | RAG pipeline with workspace access verification, input validation |
| `shared-go/auth/auth.go` | Firebase Auth, App Check, token caching, MFA status, user management |
| `shared-go/config/config.go` | Environment validation, domain cross-validation, session timeout config |
| `shared-go/postgres/pgx.go` | Cloud SQL Connector, IAM auth, connection pool, slow query detection |
| `shared-go/postgres/rls.go` | RLS enforcement: workspace-scoped, admin-scoped, and unscoped DBTX wrappers |
| `shared-go/postgres/schema.sql` | Database schema, RLS policies, CHECK constraints, indexes |
| `shared-go/postgres/roles.sql` | Three least-privilege database roles |
| `shared-go/transport/http.go` | CORS, security headers, Google OIDC auth, recovery interceptor |
| `internal/audit/logger.go` | Audit event system, SIEM integration, trace correlation |
| `internal/document/service.go` | Upload hardening, magic-byte validation, filename sanitization, malware scanning |
| `internal/malware/clamav.go` | ClamAV REST client for malware scanning |
| `internal/vectorstore/client.go` | Vertex AI Vector Search with workspace token restrictions |
| `internal/organization/service.go` | Org CRUD, secure invite tokens, last-admin guard |
| `internal/workspace/service.go` | Workspace CRUD, access checks, CUI access tiers |
| `internal/telemetry/otel.go` | OpenTelemetry tracing initialization |
| `Dockerfile` | Multi-stage build, distroless runtime, static binary |


---

# SECTION 2: CHATGPT — Backend Sales Overview

> Source: `backend/docs/security/CHATGPT_Backend_Sales_Overview.md`

---

# Latent Archon Backend — Architecture and Security Overview

Version: Mar 22, 2026

## Executive Summary
Latent Archon provides a multi-tenant Retrieval-Augmented Generation (RAG) assistant with strong access controls, rigorous auditability, and enterprise-ready operations on Google Cloud. The backend is a Go monolith exposing type-safe APIs via Connect-RPC (gRPC for browsers) and runs in Cloud Run with private Cloud SQL, Cloud Storage (GCS), Vertex AI Vector Search, and Document AI for ingestion.

Security is layered: Identity Platform/Firebase Auth with mandatory TOTP MFA, tenant isolation enforcement, per-request and per-user rate limiting, strict CORS and security headers, Google OIDC verification for internal tasks, Row-Level Security (RLS) in Postgres, and vector-level token restrictions. Comprehensive audit logs, OpenTelemetry tracing/metrics, and health/readiness endpoints support production operations and compliance.

## System Overview
- API surface: Connect-RPC for all public/admin operations (server-streaming for app); minimal REST only for health, readiness, and multipart uploads.
- Server modes (single binary):
  - public: user-facing app + search
  - admin: administration (org/workspace/doc/member CRUD)
  - ops: internal task endpoints (document processing, DLQ), Google OIDC protected
- Core domain services:
  - organization, workspace: CRUD and membership/authorization
  - document: upload → process → chunk → embed → index → manage lifecycle
  - conversation: RAG pipeline (embed → vector search → hydrate → prompt → stream response)
  - gentext: centralized text generation with streaming and model fallback
  - chatmessage: message storage/retrieval/rating
  - audit: structured audit events to Postgres + Cloud Logging

## Data Flow (App)
1) Authenticated user sends `SendMessage` (Connect server-streaming) with selected `workspace_ids`.
2) Access check: user must be a member of each workspace.
3) If configured, query is embedded (Vertex AI), searched across vector index with token restrictions on `workspace_id`.
4) Matching chunk vector IDs hydrate document text from Postgres; prompt is built; Gemini generation streams back chunks.
5) Messages are persisted asynchronously with correlation IDs for auditability.

## Data Flow (Document Ingestion)
1) Authenticated admin uploads document via REST multipart with `workspace_id`, `title`, optional `description`, `tags`.
2) Hardening: file size cap (50MB), MIME allowlist, magic-byte validation, optional ClamAV malware scan.
3) File stored to GCS; DB record created with content hash (SHA-256) for deduplication.
4) Processing via Cloud Tasks (preferred) or background goroutine (dev): download from GCS → extract (Document AI for PDFs/images/DOCX; passthrough for text) → chunk → embed → upsert vectors with token restrictions (`workspace_id`, `document_id`) → persist chunks to Postgres.
5) Status and counts updated; soft-delete and purge supported for lifecycle.

## Security Architecture
- Identity and MFA
  - Identity Platform/Firebase Auth for JWT verification; cache with TTL for performance.
  - TOTP MFA is required for all RPCs except initial auth flows; enforced server-side.
  - Step-up MFA: sensitive RPCs (invites, removals, deletions) require recent `auth_time`.
  - Session management (NIST 800-171 AC-12): idle and absolute timeouts configurable via env.
  - Firebase App Check: enforced when available; Connect interceptors forward `X-Firebase-AppCheck`.
- Tenant Isolation
  - Optional requirement that tokens originate from a tenant; rejection if project-level when required.
  - Defense-in-depth: `X-Tenant-ID` header must match token tenant; host subdomain validation to prevent cross-tenant routing mistakes.
- Authorization and Data Isolation
  - Workspace access validated per request (server-side membership check).
  - Postgres Row-Level Security (RLS): `app.workspace_ids` and `app.rls_bypass` GUCs set per-transaction.
  - DB wrappers enforce fail-closed semantics when workspace scope is missing.
  - Vertex AI Vector Search token restrictions ensure workspace- and document-scoped retrievals.
- Transport and Headers
  - TLS termination via Cloud Run; HSTS, CSP `default-src 'none'`, X-Frame-Options DENY, no-store caching, CORP/COOP set.
  - Strict Connect-aware CORS: allowlist aligns with configured domains; dev localhost only in development.
  - Request size controls: 4MB Connect-RPC body limit; 50MB multipart upload cap with server-side enforcement.
- Abuse Resistance
  - IP-based rate limit for all HTTP; user-keyed bucket for RPCs and uploads; per-invite stricter limiter.
  - Document upload hardening: magic-byte validation, MIME allowlist, optional ClamAV.
- Internal-to-internal Auth (Zero-Trust)
  - Google OIDC verification for ops endpoints (Cloud Tasks/Scheduler): signature, issuer, audience, and service-account allowlist are enforced.

## Audit, Observability, and Operations
- Audit Logging
  - Best-effort writes to `audit_events` via sqlc; includes user, action, status, optional resource type/ID.
  - Auto-enriched with request_id, tenant_id, trace/span IDs, IP, User-Agent, platform.
  - Security-sensitive actions are additionally emitted at Warn level to Cloud Logging for SIEM.
- Tracing and Metrics
  - OpenTelemetry tracing spans for HTTP and Connect-RPC.
  - Metrics middleware emits request counts/latency/error rates; slow-query warnings in DB layer.
- Health and Readiness
  - `/health` liveness; `/readyz` deep readiness probes that reflect availability of DB, vector store, document service, Cloud Tasks, gentext, and message storage.
- Graceful Shutdown
  - Signal-driven server stop, bounded shutdown timeouts, and tracking of background workers to drain streams/persists.

## Compliance Anchors (NIST 800‑171-aligned controls)
- IA-2 (Identification and Authentication): Firebase Auth for user identity; TOTP MFA enforced for RPCs; App Check verifies client integrity when configured.
- AC-3 (Access Enforcement): Workspace membership checks server-side; Postgres RLS enforces workspace scoping at the data layer.
- AC-6 (Least Privilege): Separate Cloud Run services and least-privilege service accounts; admin bypass only via explicit `app.rls_bypass` GUC in controlled code paths.
- AC-12 (Session Termination/Timeout): Idle and absolute session timeouts enforced in auth interceptor; step-up MFA for sensitive operations.
- AU-2/AU-6 (Audit Events and Review): Structured audit events persisted with correlation context; Cloud Logging integration for monitoring/alerts.
- SC-7/SC-8 (Boundary and Transmission Protection): Strict CORS and security headers; TLS via Cloud Run.
- SC-28 (Protection of Information at Rest): GCS and Cloud SQL use Google-managed encryption at rest; data scoping via RLS.
- SI-3 (Malicious Code Protection): Optional ClamAV scanning hook for uploads; MIME and magic-byte validation by default.

Note: Additional programmatic and organizational controls (e.g., account management, vulnerability management, incident response processes) are documented in repository READMEs and Incident Response documentation and are complemented by GCP-native services and policies.

## Data Handling and Privacy
- Data types: user identity (UID/email/display name), documents and derived chunks/embeddings, messages, audit events.
- Storage: Cloud SQL (primary system of record); GCS for original objects.
- Retention and Deletion: soft delete with retention; purge routine removes DB rows, vectors, and GCS objects.
- Multi-tenant segregation: enforced in DB (RLS), vector store (token restrict), and request path (membership and tenant checks).

## Deployment and Environments
- Environments: development, staging, production. Domains drive CORS allowlists and config validation.
- Cloud Run services: public (app API), admin (admin API), ops (internal tasks). Private VPC egress to Cloud SQL; least-privilege service accounts.
- Dependencies:
  - Cloud SQL (Postgres) via Cloud SQL Connector with private IP and IAM AuthN.
  - GCS for document storage.
  - Vertex AI Vector Search (index + endpoint) for embeddings and nearest-neighbor queries.
  - Document AI for PDF/image/DOCX extraction.
  - Cloud Tasks/Scheduler for async processing with OIDC-authenticated callbacks.

## Configuration and Limits (key)
- Server modes: `SERVER_MODE` in {public|admin|ops}; `ENVIRONMENT` in {development|staging|production}.
- Domains: `API_DOMAIN`, `ADMIN_DOMAIN`, `APP_DOMAIN` drive CORS allowlists.
- DB: `DB_CONNECTION_NAME`, `DB_NAME`, `DB_IAM_USER`.
- Storage/AI: `GCS_DOCUMENTS_BUCKET`, `DOCUMENT_AI_PROCESSOR_ID`, `DOCUMENT_AI_LOCATION`, `VERTEX_AI_REGION`, `EMBEDDING_MODEL` (default `gemini-embedding-2-preview`), `EMBEDDING_INDEX_ID`, `EMBEDDING_DEPLOYMENT_ID`, `EMBEDDING_DIMENSIONS`, `EMBEDDING_REGION`, `VERTEX_AI_INDEX_ENDPOINT`.
- Tasks: `DOCUMENT_PROCESSING_QUEUE_NAME`, `DOCUMENT_PROCESSING_ENDPOINT_URL`, `CLOUD_TASKS_REGION`.
- Sessions: `SESSION_IDLE_TIMEOUT_MIN` (default 30), `SESSION_ABSOLUTE_TIMEOUT_MIN` (default 720).
- RPC limits: 4MB Connect-RPC read max; Upload limits: 50MB size cap and MIME/magic-byte validation; Rate limits: 60 req/min default, 200 req/min ops; per-user buckets for RPC/upload; stricter for invites.

## Residual Risk and Hardening Roadmap
- Enable ClamAV scanning in all non-dev environments for file uploads.
- Consider adaptive rate limits and IP reputation for public endpoints behind Cloud Armor/WAF (infra-level).
- Expand sensitive RPC catalog and step-up MFA windows based on usage patterns.
- Add automated purge job and retention policy configuration surfaced to admins.

## References (Repo)
- Code: `cmd/server/*.go` (routes, interceptors, handlers), `internal/*` (services), `shared-go/*` (auth, config, postgres, transport, tasks).
- Security controls in code:
  - Auth/MFA/App Check: `cmd/server/connect_interceptors.go`, `shared-go/auth/auth.go`
  - RLS: `shared-go/postgres/rls.go`, `shared-go/postgres/pgx.go`
  - CORS/Headers: `cmd/server/main.go` (CORS, headers), `shared-go/transport/http.go`
  - Rate limiting: `cmd/server/ratelimit.go`
  - OIDC for ops: `shared-go/transport/http.go`
  - Upload hardening & malware hook: `internal/document/service.go`
  - Vector token restricts: `internal/vectorstore/client.go`
  - Audit: `internal/audit/logger.go`
  - SSO/SCIM: `internal/sso/service.go`, `internal/sso/scim_handler.go`, `internal/sso/admin_handler.go`
  - Per-tenant IP allowlisting: `internal/cloudarmor/service.go`
  - Email (Identity Platform): `internal/email/archon_service.go`
- Additional docs: `docs/APPCHECK_ENFORCEMENT.md`, `docs/DATABASE_MIGRATIONS.md`, `docs/MAGIC_LINK_ARCHITECTURE.md`, `docs/TENANT_CONFIGURATION.md`, `INCIDENT_RESPONSE.md`.

## Security-Relevant Configuration Flags
- `REQUIRE_TENANT` — Enforce Identity Platform tenant presence and matching; rejects project-level tokens when true.
- `SESSION_IDLE_TIMEOUT_MIN` — Idle timeout (AC-12); default 30.
- `SESSION_ABSOLUTE_TIMEOUT_MIN` — Absolute session lifetime (AC-12); default 720 (12h).
- `CLAMAV_ENDPOINT` — Enable malware scanning for uploads when set.
- `EMBEDDING_MODEL` (default `gemini-embedding-2-preview`), `EMBEDDING_INDEX_ID`, `EMBEDDING_DEPLOYMENT_ID`, `EMBEDDING_DIMENSIONS`, `EMBEDDING_REGION`, `VERTEX_AI_INDEX_ENDPOINT` — Vector search configuration.

## Threat Model and Mitigations
- Cross-tenant data exposure
  - Mitigations: Tenant header and host-subdomain checks; Postgres RLS on `app.workspace_ids`; vector token restrictions; per-request workspace membership checks.
- Forged/invalid JWTs or alg:none confusion
  - Mitigations: Firebase SDK verification only (no custom JWT parsing); App Check verification when available; Connect-RPC interceptor rejects invalid/missing Bearer.
- MFA bypass or stale sessions
  - Mitigations: Mandatory MFA on all RPCs except initial auth; step-up MFA (recent `auth_time`) for sensitive RPCs; idle/absolute timeouts (AC-12).
- CORS/origin abuse and CSRF-like cross-origin calls
  - Mitigations: Strict Connect-aware CORS allowlist; security headers (CSP `default-src 'none'`, X-Frame-Options DENY, HSTS, CORP/COOP); preflight handling.
- Excessive resource consumption (DoS), abusive automation
  - Mitigations: Global IP rate limit; per-user token buckets for RPC and uploads; request size limits (4MB RPC, 50MB uploads).
- Malicious or spoofed uploads
  - Mitigations: MIME allowlist; magic-byte validation; optional ClamAV; SHA-256 dedup; sanitized filenames; GCS object isolation per document.
- IDOR / unauthorized object access
  - Mitigations: Server-side membership checks; RLS fail-closed semantics; vector-layer token restricts; ops endpoints require Google OIDC with allowlisted service accounts.

## Data Governance Details
- Data minimization: user identity (UID, email, display name), documents, derived chunks/embeddings, messages, audit events.
- Encryption: TLS in transit; at-rest encryption via GCP-managed keys for Cloud SQL and GCS; Vertex AI managed by Google Cloud.
- Retention: soft-delete for documents with purge flow; audit logs persisted in DB and duplicated to Cloud Logging; retention policies governed by environment.
- Deletion and account lifecycle: tokens can be revoked and users deleted in Identity Platform; document soft-delete and purge supported; background tasks isolated by OIDC.
- Access reviews: workspace and org membership APIs enable periodic access reviews; audit logs available for administrative review.

## Operational Runbooks and SRE Practices
- Incident Response: documented in `INCIDENT_RESPONSE.md`; audit events and Cloud Logging support triage and forensics; request IDs and traces link logs across components.
- Readiness/Health: `/readyz` checks all critical dependencies with mode-aware gating; `/health` for liveness.
- Background processing: Cloud Tasks preferred with OIDC; bounded timeouts and fallbacks for dev.
- Secrets and config: environment-driven configuration with explicit validation; least-privilege service accounts per service.

## Testing and Assurance
- Unit and integration tests present across services (e.g., auth interceptors, rate limiting, RLS wrappers, workspace access, app/document handlers).
- Static analysis: `go vet` usage and logging of slow queries; typed Connect-RPC services generated via protobuf.
- Dependency hygiene: version pinning in `go.mod`; Dependabot configuration present in `.github/dependabot.yaml`.
- Security testing: red-team CLI and isolated infra (redteam/ and red-infra/) enable controlled staging exercises; ops endpoints protected by Google OIDC to constrain blast radius during testing.

## Compliance Appendix (overview)
- NIST 800-171 (selected mappings)
  - IA-2: Identity with Firebase Auth; MFA enforced server-side; App Check for client integrity.
  - AC-3/AC-6: Access enforcement via server-side checks and Postgres RLS; least-privilege service accounts; admin bypass only through explicit guarded paths.
  - AC-12: Idle and absolute session timeouts; step-up MFA for sensitive RPCs.
  - AU-2/AU-6: Structured audit events with correlation IDs, tenant, IP/UA, trace/span; logs exported to Cloud Logging for review/alerting.
  - SC-7/SC-8: Boundary protection via strict CORS and headers; TLS via Cloud Run; zero-trust OIDC between services.
  - SC-28: Encryption at rest (Cloud SQL, GCS) with Google-managed keys.
  - SI-3: Malware scanning hook; MIME/magic-byte validation.
- CMMC Level 2 alignment: Supported by above technical controls; organizational controls (policy, training, vulnerability management) addressed outside this codebase.
- FedRAMP (baseline alignment): Shared responsibility with GCP services for physical/network controls; application implements identity, access, audit, and data isolation controls described herein.

## Optional Attachments and Diagrams (on request)
- System boundary and data flow diagrams (app, ingestion, ops).
- RLS policy diagram and workspace scoping sequence.
- RBAC/membership sequence for org/workspace operations.

---
This document summarizes the backend’s architecture, security controls, and operations posture for enterprise and public-sector review. It is designed to accompany infrastructure documentation and policies maintained in the infra repositories and GCP organization.


---

# SECTION 3: CLAUDE — Infrastructure Security Review (infra/vpc/org)

> Source: `infra/docs/security/CLAUDE_Infrastructure_Security_Review.md`

---

# Latent Archon — Infrastructure Security Review

> Comprehensive security posture review of the Latent Archon platform infrastructure.
> Covers organization governance (`org/`), network isolation (`vpc/`), and application infrastructure (`infra/`).
> Prepared for government application and compliance evaluation.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Organization-Level Governance (org/)](#2-organization-level-governance)
3. [Network Security (vpc/)](#3-network-security)
4. [Application Infrastructure (infra/)](#4-application-infrastructure)
5. [Identity & Access Management](#5-identity--access-management)
6. [Data Protection & Encryption](#6-data-protection--encryption)
7. [Web Application Firewall (Cloud Armor)](#7-web-application-firewall-cloud-armor)
8. [Audit Logging & SIEM](#8-audit-logging--siem)
9. [Supply Chain & CI/CD Security](#9-supply-chain--cicd-security)
10. [Malware Scanning](#10-malware-scanning)
11. [Red Team & Penetration Testing](#11-red-team--penetration-testing)
12. [Email Service (Identity Platform)](#12-email-service-identity-platform)
13. [Monitoring & Incident Response](#13-monitoring--incident-response)
14. [NIST 800-171 Control Mapping](#14-nist-800-171-control-mapping)
15. [FedRAMP Alignment Summary](#15-fedramp-alignment-summary)

---

## 1. Architecture Overview

Latent Archon is a multi-tenant RAG (Retrieval-Augmented Generation) platform deployed on Google Cloud Platform using a **security-isolation-by-design** architecture.

### Project Isolation

The platform uses a **multi-project GCP architecture** for workload isolation:

| Project | Purpose | Surface |
|---------|---------|---------|
| `latentarchon-app-prod` | App API, Vertex AI, Firebase Auth (user pool) | `app.latentarchon.com` |
| `latentarchon-admin-prod` | Admin API, Ops, Cloud SQL, GCS, Document AI | `admin.latentarchon.com` |
| `prod-vpc-latentarchon` | Shared VPC host — centralized network control | Internal |
| `central-log-latentarchon` | Centralized logging and monitoring | Internal |
| `kms-proj-*` | Dedicated KMS Autokey projects per environment folder | Internal |

**Why multi-project?** Separate GCP projects provide hard IAM boundaries, separate billing, independent audit trails, and blast-radius containment. A compromise in the user-facing app project cannot access the admin project's Cloud SQL, GCS, or Document AI resources.

### Service Architecture

| Service | Runtime | Access | Purpose |
|---------|---------|--------|---------|
| `public` (App API) | Cloud Run | Public (Firebase Auth at app layer) | User-facing app, streaming, semantic search |
| `admin` (Admin API) | Cloud Run | Public (Firebase Auth at app layer) | Document ingestion, member management, workspace admin |
| `ops` | Cloud Run | **IAM-private only** | Document processing, cron jobs, embedding operations |
| `ClamAV` | Cloud Run | **Internal only** | Malware scanning sidecar for uploaded documents |

The `ops` service has **zero public exposure** — it is only invocable by Cloud Tasks, Cloud Scheduler, and explicitly authorized service accounts via GCP IAM.

### Infrastructure as Code

All infrastructure is defined in **Terraform/Terragrunt** and version-controlled in Git:
- `org/` — GCP Organization Foundation Blueprint (org policies, folders, projects, shared VPC, centralized logging)
- `vpc/` — VPC network, firewall rules, FQDN-based egress policy, Cloud NAT
- `infra/` — Application infrastructure (Cloud Run, Cloud SQL, Vertex AI, IAM, secrets, monitoring)

No infrastructure is provisioned manually. All changes go through code review and CI/CD validation.

---

## 2. Organization-Level Governance

**Source:** `org/`

The organization layer is based on the **Google Cloud Foundation Blueprint**, following Google's [enterprise setup checklist](https://cloud.google.com/docs/enterprise/setup-checklist).

### 2.1 Organization Policies (Enforced)

Ten organization-wide policies are enforced across all projects:

| Policy | Constraint | Effect |
|--------|-----------|--------|
| **Storage Public Access Prevention** | `storage.publicAccessPrevention` | All GCS buckets are prevented from being made public |
| **Require OS Login** | `compute.requireOsLogin` | SSH access requires IAM-based OS Login (no SSH keys) |
| **VM External IP Restriction** | `compute.vmExternalIpAccess` | VMs cannot have external IPs (enforced deny) |
| **Disable Nested Virtualization** | `compute.disableNestedVirtualization` | Prevents VM escape attack vector |
| **Disable Serial Port Access** | `compute.disableSerialPortAccess` | No serial console access to VMs |
| **SQL Restrict Authorized Networks** | `sql.restrictAuthorizedNetworks` | Cloud SQL cannot use authorized networks (public IP allow-lists) |
| **SQL Restrict Public IP** | `sql.restrictPublicIp` | Cloud SQL instances cannot have public IPs |
| **Restrict XPN Lien Removal** | `compute.restrictXpnProjectLienRemoval` | Shared VPC liens cannot be removed |
| **Skip Default Network Creation** | `compute.skipDefaultNetworkCreation` | No default VPC created in new projects (eliminates default-open firewall rules) |
| **Disable VPC External IPv6** | `compute.disableVpcExternalIpv6` | No external IPv6 addresses |

### 2.2 CMEK Autokey Encryption

Customer-Managed Encryption Keys (CMEK) are enforced at the folder level via **Autokey**:

- Dedicated KMS projects per environment folder (Production, Non-Production, Development)
- `gcp.restrictNonCmekServices` org policy denies **35+ GCP services** from using Google-managed keys — forces CMEK for:
  - Cloud SQL, Cloud Storage, Cloud Run, Secret Manager, Artifact Registry, Vertex AI, Document AI, Pub/Sub, Logging, and more
- `gcp.restrictCmekCryptoKeyProjects` limits which projects can host KMS keys — only the dedicated KMS projects

### 2.3 Resource Hierarchy

```
Organization (latentarchon.com)
├── Common/
│   ├── prod-vpc-latentarchon     (Shared VPC Host — Production)
│   ├── staging-vpc-latentarchon  (Shared VPC Host — Staging)
│   └── central-log-latentarchon  (Centralized Logging & Monitoring)
├── Production/
│   ├── latentarchon-app-prod    (App: App API + SPA)
│   ├── latentarchon-admin-prod   (Admin: API + Ops + Data)
│   └── kms-proj-*                (KMS Autokey)
├── Non-Production/
│   ├── latentarchon-app-staging
│   ├── latentarchon-admin-staging
│   └── kms-proj-*
└── Development/
    └── kms-proj-*
```

### 2.4 Shared VPC

Both production and staging environments use **Shared VPC** for centralized network governance:
- VPC host projects are in the `Common` folder
- Service projects (app, admin) are attached as Shared VPC service projects
- Network policies are managed centrally; service project teams cannot modify firewall rules
- Subnets have **VPC Flow Logs enabled** at 50% sampling with full metadata for network forensics

### 2.5 Centralized Logging

An organization-level log sink captures **all audit logs** across every project and routes them to a centralized log bucket:

- **Admin Activity** logs (always on, free)
- **System Events**
- **Data Access** logs
- **Access Transparency** logs (Google staff access)

Log retention: 30 days in centralized log bucket (configurable). Separate long-term retention buckets exist per project.

### 2.6 Centralized Monitoring

All projects are enrolled in a single **metrics scoping project** (`central-log-latentarchon`), providing:
- Single-pane-of-glass monitoring across all projects
- Cross-project alerting
- Unified dashboards

### 2.7 Security Groups

IAM is managed via Google Groups for role-based access:
- `gcp-developers@latentarchon.com` — Development access
- `gcp-logging-monitoring-viewers@latentarchon.com` — Log/metric read access
- `gcp-security-admins@latentarchon.com` — Security admin access
- `app-prod@latentarchon.com` / `admin-prod@latentarchon.com` — Production project access
- `app-staging@latentarchon.com` / `admin-staging@latentarchon.com` — Staging project access

All groups are `security` type, managed via Terraform.

---

## 3. Network Security

**Source:** `vpc/`

### 3.1 VPC Architecture

- **Custom VPC** — `auto_create_subnetworks = false` (no default subnets with overly permissive ranges)
- **Regional routing** — traffic stays within-region
- **Private Google Access** enabled on all subnets — services access Google APIs without traversing the public internet
- **Private Service Connect (PSC)** — Vertex AI Vector Search accessed via PSC endpoint within the VPC

### 3.2 FQDN-Based Egress Firewall (Zero Trust Network)

A **network firewall policy** implements FQDN-based egress control — effectively a **network-level allowlist**:

**Priority 100 — Google APIs (allowed):**
- `googleapis.com`, `oauth2.googleapis.com`, `sqladmin.googleapis.com`, `cloudsql.googleapis.com`
- `iamcredentials.googleapis.com`, `cloudtasks.googleapis.com`, `secretmanager.googleapis.com`
- `aiplatform.googleapis.com`, `generativelanguage.googleapis.com`, `storage.googleapis.com`
- `logging.googleapis.com`, `monitoring.googleapis.com`
- `firebaseauth.googleapis.com`, `identitytoolkit.googleapis.com`, `securetoken.googleapis.com`
- `firebaseappcheck.googleapis.com`

**Priority 200 — Internal APIs (allowed):**
- `app.latentarchon.com`, `admin.latentarchon.com` (production)
- `app.staging.latentarchon.com`, `admin.staging.latentarchon.com` (staging)

**Priority 65534 — Default DENY ALL:**
- `0.0.0.0/0` — all protocols blocked

**This means: the platform cannot exfiltrate data to any external endpoint.** Only explicitly allowlisted Google APIs and internal services are reachable. Email is sent via Identity Platform's server-side `sendOobCode` API (covered by the `identitytoolkit.googleapis.com` allowlist), eliminating the need for any external email provider egress.

### 3.3 Ingress Controls

- **Cloud SQL:** Only accessible from Cloud Shell admin ranges (`35.235.240.0/20`) and Direct VPC Cloud Run services
- **Cloud Tasks:** Specific Google service IP ranges for task dispatch
- **Internal VPC:** Communication between subnet components (`10.10.0.0/24`) and VPC Connector range (`10.8.0.0/28`)
- **No public SSH/RDP** — VMs (if any) require IAP tunneling

### 3.4 Cloud NAT

- Cloud Router + Cloud NAT provides outbound connectivity for private-IP Cloud Run services
- NAT logging enabled (errors only) for troubleshooting
- All Cloud Run services use **Direct VPC egress** (private subnet IPs, not public IPs)
- `prevent_destroy = true` on router and NAT gateway

### 3.5 Private Service Connect (PSC)

Vertex AI Vector Search is accessed via PSC:
- **Deterministic internal IP** (`10.10.0.5`) for the PSC endpoint
- Traffic stays within the VPC — no public internet traversal for AI operations
- Project allowlist restricts which projects can use the endpoint

---

## 4. Application Infrastructure

**Source:** `infra/`

### 4.1 Cloud Run Services

All services run on **Cloud Run Gen2** with:

- **Direct VPC egress** — services use private IPs from the VPC subnet
- **VPC network interface** binding — all traffic routes through the VPC
- **All-traffic egress** — outbound traffic goes through VPC (subject to firewall policy)
- **Resource limits** — CPU and memory bounded per service
- **Concurrency controls** — per-service concurrency limits

Production configuration:
| Service | CPU | Memory | Min/Max Scale | Auth |
|---------|-----|--------|---------------|------|
| `public` | 1 vCPU | 512Mi | 1/10 (always warm) | Firebase Auth (app layer) |
| `admin` | 1 vCPU | 512Mi | 0/5 | Firebase Auth (app layer) |
| `ops` | 2 vCPU | 1Gi | 0/5 | **IAM-private** |

### 4.2 Cloud SQL (PostgreSQL 15)

- **Private IP only** in production (`cloud_sql_enable_public_ip = false`)
- **IAM authentication** — service accounts authenticate via GCP IAM, not passwords
- **Strong random passwords** for the `postgres` superuser (generated by `random_password` with special characters)
- **Deletion protection** enabled
- **Automated daily backups** with point-in-time recovery
- **Maintenance windows** configured for low-traffic periods
- **Private VPC peering** — database is only accessible from within the VPC
- **Encrypted connections** enforced
- **Least-privilege database roles:**
  - Service account: `SELECT, INSERT, UPDATE, DELETE` on application tables only
  - Admin account: Schema migration privileges
  - Read-only account: `SELECT` only
  - Ops account: Processing-specific privileges

### 4.3 Cloud Storage

All buckets enforce:
- **Uniform bucket-level access** (no ACLs)
- **Public access prevention** (org policy + bucket setting)
- **Versioning** enabled
- **Lifecycle rules** — automatic deletion after defined retention periods
- **CORS** restricted to specific origins for document upload bucket

Buckets:
- Build cache, Vertex AI data, Cloud Build staging, document storage, Terraform logs, migration logs, job audit logs (CMEK-encrypted)

### 4.4 Firebase App Check

- **reCAPTCHA Enterprise** as the attestation provider
- Configurable enforcement mode on Firebase Authentication (`identitytoolkit.googleapis.com`)
- Prevents automated/bot access to authentication APIs

### 4.5 Secret Manager

- Secrets managed via Terraform with `google_secret_manager_secret`
- **Automatic replication** across regions
- Labels for service ownership and purpose tracking
- Secrets referenced by Cloud Run services via environment variables

### 4.6 Artifact Registry

- **Container Scanning API** enabled (`containerscanning.googleapis.com`) — automatic vulnerability scanning of container images
- Docker repositories for backend services and frontend applications
- PyPI and NPM proxy repositories (controls supply chain for dependencies)
- Go modules repository

---

## 5. Identity & Access Management

### 5.1 Service Account Least Privilege

Eight purpose-specific service accounts with narrowly scoped IAM roles:

| Service Account | Purpose | Key Roles |
|----------------|---------|-----------|
| `mainapp` | Public + Admin Cloud Run services | `cloudsql.client`, `cloudsql.instanceUser`, `storage.objectAdmin`, `aiplatform.user`, `run.invoker` |
| `backend-ops` | Ops service (document processing) | `cloudsql.client`, `cloudsql.instanceUser`, `storage.objectAdmin`, `aiplatform.user`, `cloudtasks.enqueuer`, `documentai.apiUser` |
| `mainapp-admin` | Database migrations | `cloudsql.admin`, `cloudsql.client` |
| `mainapp-readonly` | Read-only database access | `cloudsql.client`, `cloudsql.instanceUser` |
| `cloudbuild-sa` | CI/CD builds | `cloudbuild.builds.builder`, `storage.admin`, `artifactregistry.writer`, `run.admin` |
| `terraform-sa` | Infrastructure provisioning | Scoped IAM for Terraform operations |
| `github-actions` | GitHub Actions deployment | Scoped for Cloud Run deployments |
| `cloud-tasks` | Task queue operations | `cloudtasks.enqueuer` |
| `cloud-scheduler` | Cron job execution | `run.invoker` (ops service only) |

### 5.2 Workload Identity Federation (Keyless Auth)

GitHub Actions authenticates to GCP via **OIDC Workload Identity Federation** — **no service account keys**:

- Workload Identity Pool with OIDC provider (`token.actions.githubusercontent.com`)
- **Repository-owner condition**: `assertion.repository_owner == 'latentarchon'` — only the organization's repositories can authenticate
- Attribute mapping: `repository`, `actor`, `repository_owner` for audit tracing
- Per-repository binding to `github-actions` and `terraform-sa` service accounts
- `prevent_destroy = true` on pool and provider

### 5.3 MFA Enforcement

Multi-factor authentication is enforced at the application layer:
- Firebase Authentication with TOTP-based MFA
- Backend middleware checks `sign_in_second_factor` token claim
- All data routes require MFA verification
- Authentication-only routes (e.g., `/api/auth/me`) require auth but not MFA (allows MFA enrollment flow)

### 5.4 Cloud Scheduler OIDC

All scheduled jobs authenticate to the ops service using **OIDC tokens** with audience validation:
- Service account: `cloud-scheduler` (purpose-specific)
- Token audience: ops service URL
- IAM binding: `roles/run.invoker` only on the ops service

---

## 6. Data Protection & Encryption

### 6.1 Encryption at Rest

| Layer | Mechanism | Key Management |
|-------|-----------|----------------|
| Cloud SQL | CMEK (org policy enforced) | HSM-backed, 90-day rotation |
| Cloud Storage | CMEK (org policy enforced) | HSM-backed, 90-day rotation |
| Secret Manager | CMEK (org policy enforced) | Automatic |
| Audit Log Bucket | CMEK (explicit KMS key) | 90-day rotation, `prevent_destroy` |
| Vertex AI Indexes | CMEK (org policy enforced) | Automatic |

### 6.2 Encryption in Transit

- **HTTPS enforced** — HTTP→HTTPS redirect with `MOVED_PERMANENTLY_DEFAULT`
- **Google-managed SSL certificates** covering all domains
- **SSL validation** on uptime checks (`validate_ssl = true`)
- **Private Service Connect** — Vertex AI traffic stays within VPC (never hits public internet)
- **Cloud SQL connections** — via private VPC peering, IAM-authenticated

### 6.3 KMS Key Lifecycle

The KMS module includes:
- **90-day automatic rotation** of all crypto keys
- **HSM protection level** for Cloud SQL and GCS keys
- **Destroy-scheduled duration** — safety window before permanent key deletion
- **KMS lifecycle event alerts** — notifications on key disable, destroy, or version state changes

---

## 7. Web Application Firewall (Cloud Armor)

**Source:** `infra/modules/cloud-armor/`

Cloud Armor WAF is deployed in front of all load-balanced services with comprehensive protection:

### 7.1 OWASP Top 10 Protection

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

### 7.2 Rate Limiting

- Configurable requests-per-interval threshold
- Automatic **ban** on threshold exceedance (not just rate-limit — IP is banned for configurable duration)
- Protects against DDoS, brute force, and credential stuffing

### 7.3 Additional Controls

- **HTTP Method Enforcement** — only allowed methods (GET, POST, OPTIONS) pass; TRACE, DELETE, PATCH blocked
- **Origin Header Restriction** — requests with disallowed `Origin` headers are denied
- **Bot Blocking** — empty/missing `User-Agent` denied; known scanner/attack tools (curl, wget, sqlmap, nikto, nmap, nuclei, etc.) blocked
- **IP Allowlisting** — configurable for government/VPN IP ranges

---

## 8. Audit Logging & SIEM

### 8.1 GCP-Native Audit Logs

Organization-level log sink captures:
- **Admin Activity** — all API calls that modify resources (always on)
- **Data Access** — reads of resource data and metadata
- **System Events** — Google-initiated system events
- **Access Transparency** — Google staff access to customer data

Destination: centralized log bucket in `central-log-latentarchon` project.

### 8.2 Application-Level Audit Logs

The Go backend emits structured `AUDIT_EVENT` JSON logs to stdout, which Cloud Run forwards to Cloud Logging. These are routed to BigQuery via a dedicated sink for SIEM queries.

Captured events include:
- Authentication success/failure
- Member invitations, removals, role changes
- Document uploads, deletions
- Admin bootstrap and role escalation
- Workspace creation and modifications

### 8.3 BigQuery Audit Dataset

- Partitioned tables for efficient querying
- Configurable table and partition expiration
- Both GCP-native and application audit logs in a single dataset

### 8.4 Security Alert Policies

| Alert | Trigger | Purpose |
|-------|---------|---------|
| **IAM Change Alert** | `SetIamPolicy`, `CreateServiceAccount`, `DeleteServiceAccount` | Detect unauthorized IAM modifications |
| **Auth Failure Spike** | High rate of `AUDIT_EVENT` with `status=failure` | Brute force / credential stuffing detection |
| **Privilege Escalation** | Member invite/remove, role change, admin bootstrap | Detect unauthorized privilege changes |
| **Data Deletion** | `document.delete` audit events | Detect unauthorized data destruction |
| **KMS Key Lifecycle** | Key disable, destroy, version state change | Detect key compromise attempts |
| **API Down** | Uptime check failure >5 min | Service availability alerting |

### 8.5 Cloud Run Job Audit Logs

Dedicated CMEK-encrypted GCS bucket for Cloud Run Job execution logs:
- Captures start, exit, complete, and warning/error events
- 365-day retention lifecycle
- Writer identity isolated (unique per sink)

---

## 9. Supply Chain & CI/CD Security

### 9.1 Workload Identity Federation (No Static Keys)

- **Zero service account keys** in CI/CD — GitHub Actions uses OIDC tokens
- Repository-owner validation prevents unauthorized repos from authenticating
- Attribute mapping enables per-actor, per-repository audit trails

### 9.2 Container Security

- **Container Scanning API** enabled — automatic vulnerability scanning of all images in Artifact Registry
- **Artifact Registry proxy repositories** for PyPI and NPM — dependencies are cached and scanned through Google's infrastructure
- Single base image (`archon`) differentiated by `SERVER_MODE` env var — reduces image sprawl and patching surface

### 9.3 CI/CD Pipeline

The Terragrunt CI workflow (`terragrunt-ci.yml`) enforces:

1. **Format Check** — `terraform fmt` and `terragrunt hclfmt` on every PR
2. **Tenant Map Consistency** — cross-repo validation of configuration alignment
3. **Validate** — `terragrunt validate` for all module/environment combinations (staging × production × app × admin)
4. **Plan on PR** — automatic `terragrunt plan` with output posted to PR comments for review
5. **Drift Detection** — on merge to `main`, checks for configuration drift in staging

### 9.4 GitHub Repository Variables

CI/CD variables (project ID, region, service account, registry, etc.) are managed via Terraform in `github_repository_variables.tf` — no manual configuration in GitHub.

---

## 10. Malware Scanning

**Source:** `infra/modules/clamav/`

A **ClamAV REST API** runs as a private Cloud Run sidecar:

- **Image:** `benzino77/clamav-rest` (ClamAV with REST API)
- **Access:** `internal` ingress only — no public access
- **IAM:** Only the `mainapp-admin` service account can invoke it (principle of least privilege)
- **VPC:** Runs within the VPC with Direct VPC egress
- **Resources:** ~2GB RAM for virus definition loading, low concurrency (CPU-bound scanning)
- **Virus DB Updates:** Automatic via ClamAV's built-in freshclam
- **Integration:** Admin API calls ClamAV before accepting document uploads

Every document uploaded to the platform is scanned for malware before processing.

---

## 11. Red Team & Penetration Testing

**Source:** `redteam/` and `red-infra/`

### 11.1 Automated Security Testing Suite

A Go CLI tool (`redteam/`) implements **44 automated security tests** across three attack suites:

**Auth Bypass (17 tests):** No auth, empty bearer, malformed JWT, expired JWT, forged JWT, wrong audience, modified claims, cross-pool auth, MFA bypass, TOTP replay, brute force, alg:none, alg confusion, session fixation, CORS bypass, HTTP method override

**Privilege Escalation (12 tests):** Cloud SQL access, GCS access, Cloud Tasks access, KMS access, admin API from app token, ops endpoint access, IAM escalation, service account impersonation

**Data Exfiltration (15 tests):** SQL injection (search, path params, headers), workspace ID manipulation, UUID enumeration, IDOR (docs, messages), prompt injection (direct, system override, encoded), vector store direct access, pagination abuse, direct GCS access, parameter pollution, path traversal

### 11.2 Compliance Mapping

Every test case is tagged with:
- **MITRE ATT&CK** technique IDs
- **NIST 800-171** control references

Reports include executive summary, MITRE mapping, NIST controls matrix, and breach details.

### 11.3 Red Team Infrastructure

Isolated GCP project (`latentarchon-redteam`) with:
- Zero permissions on target projects (external attacker simulation)
- Isolated VPC (no peering to production)
- IAP-only SSH access
- Log sinks on target projects for audit correlation
- Monitoring dashboard: attack requests, IAM denials, auth failures, WAF blocks
- Safety: staging-only lock, rate limiting, dry-run mode, kill-on-breach switch

---

## 12. Email Service (Identity Platform)

**Source:** `internal/email/archon_service.go`

Transactional email (workspace/organization invites) is sent via **Google Identity Platform's server-side `sendOobCode` REST API** — a single-cloud GCP solution with no external email dependencies:

- **Single-cloud architecture:** All email originates from Identity Platform within GCP — no cross-cloud IAM, no external SMTP, no AWS dependencies
- **Two auth modes:** API key (simpler) or OAuth2 service account credentials (production) for the `identitytoolkit.googleapis.com` endpoint
- **DMARC alignment:** Default sender `noreply@{PROJECT_ID}.firebaseapp.com` passes DMARC on Google's domain; custom domain (`noreply@latentarchon.com`) available via Firebase console DNS configuration
- **HMAC invite tokens:** Invites use HMAC-SHA256 signed tokens with expiry, embedded in the `continueUrl` parameter
- **Domain matching:** Invite records track `inviter_email` and `domain_match` for cross-domain invite auditing (logged but not blocked — supports cross-agency collaboration)
- **Fire-and-forget:** Email sending is non-blocking; invite database records are always created even if email delivery fails
- **Provider backends:** `identity-platform` (production), `smtp` (local dev with Mailpit), `dry-run` (testing)

### Network Egress

No external email egress required. Identity Platform API calls are covered by the `identitytoolkit.googleapis.com` FQDN allowlist in the VPC firewall policy. All other external endpoints remain blocked by the default deny rule.

---

## 13. Security Email Notifications

**Source:** `internal/email/archon_service.go`, `cmd/server/connect_auth.go`

The platform includes a **real-time security notification service** that alerts organization administrators when security-critical events occur. Notifications are sent asynchronously via a dedicated goroutine to avoid blocking request processing.

### 13.1 Notifiable Events

| Event | Severity | Trigger |
|-------|----------|---------|
| `admin.role_escalation` | CRITICAL | Privilege escalation attempt or successful elevation |
| `admin.bootstrap` | CRITICAL | Initial admin bootstrap of a new organization |
| `auth.login_failed` | HIGH | Failed authentication attempt |
| `auth.mfa_challenge` | MEDIUM | MFA challenge issued (monitors enrollment and verification) |
| `member.remove` / `org.member_remove` | HIGH | Member removed from workspace or organization |
| `member.role_change` | MEDIUM | Member role changed within organization |
| `document.delete` | MEDIUM | Document permanently deleted from workspace |
| `scim.user_create` / `scim.user_patch` | MEDIUM | User provisioned or modified via SCIM |
| `scim.user_deactivate` | HIGH | User deactivated via SCIM directory sync |
| `scim.group_member_add` / `_remove` | MEDIUM | Group membership changed via SCIM |

### 13.2 Notification Safeguards

- **Deduplication window** — prevents alert storms (default 5 min per org+action, configurable)
- **Panic recovery** — notification goroutine catches panics, never crashes the server
- **Timeout protection** — 10s recipient resolution + 30s SMTP send timeout
- **Fallback recipient** — configurable default alert email when no org admins can be resolved
- **Bypasses EMAIL_ALLOWLIST** — security notifications always deliver, even in staging
- **Configurable scope** — `NOTIFICATION_EVENTS` env var overrides default event set

---

## 14. Account Closure & Data Purge

**Source:** `cmd/server/connect_auth.go`, `internal/organization/service.go`

### 14.1 Account Closure

| Capability | Detail |
|-----------|--------|
| Self-service closure | Users can close their own account via the `CloseAccount` RPC |
| Admin closure | Organization admins can close member accounts with audit trail |
| Token revocation | All Firebase tokens are revoked immediately on closure |
| Audit logging | Closure event logged with admin ID, target user ID, and org context |
| Step-up MFA | Account closure requires recent MFA verification (within 15 minutes) |

### 14.2 Data Purge (Privacy Policy §5)

A **Cloud Scheduler-triggered daily job** permanently deletes all data for accounts closed more than 90 days ago. This includes user records, org memberships, workspace memberships, documents, messages, and audit events. The purge is irreversible and fully logged.

---

## 15. Forensic Preservation

**Source:** `cmd/server/main.go` (ops endpoints)

On **P1/P2 security incidents**, a forensic preservation endpoint captures a complete database snapshot and audit trail for the affected scope. This ensures evidence is preserved before any automated purge or account lifecycle action can destroy relevant data.

- **Scope:** Organization-level or workspace-level preservation
- **Captures:** Database snapshot (documents, messages, members, audit events) + full audit trail
- **Access Control:** Restricted to the ops service with OIDC authentication (Cloud Scheduler / admin SA only)
- **Audit Trail:** Preservation operations are themselves audit-logged
- **Alignment:** Security Addendum §7.4

---

## 16. Semantic Deduplication & Document Versioning

**Source:** `internal/document/service.go`, `internal/vectorstore/service.go`

### 16.1 Semantic Deduplication

Beyond SHA-256 content hash deduplication (exact duplicate detection), the platform implements **vector similarity near-duplicate detection**:

- After embedding, new document chunks are compared against existing workspace chunks using cosine similarity
- Documents exceeding a **0.97 similarity threshold** are flagged as semantic near-duplicates
- Near-duplicate status is recorded in document metadata and surfaced in the admin UI
- Deduplication is workspace-scoped — identical documents in different workspaces are not flagged (by design, as different teams may legitimately need the same document)

### 16.2 Document Versioning

Documents support **immutable version history**:

- Each upload creates a new version with an incrementing version number
- Previous versions are retained in GCS with workspace-scoped paths
- Version metadata (uploader, timestamp, size, content hash) is stored in the database
- Versions are immutable once created — no in-place modification
- Version history is accessible via the admin API with workspace-scoped access controls

---

## 17. Image Generation in App

**Source:** `cmd/server/connect_conversation.go`

The app API supports **multimodal AI output** including inline image generation within streaming conversations:

### 17.1 Pipeline

| Step | Detail |
|------|--------|
| Model | Gemini 2.0 Flash with `ResponseModalities` image output via Vertex AI `PredictionClient` |
| Streaming | Images generated inline during server-streaming `SendMessage` RPC — no separate API call |
| Storage | Generated images uploaded to GCS with workspace-scoped paths (`generated-images/{workspace_id}/{uuid}.{ext}`) |
| Proxy | Images served via authenticated image proxy endpoint — no direct GCS URLs exposed to clients |
| Proto | `GeneratedImage` message in `conversation.proto` with `mime_type`, `gcs_path`, and `proxy_url` fields |

### 17.2 Security Controls

- **Rate limiting** — max 4 images per response, 10 MB total image payload per response
- **Graceful degradation** — GCS upload failures are logged but do not kill the stream; text continues flowing
- **Workspace scoping** — generated images inherit the workspace scope of the conversation
- **Audit logging** — image generation events logged with image count, total bytes, and correlation ID
- **No direct access** — all images served through authenticated proxy; GCS signed URLs never exposed to client

---

## 18. Data Export Service (FOIA)

**Source:** `internal/export/service.go`

A dedicated **Export Service** supports bulk data export for FOIA (Freedom of Information Act) requests, government record-keeping requirements, and data portability obligations.

| Capability | Detail |
|-----------|--------|
| Scope | Organization-level or workspace-level data export with configurable scope |
| Data Included | Documents (originals + metadata), messages, audit events, user records, workspace configurations |
| Format | Structured export package with manifest, preserving document hierarchy and metadata |
| Access Control | Export initiation restricted to organization `master_admin` role with step-up MFA |
| Audit Trail | Every export request is audit-logged with requestor ID, scope, timestamp, and completion status |
| Async Processing | Large exports processed via Cloud Tasks with progress tracking and completion notification |
| Retention | Export artifacts stored in GCS with configurable retention and automatic cleanup |

Export manifests include chain-of-custody metadata (who exported, when, what scope) to satisfy federal record-keeping requirements.

---

## 19. Usage Analytics & Cost Attribution

**Source:** `internal/analytics/service.go`

The platform includes an **Analytics Service** providing usage metrics, dashboards, and cost attribution data:

| Capability | Detail |
|-----------|--------|
| Usage Metrics | Messages, document uploads, vector searches, and API calls tracked per organization and workspace |
| Cost Attribution | Vertex AI (embedding + generation), Document AI, Cloud Storage, and compute costs attributed to tenant/workspace |
| Dashboard | Admin-facing usage dashboard with time-series charts, top-N queries, and per-workspace breakdowns |
| Access Control | Analytics endpoints restricted to organization admin role; data scoped to the admin's organization |
| Data Retention | Aggregated metrics retained indefinitely; raw event data follows standard audit log retention policies |
| Export | Analytics data exportable as CSV/JSON for integration with agency reporting systems |

---

## 20. Operational Resilience (DLQ & Health Probes)

**Source:** `cmd/server/main.go`, `internal/document/service.go`

### 20.1 Dead Letter Queue (DLQ) Management

Documents that fail processing after Cloud Tasks retry exhaustion are captured in a **Dead Letter Queue** rather than being silently dropped:

| Capability | Detail |
|-----------|--------|
| Capture | Failed documents automatically moved to DLQ after retry policy exhaustion |
| Visibility | Admin endpoint lists all DLQ items with failure reason, attempt count, and timestamps |
| Requeue | Admin endpoint requeues individual or batch DLQ items for reprocessing |
| Access Control | DLQ endpoints restricted to ops service with OIDC authentication |
| Audit Trail | DLQ operations (capture, list, requeue) are audit-logged |
| Alerting | DLQ depth integrated with Cloud Monitoring for threshold-based alerting |

### 20.2 Deep Readiness Probes (`/readyz`)

Beyond basic liveness checks (`/health`), the platform implements **deep readiness probes** that verify all critical dependencies are operational before accepting traffic:

| Dependency | Check | Mode-Aware |
|-----------|-------|-----------|
| Cloud SQL (PostgreSQL) | Connection pool ping with timeout | All modes |
| Vector Store (Vertex AI) | Index endpoint reachability | public + ops |
| Document Service (GCS) | Bucket accessibility verification | admin + ops |
| Cloud Tasks | Queue accessibility check | admin + ops |
| GenText (Gemini) | Model endpoint reachability | public |
| Message Storage | Table read verification | public |

Readiness checks are scoped to the server mode — the app service does not fail readiness for Document AI being unavailable, and the ops service does not check app storage. This prevents cascading failures across unrelated service boundaries.

### 20.3 Retry & Circuit Breaking

- **Cloud Tasks retry policy** — exponential backoff with configurable max attempts for document processing
- **DLQ capture** — documents exceeding retry limits preserved for manual review, never silently dropped
- **Processing timeout** — 10-minute per-document timeout prevents runaway processing from blocking the queue
- **Graceful degradation** — vector store or GenText unavailability returns clear errors, does not crash the service
- **Background worker tracking** — `sync.WaitGroup` ensures all in-flight async operations complete before shutdown

---

## 21. Monitoring & Incident Response

### 21.1 Uptime Monitoring

- **Public API** (`app.latentarchon.com/health`) — 60-second check interval, 10-second timeout, SSL validation
- **Admin API** (`admin.latentarchon.com/health`) — 60-second check interval, 10-second timeout, SSL validation
- **API Down Alert** — triggers after 5 minutes of consecutive failures (production only, auto-close after 30 minutes)

### 21.2 Load Balancer Logging

- Backend service logging enabled at 10% sampling rate
- Host-based URL map routing with explicit path matchers

### 21.3 Cloud NAT Logging

- Error-only logging for NAT gateway (tracks connectivity issues)

### 21.4 VPC Flow Logs

- Enabled on all Shared VPC subnets
- 50% sampling rate with full metadata
- 10-minute aggregation intervals

### 21.5 KMS Event Monitoring

- Alert on key disable, destroy, or version state changes
- 7-day auto-close window
- 5-minute notification rate limit

---

## 22. NIST 800-171 Control Mapping

The following maps key Latent Archon infrastructure controls to NIST 800-171 families:

### Access Control (3.1)

| Control | Implementation |
|---------|---------------|
| 3.1.1 Limit system access | Firebase Auth + MFA, IAM-private ops service, Cloud Armor IP allowlisting |
| 3.1.2 Limit to authorized transactions | RBAC via database roles (service, admin, read-only, ops), per-workspace scoping |
| 3.1.3 Control CUI flow | FQDN-based egress firewall, VPC private networking, PSC for AI services |
| 3.1.5 Least privilege | 8 purpose-specific service accounts with narrowly scoped IAM roles |
| 3.1.7 Prevent non-privileged users from executing privileged functions | IAM-private ops service, admin-only endpoints, MFA enforcement |
| 3.1.12 Monitor remote access | Cloud Armor WAF logging, VPC Flow Logs, uptime checks |
| 3.1.13 Employ cryptographic mechanisms for remote access | HTTPS enforced, Google-managed SSL, IAM OIDC for service-to-service |
| 3.1.22 Control CUI on public systems | Public access prevention on all storage, private-only Cloud SQL |

### Audit & Accountability (3.3)

| Control | Implementation |
|---------|---------------|
| 3.3.1 Create audit records | Organization-level log sink, application AUDIT_EVENT logs, BigQuery sink |
| 3.3.2 Unique trace to user | Firebase Auth user IDs in audit events, GCP IAM actor tracking |
| 3.3.3 Retain audit records | 30-day centralized logging, 365-day job audit logs, BigQuery with configurable expiration |
| 3.3.4 Alert on audit failure | Monitoring alert policies for auth failures, privilege changes, data deletion |
| 3.3.5 Correlate audit review | Unified BigQuery dataset with both GCP-native and application audit logs |

### Configuration Management (3.4)

| Control | Implementation |
|---------|---------------|
| 3.4.1 Baseline configurations | Terraform/Terragrunt IaC, CI/CD validation, drift detection |
| 3.4.2 Enforce security settings | Org policies (10 enforced), CMEK Autokey, format/validate CI checks |
| 3.4.6 Least functionality | FQDN egress allowlist, HTTP method enforcement, disabled serial ports/nested virt |
| 3.4.8 Apply deny-by-exception | Default deny egress firewall, Cloud Armor default deny option, IAM-private services |

### Identification & Authentication (3.5)

| Control | Implementation |
|---------|---------------|
| 3.5.1 Identify system users | Firebase Auth with unique user IDs, service account identity |
| 3.5.2 Authenticate users | Firebase Auth + TOTP MFA, OIDC for service-to-service |
| 3.5.3 Multi-factor authentication | TOTP-based MFA enforced on all data routes via `sign_in_second_factor` claim |
| 3.5.10 Store only cryptographic hashes | Firebase Auth manages credential storage (SCRAM-based) |

### Incident Response (3.6)

| Control | Implementation |
|---------|---------------|
| 3.6.1 Incident handling | Alert policies for auth failures, privilege escalation, data deletion, KMS events |
| 3.6.2 Track/document/report | BigQuery audit dataset, structured AUDIT_EVENT logs, MITRE-tagged red team reports |

### Maintenance (3.7)

| Control | Implementation |
|---------|---------------|
| 3.7.5 Require MFA for maintenance | IAP tunneling for VM access, OS Login required, MFA on admin API |

### Media Protection (3.8)

| Control | Implementation |
|---------|---------------|
| 3.8.1 Protect CUI on media | CMEK encryption on all storage (Cloud SQL, GCS, Secret Manager) |
| 3.8.9 Protect CUI at rest | HSM-backed KMS keys with 90-day rotation |

### Personnel Security (3.9)

| Control | Implementation |
|---------|---------------|
| 3.9.2 Protect CUI during personnel actions | IAM group-based access, removable via group membership |

### Physical Protection (3.10)

| Control | Implementation |
|---------|---------------|
| 3.10.1 Physical access | Google Cloud data centers (SOC 2, ISO 27001, FedRAMP certified) |

### Risk Assessment (3.11)

| Control | Implementation |
|---------|---------------|
| 3.11.1 Periodically assess risk | Red team suite (44 automated tests), MITRE ATT&CK mapping |
| 3.11.2 Scan for vulnerabilities | Container Scanning API, Cloud Armor scanner detection, ClamAV |

### Security Assessment (3.12)

| Control | Implementation |
|---------|---------------|
| 3.12.1 Assess security controls | Red team infrastructure with audit correlation |
| 3.12.3 Monitor security controls | Drift detection in CI/CD, uptime checks, alert policies |

### System & Communications Protection (3.13)

| Control | Implementation |
|---------|---------------|
| 3.13.1 Monitor at external boundary | Cloud Armor WAF, VPC Flow Logs, FQDN egress firewall |
| 3.13.2 Architectural designs | Multi-project isolation, Shared VPC, IAM-private services |
| 3.13.8 CUI in transit | HTTPS enforced, PSC for AI services, private VPC peering for Cloud SQL |
| 3.13.11 FIPS-validated cryptography | Google Cloud KMS (FIPS 140-2 Level 3 for HSM) |

### System & Information Integrity (3.14)

| Control | Implementation |
|---------|---------------|
| 3.14.1 Identify/report flaws | Container Scanning API, ClamAV, red team testing |
| 3.14.2 Protect from malicious code | ClamAV scanning on upload, Cloud Armor WAF rules |
| 3.14.6 Monitor communications for attacks | Cloud Armor OWASP rules, rate limiting, bot blocking |
| 3.14.7 Identify unauthorized use | Auth failure spike alerts, privilege escalation alerts |

---

## 23. FedRAMP Alignment Summary

| FedRAMP Control Family | Key Implementations |
|----------------------|-------------------|
| **AC — Access Control** | Firebase Auth + MFA, IAM least privilege, FQDN egress allowlist, IAM-private services |
| **AU — Audit** | Org-level log sink, BigQuery audit dataset, AUDIT_EVENT logs, 5 alert policies |
| **AT — Awareness & Training** | Red team reports with MITRE/NIST mapping for security awareness |
| **CM — Configuration Management** | Terraform IaC, CI/CD validation, drift detection, org policies |
| **CP — Contingency Planning** | Cloud SQL automated backups, GCS versioning, multi-region GCS |
| **IA — Identification & Auth** | Firebase Auth, TOTP MFA, Workload Identity Federation, OIDC |
| **IR — Incident Response** | Auth failure, privilege escalation, data deletion, KMS lifecycle alerts |
| **MA — Maintenance** | IAP tunneling, OS Login, Cloud Shell admin access only |
| **MP — Media Protection** | CMEK with HSM, FIPS 140-2 Level 3, 90-day key rotation |
| **PE — Physical & Environmental** | Google Cloud (SOC 2, ISO 27001, FedRAMP certified) |
| **PL — Planning** | IaC with PR review, plan-on-PR, centralized monitoring |
| **PS — Personnel Security** | Group-based IAM, per-project access scoping |
| **RA — Risk Assessment** | 44-test red team suite, container scanning, ClamAV |
| **SA — System Acquisition** | Artifact Registry proxy repos, supply chain scanning |
| **SC — System & Comms Protection** | HTTPS, PSC, private VPC, Cloud Armor WAF, FQDN egress |
| **SI — System & Information Integrity** | Cloud Armor OWASP, ClamAV, container scanning, monitoring alerts |

---

## Appendix: Terraform File Index

### `org/` — Organization Foundation
| File | Purpose |
|------|---------|
| `org-policy.tf` | 10 organization-wide security policies |
| `folders.tf` | 3-level folder hierarchy (Production, Non-Production, Development) |
| `projects.tf` | Shared VPC host projects, centralized logging project |
| `service-projects.tf` | 4 Shared VPC service projects (app + admin × prod + staging) |
| `network.tf` | Shared VPCs with flow logs, firewall rules with logging |
| `iam.tf` | Folder/project IAM bindings via security groups |
| `groups.tf` | Google security groups for RBAC |
| `log-export.tf` | Organization-level audit log sink to centralized bucket |
| `monitoring.tf` | Centralized metrics scoping across all projects |
| `autokey.tf` | CMEK Autokey with org policies for key restriction |

### `vpc/` — Network Infrastructure
| File | Purpose |
|------|---------|
| `vpc.tf` | VPC, subnet, firewall rules, FQDN egress policy, Cloud NAT |
| `psc_google_apis.tf` | PSC for Google APIs (placeholder for future enhancement) |
| `cloud_sql.tf` | Cloud SQL private IP outputs |

### `infra/` — Application Infrastructure
| File | Purpose |
|------|---------|
| `service_accounts.tf` | 8 purpose-specific service accounts |
| `iam.tf` | IAM role bindings (least privilege) |
| `cloud_run.tf` | 3 Cloud Run services with VPC access |
| `cloud_run_jobs.tf` | Run-to-completion jobs (migrations, backfills) |
| `cloud_sql.tf` | PostgreSQL with IAM auth, private IP, backups |
| `cloud_storage.tf` | GCS buckets with versioning, lifecycle, access prevention |
| `load_balancer.tf` | Global HTTPS LB with managed SSL |
| `vertex_ai.tf` | Vector search with PSC, dual-model deployment |
| `cloud_tasks.tf` | Async task queues with retry/rate limiting |
| `cloud_scheduler.tf` | OIDC-authenticated cron jobs |
| `secrets.tf` | Secret Manager configuration |
| `firebase.tf` | App Check with reCAPTCHA Enterprise |
| `artifact_registry.tf` | Container + package registries, container scanning |
| `cloud_build.tf` | CI/CD build configuration |
| `workload_identity.tf` | Keyless GitHub Actions → GCP auth |
| `logging.tf` | CMEK-encrypted audit log bucket |
| `monitoring.tf` | Uptime checks, API down alerts |
| `document_ai.tf` | OCR processor for document pipeline |

### `infra/modules/` — Reusable Security Modules
| Module | Purpose |
|--------|---------|
| `cloud-armor/` | WAF: OWASP Top 10, rate limiting, method/origin/bot enforcement |
| `kms/` | CMEK with HSM, 90-day rotation, lifecycle alerts |
| `audit-logs/` | BigQuery sink, IAM/auth/privilege/deletion alerts, app audit sink |
| `clamav/` | Malware scanning sidecar (internal-only Cloud Run) |

---

*Document generated from infrastructure code review. All controls are implemented as Terraform/Terragrunt IaC and are auditable, reproducible, and version-controlled.*

---

# SECTION 4: CHATGPT — Infrastructure Security Review (infra/vpc/org)

> Source: `infra/docs/security/CHATGPT_Infrastructure_Security_Review.md`

---

# Latent Archon — Security Architecture Review (ChatGPT)

Date: 2026-03-22
Scope: Infrastructure-as-code under `infra/`, stand‑alone `vpc/` repo, and organization foundation under `org/`.
Audience: Government security reviewers, enterprise buyers, and due diligence teams.

## Executive Summary

- Two‑project GCP architecture isolates public app workloads from admin/ops systems, reducing blast radius and aligning with least privilege and data minimization.
- Strong perimeter: Global HTTPS load balancers fronted by Cloud Armor WAF with OWASP Top‑10 rules, rate limiting, method enforcement, origin restrictions, and bot blocking.
- Defense‑in‑depth networking: Dedicated VPCs, private service networking to Cloud SQL, strict firewalling, Cloud NAT with logging, and an FQDN‑based egress deny‑by‑default policy with explicit allowlists (Google APIs and internal domains only).
- Robust IAM: Service‑account based access, role scoping per service, cross‑project Cloud SQL access via `roles/cloudsql.client` + `roles/cloudsql.instanceUser`, and controlled impersonation.
- Data protection: CMEK via KMS (HSM protection level) for Cloud SQL and GCS, SQL audit flags (pgaudit), PITR backups, and storage best practices (UBLA, PAP, versioning, lifecycle).
- Authentication security: Identity Platform with enforced TOTP MFA at the project level, App Check for web apps, and tenant‑aware OIDC federation with secrets sourced from Secret Manager.
- Observability and audit: Centralized audit log export to BigQuery, application audit logs sink, alerting for auth failures, privilege changes, data deletions, and KMS key lifecycle events; centralized monitoring scope.
- Content safety: Private Cloud Run ClamAV scanning service used during document ingestion.

## Architecture Overview

Source: `infra/README.md`, `infra/modules/*`, `infra/environments/production/*`.

- Split projects
  - App project (`latentarchon-app-prod`): Cloud Run API (`archon-app`), SPA hosting (`app-spa`), Cloud Armor, Identity Platform, Vertex AI client usage.
  - Admin project (`latentarchon-admin-prod`): Cloud Run (`archon-admin`, `archon-ops` [IAM‑private]), Cloud SQL (PostgreSQL 15), GCS documents bucket, Cloud Tasks, Document AI OCR, Vertex AI indices, Cloud Armor.
- Load Balancers
  - Global HTTPS LB per project with managed certs; host‑based routing sends SPA domains to SPA backend and API domains to API backend.
- Cloud Armor WAF
  - Preconfigured OWASP rules (XSS, SQLi, LFI/RFI, RCE, protocol attacks, session fixation, scanner detection, JSON SQLi), IP allowlist (optional), rate limiting with ban, method allow‑list, origin restriction, bot UA blocks.
- App→Admin cross‑project dependencies
  - App Cloud Run depends on Admin’s Vertex AI (PSC endpoint), Document AI processor, and Cloud SQL access for read/write as appropriate.

## Network Security and Segmentation

Sources: `infra/modules/vpc/main.tf`, `infra/modules/load-balancer/main.tf`, `infra/modules/cloud-armor/main.tf`, `vpc/vpc.tf`.

- VPCs and Subnets
  - Custom VPCs per project; subnets with Private Google Access and VPC flow logs (metadata included, sampling configurable).
- Private Service Networking
  - Reserved peering range and `google_service_networking_connection` enable private IP connectivity to Cloud SQL.
- Cloud NAT and Router
  - NAT provides egress for private workloads; NAT logging enabled (`ERRORS_ONLY` in vpc repo, configurable in infra module).
- Firewall strategy
  - Allow internal east‑west within subnet; explicit egress to Cloud SQL private IPs; egress to service networking; egress to PSC endpoints (Vertex AI) on port 10000; optional Cloud Shell→SQL ingress limited to Google IAP ranges for emergency.
  - FQDN‑based egress firewall policy: explicit allowlists for Google APIs (aiplatform, sqladmin, storage, logging, monitoring, identitytoolkit, securetoken, firebaseappcheck, etc.) and internal Archon domains; terminal default‑deny on egress to `0.0.0.0/0`.
- Load Balancers and WAF
  - API and SPA backends are serverless NEGs to Cloud Run. LB attaches Cloud Armor policy with WAF protections and logging enabled on backend services.

## Identity and Access Management (IAM)

Sources: `infra/modules/service-accounts/main.tf`, `infra/modules/cloud-run/main.tf`, `infra/modules/clamav/main.tf`, `infra/modules/cloud-sql/main.tf`, `org/iam.tf`.

- Service accounts per service with least‑privilege roles at project scope; bindings flattened deterministically.
- Controlled impersonation grants (`roles/iam.serviceAccountUser`) for specific SA→SA flows (e.g., task enqueueing).
- Cloud Run IAM
  - Public endpoints only when explicitly allowed (`allow_unauthenticated`); otherwise `roles/run.invoker` restricted to specified members.
  - ClamAV service is VPC‑attached and ingress `internal`; only the admin SA can invoke.
- Cloud SQL IAM
  - IAM database users per service account; cross‑project grants using `roles/cloudsql.client` and `roles/cloudsql.instanceUser` for app services needing DB access.
- Organization IAM baselines
  - Group‑based access at folder/project scopes for developer and security viewer roles; log/monitoring viewer access for oversight.

## Authentication and App‑Level Controls

Sources: `infra/modules/identity-platform/main.tf`, `infra/README.md`.

- Identity Platform
  - Project‑level MFA enforced (TOTP), App Check for the web app (reCAPTCHA Enterprise), Identity Platform API enabled.
  - Tenants per customer; optional OIDC IdPs per tenant with client secrets retrieved from Secret Manager (not stored in TF state).
- Application rate limiting (documented)
  - IP‑level pre‑auth and per‑user post‑auth rate limits layered with Cloud Armor rate limiting.

## Data Protection

Sources: `infra/modules/kms/main.tf`, `infra/modules/cloud-sql/main.tf`, `infra/modules/gcs/main.tf`.

- KMS (CMEK)
  - HSM‑backed symmetric keys; 90‑day rotation; destroy‑scheduled protection; service agents granted encrypter/decrypter. Monitoring alerts on key disable/destroy/rotation changes.
- Cloud SQL (PostgreSQL 15)
  - Private IP only, SSL required (`ENCRYPTED_ONLY`), IAM auth enabled.
  - Enterprise edition, backups + PITR (14 retained), maintenance window set, Insights enabled with client address and tags.
  - Audit and logging flags: `cloudsql.enable_pgaudit=on`, `pgaudit.log=ddl,role,write`, `log_connections=on`, `log_disconnections=on`.
- GCS (documents)
  - UBLA enabled, Public Access Prevention enforced, versioning optional, lifecycle rules (e.g., NEARLINE after 90 days, delete old versions), optional CORS for controlled direct uploads, CMEK support.

## AI/ML and Content Processing

Sources: `infra/modules/vertex-ai/main.tf`, `infra/modules/document-ai/main.tf`, `infra/modules/cloud-tasks/main.tf`, `infra/modules/clamav/main.tf`.

- Vertex AI Vector Search
  - Dedicated index endpoint with Private Service Connect (PSC) enabled; internal IP and forwarding rule within VPC; deployed index for `gemini-embedding-2-preview` (768 dimensions); model configurable via `EMBEDDING_MODEL` env var.
- Document AI
  - OCR processor provisioned in `us` for document text extraction.
- Cloud Tasks
  - Two queues (`document-processing`, `embeddings`) with bounded rate limits and retries; tasks target IAM‑private ops service.
- ClamAV (malware scanning)
  - Private Cloud Run service; health probes configured; low concurrency and warm instances to reduce scanning latency; only admin SA can invoke.

## Logging, Monitoring, and Alerting

Sources: `infra/modules/audit-logs/main.tf`, `org/log-export.tf`, `org/monitoring.tf`.

- Audit log export
  - Organization‑wide sink to centralized log bucket; project‑level sinks to BigQuery dataset with partitioning and retention.
- Application audit logs sink
  - Routes structured `AUDIT_EVENT` logs from Cloud Run to BigQuery alongside platform audit logs for unified queries.
- Alerting policies
  - IAM change detection, auth failures, privilege changes, data deletions, and KMS key lifecycle events; throttled notifications to defined channels.
- Monitoring scope
  - Centralized metrics scope includes VPC host projects and service projects (prod and staging), plus auto‑key projects.

## Organization Policies and Foundation

Sources: `org/org-policy.tf`, `org/network.tf`, `org/folders.tf`, `org/iam.tf`.

- Org Policies (selected, enforced)
  - `storage.publicAccessPrevention` (enforce), `compute.requireOsLogin`, `compute.vmExternalIpAccess` (deny), `compute.disableNestedVirtualization`, `compute.disableSerialPortAccess`, `sql.restrictAuthorizedNetworks`, `sql.restrictPublicIp`, `compute.skipDefaultNetworkCreation`, `compute.disableVpcExternalIpv6`.
- Folder hierarchy and shared VPCs
  - Production/non‑prod shared VPCs with subnets, flow logs, and ingress allowances for IAP‑based SSH/RDP only.
- Centralized logging and monitoring projects established; group‑based IAM for least privilege.

## Compliance Posture Mapping (Representative)

- NIST SP 800‑53 rev.5
  - AC‑4/SC‑7 Boundary Protection: Cloud Armor WAF, LB segmentation, firewall policies.
  - AC‑6 Least Privilege: SA‑scoped roles, IAM DB users, restricted invokers.
  - IA‑2, IA‑2(1), IA‑2(8): Identity Platform MFA (TOTP), tenant isolation.
  - SC‑12/SC‑13 Cryptographic Protection: TLS, CMEK (HSM), encrypted DB connections.
  - AU‑2/6/8 Auditing and Review: Central sinks to BigQuery, alerting, monitoring scope.
  - CP‑9/10 Information System Backup/Recovery: Cloud SQL backups + PITR.
  - SI‑4 Monitoring: Alerting on security‑relevant events; scanner/bot blocks.
- CIS GCP Foundations Benchmark (selected)
  - Ensure org policies prevent public storage access; disable default network; restrict external IPs; enforce OS Login; enable audit logging; enable VPC flow logs; centralized logging and monitoring.

## Residual Risks and Recommended Next Steps

1. ~~Cloud Armor allowlists~~: **Done** — Self-service per-tenant IP allowlisting implemented via `UpdateOrganizationSettings` RPC with Cloud Armor API sync. Org admins configure CIDR allowlists; rules enforced at WAF layer with CEL host+IP matching.
2. `prevent_destroy`: Several modules include `prevent_destroy = false` with `# RESTORE:` comments; re‑enable post‑cutover to reduce accidental deletions.
3. PSC for Google APIs (vpc repo): `psc_google_apis.tf` is placeholder/commented. Continue with current Direct VPC + FQDN egress allowlists or implement service‑specific PSC endpoints with managed DNS.
4. Vertex AI access logging: `enable_access_logging = false` on deployed indices. Evaluate enabling logs or compensating detective controls if supported in current region/service.
5. Cloud Run ingress posture: Verify all non‑public services (ops, ClamAV) are `internal` and only invoked by explicit SAs; for public APIs ensure LB/WAF is the only entry (ingress `all` is acceptable behind WAF but consider `internal-and-cloud-load-balancing` where feasible).
6. Secret management: OIDC IdP client secrets already read from Secret Manager; ensure all application secrets follow the same pattern with CMEK and appropriate rotations.
7. BigQuery retention: Confirm dataset/table retention meets agency data retention requirements; current dataset supports partition/expiration; adjust to policy (e.g., ≥365 days).
8. DLP and content safety: Consider Cloud DLP on document uploads and additional MIME/file‑type enforcement alongside ClamAV scanning.
9. SCC and posture management: Ensure Security Command Center (Standard/Enterprise) is enabled across projects with notifications integrated.
10. Supply chain: Ensure image vulnerability scanning (Container Analysis) is enabled; consider Binary Authorization or signed artifacts (SLSA‑aligned) for sensitive environments.
11. DR/Resilience: Evaluate cross‑region read replica or backup export strategy for Cloud SQL; document RTO/RPO per customer SLAs.
12. ~~Staging environment~~: **Provisioned** — `latentarchon-app-staging` and `latentarchon-admin-staging` projects created in Non-Production folder with full infrastructure parity.

## Evidence and File References

- WAF: `infra/modules/cloud-armor/main.tf`
- LB: `infra/modules/load-balancer/main.tf`
- VPC and firewall: `infra/modules/vpc/main.tf`, `vpc/vpc.tf`
- Cloud Run (API): `infra/modules/cloud-run/main.tf`; ClamAV: `infra/modules/clamav/main.tf`
- Cloud SQL: `infra/modules/cloud-sql/main.tf`
- KMS (CMEK): `infra/modules/kms/main.tf`
- GCS: `infra/modules/gcs/main.tf`
- Identity Platform & App Check: `infra/modules/identity-platform/main.tf`
- Vertex AI: `infra/modules/vertex-ai/main.tf`
- Document AI: `infra/modules/document-ai/main.tf`
- Cloud Tasks: `infra/modules/cloud-tasks/main.tf`
- Audit logs and alerts: `infra/modules/audit-logs/main.tf`, `org/log-export.tf`, `org/monitoring.tf`
- Org Policies: `org/org-policy.tf`
- Foundation Networking: `org/network.tf`
- IAM groups and bindings: `org/iam.tf`

## Operational Notes

- Terragrunt remote state: GCS backend per project with bucket‑policy‑only and versioning.
- Dependency orchestration: Terragrunt handles inter‑module and cross‑project dependencies; deploy admin first, then app.
- SPA hosting: SPAs served by dedicated nginx Cloud Run services; LB host‑based routing separates SPA vs API and applies Cloud Armor to both.

—

# SECTION 5: CLAUDE — Frontend Security Review (app/admin SPAs)

> Source: `app/docs/security/CLAUDE_Frontend_Security_Review.md`

—

# Latent Archon — Frontend Platform Review

> **Purpose**: Comprehensive technical review of the Admin and App single-page applications for use in government procurement and sales documentation.
>
> **Last Updated**: March 22, 2026

—

## 1. Executive Summary

Latent Archon provides a secure, multi-tenant document intelligence platform purpose-built for government workloads. The frontend consists of two independent React SPAs:

- **Admin Console** (`admin/`) — Organization and workspace management, document ingestion, member access control, and audit logging.
- **App Interface** (`app/`) — AI-powered conversational interface for querying uploaded documents with Retrieval-Augmented Generation (RAG), streaming responses, and source citations.

Both applications enforce **passwordless authentication** via magic links and **mandatory TOTP multi-factor authentication** for every user session, meeting NIST 800-63B AAL2 requirements. All API communication uses Connect-RPC with automatic Bearer token injection, and the production deployment runs on hardened, unprivileged nginx containers behind Google Cloud Run with comprehensive security headers.

—

## 2. Architecture Overview

### 2.1 Two-App Isolation Model

The platform deliberately separates admin and end-user functionality into independent SPAs, each served from its own Cloud Run service and backed by its own Firebase Identity Platform project:

| Property | Admin Console | App Interface |
|---|---|---|
| **Purpose** | Org/workspace/document/member management | Document Q&A with RAG |
| **Dev Port** | 3001 | 3000 |
| **Firebase Project** | `latentarchon-admin` | `latentarchon-app` |
| **API Surface** | OrganizationService, WorkspaceService, DocumentService, AuditService, AuthService | ConversationService, ChatMessageService, WorkspaceService, AuthService |
| **Production Domain** | `admin.latentarchon.com` | `app.latentarchon.com` |

This separation provides **auth pool isolation** — admin users and end users exist in entirely different Firebase Identity Platform tenant pools, preventing cross-privilege escalation by design.

### 2.2 Technology Stack

| Layer | Technology | Version |
|---|---|---|
| **Framework** | React | 19.1.0 |
| **Routing** | React Router | 7.8.2 |
| **Build Tool** | Vite | 6.3.5 |
| **Styling** | TailwindCSS | 3.4.1 |
| **Language** | TypeScript | 5.8.3 (strict mode) |
| **API Protocol** | Connect-RPC (buf.build) | 1.7.0 |
| **Auth Provider** | Firebase Identity Platform | 11.8.1 |
| **MFA** | TOTP via Google Authenticator / compatible apps | Native Firebase MFA |
| **Markdown Rendering** | react-markdown (app only) | 9.0.3 |
| **QR Code Generation** | qrcode.react | 4.2.0 |
| **Container Runtime** | nginx-unprivileged (Alpine) | 1.27 |
| **Node.js** | ≥ 20 (LTS) | Required |

### 2.3 Deployment Architecture

Both SPAs are containerized via multi-stage Docker builds:

1. **Build stage**: `node:20-alpine` — `npm ci --ignore-scripts` + `npm run build` (Vite production build with TypeScript compilation)
2. **Serve stage**: `nginxinc/nginx-unprivileged:1.27-alpine` — Minimal attack surface, runs as non-root user, listens on port 8080 (Cloud Run standard)

Production hosting: Google Cloud Run behind a global HTTP(S) load balancer with Cloud Armor WAF, host-based routing, and managed TLS certificates.

—

## 3. Authentication & Authorization

### 3.1 Authentication Flow

Latent Archon implements a **zero-password authentication model** with mandatory MFA:

```
User enters email → Magic link sent via Firebase → User clicks link →
  ├── If MFA enrolled: TOTP challenge (6-digit code) → Authenticated
  └── If MFA not enrolled: Forced TOTP enrollment (QR scan) → Verify code → Authenticated
```

**Key security properties:**

- **No passwords stored or transmitted** — eliminates credential stuffing, password spray, and phishing of static credentials
- **Magic links are single-use, time-limited**, and scoped to the originating domain
- **MFA is mandatory** — the `AuthGate` component blocks access to all application content until MFA enrollment is complete and verified
- **TOTP codes are time-based** (RFC 6238) with standard 30-second windows
- **Firebase tenant scoping** — each SPA binds to a specific Identity Platform tenant, and tokens include a `firebase.tenant` claim verified server-side

### 3.2 AuthGate State Machine

The `AuthGate` component enforces a strict state machine that gates all application access:

| State | User Sees | Can Access App? |
|---|---|---|
| `loading` | Spinner | No |
| `unauthenticated` | Login page (email input) | No |
| `magic_link_sent` | "Check your email" confirmation | No |
| `mfa_enrollment_required` | QR code + TOTP setup | No |
| `mfa_challenge_required` | 6-digit TOTP input | No |
| `authenticated` | Application content | **Yes** |

There is no way to bypass MFA enrollment — the application literally does not render protected routes until `authState === 'authenticated'`.

### 3.3 Multi-Tenancy

The platform supports multi-tenancy via Firebase Identity Platform tenants:

- **Explicit tenant override**: `VITE_FIREBASE_TENANT_ID` environment variable
- **Subdomain-based discovery**: `VITE_TENANT_MAP` JSON mapping (e.g., `{"acme": "tenant-abc123"}`)
- **Graceful degradation**: If tenant discovery is configured but no tenant matches the current hostname, a dedicated `TenantNotFound` page is rendered instead of the application

This enables a single deployment to serve multiple government agencies, each isolated by their own Identity Platform tenant with separate user directories.

### 3.4 Token Management

- Firebase ID tokens are obtained via `getIdToken()` and automatically refreshed
- The Connect-RPC transport interceptor attaches `Authorization: Bearer <token>` to every API request
- Token refresh is handled transparently by the Firebase SDK
- No tokens are stored in localStorage (Firebase SDK manages its own secure storage)

—

## 4. Admin Console — Detailed Review

### 4.1 Route Structure

| Route | Component | Purpose |
|---|---|---|
| `/` | `Dashboard` | Organization overview, workspace grid, create workspace |
| `/workspaces/:workspaceId` | `WorkspaceDetail` | Workspace documents + members, upload, invite |
| `/workspaces/:workspaceId/documents` | `Documents` | Full document management (upload, edit, delete, reprocess, filter) |
| `/members` | `Members` | Organization-level member list + invite |
| `/audit` | `AuditLog` | Paginated audit event log with filtering + detail expansion |
| `/auth/callback` | Redirect to `/` | Magic link return handler |

### 4.2 Dashboard (`Dashboard.tsx`)

- Lists all organizations the authenticated admin belongs to
- Displays workspace grid with document count and member count per workspace
- Inline workspace creation form with name and description fields
- Uses Connect-RPC `OrganizationService.ListOrganizations` and `WorkspaceService.ListWorkspaces/CreateWorkspace`

### 4.3 Workspace Detail (`WorkspaceDetail.tsx`)

- Tabbed interface: **Documents** and **Members**
- **Documents tab**:
  - Document upload via file picker with metadata modal (title, description, freeform tags)
  - Auto-fills title from filename (strips extension, converts underscores/hyphens to spaces)
  - Freeform tag input with Enter/comma delimiters and backspace-to-delete
  - Document list with status indicators (pending → processing → ready / error)
  - Automatic 5-second polling while any document is in pending/processing state
  - Displays file size, chunk count, page count, and tags
  - Accepted file types: PDF, DOCX, DOC, TXT, MD
- **Members tab**:
  - Member list with role display (admin/editor/viewer)
  - Inline invite form with email input
  - Invites default to viewer role

### 4.4 Documents Page (`Documents.tsx`)

Full-featured document management with capabilities beyond the workspace detail view:

- **Multi-file upload**: Select multiple files, configure title/description/tags for each, upload all in sequence
- **Drag-and-drop upload area**: Supports drag-over and drop events
- **Filtering**: Debounced title search (300ms), comma-separated tag filter, status dropdown (pending/processing/ready/error)
- **Edit metadata**: Modal to update title, description, and tags on existing documents
- **Delete**: Confirmation dialog before deleting document and all associated chunks
- **Reprocess**: Re-trigger document processing pipeline for failed documents
- **Dead Letter Queue (DLQ) pattern**: Error documents are surfaced in a separate red-highlighted section at the top with reprocess/edit/delete actions
- **Status polling**: Automatic 5-second refresh interval while any document is processing

### 4.5 Members Page (`Members.tsx`)

- Organization-level member management
- Lists all members with roles (owner/admin)
- Invite form for adding new organization admins by email
- Uses Connect-RPC `OrganizationService.GetOrganization` for member details and `OrganizationService.InviteMember` for invitations

### 4.6 Audit Log (`AuditLog.tsx`)

- **Paginated table view** with 25 events per page
- **Fields displayed**: Timestamp, Action (e.g., `document.upload`), Status (success/started/failure), User ID, Resource type + ID, Error message
- **Action filter**: Text input to filter by action type
- **Expandable rows**: Click any row to reveal full details including:
  - Event ID, Correlation ID (for request tracing)
  - Organization ID, Workspace ID
  - IP Address, User Agent
  - Raw metadata JSON (pretty-printed)
- **Pagination controls**: Previous/Next with page count display
- Uses Connect-RPC `AuditService.ListAuditEvents`

### 4.7 Admin API Client (`client.ts`)

Five typed Connect-RPC service clients:
- `getAuthClient()` → `AuthService`
- `getOrgClient()` → `OrganizationService`
- `getWorkspaceClient()` → `WorkspaceService`
- `getDocumentClient()` → `DocumentService`
- `getAuditClient()` → `AuditService`

Plus one REST endpoint for multipart file upload: `apiUpload('/api/documents', formData)` — the sole endpoint that cannot use Connect-RPC due to binary file transfer.

—

## 5. App Interface — Detailed Review

### 5.1 Route Structure

| Route | Component | Purpose |
|---|---|---|
| `/` | `Chat` | Main conversational interface |
| `/auth/callback` | Redirect to `/` | Magic link return handler |

### 5.2 App Chat Page (`Chat.tsx`)

The core user-facing experience:

- **Workspace selector sidebar**:
  - Checkbox-based multi-workspace selection
  - Shows document count per workspace
  - All workspaces selected by default on load
  - User must select at least one workspace to send messages

- **Conversational interface**:
  - Chat history loaded on mount via `ChatMessageService.RetrieveMessages` (last 50 messages)
  - Messages displayed in a scrollable area with auto-scroll to bottom
  - User messages styled as blue bubbles (right-aligned)
  - Assistant responses rendered as Markdown via `react-markdown` with Tailwind Typography plugin
  - Code blocks, lists, headings, and inline formatting supported in responses

- **Streaming RAG responses**:
  - Uses Connect-RPC server streaming via `ConversationService.SendMessage`
  - Typing indicator (animated dots) displayed while waiting for first token
  - Tokens appended in real-time as they arrive from the server
  - Abort controller support for cancellation
  - Server-assigned message IDs update client-side IDs when received

- **Source citations**:
  - Each assistant response can include citations from source documents
  - Citations display: document name, page number, relevance score, and excerpt
  - Citations arrive as part of the streaming response and are rendered below the message text
  - Provides full traceability from AI response back to original source material

- **Error handling**:
  - Failed streams display an error message in the assistant bubble
  - Error state is visually distinct (red border + text)

### 5.3 App API Client (`client.ts`)

Four typed Connect-RPC service clients:
- `getAuthClient()` → `AuthService`
- `getWorkspaceClient()` → `WorkspaceService`
- `getConversationClient()` → `ConversationService` (server streaming)
- `getChatMessageClient()` → `ChatMessageService`

—

## 6. Security Posture

### 6.1 Authentication Security

| Control | Implementation |
|---|---|
| **Passwordless auth** | Magic link (email) — no static credentials |
| **Mandatory MFA** | TOTP enforced at the application gate layer |
| **Auth pool isolation** | Separate Firebase Identity Platform projects for admin vs. user |
| **Tenant scoping** | Identity Platform multi-tenancy with `firebase.tenant` claim |
| **Token transport** | Bearer tokens over HTTPS, auto-refreshed |
| **Session management** | Firebase SDK-managed, no localStorage token storage |

### 6.2 Transport Security (nginx)

The nginx configuration enforces comprehensive security headers:

| Header | Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | HSTS with 2-year max-age, HSTS preload eligible |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME type sniffing |
| `X-Frame-Options` | `DENY` | Prevent all framing (clickjacking protection) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limit referrer information leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Disable unnecessary browser APIs |
| `Content-Security-Policy` | Strict allowlist | Default `self`, explicit allowlists for Firebase/Google auth endpoints only |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` | Isolate browsing context (Spectre mitigation) |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevent cross-origin resource loading |
| `server_tokens` | `off` | Suppress nginx version disclosure |

### 6.3 Content Security Policy Breakdown

The CSP is tightly scoped:
- **`default-src 'self'`** — Block all resources not explicitly allowed
- **`script-src 'self'`** — Only same-origin scripts (no CDN, no inline)
- **`style-src 'self' 'unsafe-inline'`** — Same-origin styles + Tailwind-generated inline styles
- **`img-src 'self' data: https://*.googleapis.com`** — Same-origin + data URIs (QR codes) + Google APIs
- **`connect-src`** — Explicitly allowlisted: Firebase Auth, Identity Toolkit, Secure Token, and Google OAuth endpoints
- **`frame-src https://accounts.google.com`** — Only Google OAuth popups allowed
- **`object-src 'none'`** — No plugins (Flash, Java, etc.)
- **`frame-ancestors 'none'`** — Cannot be embedded in any frame (defense-in-depth with X-Frame-Options)
- **`upgrade-insecure-requests`** — Force HTTPS for all subresources

### 6.4 Container Security

- **Non-root execution**: `nginxinc/nginx-unprivileged` base image runs as UID 101, not root
- **Alpine Linux**: Minimal base image (~5MB), reduced attack surface
- **Multi-stage build**: Build tools and source code are not present in the production image
- **No install scripts**: `npm ci --ignore-scripts` prevents pre/post-install script execution
- **Read-only filesystem compatible**: Only static assets are served, no write operations required

### 6.5 Frontend Security Practices

- **No secrets in client code**: All sensitive configuration via environment variables injected at build time
- **No inline scripts**: CSP-compliant, no `eval()` or `new Function()`
- **Input validation**: Forms validate presence (e.g., title, email). Tags normalized to lowercase; commas/enter delimiters controlled.
- **Error messages**: Generic error display, no stack traces or internal details exposed to users
- **XSS prevention**: React's default JSX escaping + CSP + `X-Content-Type-Options: nosniff`

—

## 7. API Protocol & Type Safety

### 7.1 Connect-RPC

All API communication uses **Connect-RPC** (from buf.build), a modern RPC framework that:
- Generates fully typed TypeScript clients from Protocol Buffer definitions
- Supports unary RPCs (request/response) and server streaming (real-time token delivery)
- Works natively in browsers via `@connectrpc/connect-web` (no gRPC proxy required)
- Provides automatic serialization/deserialization with type-safe request/response objects

### 7.2 Generated Service Definitions

The proto-generated code covers the full API surface:

| Service | RPCs | Used By |
|---|---|---|
| `AuthService` | Auth verification, session info | Both apps |
| `OrganizationService` | List, Get, Create, InviteMember | Admin |
| `WorkspaceService` | List, Get, Create, InviteMember | Both apps |
| `DocumentService` | List, Update, Delete, Reprocess | Admin |
| `ConversationService` | SendMessage (server streaming) | App |
| `ChatMessageService` | RetrieveMessages, RateAssistantMessage | App |
| `AuditService` | ListAuditEvents | Admin |

### 7.3 Shared Protobuf Types

Common enums and types defined in `common_pb.ts`:
- `DocumentStatus`: PENDING, PROCESSING, READY, ERROR
- `WorkspaceRole`: ADMIN, EDITOR, VIEWER
- `OrgRole`: OWNER, ADMIN

—

## 8. Multi-Tenant Data Model

### 8.1 Hierarchy

```
Organization (tenant)
  └── Workspace (data boundary)
        ├── Documents (uploaded files)
        │     └── Chunks (embedded segments for RAG)
        ├── Members (users with role-based access)
        └── Messages (conversation history)
```

### 8.2 Roles & Permissions

| Level | Role | Capabilities |
|---|---|---|
| **Organization** | Owner | Full org management, workspace creation, member invitation |
| **Organization** | Admin | Workspace management, member invitation |
| **Workspace** | Admin | Document upload/delete, member management |
| **Workspace** | Editor | Document upload |
| **Workspace** | Viewer | Read-only document queries via app |

### 8.3 Workspace-Scoped Queries

The app interface supports **cross-workspace queries** — users can select multiple workspaces and the RAG pipeline searches across all selected workspace document sets simultaneously, while respecting workspace-level access controls enforced server-side.

—

## 9. Document Processing Pipeline

### 9.1 Supported Formats

- PDF (`.pdf`)
- Microsoft Word (`.docx`, `.doc`)
- Plain text (`.txt`)
- Markdown (`.md`)

### 9.2 Upload-to-Query Lifecycle

```
Upload (multipart/form-data) → Pending → Processing (OCR/text extraction) →
  Chunking → Embedding (Vertex AI) → Ready (queryable via RAG)
```

### 9.3 Document Metadata

Each document carries:
- **Title** (required, auto-generated from filename)
- **Description** (optional)
- **Tags** (freeform, stored as JSON array)
- **Status** with automatic polling for updates
- **Metrics**: file size, page count, chunk count

### 9.4 Error Recovery

- Failed documents are surfaced in a dedicated DLQ-style section
- Administrators can **reprocess** failed documents without re-uploading
- Administrators can **edit metadata** and **delete** documents at any time

—

## 10. Compliance Alignment

### 10.1 NIST 800-63B (Digital Identity)

| Requirement | Implementation |
|---|---|
| **AAL2** (multi-factor) | Magic link (something you have: email account) + TOTP (something you have: authenticator device) |
| **Phishing resistance** | No static passwords to phish; magic links are single-use and domain-scoped |
| **Verifier compromise resistance** | No password hashes stored; TOTP secrets managed by Firebase Identity Platform |

### 10.2 NIST 800-53 (Security Controls)

| Control Family | Relevant Controls | Implementation |
|---|---|---|
| **AC (Access Control)** | AC-2, AC-3, AC-6 | Role-based access (org/workspace level), least-privilege workspace roles |
| **AU (Audit)** | AU-2, AU-3, AU-6 | Full audit log with action, user, resource, IP, user agent, correlation IDs |
| **IA (Identification & Auth)** | IA-2, IA-5, IA-8 | Magic link + mandatory TOTP MFA, Identity Platform tenant isolation |
| **SC (System & Comms)** | SC-8, SC-13, SC-28 | HTTPS + HSTS, CSP, transport encryption via TLS |
| **CM (Configuration Mgmt)** | CM-2, CM-6 | Hardened nginx, minimal Alpine container, no unnecessary services |
| **SI (System & Info Integrity)** | SI-3, SI-10 | Input validation, CSP, XSS protection, MIME sniffing prevention |

### 10.3 FedRAMP Alignment

| FedRAMP Requirement | Status |
|---|---|
| Multi-factor authentication | Mandatory TOTP for all users |
| Encryption in transit | TLS 1.2+ (Cloud Run managed), HSTS preload |
| Audit logging | Comprehensive event capture with filterable viewer |
| Least privilege | Role hierarchy (owner > admin > editor > viewer) |
| Session management | Firebase SDK-managed with automatic token refresh |
| Input validation | Client-side + server-side validation |
| Container hardening | Non-root nginx, Alpine base, multi-stage build |

—

## 11. Operational Characteristics

### 11.1 Performance

- **Vite production builds**: Tree-shaken, code-split, content-hashed static assets
- **Aggressive caching**: `/assets/` served with `Cache-Control: public, immutable` and 1-year expiry (safe due to Vite's content hashing)
- **Gzip compression**: Enabled for all text-based content types
- **Streaming responses**: App tokens delivered via server streaming, not polling — sub-second time-to-first-token

### 11.2 Reliability

- **Health check endpoint**: `/healthz` for Cloud Run startup/liveness probes
- **Document status polling**: Automatic refresh while documents are being processed
- **Error recovery**: Comprehensive error display with dismissible alerts, document reprocessing
- **Graceful degradation**: Tenant not found page when multi-tenancy is misconfigured

### 11.3 Observability

- **Audit trail**: Every significant action logged with user, resource, IP, user agent, and correlation ID
- **Correlation IDs**: Enables end-to-end request tracing across frontend → API → backend services
- **Structured error display**: Errors surfaced to admins with actionable context

—

## 12. Source File Inventory

### 12.1 Admin Console (`admin/`)

| File | Lines | Purpose |
|---|---|---|
| `src/main.tsx` | 86 | App bootstrap, Firebase init, tenant discovery, API client init |
| `src/App.tsx` | 24 | Route definitions wrapped in AuthGate |
| `src/auth/AuthContext.tsx` | 302 | Full auth state machine (magic link + TOTP MFA) |
| `src/auth/AuthGate.tsx` | 45 | State-driven gate component |
| `src/auth/LoginPage.tsx` | 105 | Magic link email input + confirmation |
| `src/auth/MfaChallenge.tsx` | 82 | TOTP verification on sign-in |
| `src/auth/MfaEnrollment.tsx` | 104 | TOTP enrollment with QR code |
| `src/lib/auth.ts` | 39 | Firebase app/auth initialization with tenant support |
| `src/lib/client.ts` | 105 | Connect-RPC clients + multipart upload helper |
| `src/types/models.ts` | 62 | TypeScript domain model interfaces |
| `src/pages/Dashboard.tsx` | 218 | Org/workspace overview + creation |
| `src/pages/WorkspaceDetail.tsx` | 466 | Workspace documents + members with upload |
| `src/pages/Documents.tsx` | 574 | Full document management (CRUD, multi-upload, filter, DLQ) |
| `src/pages/Members.tsx` | 131 | Organization member list + invite |
| `src/pages/AuditLog.tsx` | 244 | Paginated audit event viewer |
| `src/pages/TenantNotFound.tsx` | 51 | Tenant resolution error page |
| `nginx.conf` | 43 | Hardened nginx with security headers + CSP |
| `Dockerfile` | 34 | Multi-stage build (node:20-alpine → nginx-unprivileged) |
| **Total** | **~2,715** | |

### 12.2 App Interface (`app/`)

| File | Lines | Purpose |
|---|---|---|
| `src/main.tsx` | 87 | App bootstrap, Firebase init, tenant discovery, API client init |
| `src/App.tsx` | 17 | Route definitions wrapped in AuthGate |
| `src/auth/AuthContext.tsx` | 302 | Full auth state machine (magic link + TOTP MFA) |
| `src/auth/AuthGate.tsx` | 45 | State-driven gate component |
| `src/auth/LoginPage.tsx` | 105 | Magic link email input + confirmation |
| `src/auth/MfaChallenge.tsx` | 82 | TOTP verification on sign-in |
| `src/auth/MfaEnrollment.tsx` | 104 | TOTP enrollment with QR code |
| `src/lib/auth.ts` | 39 | Firebase app/auth initialization with tenant support |
| `src/lib/client.ts` | 63 | Connect-RPC clients (conversation + message history) |
| `src/pages/Chat.tsx` | 367 | RAG conversation with streaming, citations, workspace selection |
| `src/pages/TenantNotFound.tsx` | 51 | Tenant resolution error page |
| `nginx.conf` | 43 | Hardened nginx with security headers + CSP |
| `Dockerfile` | 34 | Multi-stage build (node:20-alpine → nginx-unprivileged) |
| **Total** | **~1,339** | |

### 12.3 Generated Protocol Buffer Code (both apps)

| File | Purpose |
|---|---|
| `auth_connect.ts` / `auth_pb.ts` | Authentication service definitions |
| `organization_connect.ts` / `organization_pb.ts` | Organization CRUD + member management |
| `workspace_connect.ts` / `workspace_pb.ts` | Workspace CRUD + member management |
| `document_connect.ts` / `document_pb.ts` | Document lifecycle management |
| `conversation_connect.ts` / `conversation_pb.ts` | RAG conversation streaming |
| `chatmessage_connect.ts` / `chatmessage_pb.ts` | Message history + rating |
| `audit_connect.ts` / `audit_pb.ts` | Audit event queries |
| `common_pb.ts` | Shared enums (DocumentStatus, WorkspaceRole, OrgRole) |

—

## 13. Dependency Audit

### 13.1 Production Dependencies

| Package | Version | License | Purpose | Gov't Risk |
|---|---|---|---|---|
| `react` | 19.1.0 | MIT | UI framework | Low — Meta maintained, widely adopted |
| `react-dom` | 19.1.0 | MIT | React DOM renderer | Low |
| `react-router-dom` | 7.8.2 | MIT | Client-side routing | Low — Remix maintained |
| `firebase` | 11.8.1 | Apache 2.0 | Auth + Identity Platform SDK | Low — Google maintained |
| `@bufbuild/protobuf` | 1.10.1 | Apache 2.0 | Protobuf runtime | Low — Buf maintained |
| `@connectrpc/connect` | 1.7.0 | Apache 2.0 | Connect-RPC client | Low — Buf maintained |
| `@connectrpc/connect-web` | 1.7.0 | Apache 2.0 | Browser Connect transport | Low |
| `tailwindcss` | 3.4.1 | MIT | Utility-first CSS | Low — Tailwind Labs |
| `qrcode.react` | 4.2.0 | ISC | QR code SVG generation | Low — Minimal, no network calls |
| `react-markdown` | 9.0.3 | MIT | Markdown rendering (app) | Low — Unified ecosystem |
| `@tailwindcss/typography` | 0.5.19 | MIT | Prose typography (app) | Low |

All dependencies use permissive open-source licenses (MIT, Apache 2.0, ISC) compatible with government procurement.

### 13.2 Dev Dependencies

Build-time only, not present in production containers:

| Package | Purpose |
|---|---|
| `typescript` | Type checking |
| `vite` | Build tool |
| `@vitejs/plugin-react` | React JSX transform |
| `autoprefixer` | CSS vendor prefixing |
| `postcss` | CSS processing |

—

## 14. Key Differentiators for Government

1. **Zero-password architecture** — Eliminates the #1 attack vector for government systems
2. **Mandatory MFA** — Not optional, not bypassable — enforced at the UI gate layer and verified server-side
3. **Auth pool isolation** — Admin and user authentication are entirely separate identity pools
4. **Multi-tenant by design** — Serve multiple agencies from a single deployment with full data isolation
5. **Full audit trail** — Every action logged with user, resource, IP, user agent, and correlation ID
6. **Source citations** — AI responses include traceable citations to original source documents, enabling verification
7. **Hardened containers** — Non-root nginx, Alpine base, multi-stage builds, comprehensive security headers
8. **Strict CSP** — No inline scripts, explicit allowlists, frame-ancestors none
9. **Type-safe API** — Connect-RPC with generated TypeScript eliminates entire classes of integration bugs
10. **Document lifecycle management** — Upload, process, embed, query, reprocess, delete — with status visibility at every stage


—
---

# SECTION 6: CHATGPT — Frontend Security Review (app/admin SPAs)

> Source: `app/docs/security/CHATGPT_Frontend_Security_Review.md`

---

# ChatGPT Security Review — App and Admin SPAs (Latent Archon)

## Executive Summary
- The App (end-user) and Admin (operator) single-page applications are modern, security-conscious SPAs served via Cloud Run (nginx) behind a Google Cloud HTTPS Load Balancer with host-based routing and Cloud Armor.
- Authentication uses Google Identity Platform (Firebase Auth) with multi-tenancy and enforced TOTP-based MFA. Authentication is passwordless via magic link, followed by MFA enrollment and challenge workflows.
- API access uses Connect-RPC over HTTPS with an auth interceptor that attaches a short-lived Bearer ID token. Document uploads use a single, scoped multipart REST endpoint.
- Tenancy is derived from subdomain-to-tenant mapping at the client and is expected to be strictly enforced on the backend (RLS and request scoping). Frontend prevents token persistence beyond runtime memory; only the pending magic-link email is stored transiently in localStorage and removed once used.
- Client-side rendering uses React and `react-markdown` (default safe mode) to render assistant responses, reducing XSS risk from model output. Admin UI supports metadata-rich document uploads and member invitations; an Audit UI exists, implying server-side audit logging.

Overall, the implementation demonstrates strong alignment with security best practices. The recommended next steps focus on codifying HTTP security headers, CSP hardening, additional auth safeguards (session idle timeout, re-auth for sensitive actions), and privacy controls.

## Scope
- Frontend SPAs under `app/` and `admin/` directories, including:
  - Entry points, auth flows, API clients, streaming, data handling, and tenant resolution.
- Security-relevant architecture from infra and backend where it directly affects client assurances (hosting, transport, identity, tenancy enforcement, logging).

## Architecture Overview
- Hosting: Each SPA runs in Cloud Run using `nginxinc/nginx-unprivileged:alpine`. HTTPS LB routes based on hostname:
  - `app.*.latentarchon.com` → App SPA
  - `api.app.*.latentarchon.com` → User-facing API (app stream, auth)
  - `admin.*.latentarchon.com` → Admin SPA
  - `api.admin.*.latentarchon.com` → Admin API (ingestion, org/workspace)
- Transport: All API calls use HTTPS. Connect-RPC (gRPC-web style) via `@connectrpc/connect-web` with an interceptor injecting `Authorization: Bearer <idToken>`.
- Streaming: App uses server-streaming Connect-RPC for incremental assistant output and citation delivery.

## Authentication & Session Management
- Identity: Google Identity Platform (Firebase Auth) multi-tenant.
- Login: Magic link emailed to user, handled via `isSignInWithEmailLink` + `signInWithEmailLink`.
- MFA: TOTP enforced. Enrollment via QR code; challenge flows supported via `MultiFactorResolver`.
- Token Handling: `getIdToken()` retrieved on demand; attached per request by interceptor. Tokens are not persisted in localStorage/sessionStorage. The only localStorage use is `archon_magic_link_email` during link flow, cleared immediately after use.
- Tenant Resolution: `VITE_TENANT_MAP` JSON maps subdomains to tenant IDs; applied at app init so tokens carry the `firebase.tenant` claim.
- Session State: Client tracks `authState` transitions to gate access (`AuthGate`). Sign-out clears in-memory state and MFA context.

## Authorization & Multi-Tenancy
- Frontend expresses org/workspace scoping in requests:
  - App selects workspace IDs to constrain retrieval and RAG context.
  - Admin restricts actions to the selected org/workspace (list, create, invite, upload, document management).
- Role Surfacing:
  - Admin maps backend enums to `owner/admin` at org level and `admin/editor/viewer` at workspace level.
- Enforcement Assumption: Backend validates tenant claim, user membership, and role per request (not visible in SPA, but indicated by architecture and service boundaries). DB RLS is expected to further restrict data access.

## Data Handling & Privacy
- Data Types:
  - PII: user email addresses (for auth and invites), display names if provided.
  - Business Data: uploaded documents (filenames, sizes, types), extracted content (processed server-side), metadata (title, description, tags), conversation content and citations.
- Client Storage:
  - No tokens stored at rest on client. Only pending email saved transiently during magic-link flow.
  - UI state (e.g., messages, uploads) lives in memory.
- Uploads:
  - Admin uses `apiUpload('/api/documents', FormData)` with `Authorization` header. Supports title/description/tags. Filename-derived default title reduces user error.
- Rendering Safety:
  - `react-markdown` used in App for assistant content. By default, it escapes HTML, mitigating XSS from model output. No `rehype-raw` usage detected.

## Client-Side Security Controls
- Auth Gate:
  - Central component determines whether to show login, MFA enrollment/challenge, or the protected app.
- Error Handling:
  - Errors shown to users in Admin; Chat logs stream errors and provides a safe fallback message.
- Input Validation:
  - Forms validate presence (e.g., title, email). Tags normalized to lowercase; commas/enter delimiters controlled.
- Streaming Abort:
  - Chat supports cancelation via `AbortController`, preventing dangling requests.

## API & Transport Security
- Connect-RPC transport with auth interceptor ensures each RPC carries a valid Bearer ID token.
- REST only for multipart uploads; still includes Authorization header.
- CORS is configured server-side per environment/domains (per architecture notes). Clients make same-origin calls to `VITE_API_BASE_URL`.
- TLS termination at Google HTTPS Load Balancer; Cloud Armor policies in place per environment.

## Logging, Auditing, and Monitoring
- Admin app references an `AuditService` client and `AuditLog` route, indicating exposure of audit trails to operators.
- Client console logs capture operational errors (non-sensitive). Security-relevant events (auth, invites, document lifecycle) expected to be recorded server-side for integrity and compliance.

## Dependency & Supply Chain
- Key packages: `react`, `react-router-dom`, `firebase` (auth), `@connectrpc/connect(-web)`, `react-markdown`.
- Recommendation: Maintain lockfiles, enable Dependabot or equivalent, and enforce `npm audit`/SCA in CI for both apps.

## Threat Model Highlights & Mitigations
- Token Theft (XSS/Storage):
  - Mitigation: No token persistence beyond runtime memory; CSP and JSX-escaped rendering reduce risk. Recommend strict CSP (see below).
- Prompt Injection / Untrusted Content:
  - Mitigation: Markdown rendering is sanitized by default; citations are plain text. Continue to avoid raw HTML. Consider server-side content sanitization and provenance tagging.
- CSRF:
  - Mitigation: Bearer tokens + CORS; APIs designed for XHR with Authorization header. No cookie-based sessions in SPA.
- Multi-Tenancy Isolation Bypass:
  - Mitigation: Tenant claim embedded in tokens; backend must enforce per-tenant/org/workspace access checks and RLS. Recommend explicit negative tests in CI.
- Upload Abuse / Malware:
  - Mitigation: Uploads require auth and workspace scoping. Recommend server-side MIME/AV scanning, file size/type allowlist, quota/rate limits.
- Streaming DoS:
  - Mitigation: Client supports abort; recommend server rate limiting and per-user concurrency caps.

## Compliance Alignment (High-Level)
- NIST 800-53 (Moderate) mapping examples:
  - AC (Access Control): Role-based access (org/workspace), token-based API access.
  - IA (Identification & Authentication): Identity Platform, magic link + enforced TOTP MFA, tenant claims.
  - SC (System & Communications Protection): TLS, Cloud Armor, CORS, sanitized markdown rendering.
  - AU (Audit & Accountability): Audit service exposure in Admin; recommend immutable, centralized logs with retention.
  - MP/CM (Media/Config Management): Document uploads with server-side validation and processing; SPA build artifacts served from controlled images.
- SOC 2: Controls present in Security and Availability trust principles; Privacy depends on server-side policies (data minimization, retention, right-to-delete processes).

## Residual Risks & Recommendations (Prioritized)
1) Security Headers & CSP
- Add strict CSP (nonce-based for scripts/styles), default-src 'self'; connect-src limited to API domains; img-src as needed; block inline/eval.
- Add HSTS (preload), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-Frame-Options/Frame-Options.

2) Session & Auth Hardening
- Enforce session idle timeout and step-up auth for sensitive actions (e.g., inviting admins, deleting docs).
- Consider detection of anomalous sign-ins and device signals via Identity Platform.

3) Upload & Content Controls
- Server-side AV/MIME scanning, size limits, and per-tenant quotas; backpressure for processing queues.
- Redact or quarantine files with embedded active content (macro-enabled docs) if supported.

4) Multi-Tenancy Guardrails
- Ensure backend enforces `firebase.tenant` + membership checks on every request; add integration tests for cross-tenant access attempts.
- Validate `VITE_TENANT_MAP` provisioning in CI to prevent orphaned subdomains.

5) Privacy & Data Minimization
- Expand Admin UX for document retention and deletion workflows; expose immutable audit of deletions.
- Classify PII vs. sensitive business data; tag documents with data categories for downstream policy.

6) SCA & Build Integrity
- Pin dependency versions; enable CI SCA scanning and image vulnerability scans; sign images (SLSA/COSIGN) and verify at deploy.

7) Monitoring & Detection
- Emit security telemetry to SIEM (auth events, role/admin changes, document lifecycle, anomalous requests). Implement alerting for brute-force and abuse patterns.

## Appendix — Key Client Artifacts Reviewed
- App
  - `app/src/main.tsx`: Tenant resolution (`VITE_TENANT_MAP`), Firebase init, API client init, `AuthProvider` wiring.
  - `app/src/auth/AuthContext.tsx`: Magic link + TOTP MFA flows; no token persistence; localStorage used only for pending email.
  - `app/src/auth/AuthGate.tsx`: Gated render based on `authState`.
  - `app/src/lib/client.ts`: Connect-RPC transport + auth interceptor; workspace/conversation clients.
  - `app/src/pages/Chat.tsx`: Workspace selection, history retrieval, streaming send with abort, sanitized markdown rendering, citations.
- Admin
  - `admin/src/main.tsx`: Same tenant resolution and auth/API init pattern.
  - `admin/src/auth/AuthContext.tsx` + `AuthGate.tsx`: Same magic link + MFA enforcement.
  - `admin/src/lib/client.ts`: Connect-RPC clients for org/workspace/document/audit; `apiUpload` for multipart with auth.
  - `admin/src/pages/Dashboard.tsx`: Org/workspace listing, workspace creation.
  - `admin/src/pages/WorkspaceDetail.tsx`: Document list and single-file upload with title/description/tags; invite members.
  - `admin/src/pages/Documents.tsx`: Document listing with filters, metadata edit, delete, reprocess; multi-file queued upload with metadata per file.
  - `admin/src/pages/Members.tsx`: Org member listing and invites.

---
Prepared for government sales/security review. For deeper compliance mapping (e.g., FedRAMP baselines), pair this with backend/infra controls (RLS, KMS, VPC-SC/PSC, Cloud Armor policies, audit pipelines, DR/BCP).
