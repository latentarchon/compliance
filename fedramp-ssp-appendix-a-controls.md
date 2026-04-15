# Appendix A: FedRAMP Security Control Implementations

> **Parent Document**: SSP-LA-001 (fedramp-ssp.md)  
> **Baseline**: NIST SP 800-53 Rev. 5 — High Impact (IL5)  
> **High Enhancement Controls**: See Appendix A-2 for 85+ FedRAMP High-delta controls  
> **Date**: April 2026

This appendix documents the implementation narrative for each NIST 800-53 Rev. 5 High baseline control. The system operates within GCP IL5 Assured Workloads, satisfying DFARS 252.204-7012 and NIST SP 800-171 requirements. Each control includes: responsibility designation, implementation status, and a detailed narrative covering who, what, how, where, and when.

**Responsibility Key**: `CSP` = Latent Archon, `Inherited` = GCP FedRAMP High, `Shared` = Joint, `Customer` = Agency

---

## AC — Access Control

### AC-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon maintains a formal Access Control Policy (POL-AC-001, `policies/access-control.md`) that defines account management procedures, authentication requirements, authorization model, data isolation controls, and network-level access controls. The policy is reviewed annually by the CEO / ISSO. The policy is approved by the CEO and disseminated to all personnel via the compliance document repository. Changes to the policy follow the Change Management Policy (POL-CM-001) requiring PR-based review and approval.

**Customer Responsibility**: Customer agencies are responsible for establishing complementary access control policies for their end users that align with agency-specific requirements.

### AC-2: Account Management

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**:

**(a)** Latent Archon defines four organization-level account types: `master_admin`, `admin`, `editor`, and `viewer`. Each account type has specific privileges documented in the RBAC matrix (see Section 7.3 of the SSP). Account types are enforced per-RPC in the Connect-RPC interceptor chain. Additionally, **service accounts** (e.g., `noreply@latentarchon.com` for transactional email) are a distinct, non-interactive account type — they are blocked from authentication at the application layer and cannot be provisioned into any organization or workspace.

**(b)** Account managers are designated per customer organization. The `master_admin` role serves as the organization account manager with authority to create, modify, disable, and remove accounts. Latent Archon platform operations serve as the system-level account manager.

**(c)** Conditions for group and role membership are enforced by the RBAC model. Users must be explicitly invited to an organization (via invite token or SCIM provisioning) and explicitly granted workspace access. The auth interceptor enforces an **org membership gate** — users not belonging to any organization are rejected with `PermissionDenied` on all non-AuthService RPCs.

**(d)** Authorized users, group and role membership, and access authorizations are specified per-organization by the `master_admin` through the admin API (`InviteMember`, `UpdateMemberRole`, `RemoveMember` RPCs). For SCIM-enabled organizations, user lifecycle is managed automatically by the customer IdP.

**(e)** Account creation requires approval by an org admin (explicit invite) or automated provisioning via SCIM 2.0 from an authorized customer IdP. JIT (Just-In-Time) provisioning automatically creates accounts for federated users on first SSO login when an SSO configuration exists for the organization.

**(f)** Accounts are created via invite tokens (time-limited), SCIM 2.0 provisioning, or JIT provisioning. Accounts are modified via admin API RPCs. Accounts are disabled via Firebase Admin SDK `DisableUser()` or SCIM DELETE. Accounts are removed via `RemoveMember` RPC or self-service `CloseAccount` RPC (requires step-up MFA). Automated 90-day data purge runs via Cloud Scheduler (FedRAMP High mgmt project) → Pub/Sub push → ops Cloud Run for closed accounts.

**(g)** System access is monitored through comprehensive audit logging (`internal/audit/logger.go`). All authentication events, role changes, member additions/removals, and SCIM provisioning actions are recorded with user ID, IP address, user agent, timestamp, and correlation ID.

**(h)** Account managers (org `master_admin`) are notified of account changes via real-time security email notifications. Notifications cover: role escalation, auth failures, member changes, SCIM events, and deletions.

**(i)** Authorization to access the system requires: (1) valid Firebase Auth JWT, (2) MFA verification, (3) organization membership, (4) appropriate RBAC role, and (5) workspace membership for data access.

**(j)** All accounts are reviewed by the org `master_admin` through the admin dashboard. Latent Archon recommends quarterly access reviews. Compliance with review schedules is tracked via Drata.

**(k)** When personnel are transferred within an organization, org admins update role assignments via the admin API. SCIM-enabled organizations handle transfers automatically through IdP group-to-role mapping.

**(l)** Accounts are deprovisioned within 24 hours of notification via SCIM DELETE (automated) or manual removal by org admin. Self-service account closure is available via `CloseAccount` RPC with step-up MFA.

**Customer Responsibility**: Customers are responsible for timely notification of personnel transfers, terminations, and role changes. For SCIM-enabled organizations, this is automated through the customer IdP.

### AC-2(1): Automated Account Management

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Latent Archon provides a SCIM 2.0 server (`internal/sso/scim_handler.go`) conforming to RFC 7643/7644. The SCIM server supports automated user provisioning (create), deprovisioning (delete), attribute updates (replace/patch), and group management. Customer IdPs (Okta, Azure AD, etc.) connect via SCIM bearer token authentication with SHA-256 hashed tokens stored in the `scim_tokens` table. JIT provisioning auto-creates user accounts on first federated login when SCIM has not yet provisioned the user. All automated account actions are audit-logged.

### AC-2(2): Automated Temporary and Emergency Accounts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system does not support anonymous or temporary accounts. All invite tokens are time-limited and single-use. Emergency access to GCP infrastructure uses IAM Conditions with time-limited grants (maximum 4 hours) and requires CEO/CTO approval documented in the incident response log.

### AC-2(3): Disable Accounts

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Accounts are disabled via: (1) Firebase Admin SDK `DisableUser()` called by org admins or platform operations, (2) SCIM DELETE from customer IdP, (3) self-service `CloseAccount` RPC requiring step-up MFA. Disabled accounts cannot authenticate — the Firebase Auth SDK rejects tokens from disabled accounts before they reach the application. Automated 90-day data purge via Cloud Scheduler (FedRAMP High mgmt project) → Pub/Sub push removes personal data from closed accounts.

### AC-2(4): Automated Audit Actions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All account lifecycle events are automatically audit-logged via `internal/audit/logger.go`. Events include: `user.created`, `user.invited`, `user.joined`, `user.removed`, `user.disabled`, `user.role_changed`, `user.account_closed`, `scim.user_created`, `scim.user_deleted`, `scim.user_updated`. Each event records: user_id, org_id, action, status (success/failure), IP address, user agent, timestamp, and JSONB metadata including idp_pool_id, request_id, trace_id.

### AC-2(5): Inactivity Logout

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The auth interceptor (`cmd/server/connect_interceptors.go`) enforces server-side session timeouts on every request. Idle timeout defaults to 25 minutes; absolute timeout defaults to 12 hours. Both are calculated from JWT `auth_time` and `iat` claims. Per-organization configurable timeouts allow agencies to set stricter values (idle: 5-480 minutes, absolute: 60-1440 minutes) via `UpdateOrganizationSettings` RPC. Expired sessions receive `Unauthenticated` responses requiring re-authentication.

### AC-3: Access Enforcement

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Access enforcement operates at five layers:

1. **Auth Interceptor**: Every RPC (except `/health` and CORS preflight) passes through the auth interceptor which verifies the Firebase JWT, enforces IDP pool isolation, validates MFA status, checks session timeouts, enforces org membership, and validates subdomain-to-org routing.

2. **RBAC**: Each RPC handler performs explicit role-based authorization checks before executing business logic. Organization operations require `IsOrgAdmin()` or `IsMasterAdmin()`. Workspace operations require `CanUserAccessWorkspace()` (explicit membership or master_admin).

3. **PostgreSQL RLS**: Row-Level Security policies on all data tables scope queries to the authenticated user's organization and workspace. RLS is fail-closed: missing session variables return zero rows. The `app_ro` role cannot INSERT/UPDATE/DELETE data tables.

4. **Vector Store Scoping**: Vertex AI vector search queries are restricted by workspace-scoped token filters, preventing cross-workspace semantic search.

5. **Subdomain→Org Validation**: The auth interceptor resolves Host header subdomains against the `organizations` table via `GetOrgIDBySlug`. Unknown subdomains are rejected (`PermissionDenied: "unknown organization"`). Cross-org mismatches (user's org ≠ subdomain org) are rejected (`PermissionDenied: "organization mismatch"`).

### AC-4: Information Flow Enforcement

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Information flow is controlled at multiple layers:

- **Network**: VPC with private IP only (no public IPs on any service). FQDN-based egress firewall with default-deny-all and explicit allowlist for Google APIs and Microsoft Graph API (`graph.microsoft.com`, `login.microsoftonline.com` for SharePoint/OneDrive document sync). Cloud Armor WAF with OWASP Core Rule Set.
- **Application**: RLS enforces workspace-scoped data access. Vector store token restrictions prevent cross-workspace search. The auth interceptor prevents cross-org request routing via DB-backed subdomain validation.
- **Per-Org IP Allowlisting**: Organization administrators configure CIDR-based IP allowlists via `UpdateOrganizationSettings`. Allowlists are synced to Cloud Armor WAF rules using CEL expressions matching org hostname + IP range. This enables agencies to restrict access to government/VPN IP ranges.

**Customer Responsibility**: Customers are responsible for configuring IP allowlists appropriate for their network environment.

### AC-5: Separation of Duties

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Separation of duties is enforced through:

- **Service Isolation**: Three Cloud Run services (`archon-app`, `archon-admin`, `archon-ops`) operate with distinct PostgreSQL roles (`archon_app_ro`, `archon_admin_rw`, `archon_ops_rw`) enforced via migration `20260328120000_enforce_least_privilege_db_roles.sql`. Default `PUBLIC` privileges are revoked — only named roles have table access. The app service cannot modify reference data. The ops service has write access limited to document processing tables only.
- **Project Isolation**: Three GCP projects (app, ops, admin) with separate Identity Platform pools (app and admin), Cloud Armor policies, and IAM configurations. The ops project has no identity pool and no public ingress — it is a pure data tier. Cross-pool identity bridging is explicitly prohibited (see `docs/POOL_ISOLATION.md`).
- **RBAC**: Only `master_admin` can promote others to `master_admin`. Self-MFA-reset is blocked. Last-admin guard prevents lockout.
- **CI/CD**: Production deploys require PR approval. Terraform plans are posted as PR comments for review before apply.

### AC-6: Least Privilege

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**:

- **GCP IAM**: The Terraform service account has 20 IAM roles including `roles/editor` for broad infrastructure management (no `roles/owner`). Each Cloud Run service account has scoped permissions: `archon-ops` has 12 roles for document processing, `archon-admin` and `archon-app` receive cross-project grants for Cloud SQL, Cloud Tasks, GCS, and Vertex AI access only. Workload Identity Federation eliminates static service account keys.
- **Database**: Four distinct PostgreSQL roles with minimum necessary grants, enforced via Atlas migration. Default `PUBLIC` privileges are revoked on all tables and sequences. `archon_app_ro` is read-only on reference data (SELECT + INSERT only for app persistence). `archon_ops_rw` is scoped to document processing tables (cannot touch org/member/invite data). Audit table is INSERT-only for non-admin roles. Schema migrations run under an `archon_migrator` role assumed via IAM auth (`SET ROLE`) — no static credentials are used in the normal migration path. A `postgres` superuser password exists in Secret Manager as a break-glass mechanism, accessible only to human security administrators and not mounted on any service or job by default.
- **Application**: RBAC enforces per-RPC authorization. Viewers cannot modify data. Editors cannot manage members. Only admins can manage workspaces. Service accounts used for system functions (e.g., transactional email sending) are explicitly blocked from interactive authentication and auto-provisioning via a configurable blocklist (`SERVICE_ACCOUNT_EMAILS`) enforced in the auth interceptor and magic link handler.
- **Microsoft Graph**: Connection management (create, list, revoke) restricted to org admins. Sync source configuration requires workspace admin permission. Source-level sync history queries require workspace document-edit permission. OAuth refresh tokens encrypted via Cloud KMS before storage.

### AC-6(1): Authorize Access to Security Functions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security functions are restricted to the `master_admin` role: promoting/demoting admin roles, configuring SSO/SCIM, managing IP allowlists, configuring session timeouts. MFA reset is restricted to org admins, with self-MFA-reset explicitly blocked. All security function invocations are audit-logged at WARN level.

### AC-6(2): Non-Privileged Access for Nonsecurity Functions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Engineers access development and staging environments with standard (non-privileged) GCP IAM roles. Production access requires time-limited IAM Condition grants (break-glass only, CEO/CTO approval, maximum 4 hours). Day-to-day operations (deployment, monitoring) are performed via CI/CD automation with Workload Identity Federation, not human credentials.

### AC-6(5): Privileged Accounts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Privileged accounts include: (1) GCP Organization Owner — restricted to CEO, used for break-glass only; (2) Terraform service account — used only by CI/CD via WIF, 20 IAM roles including `roles/editor`; (3) `master_admin` application role — per-customer org admin. All privileged actions are audit-logged. No shared accounts are used.

### AC-6(9): Log Use of Privileged Functions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All privileged operations are logged via `internal/audit/logger.go` at WARN level, including: role changes, member removal, org settings changes, SSO/SCIM configuration, MFA reset. GCP Cloud Audit Logs capture all IAM and infrastructure changes. Logs are exported to Cloud Logging (30-day retention) with optional SIEM export via Pub/Sub.

### AC-6(10): Prohibit Non-Privileged Users from Executing Privileged Functions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Every RPC handler includes explicit authorization checks before business logic execution. Non-admin users attempting admin operations receive `PermissionDenied`. The RBAC checks verify role from the database, not from client-provided claims. Role checks cannot be bypassed because they execute server-side after JWT verification.

### AC-7: Unsuccessful Logon Attempts

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Identity Platform provides built-in brute-force protection that temporarily locks accounts after repeated failed login attempts. The application implements two-tier rate limiting: (1) IP-based rate limiting at Cloud Armor, (2) per-user rate limiting in the Connect-RPC interceptor chain. Failed authentication attempts are logged with IP address and user agent for security monitoring.

**Customer Responsibility**: Customers may configure additional login attempt restrictions through their SSO Identity Provider.

### AC-8: System Use Notification

- **Responsibility**: Customer
- **Status**: Partially Implemented

**Implementation**: The SPA login pages support configurable system use notification banners. Customer agencies are responsible for providing the notification text per their agency policy.

**Customer Responsibility**: Customers must provide system use notification language compliant with their agency's requirements.

### AC-10: Concurrent Session Control

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Concurrent session limiting is enforced server-side per NIST AC-10. The auth interceptor (`connect_interceptors.go`) derives a session ID from `SHA-256(user_id + auth_time)` and upserts it into the `user_sessions` table on every authenticated request. After upserting, it counts active sessions (those with `last_seen_at` within the idle timeout window) via `CountActiveUserSessions`. If the count exceeds `MAX_CONCURRENT_SESSIONS` (default: 3, configurable via environment variable), the request is rejected with `ResourceExhausted: "too many active sessions"`. Stale sessions are cleaned by `CleanExpiredSessions` (run via Cloud Scheduler). Session records include: user_id, session_id, auth_time, client_ip, user_agent, and last_seen_at — enabling audit trail of all active sessions per user. In development mode, session concurrency checks are skipped for testing ergonomics.

### AC-11: Device Lock

- **Responsibility**: Customer
- **Status**: N/A (Customer Responsibility)

**Implementation**: Device lock is the responsibility of the customer agency and end-user device management. Latent Archon's server-side session timeouts complement client-side device lock by requiring re-authentication after idle/absolute timeout expiration.

### AC-12: Session Termination

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The auth interceptor enforces two server-side session timeout checks on every request:

1. **Idle Timeout**: Calculated from JWT `auth_time` claim. Default: 25 minutes. Configurable per-org: 5-480 minutes.
2. **Absolute Timeout**: Calculated from JWT `iat` (issued-at) claim. Default: 12 hours. Configurable per-org: 60-1440 minutes.

Organization administrators configure timeouts via `UpdateOrganizationSettings` RPC. The timeouts are stored in the organization settings JSONB and loaded on each request. Expired sessions receive `Unauthenticated` responses. The client SPAs detect this and redirect to the login page.

### AC-14: Permitted Actions Without Identification or Authentication

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Only two endpoints are accessible without authentication: (1) `/health` — returns service health status for load balancer probes, (2) CORS preflight requests (OPTIONS method). All other endpoints, including all data access and API calls, require full authentication through the auth interceptor chain.

### AC-17: Remote Access

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: All access to Latent Archon is remote by design (cloud-native SaaS). Remote access protections include: TLS 1.2+ enforced on all connections, HSTS with 2-year max-age and preload, Cloud Armor WAF with OWASP CRS, per-org IP allowlisting, and MFA enforcement. No VPN or direct infrastructure access is provided to customers. Infrastructure access for Latent Archon engineers uses GCP IAM with WIF (no static credentials).

### AC-17(1): Monitoring and Control of Remote Access

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Cloud Logging captures all API access with source IP, user agent, and authentication context. Cloud Armor logs all blocked requests with rule match details. Audit events record all data access with user identity, action, and resource. Cloud Monitoring dashboards provide real-time visibility into access patterns.

### AC-17(2): Protection of Confidentiality and Integrity of Remote Access

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: TLS 1.2+ is enforced on all connections (Google Front End terminates TLS with FIPS 140-2 validated modules). HSTS headers with 2-year max-age prevent protocol downgrade. Private Service Connect (PSC) provides encrypted internal communication to Vertex AI. No unencrypted communication paths exist within or to the system.

### AC-20: Use of External Systems

- **Responsibility**: Customer
- **Status**: N/A (Customer Responsibility)

**Implementation**: Customer agencies are responsible for policies governing use of external systems to access Latent Archon.

### AC-21: Information Sharing

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Information sharing is controlled at the workspace level. Users can only access documents within workspaces to which they have been explicitly granted membership. Cross-workspace and cross-org data access is prevented by RLS policies and the auth interceptor's org isolation enforcement. Document export capabilities are restricted to authorized roles (admin, master_admin) with step-up MFA.

### AC-22: Publicly Accessible Content

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: No customer content is publicly accessible. All document access requires authentication (valid JWT), MFA verification, organization membership, and workspace membership. Per-org IP allowlisting via Cloud Armor CEL expressions provides additional network-level access restriction. The system has no public-facing content pages — both SPAs require authentication before rendering any data.

---

## AT — Awareness and Training

### AT-1: Policy and Procedures

- **Responsibility**: CSP + Customer
- **Status**: Implemented

**Implementation**: Latent Archon maintains a Security Awareness & Training Policy (POL-AT-001, `policies/security-awareness-training.md`) defining mandatory training requirements, onboarding checklists, role-based training topics, and compliance tracking. The policy is reviewed annually. Customer agencies are responsible for user awareness training per their agency policies.

### AT-2: Literacy Training and Awareness

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: All Latent Archon personnel complete security awareness training upon onboarding and annually thereafter. Training covers: phishing recognition, password/credential hygiene, incident reporting procedures, data handling requirements, social engineering, and CUI handling. Training completion is tracked in Drata. Customer agencies are responsible for end-user security awareness training.

### AT-2(2): Insider Threat

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security awareness training includes insider threat recognition. Technical controls provide defense-in-depth: separation of duties (three services with distinct DB roles), comprehensive audit logging of all privileged actions, code review requirements (PR-based workflow), and the principle of least privilege for all accounts.

### AT-3: Role-Based Training

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Role-specific training is provided based on function: (1) Engineers receive secure coding training covering OWASP Top 10, Go-specific security patterns, and the Latent Archon security architecture; (2) Operations personnel receive incident response training and GCP security operations training; (3) All personnel receive general security awareness training. Training records are maintained and tracked.

### AT-4: Training Records

- **Responsibility**: CSP + Customer
- **Status**: Implemented

**Implementation**: Latent Archon maintains training records in Drata including: personnel name, training course, completion date, and next due date. Records are retained for the duration of employment plus one year. Customer agencies are responsible for maintaining their own user training records.

---

## AU — Audit and Accountability

### AU-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Audit logging is a mandatory, always-on capability of the Latent Archon platform. It cannot be disabled by customers or administrators. Audit logging requirements are documented in the Security Architecture Whitepaper and enforced in code via `internal/audit/logger.go`.

### AU-2: Event Logging

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The following event categories are logged:

- **Authentication**: Login success/failure, MFA verification, token refresh, session timeout
- **Authorization**: RBAC check pass/fail, workspace access grant/deny, org membership validation
- **Account Lifecycle**: User creation, invitation, join, removal, role change, account closure, SCIM provisioning/deprovisioning
- **Data Access**: Document upload, download, delete, search queries, conversation messages
- **Administrative**: Org settings changes, SSO/SCIM configuration, IP allowlist updates, member management
- **Security**: Failed auth attempts, cross-org access attempts, rate limit hits, WAF blocks

The event types are reviewed annually and updated as new features are added.

### AU-3: Content of Audit Records

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Each audit event record contains: `user_id` (actor), `organization_id` (org scope), `workspace_id` (workspace scope, where applicable), `action` (event type string), `status` (success/failure), `resource_type` and `resource_id` (target), `ip_address` (source IP), `user_agent` (client identifier), `trace_id` (distributed tracing correlation), `correlation_id` (multi-event correlation), `session_id` (session identification), `mfa_method` (MFA method used, e.g., TOTP), and `created_at` (UTC timestamp).

### AU-3(1): Additional Audit Information

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Audit events include a JSONB `metadata` field containing: `request_id`, `idp_pool_id` (Identity Platform tenant), `trace_id` (OpenTelemetry), `span_id`, `error_code` (for failures), `duration_ms` (request duration), and `platform` (admin/app/ops). Additionally, top-level `session_id` and `mfa_method` columns provide session correlation and MFA method tracking (e.g., TOTP) per AU-3(1) requirements. This enables correlation across distributed services and integration with SIEM systems. See Security Whitepaper: "Schema future-proofing".

### AU-4: Audit Log Storage Capacity

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Cloud Logging provides auto-scaling log storage with no capacity limits. Application audit events are stored in the Cloud SQL `audit_events` table with no automatic expiration (indefinite retention). BigQuery audit dataset uses no table or partition expiration (CMEK-encrypted via US multi-region KMS keyring). GCS WORM audit buckets provide immutable long-term archival with locked retention policies (7 years in production). All storage uses cost-optimized tiering (STANDARD → NEARLINE → COLDLINE) with zero deletion.

### AU-5: Response to Audit Logging Process Failures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The audit logger uses a best-effort async design (`EventAsync()`). If database persistence fails, the event is still emitted as a structured log to Cloud Logging (stdout), ensuring no audit data is lost even if the primary persistence path fails. Audit failures never block user requests — the system prioritizes availability while ensuring audit data reaches at least one persistent store.

### AU-5(1): Storage Capacity Warning

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Cloud Monitoring alerts are configured for Cloud SQL storage utilization. When storage exceeds 80% capacity, alerts notify the operations team. Cloud Logging storage is auto-scaling and does not require capacity monitoring.

### AU-6: Audit Record Review, Analysis, and Reporting

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Audit records are reviewed through multiple mechanisms: (1) Cloud Logging dashboards with pre-configured filters for security events; (2) Cloud Monitoring alert policies triggered on WARN-level audit events (role escalation, auth failures, cross-org attempts); (3) Real-time security email notifications to org admins for critical events; (4) Pub/Sub SIEM export pipeline enabling customer agencies to ingest audit data into their Splunk/Sentinel/Chronicle instances for agency-specific analysis.

### AU-6(1): Automated Process Integration

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Audit review is automated through: Cloud Monitoring alert policies that trigger on specific event patterns, real-time email notifications to org admins, and the Pub/Sub SIEM export pipeline for automated ingestion by agency security tools. The Drata integration provides continuous compliance monitoring against control requirements.

### AU-7: Audit Record Reduction and Report Generation

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Cloud Logging provides filtering, search, and aggregation over all audit records using structured JSON format. Correlation IDs (`trace_id`, `correlation_id`) enable cross-event linking for investigation. The FOIA Export Service supports org-level and workspace-level audit data export with chain-of-custody metadata.

### AU-8: Time Stamps

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Cloud Run instances use Google NTP for time synchronization. All audit events use `time.Now().UTC()` for consistent UTC timestamps. Cloud Logging adds its own timestamp on ingestion, providing an independent time reference.

### AU-9: Protection of Audit Information

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Audit records are protected through multiple mechanisms: (1) The `audit_events` database table grants INSERT-only access to the `app_ro` role — no application role can UPDATE or DELETE audit records; (2) Cloud Logging records are immutable once written; (3) GCS WORM audit buckets use locked retention policies (`is_locked = true` in production) preventing object deletion before the retention period expires — retention cannot be shortened or removed, even by project owners; (4) BigQuery audit dataset has no table/partition expiration and is CMEK-encrypted; (5) All GCS buckets have `force_destroy = false` and object versioning enabled; (6) 90-day soft-delete recovery window (GCS maximum) on all buckets; (7) Access to raw audit data requires `master_admin` role at the application level or GCP IAM privileges at the infrastructure level.

### AU-9(4): Access by Subset of Privileged Users

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Direct database access to audit records is restricted to the `ops_rw` database role (used only by the ops service). Application-level audit access requires `master_admin` role. GCP-level audit log access requires IAM `logging.viewer` role, which is restricted to the operations team.

### AU-11: Audit Record Retention

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Audit records are retained indefinitely with a zero-deletion policy across all tiers: (1) Cloud Logging: 30 days in hot storage (configurable via log bucket retention); (2) Database `audit_events` table: indefinite retention (no automatic expiration); (3) BigQuery audit dataset: indefinite retention (no table or partition expiration, CMEK-encrypted); (4) GCS WORM audit buckets: 7-year locked retention in production (1-year unlocked in staging), with object versioning and 90-day soft-delete; (5) All GCS lifecycle rules tier storage class for cost optimization (NEARLINE at 90 days, COLDLINE at 365 days) but never delete objects. No automated process permanently deletes any audit data. Forensic preservation holds can additionally exempt specific data from any future policy changes.

### AU-12: Audit Record Generation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Audit events are generated by the application via `internal/audit/logger.go` using `EventAsync()` for non-blocking persistence. Events are generated at all three Cloud Run services (app, admin, ops) for their respective operations. Every service generates audit events for authentication, authorization, and data access operations within its scope.

At the infrastructure level, GCP Data Access audit logging is enabled for all critical services: BigQuery (DATA_READ + DATA_WRITE), Cloud SQL (DATA_READ + DATA_WRITE), Cloud Run (DATA_READ + DATA_WRITE), Cloud KMS (DATA_READ + DATA_WRITE), IAM (DATA_READ), and Cloud Storage (DATA_READ + DATA_WRITE). These logs capture who accessed which GCP resource and when, providing the forensic trail required for incident investigation. Admin Activity logs are always on by default.

---

## CA — Assessment, Authorization, and Monitoring

### CA-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The FedRAMP System Security Plan (this document), Security Architecture Whitepaper, and subordinate policies collectively document the security assessment and authorization framework. Policies are reviewed annually.

### CA-2: Control Assessments

- **Responsibility**: CSP
- **Status**: Partially Implemented

**Implementation**: Internal security assessments are conducted through: (1) Red team program with 99 automated attacks mapped to MITRE ATT&CK across six suites (auth bypass, privilege escalation, data exfiltration, left-field/cloud-native, OWASP Top 10 web application testing, external tool-based assessment); (2) Code review via PR-based workflow; (3) SAST pipeline (GoSec, Semgrep, Trivy, govulncheck). _Independent 3PAO assessment is pending engagement (see POA-4)._

### CA-2(1): Independent Assessors

- **Responsibility**: CSP
- **Status**: Planned

**Implementation**: _An independent Third-Party Assessment Organization (3PAO) will be engaged for the formal FedRAMP High + IL5 assessment. Target: Q3 2026._

### CA-3: Information Exchange

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The only cross-project system interconnection is a single IAM grant: the app project service account receives `roles/cloudsql.client` and `roles/cloudsql.instanceUser` on the admin project for Cloud SQL database access. All other services are project-isolated. External interconnections (customer IdP SAML/SCIM, Cloudflare DNS) are documented in Section 4 of the SSP.

### CA-5: Plan of Action and Milestones

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: POA&M items are tracked in Appendix I of this SSP and in Drata. Each finding includes: unique ID, description, risk level, remediation milestone, target date, and current status. POA&M is reviewed and updated monthly.

### CA-6: Authorization

- **Responsibility**: CSP
- **Status**: Planned

**Implementation**: _FedRAMP Agency Authorization is pending agency sponsor identification and 3PAO engagement. This SSP is prepared in anticipation of the authorization process._

### CA-7: Continuous Monitoring

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Continuous monitoring is implemented through: Cloud Monitoring dashboards for infrastructure metrics, Cloud Armor analytics for WAF/DDoS events, Cloud Logging for all application and infrastructure logs, Drata automated compliance monitoring (continuous), automated vulnerability scanning (continuous via Dependabot, weekly via Trivy/GoSec/Semgrep), red team attack suite execution (monthly), access reviews (quarterly), automated KSI (Key Security Indicator) evidence collection via Go CLI (`cmd/ksi-evidence`) running weekly in CI — queries GCP APIs for firewall rules, Cloud Run services, Cloud Armor policies, KMS key rotation, log sinks, container images, SQL backup configuration, and GCS versioning — and produces structured JSON evidence files, and OSCAL v1.1.3 SSP JSON generation and validation via CI (`scripts/generate-oscal-ssp.mjs` + `oscal-cli`). See Appendix G for the full Continuous Monitoring Plan.

### CA-8: Penetration Testing

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon maintains an internal red team program (`redteam/` repository) with 99 automated attacks across 6 suites, mapped to MITRE ATT&CK tactics. The red team CLI is executed monthly against staging and can target production. Attacks cover: authentication bypass, privilege escalation, data exfiltration, left-field/cloud-native attacks, OWASP Top 10 web application testing (SQLi, XSS, XXE, SSRF, file handling, business logic), and external tool-based assessment (nuclei, nikto, sqlmap, ffuf, nmap). Results are uploaded to Drata as evidence.

### CA-9: Internal System Connections

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Internal system connections include: (1) Cloud Tasks → Cloud Run ops service (OIDC-authenticated); (2) Cloud Run services → Cloud SQL (IAM-authenticated, private VPC); (3) Cloud Run services → Vertex AI (service account IAM, PSC endpoint); (4) Cloud Run admin → ClamAV Cloud Run (internal-only, archon-admin invoker IAM). All internal connections use TLS and IAM authentication.

---

## CM — Configuration Management

### CM-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon maintains a Change Management Policy (POL-CM-001, `policies/change-management.md`) that defines baseline configuration management, change control processes, dependency governance, CI/CD security, container hardening, emergency change procedures, and rollback procedures. The policy is reviewed annually.

### CM-2: Baseline Configuration

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All infrastructure is defined as code via Terraform/Terragrunt (`infra/` repository with 14+ modules). Baseline configurations are versioned in Git with full history. No manual console changes are permitted in staging or production — a `gcloud` guardrail wrapper blocks destructive commands. Docker container images use distroless base images with pinned versions. Go dependencies are managed via `go.mod` with checksums in `go.sum`.

### CM-2(1): Reviews and Updates

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Infrastructure configurations are reviewed: (1) On every PR via Terragrunt plan posted as PR comments; (2) Weekly via Dependabot dependency update PRs; (3) Quarterly via comprehensive configuration review. All configuration changes require PR approval before merge.

### CM-3: Configuration Change Control

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All changes follow a PR-based workflow: (1) Developer creates feature branch; (2) CI runs automated checks (lint, test, vet, security scans); (3) Automated SCN (Significant Change Notification) classifier (`cmd/classify-scn`) runs on every PR, analyzing changed files against security-critical path patterns and classifying the change as SIGNIFICANT or ROUTINE — significant changes require an SCN filing with FedRAMP PMO before merge; (4) Peer review required for approval; (5) Merge to main triggers CI/CD deployment; (6) Terragrunt plan/apply for infrastructure changes. Emergency changes follow an expedited process with post-hoc review within 24 hours. All changes are audit-trailed in Git history and CI/CD logs.

### CM-3(2): Testing, Validation, and Documentation of Changes

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Changes are validated through: (1) Unit tests and integration tests in CI; (2) `go vet` and `go build` validation; (3) SAST pipeline (GoSec, Semgrep, govulncheck); (4) Trivy container image scanning; (5) Terragrunt plan review for infrastructure changes; (6) Staging environment deployment and validation before production. Failed CI checks block PR merge.

### CM-4: Impact Analysis

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Impact analysis is performed through: (1) Terraform plan output showing exact infrastructure changes before apply; (2) PR description template requiring change impact assessment; (3) Breaking change detection in CI (proto backward-compat checks, migration validation); (4) Dependabot vulnerability impact assessment for dependency updates.

### CM-5: Access Restrictions for Change

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Change access is restricted through: (1) GitHub branch protection rules requiring PR review and passing CI; (2) Terraform service account with 20 IAM roles (including `roles/editor` for infrastructure management, no `roles/owner`); (3) Workload Identity Federation for keyless CI/CD authentication; (4) No direct production console access — all changes via IaC pipeline; (5) Artifact Registry image push restricted to CI/CD service account.

### CM-6: Configuration Settings

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security-relevant configuration settings include: (1) Cloud Armor WAF rules (OWASP CRS, bot blocking, rate limiting); (2) TLS configuration (1.2+ only, HSTS 2-year preload); (3) Database RLS policies (fail-closed); (4) Auth interceptor settings (REQUIRE_IDP_POOL, REQUIRE_MFA); (5) Session timeout defaults. All settings are managed in Terraform variables and environment variable configurations, versioned in Git. A Customer Secure Configuration Guide (`customer-secure-configuration-guide.md`, GUIDE-SCG-001) is published for customer agencies, covering MFA enrollment, session timeout configuration, RBAC role assignment, SSO/SCIM setup, IP allowlisting, data retention, and quarterly review procedures.

### CM-7: Least Functionality

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Services are restricted to essential functions: (1) Cloud Run containers use distroless base images with no shell, package manager, or unnecessary utilities; (2) FQDN egress firewall blocks all outbound except Google APIs; (3) Only HTTP methods GET, POST, OPTIONS are permitted through Cloud Armor; (4) No SSH, FTP, or remote administration services are exposed; (5) Cloud Run services have `--no-allow-unauthenticated` set (except SPAs which serve the static app bundle).

### CM-7(1): Periodic Review

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Service functionality is reviewed quarterly as part of configuration management. Unnecessary services, ports, or features identified during review are removed via the standard change management process. Container image contents are audited via SBOM (CycloneDX + SPDX) generated on every build.

### CM-8: System Component Inventory

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System component inventory is maintained through: (1) Terraform state files listing all GCP resources (Cloud Run services, Cloud SQL instances, GCS buckets, etc.); (2) SBOM generation on every Docker build (CycloneDX + SPDX format) capturing all Go dependencies and their versions; (3) `go.mod` + `go.sum` pinning all direct and transitive dependencies; (4) Drata asset registry with 30 assets (20 virtual GCP infrastructure, 6 software, 4 data). Inventory is auto-updated on each CI/CD build.

### CM-8(1): Updates During Installation and Removal

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Component inventory is automatically updated: (1) Terraform state is updated on every `terragrunt apply`; (2) SBOM is regenerated on every Docker image build; (3) Drata asset sync runs weekly; (4) Dependabot automatically detects new/changed dependencies and creates update PRs.

### CM-9: Configuration Management Plan

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: See Appendix E (Configuration Management Plan) for the full CMP including roles, responsibilities, procedures, and tools.

### CM-10: Software Usage Restrictions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All software dependencies are open-source with license compliance verification. The Vendor Risk Policy (POL-VR-001) defines acceptable license types. `go.mod` pins all dependencies with cryptographic checksums in `go.sum`. No proprietary third-party software is used beyond GCP services (covered under GCP FedRAMP authorization).

### CM-11: User-Installed Software

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: User-installed software is not applicable to the SaaS delivery model. Cloud Run containers are built exclusively via CI/CD from a known Dockerfile. There is no shell access to running containers. Container images use distroless base images that cannot execute arbitrary binaries.

---

## CP — Contingency Planning

### CP-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon maintains a Business Continuity & Disaster Recovery Policy (POL-BC-001, `policies/business-continuity.md`) defining recovery objectives, backup strategy, DR procedures, communication plan, and testing schedule.

### CP-2: Contingency Plan

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: See Appendix D (Information System Contingency Plan) for the complete ISCP including: mission-essential functions, recovery priority list, roles and responsibilities, step-by-step recovery procedures, communication plan, and recovery time/point objectives by service tier.

### CP-3: Contingency Training

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Operations personnel receive contingency plan training upon assignment and annually thereafter. Training covers: incident classification, recovery procedures for each failure scenario (database, Cloud Run, GCS, Vector Search, regional), communication protocols, and escalation paths. Training is tracked in Drata.

### CP-4: Contingency Plan Testing

- **Responsibility**: CSP
- **Status**: Partially Implemented

**Implementation**: Contingency plan testing includes: (1) Infrastructure rebuild validation via Terragrunt (IaC ensures reproducible deployments); (2) Cloud SQL point-in-time recovery testing; (3) GCS object versioning recovery validation. _Full tabletop exercise and documented test results are planned for Q3 2026. See POA-5._

### CP-6: Alternate Storage Site

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: GCP provides automatic geographic redundancy for all storage services: Cloud SQL automated backups (cross-region), GCS multi-region storage option, and regional failover capabilities. All data resides within US regions per data sovereignty requirements, enforced by `gcp.resourceLocations` org policy (restricts all projects to `us-east4`, `us-east1`, `us-central1`, and `us` multi-region).

### CP-7: Alternate Processing Site

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: GCP Cloud Run supports multi-region deployment. Current architecture uses regional deployment with failover capability to alternate US regions. IaC-managed infrastructure enables rapid redeployment to alternate regions within 4 hours (RTO for Tier 1 services).

### CP-8: Telecommunications Services

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: GCP provides redundant telecommunications services including multiple internet connectivity paths, redundant networking equipment, and automatic failover. This is inherited from GCP's FedRAMP High authorization.

### CP-9: System Backup

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Backup strategy by component:

- **Cloud SQL**: Automated daily backups (14 retained, count-based) + point-in-time recovery (PITR) with 7-day transaction log retention. Backups start at 03:00 UTC. Backup location is configurable via `backup_location` variable — defaults to the instance region but can be set to a different US region for cross-region disaster recovery (e.g., `us-west1` when the primary is `us-east1`). Backups encrypted with CMEK (Cloud KMS). Maintenance window: Sunday 04:00 UTC, stable update track.
- **Cloud Storage**: Object versioning enabled (all versions preserved indefinitely via lifecycle rules — current objects transition to nearline after 90 days, archived versions transition to coldline after 90 days, no deletion). Soft delete with 90-day recovery window. CMEK encryption via Cloud KMS.
- **Terraform State**: Stored in GCS with versioning. State backup is inherent.
- **Vertex AI Indexes**: Rebuilt from source documents via ops service. RPO = time to re-embed (hours for large collections).
- **Configuration**: All configuration in Git with full version history.

### CP-10: System Recovery and Reconstitution

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Recovery procedures are documented in the Contingency Plan (Appendix D) for five failure scenarios: (1) Database failure → Cloud SQL PITR; (2) Cloud Run failure → redeploy from Artifact Registry; (3) GCS failure → restore from versioned objects; (4) Vector Search failure → rebuild from source documents; (5) Regional failure → redeploy to alternate US region via Terragrunt. Target RTOs: Tier 1 < 1 hour, Tier 2 < 4 hours.

---

## IA — Identification and Authentication

### IA-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Authentication policy is documented in the Access Control Policy (POL-AC-001) and Security Architecture Whitepaper. Authentication is implemented via Google Identity Platform (Firebase Auth) with multi-pool isolation.

### IA-2: Identification and Authentication (Organizational Users)

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All users are uniquely identified via Firebase UID (unique per Identity Platform pool). Authentication requires a valid Firebase ID token (JWT) verified by the auth interceptor against Google's public keys. User identity is resolved from the database (`users` table) after token verification. No shared accounts are permitted.

### IA-2(1): Multi-Factor Authentication to Privileged Accounts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: MFA is enforced on all accounts (not just privileged) when `REQUIRE_MFA=true`. The auth interceptor verifies the `firebase.sign_in_provider` claim to confirm MFA completion. Privileged operations (member invite/remove, document delete, role changes) require step-up MFA — a fresh MFA verification within the last 5 minutes (configurable), checked via `auth_time` claim comparison.

### IA-2(2): Multi-Factor Authentication to Non-Privileged Accounts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: MFA is enforced for all users, not just privileged accounts. TOTP-based MFA is the supported method. The auth interceptor rejects tokens without MFA verification when enforcement is enabled.

### IA-2(8): Access to Accounts — Replay Resistant

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Authentication is replay-resistant: Firebase ID tokens are short-lived JWTs (1 hour) verified against Google's public key rotation. Session timeouts (idle and absolute) provide additional replay resistance. TOTP MFA codes are time-based and single-use.

### IA-2(12): Acceptance of PIV Credentials

- **Responsibility**: Customer
- **Status**: Supported

**Implementation**: Through SAML 2.0 SSO federation, customer agencies can configure their Identity Provider to require PIV/CAC card authentication. The SAML assertion is passed to Identity Platform, and the resulting Firebase token is used by Latent Archon. PIV enforcement is the responsibility of the customer IdP.

### IA-3: Device Identification and Authentication

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Service-to-service communication uses GCP IAM authentication (service account tokens). Cloud Tasks → Cloud Run uses OIDC tokens verified by the receiving service. ClamAV invocation requires `archon-admin` invoker IAM role. Device identification for end-user clients is handled by Firebase App Check (reCAPTCHA Enterprise), which attestation client authenticity.

### IA-4: Identifier Management

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: User identifiers are managed by Identity Platform (Firebase UIDs — globally unique, system-generated). Organization identifiers are PostgreSQL UUIDs (system-generated). IDP Pool IDs are assigned by GCP Identity Platform. No user-chosen identifiers are used for authentication. Identifiers are unique, non-reusable, and never recycled.

### IA-5: Authenticator Management

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Authenticator types include: (1) Firebase ID tokens (JWT, 1-hour lifetime, automatically refreshed by client SDK); (2) TOTP MFA secrets (AES-encrypted in Identity Platform); (3) SAML assertions (from customer IdP); (4) SCIM bearer tokens (SHA-256 hashed in database); (5) GCP IAM service account tokens (Workload Identity Federation — no static keys).

Password complexity and rotation policies are enforced by Identity Platform for password-based accounts. Magic link (passwordless) authentication is preferred and recommended. SSO federation eliminates password management for enterprise customers.

### IA-5(1): Password-Based Authentication

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: For non-SSO accounts, Identity Platform enforces: minimum password length (platform default), password complexity requirements, and brute-force lockout. However, Latent Archon recommends and defaults to magic link (passwordless) authentication. SSO-federated accounts have no Latent Archon passwords — authentication is delegated to the customer IdP.

### IA-5(2): Public Key-Based Authentication

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Public key authentication is used for: (1) JWT verification — Firebase ID tokens are verified using Google's published RSA public keys (rotated automatically); (2) Workload Identity Federation — CI/CD authenticates using OIDC tokens verified by GCP using GitHub's public keys; (3) DNSSEC — zone signing uses public key cryptography for DNS record authentication.

### IA-5(6): Protection of Authenticators

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Authenticators are protected as follows: (1) TOTP secrets are stored encrypted in Identity Platform (Google-managed encryption); (2) SCIM tokens are SHA-256 hashed before storage — plaintext tokens are never persisted; (3) No static service account keys exist — all service authentication uses Workload Identity Federation (keyless); (4) JWT signing keys are managed by Google and not accessible to application code; (5) Microsoft Graph OAuth refresh tokens are encrypted at rest via Cloud KMS `app_secrets` key (AES-256-GCM, HSM-backed) before database storage — plaintext tokens are never persisted. The OAuth client secret (`MSGRAPH_CLIENT_SECRET`) is injected as a runtime environment variable and never stored in the database.

### IA-6: Authentication Feedback

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Authentication feedback obscures passwords and MFA codes during entry (client-side SPA behavior). Error messages do not reveal whether a username exists or whether a password was close to correct. Failed authentication returns generic error messages to prevent account enumeration.

### IA-7: Cryptographic Module Authentication

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All cryptographic operations use FIPS 140-2 validated modules: Google BoringCrypto (Go runtime, Cert #4407) for application-level cryptography, Google Front End for TLS termination, Cloud KMS (FIPS 140-2 Level 3) for key management. See Section 10 (Cryptographic Modules) of the SSP.

### IA-8: Identification and Authentication (Non-Organizational Users)

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Non-organizational users (e.g., Latent Archon support engineers) authenticate via GCP IAM with Workload Identity Federation or Google Workspace credentials. There is no shared admin portal accessible to non-organizational users. Customer end-users must be explicitly invited to an organization and authenticate through that organization's Identity Platform pool.

### IA-8(1): Acceptance of PIV Credentials from Other Agencies

- **Responsibility**: Customer
- **Status**: Supported

**Implementation**: Cross-agency PIV acceptance is supported through SAML 2.0 federation. Each agency configures their IdP with their certificate trust chain. Identity Platform accepts SAML assertions from any configured IdP.

### IA-8(2): Acceptance of External Authenticators

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: External authenticators are accepted via SAML 2.0 SSO federation and SCIM 2.0 provisioning. The platform validates SAML assertions from configured customer IdPs and maps external identities to Latent Archon user accounts via the `external_identities` table.

### IA-11: Re-Authentication

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Re-authentication is required: (1) After idle timeout expiration (default 25 minutes, per-org configurable); (2) After absolute session timeout (default 12 hours, per-org configurable); (3) For step-up operations (member management, document deletion, role changes) — requires MFA verification within last 5 minutes. Re-authentication forces full JWT refresh through Identity Platform.

---

## IR — Incident Response

### IR-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon maintains an Incident Response Policy (POL-IR-001, `policies/incident-response.md`) defining incident classification (SEV-1 through SEV-4 with MITRE ATT&CK mapping), response team roles, detection sources, 5-phase response process, forensic preservation, US-CERT/CISA reporting timelines, FedRAMP PMO notification, and customer notification procedures. The policy is reviewed annually and updated after each significant incident or exercise.

### IR-2: Incident Response Training

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All Latent Archon personnel receive incident response training upon onboarding and annually thereafter. Operations personnel receive additional hands-on training covering: incident detection tools (Cloud Armor analytics, Cloud Logging queries), containment procedures (Identity Platform session revocation, Cloud Armor emergency rules), and communication protocols. Training is tracked in Drata.

### IR-3: Incident Response Testing

- **Responsibility**: CSP
- **Status**: Partially Implemented

**Implementation**: Incident response capabilities are tested through: (1) Red team program (99 automated attacks across 6 suites executed monthly) validates detection and response procedures; (2) Tabletop exercises are planned annually. _First full tabletop exercise planned for Q3 2026. See POA-6._

### IR-4: Incident Handling

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Incident handling follows a 5-phase process: (1) **Detection** — Cloud Armor WAF alerts, Cloud Monitoring anomaly detection, audit event analysis, red team findings, customer reports; (2) **Analysis** — severity classification (SEV-1 through SEV-4), MITRE ATT&CK mapping, scope determination; (3) **Containment** — Identity Platform session revocation, Cloud Armor IP blocking, IDP pool disabling for affected org; (4) **Eradication** — root cause remediation, credential rotation, configuration correction; (5) **Recovery** — service restoration, monitoring validation, customer notification.

### IR-5: Incident Monitoring

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Incidents are tracked from detection through resolution in an incident management log. Each incident record includes: unique ID, detection timestamp, severity level, MITRE ATT&CK tactics, affected systems/organizations, timeline of actions, root cause, remediation steps, and lessons learned. Cloud Monitoring dashboards provide real-time incident status visibility.

### IR-6: Incident Reporting

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Incident reporting follows these timelines per the IR policy:

- **US-CERT/CISA**: CAT 1 (unauthorized root access) — 1 hour; CAT 2 (denial of service) — 2 hours; CAT 3 (successful breach) — 72 hours; CAT 4 (scanning/probing) — monthly
- **FedRAMP PMO**: Significant incidents reported within 72 hours with formal incident report
- **Agency customers**: Real-time notification for incidents affecting their data; summary report within 48 hours of containment

### IR-7: Incident Response Assistance

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon provides incident response assistance to customer agencies through: (1) Real-time incident notifications via email; (2) Audit log export via Pub/Sub SIEM pipeline enabling customer investigation; (3) Incident summary reports with timeline, scope, and remediation details; (4) Coordination with customer security teams during active incidents.

### IR-8: Incident Response Plan

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: See Appendix F (Incident Response Plan) for the full IRP including organizational structure, roles, communication procedures, detection mechanisms, response procedures by severity level, and post-incident activities.

---

## MA — Maintenance

### MA-1: Policy and Procedures

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Physical maintenance of computing infrastructure is inherited from GCP's FedRAMP High authorization. Application-level maintenance (patches, updates, configuration changes) follows the Change Management Policy (POL-CM-001).

### MA-2: Controlled Maintenance

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: GCP performs all physical hardware maintenance within their FedRAMP High authorized data centers. Application maintenance (deployments, patches) is performed via the CI/CD pipeline with PR-based approval and automated testing.

### MA-3: Maintenance Tools

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Physical maintenance tools are controlled by GCP per their FedRAMP High authorization. Application maintenance uses: Terraform/Terragrunt (IaC), GitHub Actions (CI/CD), Docker (containerization), and Go toolchain — all version-controlled and audited.

### MA-4: Nonlocal Maintenance

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: All system maintenance is performed nonlocally (cloud-native SaaS). Infrastructure changes are applied via Terragrunt through the CI/CD pipeline using Workload Identity Federation (no static credentials). Emergency break-glass access uses time-limited IAM Conditions with documented approval.

### MA-5: Maintenance Personnel

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: GCP maintenance personnel are vetted per GCP's FedRAMP High authorization. Latent Archon engineering personnel undergo background checks and must complete security training before receiving system access. Access is scoped to specific roles with least privilege.

### MA-6: Timely Maintenance

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: GCP provides spare parts and maintenance support per their SLA. Application-level patches follow remediation timelines defined in the Vulnerability Scanning Strategy: Critical — 15 days, High — 30 days, Medium — 90 days, Low — 180 days.

---

## MP — Media Protection

### MP-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Media protection policy is documented in the Data Classification & Retention Policy (POL-DC-001, `policies/data-classification.md`). The policy defines classification levels, handling requirements, retention schedules, and disposal procedures.

### MP-2: Media Access

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Physical media access is controlled by GCP per their FedRAMP High authorization. Digital media (Cloud Storage objects, database backups) is protected by GCP IAM, encrypted with CMEK, and accessible only through authenticated API calls.

### MP-3: Media Marking

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Digital media is classified according to the 4-level data classification scheme (CUI/Restricted, Confidential, Internal, Public). Customer documents are classified as CUI by default. System data is classified per the Data Classification Policy data inventory table.

### MP-4: Media Storage

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: All data is stored encrypted at rest using AES-256-GCM with Cloud KMS-managed keys (CMEK). Cloud Storage uses object versioning (all versions preserved indefinitely) with 90-day soft-delete recovery and CMEK encryption. Cloud SQL uses automated encrypted backups with CMEK. Audit data is stored in immutable WORM buckets with 7-year locked retention in production. All storage is within US regions per data sovereignty requirements, enforced by `gcp.resourceLocations` org policy.

### MP-5: Media Transport

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: All data in transit is encrypted with TLS 1.2+ (FIPS 140-2 validated modules). Internal GCP communication uses Google's encrypted inter-data-center network. Private Service Connect provides encrypted communication to Vertex AI without traversing the public internet.

### MP-6: Media Sanitization

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Physical media sanitization is inherited from GCP's FedRAMP High authorization (NIST 800-88 compliant). Application-level data sanitization includes: (1) Account closure triggers 90-day automated data purge via Cloud Scheduler (FedRAMP High mgmt project) → Pub/Sub push → ops Cloud Run; (2) Document deletion is permanent after soft-delete retention period; (3) Cryptographic erasure is supported by rotating CMEK keys to render encrypted data irrecoverable.

### MP-7: Media Use

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Restrictions on media use within GCP data centers are inherited from GCP's FedRAMP High authorization. The SaaS delivery model eliminates the need for portable media in the operational environment.

---

## PE — Physical and Environmental Protection

### PE-1 through PE-18: Physical Security Controls

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: All physical and environmental protection controls (PE-1 through PE-18) are fully inherited from Google Cloud Platform's FedRAMP High authorization. GCP operates data centers with comprehensive physical security including: multi-layer access control, 24/7 security monitoring, biometric access, visitor management, environmental controls (HVAC, fire suppression, power redundancy), and geographic distribution.

Supplementary controls for Latent Archon remote personnel are documented in the Physical Security Policy (POL-PE-001, `policies/physical-security.md`), covering: device encryption requirements (FileVault/BitLocker), screen lock requirements (5-minute timeout), device loss/theft procedures, and media disposal requirements for employee devices.

---

## PL — Planning

### PL-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security planning is governed by the Information Security Policy (POL-IS-001, `policies/information-security.md`) which defines the overarching information security program, objectives, governance structure, and subordinate policy hierarchy. The policy references NIST SP 800-53 High and DFARS 252.204-7012 as the primary compliance frameworks.

### PL-2: System Security and Privacy Plans

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: This System Security Plan (SSP) serves as the formal security plan for the Latent Archon platform. It documents the authorization boundary, system architecture, data flows, security controls, and responsibility model. The SSP is reviewed and updated at least annually or when significant system changes occur.

### PL-4: Rules of Behavior

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Rules of behavior are documented in `rules-of-behavior.md` (ROB-LA-001) and the Acceptable Use Policy (POL-AU-001, `policies/acceptable-use.md`). Users must electronically accept the ROB before accessing either the app or admin frontend. Acceptance is enforced in-application: after authentication and MFA, the `AuthGate` component renders a `RobAcceptance` screen with a summary of rules, checkbox acknowledgment, and accept button. Acceptance is recorded server-side in the `rob_acceptances` database table (per user, per ROB version, per client app) with IP address and user-agent for audit. The backend REST endpoints `GET /api/auth/rob-status` and `POST /api/auth/accept-rob` gate access. When the ROB version is updated (backend `currentROBVersion` constant), all users must re-accept before regaining access. The policy covers: acceptable and prohibited system use, customer data handling, credential management, infrastructure use (IaC-only), personal device requirements, and incident reporting obligations. Violations result in tiered enforcement (warning → access suspension → termination).

### PL-4(1): Social Media and External Site/Application Usage Restrictions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Acceptable Use Policy prohibits sharing system credentials, architecture details, customer data references, or security vulnerability details on social media or external sites. CUI-related information must never be discussed in public forums.

### PL-10: Baseline Selection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The NIST SP 800-53 Rev. 5 High baseline has been selected based on the FIPS 199 categorization (High confidentiality, High integrity, Moderate availability) and DoD IL5 requirements. This baseline is appropriate for a system processing Controlled Unclassified Information (CUI) and DoD mission data within IL5 Assured Workloads. The system satisfies DFARS 252.204-7012 and NIST SP 800-171 requirements. FedRAMP High enhancement controls are documented in Appendix A-2.

### PL-11: Baseline Tailoring

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Moderate baseline has been tailored as follows: (1) Physical security controls (PE family) are inherited from GCP FedRAMP High authorization; (2) Maintenance controls (MA family) are largely inherited from GCP; (3) Controls are supplemented with CSP-specific implementations where the SaaS model provides additional protections beyond the baseline requirement (e.g., distroless containers for CM-7, fail-closed RLS for AC-3).

---

## PM — Program Management

### PM-1: Information Security Program Plan

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Latent Archon information security program is governed by the Information Security Policy (POL-IS-001). The program plan encompasses: (1) security governance structure with defined roles (CEO as executive sponsor and ISSO); (2) hierarchy of 13 subordinate security policies; (3) compliance framework alignment (NIST 800-53 High, FedRAMP High, DoD IL5, DFARS 252.204-7012); (4) risk management integration; (5) continuous improvement through Drata automated monitoring.

### PM-2: Information Security Program Leadership Role

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The CEO (Andrew Hendel) serves as both executive sponsor and Information System Security Officer (ISSO) for the information security program, responsible for security program management, control implementation oversight, and compliance coordination. Formal ISSO self-appointment letter issued (ISSO-APPT-001). As the organization scales, a dedicated Security Lead will assume day-to-day ISSO duties (POA-15).

### PM-3: Information Security and Privacy Resources

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security resources are allocated through: (1) Dedicated security budget for tools (Drata, scanning tools, Cloud Armor), 3PAO engagement, and training; (2) Engineering time allocation for security controls implementation (estimated 30% of engineering capacity); (3) Automated compliance tooling (Drata sync, CI/CD security pipeline) to reduce manual compliance burden.

### PM-4: Plan of Action and Milestones Process

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: POA&M items are tracked in Appendix I of this SSP and synchronized to Drata. The POA&M process includes: (1) Identification of findings from assessments, scans, and red team exercises; (2) Risk-based prioritization using 5×5 likelihood/impact matrix; (3) Assignment of remediation owner and target date; (4) Monthly review and status update; (5) Closure verification with evidence.

### PM-5: System Inventory

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system inventory is maintained through: (1) Terraform state files (authoritative infrastructure inventory); (2) Drata asset registry (30 registered assets); (3) SBOM generation on each build (software dependency inventory). The inventory is updated automatically via CI/CD and weekly Drata sync.

### PM-6: Measures of Performance

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security performance metrics tracked include: (1) Mean time to remediate vulnerabilities by severity; (2) Percentage of controls implemented vs. baseline; (3) Red team attack success rate over time; (4) SCIM provisioning latency; (5) Audit event capture rate; (6) Uptime/availability metrics. Metrics are reviewed monthly and reported to executive leadership.

### PM-7: Enterprise Architecture

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Latent Archon security architecture is integrated into the enterprise architecture through: (1) Three-project GCP architecture for blast-radius isolation and data-plane compartmentalization; (2) Infrastructure-as-Code (Terraform/Terragrunt) ensuring security controls are embedded in infrastructure definitions; (3) Security Architecture Whitepaper documenting the complete security design; (4) Architecture decisions documented in ADRs and design docs (e.g., `POOL_ISOLATION.md`, `TENANT_CONFIGURATION.md`).

### PM-8: Critical Infrastructure Plan

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Critical infrastructure protection is addressed through the Business Continuity & DR Policy (POL-BC-001) and the Contingency Plan (Appendix D). Service tiers define recovery priorities: Tier 1 (auth, database) has RTO < 1 hour; Tier 2 (API, search) has RTO < 4 hours.

### PM-9: Risk Management Strategy

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Risk Management Policy (POL-RM-001, `policies/risk-management.md`) defines: risk assessment methodology (5×5 likelihood/impact matrix), inherent vs. residual scoring, treatment options (mitigate, transfer, accept, avoid), risk appetite statement, formal 12-entry risk register, and monitoring cadence. Risks are synced to Drata with inherent and residual scores.

### PM-10: Authorization Process

- **Responsibility**: CSP
- **Status**: Partially Implemented

**Implementation**: This SSP and its appendices constitute the security authorization package. The authorization process will follow FedRAMP Agency Authorization: (1) Agency sponsor identification; (2) 3PAO readiness assessment; (3) Full 3PAO assessment; (4) SAR review; (5) POA&M remediation; (6) Agency AO risk acceptance and ATO issuance. _Agency sponsor identification is in progress. See POA-4._

### PM-11: Mission and Business Process Definition

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system's mission is defined in Section 2 of the SSP: providing secure document intelligence capabilities for government agencies handling CUI. Business processes include document upload/management, AI-powered search, workspace collaboration, and enterprise identity management. All processes are designed with security and privacy as primary requirements.

### PM-14: Testing, Training, and Monitoring

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The security testing, training, and monitoring program includes: (1) **Testing**: Red team program (monthly), SAST pipeline (continuous), vulnerability scanning (weekly), penetration testing (annual); (2) **Training**: Security awareness (annual), secure development (onboarding + annual), incident response (annual); (3) **Monitoring**: Cloud Monitoring (continuous), Cloud Armor analytics (continuous), Drata compliance monitoring (continuous), audit log analysis (continuous).

### PM-15: Security and Privacy Groups and Associations

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon personnel maintain awareness of emerging threats and best practices through: FedRAMP PMO communications, CISA advisories, NIST publications, Go security advisories (golang.org/x/vuln), GCP security bulletins, and industry security communities.

### PM-16: Threat Awareness Program

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Threat awareness is maintained through: (1) Dependabot automatic vulnerability alerting for all dependencies; (2) govulncheck for Go-specific vulnerability detection; (3) CISA KEV (Known Exploited Vulnerabilities) monitoring; (4) Red team program incorporating MITRE ATT&CK-mapped attack scenarios; (5) Cloud Armor threat intelligence integration for WAF rule updates.

---

## PS — Personnel Security

### PS-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Personnel security requirements are documented in the Information Security Policy (POL-IS-001) and Acceptable Use Policy (POL-AU-001). The policies define background check requirements, access authorization procedures, acceptable use rules, and termination/transfer procedures.

### PS-2: Position Risk Designation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Personnel positions are categorized by risk level: (1) **High Risk**: CEO/ISSO and anyone with production infrastructure access — requires comprehensive background check; (2) **Moderate Risk**: Personnel with code commit access — requires standard background check; (3) **Low Risk**: Non-technical roles without system access — requires basic identity verification. Risk designations are reviewed annually.

### PS-3: Personnel Screening

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All Latent Archon personnel undergo background screening appropriate to their position risk designation before receiving system access. Screening includes identity verification and criminal history check. For High Risk positions, screening additionally includes employment verification and reference checks. Screening is re-conducted every 5 years or upon position change.

### PS-4: Personnel Termination

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Upon personnel termination: (1) All system access is revoked within 4 hours (GCP IAM roles removed, GitHub access revoked); (2) Any active sessions are terminated; (3) Company devices are collected and wiped; (4) Exit interview includes security debriefing and NDA reminder; (5) Termination is audit-logged. For involuntary terminations, access revocation occurs immediately upon notification.

### PS-5: Personnel Transfer

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: When personnel transfer to a different role: (1) Access is reviewed and adjusted to match new position requirements (least privilege); (2) Previous role-specific access is revoked; (3) New role-specific access is granted after appropriate authorization; (4) Transfer is documented in personnel records and audit log. Access adjustments occur within 24 hours of transfer effective date.

### PS-6: Access Agreements

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All personnel must sign before receiving system access: (1) Acceptable Use Policy acknowledgment; (2) Non-Disclosure Agreement (NDA) covering customer data and system architecture; (3) Rules of Behavior electronic acceptance (enforced in-application via `rob_acceptances` table — see PL-4). Access agreements are reviewed and re-signed annually (ROB re-acceptance is enforced by incrementing `currentROBVersion`). Agreements are retained in HR records and the `rob_acceptances` audit table (IP, user-agent, timestamp per acceptance).

### PS-7: External Personnel Security

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon does not currently use external contractors for system development or operations. If contractors are engaged, they will be subject to the same background screening, access agreement, and least-privilege access requirements as employees. Third-party vendor security is governed by the Vendor Risk Management Policy (POL-VR-001).

### PS-8: Personnel Sanctions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Personnel who violate security policies are subject to tiered sanctions as defined in the Acceptable Use Policy: (1) First offense/minor violation — written warning with mandatory remedial training; (2) Repeat offense/moderate violation — temporary access suspension with investigation; (3) Severe violation/willful misconduct — immediate access revocation and termination. Sanctions are documented and reviewed by the CEO / ISSO.

---

## PT — PII Processing and Transparency

### PT-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: PII processing policies are documented in the Data Classification & Retention Policy (POL-DC-001) and this SSP. The policies define PII categories processed by the system, legal basis for processing, minimization requirements, consent mechanisms, and data subject rights.

### PT-2: Authority to Process PII

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Latent Archon processes PII under the authority of: (1) Customer agency contracts/agreements that authorize data processing for the document intelligence service; (2) The Privacy Act of 1974 as applicable; (3) Terms of Service that define permitted data processing activities. PII processing is limited to what is necessary to provide the contracted service.

### PT-3: PII Processing Purposes

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: PII is processed exclusively for the following purposes: (1) **User Authentication**: Email addresses and names for account identification; (2) **Audit Logging**: IP addresses and user agents for security monitoring; (3) **Service Delivery**: Document content processing for RAG search (may contain PII within customer documents); (4) **Account Management**: User profiles for RBAC and workspace membership. PII is not used for marketing, profiling, or purposes beyond service delivery.

### PT-4: Consent

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Users consent to PII processing through: (1) Terms of Service acceptance during account creation; (2) Organization-level data processing agreements between Latent Archon and customer agencies; (3) Opt-in for optional features that process additional PII. Users may withdraw consent by closing their account via the `CloseAccount` RPC (requires step-up MFA), which triggers automated data purge.

**Customer Responsibility**: Customer agencies are responsible for obtaining appropriate consent from their end users per agency privacy policies.

### PT-5: Privacy Impact Assessment

- **Responsibility**: CSP
- **Status**: Partially Implemented

**Implementation**: See the Privacy Impact Assessment (PIA) document (`pia.md`) for the formal privacy impact analysis covering: system description, PII inventory, data flows, privacy risks, and mitigations. _PIA to be updated in conjunction with 3PAO engagement. See POA-7._

### PT-6: System of Records Notice

- **Responsibility**: Customer
- **Status**: N/A (Customer Responsibility)

**Implementation**: System of Records Notices (SORNs) are the responsibility of customer agencies for any Privacy Act-covered records stored in the system.

### PT-7: Specific Categories of PII

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system processes the following PII categories: (1) **Contact Information**: Email addresses, display names; (2) **Technical Identifiers**: IP addresses, user agents, Firebase UIDs; (3) **Authentication Data**: TOTP MFA enrollment (encrypted, managed by Identity Platform); (4) **Customer Document Content**: May contain any PII category depending on documents uploaded by the customer. Document content PII is classified as CUI and protected by RLS, encryption, and workspace isolation.

### PT-8: Computer Matching Requirements

- **Responsibility**: Customer
- **Status**: N/A (Customer Responsibility)

**Implementation**: Computer matching agreements, if required, are the responsibility of customer agencies.

---

## RA — Risk Assessment

### RA-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Risk assessment procedures are documented in the Risk Management Policy (POL-RM-001, `policies/risk-management.md`). The policy defines the risk assessment methodology, scoring framework, treatment options, and monitoring cadence.

### RA-2: Security Categorization

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system is categorized as FIPS 199 High (Confidentiality: High, Integrity: High, Availability: Moderate). The system processes CUI and DoD mission data within IL5 Assured Workloads. Categorization is based on the information types processed (see Section 6 of the SSP) and reviewed annually or upon significant system changes.

### RA-3: Risk Assessment

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Formal risk assessments are conducted: (1) **Annually**: Comprehensive review of 12-entry risk register with inherent/residual scoring (5×5 likelihood × impact matrix); (2) **On significant change**: Architecture changes, new features, or new integrations trigger targeted risk assessment; (3) **Continuously**: Drata automated risk monitoring and vulnerability scanning provide real-time risk visibility. Risk register is maintained in Drata and synced via the compliance CLI tool.

### RA-3(1): Supply Chain Risk Assessment

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Supply chain risks are assessed through: (1) Dependency vulnerability scanning (Dependabot, govulncheck, Trivy) on every build; (2) SBOM generation (CycloneDX + SPDX) for full dependency transparency; (3) Vendor risk assessment per the Vendor Risk Policy; (4) License compliance verification for all open-source dependencies.

### RA-5: Vulnerability Monitoring and Scanning

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Vulnerability scanning operates at multiple layers with the schedule defined in the Vulnerability Scanning Strategy (DOC-VS-001, `policies/vulnerability-scanning.md`):

- **Continuous**: Dependabot dependency vulnerability alerts, govulncheck Go vulnerability database
- **Per-build**: Trivy container image scanning, GoSec SAST, Semgrep pattern matching, Gitleaks secret detection, SBOM generation
- **Monthly**: Red team attack suite execution (99 attacks, 6 suites)
- **Remediation SLAs**: Critical — 15 days, High — 30 days, Medium — 90 days, Low — 180 days (tightened to FedRAMP High-baseline timelines)

Cloud Run serverless deployment means OS-level patching is inherited from GCP.

### RA-5(2): Update Vulnerabilities to be Scanned

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Vulnerability databases are automatically updated: Dependabot checks for new CVEs daily, govulncheck uses the Go vulnerability database (updated hourly), Trivy database is updated on each scan, and Semgrep rules are updated via registry. No manual database updates are required.

### RA-5(5): Privileged Access

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Vulnerability scans execute with the minimum privilege necessary. CI/CD scans run with read-only access to source code. Container scans analyze images without runtime access. No scans require production data access or elevated database privileges.

### RA-7: Risk Response

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Risk response follows the Risk Management Policy treatment framework: (1) **Mitigate**: Implement technical or administrative controls to reduce risk to acceptable levels; (2) **Transfer**: Use GCP FedRAMP-authorized services to transfer infrastructure risk; (3) **Accept**: Formally document acceptance with CEO approval for risks below appetite threshold; (4) **Avoid**: Eliminate risk by not implementing the risky capability.

### RA-9: Criticality Analysis

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System criticality analysis identifies mission-essential functions and their dependencies: (1) Authentication/authorization (Identity Platform, auth interceptor) — Tier 1; (2) Data persistence (Cloud SQL, GCS) — Tier 1; (3) API services (Cloud Run) — Tier 2; (4) AI/search (Vertex AI) — Tier 2; (5) Background processing (Cloud Tasks, ops service) — Tier 3. Criticality designations drive recovery priorities in the Contingency Plan.

---

## SA — System and Services Acquisition

### SA-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System acquisition policies are documented in the Vendor Risk Management Policy (POL-VR-001, `policies/vendor-risk.md`), covering vendor classification, pre-engagement assessment, ongoing monitoring, and open-source governance.

### SA-2: Allocation of Resources

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security is integrated into the system development lifecycle: (1) Security controls are implemented as part of feature development (not bolt-on); (2) CI/CD pipeline includes mandatory security gates (SAST, container scanning, secret detection); (3) Security review is part of the PR approval process; (4) Dedicated budget for 3PAO assessment and continuous monitoring tools.

### SA-3: System Development Life Cycle

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon follows a security-integrated SDLC: (1) **Planning**: Threat modeling and security requirements during design; (2) **Development**: Secure coding practices, dependency pinning, FIPS 140-2 BoringCrypto; (3) **Testing**: Unit tests, integration tests, SAST, container scanning, red team exercises; (4) **Deployment**: Automated CI/CD with security gates, distroless containers, WIF; (5) **Operations**: Continuous monitoring, vulnerability management, incident response; (6) **Disposal**: Automated data purge for account closure, cryptographic erasure capability.

### SA-4: Acquisition Process

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All third-party services and dependencies are evaluated for security before adoption: (1) GCP is the sole infrastructure vendor (FedRAMP High authorized); (2) Open-source dependencies are vetted for security, license compliance, and maintenance activity; (3) Vendor risk assessments are conducted per the Vendor Risk Policy tiered framework (Critical, High, Medium, Low).

### SA-4(1): Functional Properties of Controls

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security control functionality is verified through: unit tests validating RBAC enforcement, integration tests validating RLS isolation, red team exercises validating auth bypass resistance, and Terragrunt plan validation for infrastructure controls.

### SA-4(2): Design and Implementation Information for Controls

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security control design and implementation are documented in: (1) This SSP and its appendices; (2) Security Architecture Whitepaper (770+ lines); (3) Architecture decision documents (`POOL_ISOLATION.md`, `TENANT_CONFIGURATION.md`); (4) Inline code documentation; (5) Terraform/Terragrunt module documentation.

### SA-4(9): Functions, Ports, Protocols, and Services in Use

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All system functions, ports, protocols, and services are documented in Section 9 (Ports, Protocols, and Services) of the SSP. Only HTTPS (443) is externally accessible. All other ports are internal-only within the VPC.

### SA-5: System Documentation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System documentation includes: (1) This SSP with architecture diagrams and data flows; (2) Security Architecture Whitepaper with detailed technical descriptions; (3) 13 security policy documents; (4) Infrastructure documentation via Terraform module README files and variable descriptions; (5) API documentation via protobuf service definitions.

### SA-8: Security and Privacy Engineering Principles

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security engineering principles applied include: (1) **Defense in depth**: 5-layer org isolation (interceptor → RLS → DB roles → vector scoping → audit); (2) **Fail-closed**: RLS returns zero rows if session variables unset, ClamAV rejects uploads if endpoint unavailable in production; (3) **Least privilege**: Scoped IAM roles, minimal DB grants, RBAC; (4) **Separation of duties**: Three services with distinct DB roles; (5) **Zero trust**: Every request authenticated and authorized regardless of network origin.

### SA-9: External System Services

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: External services used by the system: (1) **GCP** (Critical vendor, FedRAMP High authorized): Cloud Run, Cloud SQL, GCS, Vertex AI, Cloud Armor, Identity Platform, Cloud KMS, Cloud Tasks, Cloud Logging, Cloud Monitoring; (2) **Cloudflare** (DNS, FedRAMP Moderate): Authoritative DNS with DNSSEC; (3) **GitHub** (High vendor): Source code management, CI/CD; (4) **Microsoft** (High vendor, FedRAMP High authorized): Microsoft Graph API and Microsoft Entra ID (Azure AD) for SharePoint/OneDrive document sync via OAuth2 authorization code grant. Only delegated read-only permissions are requested (`Files.Read.All`, `Sites.Read.All`). OAuth refresh tokens are encrypted via Cloud KMS before storage. Vendor monitoring is conducted per the Vendor Risk Policy with quarterly reviews for Critical vendors.

### SA-10: Developer Configuration Management

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Developer configuration management includes: (1) Git version control with full commit history; (2) Branch protection rules requiring PR review and passing CI; (3) Signed commits encouraged; (4) Dependency pinning via `go.mod` + `go.sum`, `package-lock.json`; (5) Infrastructure changes tracked via Terraform state with drift detection; (6) CI/CD builder images pinned by version substitution variable (cloud-sdk, kaniko, trivy, syft, gitleaks, atlas) — centrally managed in `cloudbuild.yaml` substitutions.

### SA-11: Developer Testing and Evaluation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Developer security testing includes: (1) Unit tests for authentication, authorization, and data isolation logic; (2) GoSec static analysis for Go security vulnerabilities; (3) Semgrep pattern matching for common vulnerability patterns; (4) govulncheck for known Go dependency vulnerabilities; (5) Trivy container image scanning; (6) Gitleaks secret detection in commit history; (7) Red team attack suite (99 attacks, 6 suites) for integration-level security validation including OWASP Top 10 and external tool-based assessment.

### SA-11(1): Static Code Analysis

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Static code analysis is performed on every build via: GoSec (Go-specific security scanner), Semgrep (multi-language pattern matching), and govulncheck (Go vulnerability database). Analysis failures block PR merge. Results are tracked in CI/CD logs and uploaded to Drata as evidence.

---

## SC — System and Communications Protection

### SC-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System and communications protection policies are documented across the Encryption Policy (POL-EN-001, `policies/encryption.md`), Access Control Policy (POL-AC-001), and Security Architecture Whitepaper. These documents define cryptographic standards, network security controls, and data protection mechanisms.

### SC-2: Separation of Application and Management Functionality

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Application and management functionality are separated through: (1) Three GCP projects (app, admin, ops) with two separate Identity Platform pools (app and admin); (2) Three Cloud Run services with distinct database roles (app_ro, admin_rw, ops_rw); (3) Admin operations require the `admin` or `master_admin` RBAC role, inaccessible from the app; (4) GCP management operations use separate IAM credentials from application service accounts.

### SC-4: Information in Shared System Resources

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Shared system resources are protected through: (1) Cloud Run containers are isolated at the gVisor sandbox level (GCP infrastructure control); (2) PostgreSQL RLS prevents cross-organization data leakage at the database level; (3) Vector search results are scoped by workspace tokens preventing cross-workspace semantic leakage; (4) Cloud Storage object paths are workspace-scoped preventing cross-workspace file access.

### SC-5: Denial-of-Service Protection

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: DoS/DDoS protection is provided at multiple layers: (1) **Cloud Armor WAF**: DDoS absorption at Google's global edge network with adaptive protection; (2) **Rate Limiting**: Per-IP and per-user request rate limits enforced at Cloud Armor and application layers; (3) **Cloud Run Auto-scaling**: Automatic scaling with configurable max instances prevents resource exhaustion; (4) **FQDN Egress Firewall**: Prevents the system from being used as a DDoS amplifier.

### SC-7: Boundary Protection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System boundary protection includes:

- **External boundary**: Cloud Armor WAF (OWASP CRS, HTTP method enforcement, origin restriction, bot blocking, per-org IP allowlisting) → Global HTTPS Load Balancer → Cloud Run (private IP only)
- **Internal boundary**: VPC with no public IPs on any service. FQDN-based egress firewall with default-deny-all. Only Google API endpoints are reachable outbound.
- **Cross-project boundary**: Scoped cross-project IAM grants: `archon-admin` SA receives `cloudtasks.enqueuer` and `storage.objectAdmin` on the ops project; `archon-app` SA receives `aiplatform.user` and `storage.objectViewer` on the ops project; Cloud SQL access via `cloudsql.client` and `cloudsql.instanceUser`. Each grant is minimum-necessary for the service's function.
- **Org boundary**: 5-layer org isolation in auth interceptor prevents cross-org request routing via DB-backed subdomain validation

### SC-7(3): Access Points

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: External access points are minimized to: (1) App project HTTPS endpoint (app.latentarchon.com); (2) Admin project HTTPS endpoint (admin.latentarchon.com); (3) SCIM endpoint (admin API path). All access points terminate at Cloud Armor WAF → Global HTTPS Load Balancer. No other external access points exist. No SSH, VPN, or direct infrastructure access is provided.

### SC-7(4): External Telecommunications Services

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: GCP provides managed external telecommunications with redundant internet connectivity and DDoS mitigation at the network edge. This is inherited from GCP's FedRAMP High authorization.

### SC-7(5): Deny by Default / Allow by Exception

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Network traffic follows deny-by-default: (1) **Egress**: FQDN firewall denies all outbound except explicitly allowlisted Google API domains; (2) **Cloud Armor**: Default action is configurable per environment (deny(403) in production, allow in staging); (3) **Auth interceptor**: All requests denied unless authenticated, MFA-verified, and org-membership validated; (4) **RLS**: Database queries return zero rows unless session variables are properly set (fail-closed).

### SC-7(7): Split Tunneling Prevention

- **Responsibility**: CSP
- **Status**: N/A

**Implementation**: Split tunneling is not applicable to the SaaS delivery model. All system traffic traverses the defined boundary (Cloud Armor → Load Balancer → VPC). There are no VPN connections or client-side agents.

### SC-7(8): Route Traffic to Authenticated Proxy Servers

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All inbound traffic is routed through Google Cloud Load Balancer (authenticated proxy) which terminates TLS and forwards to Cloud Run services. All outbound API traffic is routed through VPC network infrastructure with FQDN egress filtering. Private Service Connect routes Vertex AI traffic through Google's private backbone without traversing the public internet.

### SC-8: Transmission Confidentiality and Integrity

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All data in transit is protected by TLS 1.2+ using FIPS 140-2 validated cryptographic modules (Google Front End). HSTS headers with 2-year max-age and preload flag prevent protocol downgrade attacks. Internal service-to-service communication within GCP uses Google's encrypted inter-data-center protocol (ALTS). Private Service Connect provides encrypted private connectivity to Vertex AI. Outbound connections to Microsoft Graph API (`graph.microsoft.com`) and Microsoft Entra ID (`login.microsoftonline.com`) for SharePoint/OneDrive document sync use TLS 1.2+ with Microsoft-managed certificates.

### SC-8(1): Cryptographic Protection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Cryptographic protection for data in transit uses: TLS 1.2+ with ECDHE key exchange and AES-256-GCM encryption (negotiated by Google Front End, FIPS 140-2 Level 1 validated). Internal communication uses Application Layer Transport Security (ALTS). No unencrypted communication paths exist.

### SC-10: Network Disconnect

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The auth interceptor enforces server-side session disconnection: idle timeout (default 25 minutes, per-org configurable 5-480 min) and absolute timeout (default 12 hours, per-org configurable 60-1440 min). Expired sessions are rejected with `Unauthenticated` on the next API request. No persistent network connections are maintained — all communication is request-response over HTTPS.

### SC-12: Cryptographic Key Establishment and Management

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Key management uses Cloud KMS with HSM-backed keys (FIPS 140-2 Level 3) and automatic 90-day rotation: (1) CMEK keys encrypt data at rest for Cloud SQL, Cloud Storage, BigQuery (audit logs), Cloud Logging, Vertex AI, Artifact Registry, Cloud Tasks, and application-level secrets — all using AES-256-GCM with 90-day automatic rotation and 30-day destroy-scheduled safety windows; (2) Per-tenant CMEK anchor via `organizations.kms_key_name` column for future per-tenant encryption key isolation; (3) JWT signing keys managed by Google Identity Platform (automatic rotation); (4) SCIM tokens are random 32-byte values, SHA-256 hashed before storage; (5) No static service account keys — all service authentication uses Workload Identity Federation; (6) TLS certificate keys are self-managed regional SSL certificates uploaded to the regional LB; (7) Cloud KMS `app_secrets` key (AES-256-GCM, HSM-backed, 90-day rotation) encrypts Microsoft Graph OAuth refresh tokens before database storage; (8) KMS key lifecycle alerts monitor for key disable, destroy, and version state changes with notifications to security operations. See Security Whitepaper: "Schema future-proofing".

### SC-12(1): Availability

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Cloud KMS provides 99.999% availability for key operations with automatic replication across multiple availability zones. Key material is protected at FIPS 140-2 Level 3 within Hardware Security Modules (HSMs).

### SC-13: Cryptographic Protection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All cryptographic operations use FIPS 140-2 validated modules: (1) Go runtime uses BoringCrypto (Cert #4407) via `GOEXPERIMENT=boringcrypto`; (2) Cloud KMS uses FIPS 140-2 Level 3 HSMs; (3) Google Front End uses FIPS 140-2 Level 1 for TLS; (4) Prohibited algorithms: DES, 3DES, RC4, MD5, SHA-1 (for signatures), TLS < 1.2, RSA < 2048 bits.

### SC-15: Collaborative Computing Devices and Applications

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system does not include collaborative computing devices (cameras, microphones). The RAG conversation feature is text-only. No audio/video capabilities exist within the application.

### SC-17: Public Key Infrastructure Certificates

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: TLS certificates are self-managed regional SSL certificates on the regional external Application Load Balancer. Certificate Manager is not used because it is not IL5-supported. SAML IdP certificates are managed by customer agencies. DNSSEC uses Cloudflare-managed zone signing keys with DS records registered at the domain registrar.

### SC-18: Mobile Code

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The React SPAs (app and admin) are the only mobile code executed on client devices. SPAs are served from Cloud Run containers in a gVisor sandbox. Content Security Policy (CSP) headers restrict script sources. No Java applets, Flash, ActiveX, or other plugin-based mobile code is used.

### SC-20: Secure Name/Address Resolution Service (Authoritative Source)

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Cloudflare DNS provides authoritative DNS with DNSSEC enabled (`cloudflare_zone_dnssec` Terraform resource). DS record is registered at the domain registrar. Authoritative zone signing provides data origin authentication and integrity protection for all DNS responses.

### SC-21: Secure Name/Address Resolution Service (Recursive/Caching)

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: DNSSEC validation is performed on Cloudflare resolvers. GCP internal DNS resolves via Google Public DNS (DNSSEC-validating). This ensures authenticity of DNS responses for all platform services.

### SC-22: Architecture and Provisioning for Name/Address Resolution Service

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: DNS services are provisioned for fault tolerance through: (1) Cloudflare operates globally distributed authoritative DNS with anycast routing; (2) GCP internal DNS uses Google's global DNS infrastructure; (3) Multiple NS records provide redundancy. DNS is managed via Terraform (`cloudflare_zone_dnssec` resource) for reproducibility.

### SC-23: Session Authenticity

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Session authenticity is verified through: (1) JWT-based sessions with cryptographic signature verification against Google's public keys; (2) TOTP MFA provides a second authentication factor; (3) Five-layer org isolation: IDP pool presence, IDP pool header match, org membership gate, subdomain→org DB validation, cross-org check; (4) Firebase ID tokens are short-lived (1 hour) reducing the window for session hijacking.

### SC-28: Protection of Information at Rest

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All data at rest is encrypted with Customer-Managed Encryption Keys (CMEK) backed by Cloud KMS HSMs (FIPS 140-2 Level 3): (1) Cloud SQL: AES-256 with CMEK (90-day auto-rotation); (2) Cloud Storage: AES-256-GCM with CMEK; (3) BigQuery audit datasets: AES-256 with CMEK via US multi-region KMS keyring (location must match dataset); (4) Vertex AI: CMEK; (5) Artifact Registry: CMEK; (6) Cloud Logging: CMEK via regional KMS keyring; (7) Terraform state: Encrypted in GCS with versioning and CMEK; (8) Microsoft Graph OAuth refresh tokens: AES-256-GCM with Cloud KMS `app_secrets` key (HSM-backed, 90-day rotation) — application-level encryption before database storage, providing defense-in-depth on top of Cloud SQL CMEK. Two KMS keyrings per project: regional (`us-east4`) for Cloud SQL/GCS/Vertex AI/AR/Logging, and multi-region (`us`) for BigQuery. All keys use HSM protection, 90-day rotation, and `prevent_destroy` lifecycle rules. Cryptographic erasure is supported by rotating CMEK keys.

### SC-28(1): Cryptographic Protection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Cryptographic protection at rest uses AES-256 with Cloud KMS CMEK (FIPS 140-2 Level 3). Key hierarchy: Cloud KMS master key → data encryption keys (DEK) → per-object encryption. DEKs are automatically rotated. Key access is restricted to specific service accounts via IAM.

### SC-39: Process Isolation

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Process isolation operates at multiple levels: (1) **Container isolation**: Cloud Run uses gVisor sandboxing for container isolation (GCP); (2) **Service isolation**: Three separate Cloud Run services with distinct service accounts and database roles; (3) **Project isolation**: Three GCP projects (app, ops, admin) with separate IAM boundaries; (4) **Data isolation**: PostgreSQL RLS provides row-level data isolation between organizations.

---

## SI — System and Information Integrity

### SI-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System integrity policies are documented across the Change Management Policy (POL-CM-001), Vulnerability Scanning Strategy (DOC-VS-001), and Security Architecture Whitepaper. These documents define vulnerability management, malware protection, software integrity verification, and monitoring requirements.

### SI-2: Flaw Remediation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Flaw remediation follows defined SLAs: Critical CVSSv3 — 15 days, High — 30 days, Medium — 90 days, Low — 180 days. Remediation sources include: Dependabot PRs (automatic), govulncheck findings, Trivy scan results, GoSec findings, red team discoveries, and customer/3PAO reports. Remediation is tracked in POA&M and Drata. Emergency patches for actively exploited vulnerabilities follow the expedited change process (deploy within 24 hours, post-hoc review).

### SI-2(2): Automated Flaw Remediation Status

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Flaw remediation status is tracked through: (1) Dependabot automatically creates PRs for dependency vulnerabilities; (2) CI/CD pipeline fails on new Critical/High findings; (3) Drata provides continuous compliance monitoring dashboard; (4) POA&M items are reviewed monthly.

### SI-3: Malicious Code Protection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Malicious code protection includes:

- **File upload scanning**: ClamAV REST service (`benzino77/clamav-rest` on Cloud Run, internal-only) scans all uploaded documents before storage. In production admin/ops mode, the system is **fail-closed** — uploads are rejected if the ClamAV endpoint is not available. ClamAV signature database updates automatically.
- **Magic-byte validation**: File type is verified by inspecting file content magic bytes, not relying on client-provided Content-Type or file extension.
- **File type allowlisting**: Only explicitly permitted document types are accepted for upload.
- **Container security**: Distroless base images with no package manager or shell prevent installation of malicious code at the container level.
- **Dependency scanning**: Trivy, GoSec, and govulncheck detect known malicious or vulnerable dependencies.

### SI-3(1): Central Management

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: ClamAV is centrally managed as a Cloud Run service in the admin project. Signature updates are pulled automatically from ClamAV mirrors. All upload-accepting services route scans through the central ClamAV service.

### SI-4: System Monitoring

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System monitoring operates at multiple layers:

- **Infrastructure**: Cloud Monitoring dashboards for CPU, memory, request latency, error rates, Cloud SQL connections. Alert policies for anomalies.
- **WAF**: Cloud Armor analytics for blocked requests, OWASP CRS matches, DDoS events, bot traffic.
- **Application**: Structured audit logging capturing all authentication, authorization, and data access events. WARN-level logging for security-critical operations.
- **Security**: Real-time email notifications to org admins for: role escalation, auth failures exceeding thresholds, cross-org access attempts, SCIM token events, member changes. Pub/Sub SIEM export pipeline for customer agency security tools.

### SI-4(1): System-Wide Intrusion Detection System

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Intrusion detection is provided by: (1) Cloud Armor with OWASP CRS for web application attacks (SQLi, XSS, LFI, RFI, RCE); (2) Red team program for proactive detection validation; (3) Audit event analysis for anomalous access patterns; (4) Cloud Monitoring anomaly detection for infrastructure-level indicators. Customer agencies can ingest audit data via Pub/Sub for integration with their own IDS/SIEM.

### SI-4(2): Automated Tools and Mechanisms for Real-Time Analysis

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Real-time analysis tools include: Cloud Armor real-time request analysis and blocking, Cloud Monitoring real-time metric analysis with alert policies, structured audit logging with immediate Cloud Logging ingestion, and real-time security email notifications triggered by audit events.

### SI-4(4): Inbound and Outbound Communications Traffic

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Inbound traffic is monitored through Cloud Armor (all requests logged with source IP, matched rules, and action). Outbound traffic is monitored through VPC flow logs and FQDN egress firewall logs (blocked attempts are logged). Internal traffic between services is logged at the application level via audit events.

### SI-4(5): System-Generated Alerts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Automated alerts are generated for: (1) Cloud Armor WAF rule matches; (2) Cloud Monitoring metric thresholds (error rate > 5%, latency > 2s, CPU > 80%); (3) Audit events at WARN level (role escalation, cross-org attempts, auth failures); (4) Dependabot vulnerability discoveries; (5) CI/CD security scan failures; (6) Binary Authorization admission denials (image rejected due to missing/invalid attestation); (7) Binary Authorization break-glass overrides (emergency deploy bypassing attestation). Alerts route to operations team via Cloud Monitoring notification channels.

### SI-5: Security Alerts, Advisories, and Directives

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security intelligence sources monitored: (1) CISA KEV (Known Exploited Vulnerabilities) catalog; (2) Go vulnerability database (govulncheck); (3) GitHub Advisory Database (Dependabot); (4) GCP security bulletins; (5) FedRAMP PMO directives. Critical advisories trigger immediate assessment and expedited remediation per the flaw remediation process. GCP Essential Contacts are configured at the organization level to route security notifications and suspension warnings to `gcp-security-admins@`, technical advisories to `gcp-organization-admins@`, and billing alerts to `gcp-billing-admins@`. GCP Access Approval is enabled org-wide, requiring explicit approval from security admins before Google support can access customer data.

### SI-6: Security and Privacy Function Verification

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security function verification through: (1) Unit tests validating RBAC enforcement for each role level; (2) Integration tests validating RLS data isolation; (3) Red team suite (99 attacks, 6 suites) validating authentication bypass resistance, privilege escalation prevention, data exfiltration prevention, OWASP Top 10 web application defenses, and external tool-based vulnerability assessment; (4) CI/CD pipeline verifying all security gates pass on every build.

### SI-7: Software, Firmware, and Information Integrity

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Software integrity is verified through: (1) `go.sum` cryptographic checksums for all Go dependencies; (2) `package-lock.json` integrity hashes for JavaScript dependencies; (3) Docker image digests pinned in deployment configurations; (4) Terraform lock file (`.terraform.lock.hcl`) pinning provider versions with hashes; (5) Gitleaks scanning for unauthorized modifications to commit history.

### SI-7(1): Integrity Checks

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Integrity checks are performed: (1) On every build via `go build` checksum verification; (2) On every deploy via Docker image digest verification; (3) On every Terraform plan via provider hash verification; (4) Dependabot alerts on dependency integrity changes. Integrity violations fail the CI/CD pipeline.

### SI-8: Spam Protection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Spam protection is provided by: (1) Firebase App Check with reCAPTCHA Enterprise for client attestation; (2) Cloud Armor bot/scanner blocking rules; (3) Rate limiting at IP and per-user levels; (4) No user-to-user messaging within the platform (conversation is user-to-AI only).

### SI-10: Information Input Validation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Input validation is performed at multiple layers: (1) **Protobuf**: Strong typing and schema validation for all API requests via Connect-RPC; (2) **Application**: Business logic validation (CIDR format for IP allowlists, DNS-safe regex for org slugs, reserved-slug blocklist, session timeout range validation); (3) **Database**: PostgreSQL type constraints and foreign key integrity; (4) **Cloud Armor**: OWASP CRS for injection detection (SQLi, XSS, etc.); (5) **File upload**: Magic-byte validation, file type allowlisting, size limits (50 MB).

### SI-11: Error Handling

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Error handling follows security best practices: (1) User-facing errors return generic messages without system internals (e.g., `PermissionDenied: "organization mismatch"` without revealing the expected org); (2) Detailed error information is logged server-side in structured logs with correlation IDs for debugging; (3) Stack traces are never returned to clients; (4) Authentication failures return generic `Unauthenticated` without distinguishing invalid token vs. expired token vs. disabled account.

### SI-12: Information Management and Retention

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Information retention follows a zero-deletion policy for government compliance: (1) Customer documents: retained indefinitely with object versioning (all versions preserved), 90-day soft-delete recovery window, and CMEK encryption; (2) Audit logs: indefinite retention in BigQuery (no table/partition expiration, CMEK-encrypted) + GCS WORM audit buckets (7-year locked retention in production, 1-year unlocked in staging) + Cloud SQL `audit_events` table (no automatic expiration); (3) All GCS buckets: zero auto-delete lifecycle rules — old data tiers to NEARLINE (90 days) then COLDLINE (365 days) for cost optimization but is never deleted; (4) `force_destroy = false` on all buckets prevents accidental deletion via Terraform; (5) User PII: purged 90 days after account closure per privacy policy, with forensic preservation holds available for active investigations. No automated process permanently deletes any government record, audit trail, or document. Cryptographic erasure is available via CMEK key rotation for end-of-life data destruction when required by contract.

### SI-16: Memory Protection

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Memory protection is provided by: (1) Go runtime with garbage collection and bounds checking (no buffer overflows); (2) Cloud Run gVisor sandboxing provides memory isolation between containers; (3) Distroless containers have no shell or debugging tools that could be used to dump memory.

---

## SR — Supply Chain Risk Management

### SR-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Supply chain risk management policies are documented in the Vendor Risk Management Policy (POL-VR-001, `policies/vendor-risk.md`) and Supply Chain Risk Management Plan (Appendix H). These documents define vendor classification tiers, pre-engagement assessment requirements, ongoing monitoring procedures, and open-source dependency governance.

### SR-2: Supply Chain Risk Assessment

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Supply chain risk assessment includes: (1) **Vendor assessment**: GCP classified as Critical vendor (FedRAMP High authorized), GitHub as High vendor — both assessed per the tiered framework in the Vendor Risk Policy with annual reassessment; (2) **Dependency assessment**: SBOM generation (CycloneDX + SPDX) on every build provides full dependency transparency; (3) **Vulnerability scanning**: Dependabot, govulncheck, and Trivy continuously scan for known vulnerabilities in dependencies; (4) **License compliance**: All open-source dependencies verified for acceptable license types.

### SR-3: Supply Chain Controls and Processes

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Supply chain controls include: (1) `go.mod` + `go.sum` cryptographic pinning of all Go dependencies; (2) `package-lock.json` integrity verification for JavaScript dependencies; (3) Docker base images pinned by digest (distroless); (4) Terraform provider versions locked via `.terraform.lock.hcl`; (5) Dependabot automated dependency update PRs with CI validation before merge; (6) Gitleaks scanning for unauthorized credential exposure in supply chain; (7) CI/CD builder images (cloud-sdk, kaniko, trivy, syft, gitleaks, atlas) pinned by version substitution variable — no `:latest` tags; (8) Binary Authorization enforcement on Cloud Run — images without valid attestation are rejected at deploy time.

### SR-5: Acquisition Strategies, Tools, and Methods

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Software acquisition follows: (1) Preference for FedRAMP-authorized services (GCP); (2) Open-source preference with license compliance verification; (3) Minimal dependency principle — avoid unnecessary libraries; (4) Automated dependency update pipeline (Dependabot weekly scans); (5) Vendor risk assessment before any new service adoption.

### SR-6: Supplier Assessments and Reviews

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Supplier reviews follow the Vendor Risk Policy tiered schedule: (1) Critical vendors (GCP): Quarterly review of FedRAMP authorization status, SLA compliance, security bulletins; (2) High vendors (GitHub): Semi-annual review; (3) Medium/Low vendors: Annual review. Reviews include: authorization status verification, incident history check, and SLA performance review. Results tracked in Drata vendor registry.

### SR-8: Notification Agreements

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Notification requirements are established through: (1) GCP provides security bulletin notifications and SLA incident reports; (2) GitHub provides security advisory notifications via Dependabot; (3) Open-source vulnerability databases provide automated notifications via govulncheck and Trivy database updates. Latent Archon monitors all notification channels per the Threat Awareness Program (PM-16).

### SR-10: Inspection of Systems or Components

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System components are inspected through: (1) SBOM analysis on every build revealing all component versions and known vulnerabilities; (2) Container image scanning via Trivy before deployment; (3) Terraform plan review showing exact infrastructure component changes; (4) Red team exercises testing deployed components for exploitable vulnerabilities. No hardware components are within the authorization boundary (all inherited from GCP).

### SR-11: Component Authenticity

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Component authenticity is verified through: (1) Go module checksums via `go.sum` (cryptographic verification against Go module mirror); (2) Docker image digests for base images; (3) Terraform provider checksums in lock file; (4) NPM package integrity hashes in `package-lock.json`; (5) Artifact Registry stores built images with digest verification.

### SR-12: Component Disposal

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Component disposal follows: (1) Deprecated container images are removed from Artifact Registry via lifecycle policies; (2) Removed Go dependencies are automatically cleaned from `go.sum` on next `go mod tidy`; (3) Decommissioned infrastructure is destroyed via `terragrunt destroy` with state cleanup; (4) Cryptographic erasure via CMEK key rotation for data associated with decommissioned components.

---

## End of Appendix A

**Total Controls Documented**: ~230+ Moderate baseline controls + 85+ High enhancement controls across 20 families (AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR)

**Control Status Summary**:
- **Implemented**: ~216 (includes AC-10 concurrent session control)
- **Partially Implemented**: ~7 (CA-2(1), CP-4, IR-3, PM-10, PT-5 + pending POA&M items)
- **Inherited (GCP)**: ~20+ (PE family, portions of MA, MP, CP, SC)
- **Customer Responsibility**: ~10 (AC-8, AC-11, AC-20, PT-6, PT-8, IA-2(12), IA-8(1))

---

## Appendix A-2: FedRAMP High Enhancement Controls

> The following controls are FedRAMP High enhancements beyond the Moderate baseline.
> These are documented here to demonstrate High-readiness.
> **85 controls** across 17 families — organized in NIST SP 800-53 Rev. 5 numerical order.

## AC — Access Control (High Enhancements)

### AC-2(6): Dynamic Privilege Management

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon enforces dynamic privilege management — no static or permanent elevated access exists. Organization administrators adjust RBAC role assignments (`master_admin`, `admin`, `editor`, `viewer`) in real time via the `UpdateMemberRole` RPC. SCIM 2.0 provisioning (`internal/sso/scim_handler.go`) auto-provisions and auto-deprovisions accounts based on customer IdP group membership changes. Role changes take effect on the next RPC call — the auth interceptor (`cmd/server/connect_interceptors.go`) evaluates current role from the database on every request, not from cached JWT claims. All role modifications are audit-logged with before/after values and trigger real-time security email notifications to org administrators.

### AC-2(7): Privileged User Accounts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The `master_admin` role is the sole privileged account tier in the application. Privileged account restrictions include: (1) `master_admin` cannot self-promote — role escalation requires another `master_admin` to grant the role, (2) last-admin guard prevents the final `master_admin` from being demoted or removed, preventing organization lockout, (3) all `master_admin` actions are audit-logged via `internal/audit/logger.go` with user_id, IP address, session_id, and MFA method, (4) MFA is mandatory for all users including privileged accounts — the auth interceptor rejects requests from users without verified MFA, (5) sensitive operations (SSO configuration, SCIM token management, IP allowlist changes, session timeout changes) require the `master_admin` role and are logged at WARN level. At the infrastructure layer, GCP IAM privileged access is limited to time-bounded break-glass grants (maximum 4 hours, CEO/CTO approval required).

### AC-2(11): Usage Conditions

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: The system enforces the following usage conditions at the auth interceptor level (`cmd/server/connect_interceptors.go`): (1) **Session timeouts** — idle timeout (default 25 minutes, configurable 5–480 minutes) and absolute timeout (default 12 hours, configurable 60–1440 minutes) are enforced server-side on every RPC, (2) **IP allowlisting** — per-organization CIDR-based IP restrictions are synced to Cloud Armor WAF rules, restricting access to authorized network ranges, (3) **ROB acceptance** — users must accept the current version of the Rules of Behavior (`rob_acceptances` table); version changes trigger mandatory re-acceptance before access is granted, (4) **MFA enforcement** — TOTP MFA is mandatory for all users; the interceptor verifies `mfa_verified` status on every request. These conditions are evaluated collectively on every authenticated request — failure of any condition results in rejection.

**Customer Responsibility**: Customers configure organization-specific session timeout values and IP allowlists appropriate for their security posture.

### AC-2(12): Account Monitoring for Atypical Usage

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Atypical usage is monitored through multiple channels: (1) **Real-time security email notifications** alert org administrators on authentication failures, role escalation attempts, cross-org access attempts, SCIM provisioning events, and member removal actions, (2) **Cloud Monitoring alerts** (`infra/gcp/modules/monitoring/main.tf`) detect WAF block spikes, rate-limit ban events, Cloud SQL authentication failures, and adaptive DDoS protection triggers, (3) **IAM privilege escalation alerts** detect unauthorized `SetIamPolicy` calls in GCP, (4) **Audit log analysis** — all events are written to three stores (Cloud SQL `audit_events`, BigQuery, GCS WORM buckets) enabling retrospective analysis for anomalous patterns such as unusual login times, geographic anomalies, or rapid privilege changes, (5) **Pub/Sub SIEM export pipeline** enables customer agencies to ingest security events into their own SIEM for agency-specific correlation and alerting.

### AC-2(13): Disable Accounts for High-Risk Individuals

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Accounts for high-risk individuals are disabled within 24 hours of notification through: (1) **Org admin action** — administrators invoke `RemoveMember` or disable users via the admin dashboard, which calls Firebase Admin SDK `DisableUser()` to immediately invalidate all active sessions, (2) **SCIM DELETE** — customer IdPs automatically deprovision high-risk individuals via SCIM 2.0 (`internal/sso/scim_handler.go`), triggering immediate account deactivation, (3) **Firebase brute-force protection** — accounts exhibiting brute-force authentication patterns are automatically locked by Firebase Identity Platform. Disabled accounts cannot authenticate — Firebase rejects tokens for disabled users before they reach the application layer. Post-closure, the automated account purge service (`internal/accountpurge/service.go`) removes personal data after 90 days via Cloud Scheduler.

**Customer Responsibility**: Customers are responsible for timely notification of high-risk individuals or automated deprovisioning via SCIM integration with their IdP.

### AC-3(3): Mandatory Access Control

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: PostgreSQL Row-Level Security (RLS) policies on all data tables enforce mandatory, workspace-scoped access control. RLS policies are not discretionary — users cannot override, relax, or delegate access beyond their assigned workspace scope. The RLS implementation is fail-closed: if session variables (`app.current_org_id`, `app.current_workspace_id`) are missing or invalid, queries return zero rows. Three database roles (`archon_app_ro`, `archon_admin_rw`, `archon_ops_rw`) further constrain operations — the app role is read-only and cannot modify data tables. Default `PUBLIC` privileges are revoked via migration, ensuring no implicit grants exist. This mandatory access model ensures that even if application-layer authorization is bypassed, the database enforces tenant isolation independently.

### AC-6(3): Network Access to Privileged Commands

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Network access to privileged commands and functions is restricted to authorized sources only. No SSH, VPN, or direct console access to Cloud Run containers exists — containers are distroless with no shell. GCP Console access requires Google Workspace authentication with mandatory MFA. Infrastructure changes are applied exclusively via Terraform/Terragrunt through Cloud Build (`infra/gcp/modules/`), requiring PR approval with branch protection. Workload Identity Federation eliminates static service account keys (enforced by GCP org policy `iam.disableServiceAccountKeyCreation`). Privileged GCP IAM operations (e.g., `SetIamPolicy`) are detected by Cloud Monitoring alerts and logged in Cloud Audit Logs. Emergency break-glass access uses time-limited IAM Conditions (maximum 4 hours) with CEO/CTO approval.

### AC-6(7): Review of User Privileges

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Organization administrators review user privileges via the admin dashboard, which displays all org members with their current RBAC roles and workspace memberships. Latent Archon recommends quarterly privilege reviews aligned with agency access review cycles. For SCIM-enabled organizations, privilege review is partially automated — role assignments are continuously synchronized with the customer IdP, and deprovisioning occurs automatically when users are removed from IdP groups. Drata integration (`compliance/drata/`) tracks access review compliance as part of continuous monitoring. All role assignments and changes are recorded in the audit log, providing a complete privilege history for review.

**Customer Responsibility**: Customers are responsible for conducting periodic access reviews and ensuring IdP group memberships remain current.

### AC-6(8): Privilege Levels for Code Execution

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system restricts code execution privileges at multiple layers: (1) **Distroless containers** — all three Cloud Run services (`archon-app`, `archon-admin`, `archon-ops`) use distroless base images with no shell, package manager, or user-accessible runtime, preventing arbitrary code execution, (2) **Non-root execution** — Cloud Run containers execute as non-root users, (3) **Scoped service accounts** — each Cloud Run service operates under a distinct GCP service account with minimum IAM roles scoped to its function (e.g., `archon-ops` has document processing roles, `archon-app` has read-only data access), (4) **No code execution API** — the platform provides no RPC or endpoint that allows users to execute arbitrary code, scripts, or queries. User-uploaded documents are processed through a controlled pipeline (ClamAV scan, magic-byte validation, file type allowlist) with no executable content permitted.

### AC-16: Security and Privacy Attributes

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system associates security and privacy attributes with information at multiple levels: (1) **Data classification** — the Data Classification Policy (POL-DC-001, `policies/data-classification.md`) defines four tiers: CUI, Sensitive, Internal, and Public, with handling requirements for each, (2) **Tenant isolation attributes** — every data record is scoped to an organization and workspace via RLS. The `org_id` and `workspace_id` columns serve as mandatory security attributes enforced at the database layer, (3) **Identity pool separation** — Firebase Identity Platform maintains separate pools for admin and app contexts, preventing cross-pool identity bridging, (4) **Audit event attributes** — each audit record carries security-relevant attributes including user_id, org_id, ip_address, user_agent, session_id, trace_id, mfa_method, and idp_pool_id, enabling attribute-based analysis and correlation. Classification labels are applied to infrastructure resources via Terraform labels and to code repositories via automated SCN classification.

### AC-17(9): Disconnect / Disable Access

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: The system provides the capability to immediately disconnect or disable remote access: (1) **Session termination** — the auth interceptor (`cmd/server/connect_interceptors.go`) enforces idle and absolute session timeouts on every request, disconnecting users who exceed configured limits, (2) **Account disablement** — Firebase Admin SDK `DisableUser()` immediately invalidates all active sessions for a user; subsequent requests are rejected at the Firebase token verification layer before reaching the application, (3) **SCIM-triggered revocation** — SCIM DELETE from customer IdPs (`internal/sso/scim_handler.go`) triggers immediate account deactivation and session invalidation, (4) **Admin member removal** — org administrators can instantly remove members via the `RemoveMember` RPC, revoking all access, (5) **IP allowlist enforcement** — changes to per-org IP allowlists are synced to Cloud Armor WAF rules, immediately blocking connections from unauthorized networks.

**Customer Responsibility**: Customers initiate disconnect actions via their IdP (SCIM) or admin dashboard for their organization's users.

---

## AT — Awareness and Training (High Enhancements)

### AT-2(3): Social Engineering and Mining

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon's Security Awareness Training Policy (POL-AT-001, `policies/security-awareness-training.md`) includes social engineering awareness covering phishing, pretexting, baiting, and information mining techniques. Training completion is tracked in `compliance/cybersecurity-education-tracker.md`. Red team exercises (`redteam/`) include social engineering test cases within the 99-attack, 6-suite monthly exercise program — these validate personnel resilience against targeted social engineering scenarios. Training is delivered annually with supplemental updates when new social engineering techniques are identified. All personnel, including developers, operations staff, and administrators, are required to complete social engineering training within 30 days of onboarding and annually thereafter.

---

## AU — Audit and Accountability (High Enhancements)

### AU-10: Non-Repudiation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Non-repudiation is enforced through: (1) Every audit event records `user_id`, `ip_address`, `user_agent`, `session_id`, and `trace_id` — uniquely attributing each action to an authenticated identity; (2) Audit events are persisted to three independent stores (Cloud SQL `audit_events`, BigQuery, GCS WORM buckets) providing tamper-evident redundancy; (3) GCS WORM audit buckets use locked retention policies (7 years in production) — objects cannot be modified or deleted, even by project owners; (4) JWT-based authentication with cryptographic signature verification prevents identity spoofing; (5) Step-up MFA for sensitive operations provides additional non-repudiation for high-risk actions.

### AU-12(1): System-Wide / Time-Correlated Audit Trail

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: A system-wide, time-correlated audit trail is maintained through: (1) `trace_id` (OpenTelemetry) and `correlation_id` fields in every audit event enable cross-service correlation across the three Cloud Run services (app, admin, ops); (2) All services use `time.Now().UTC()` with Google NTP synchronization for consistent timestamps; (3) Cloud Logging ingestion adds an independent timestamp on each event; (4) `request_id` in audit metadata enables per-request correlation; (5) Pub/Sub SIEM export pipeline preserves all correlation fields for customer agency analysis.

### AU-12(3): Changes by Authorized Individuals

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The ability to modify audit logging configuration is restricted to authorized personnel through multiple controls: (1) **Infrastructure as Code** — all audit log infrastructure (Cloud SQL `audit_events` table, BigQuery dataset, GCS WORM buckets, Pub/Sub export pipeline) is managed via Terraform/Terragrunt (`infra/gcp/modules/`), and changes require PR review with branch protection, (2) **INSERT-only audit table** — non-admin database roles (`archon_app_ro`, `archon_ops_rw`) have INSERT-only access to the `audit_events` table; they cannot UPDATE, DELETE, or TRUNCATE audit records, (3) **GCS WORM retention** — production audit buckets use locked retention policies (7-year retention), preventing modification or deletion even by project owners or GCP organization administrators, (4) **Cloud Audit Logs** — GCP-level audit configuration changes (e.g., modifying data access log settings) are themselves logged in Admin Activity audit logs, which cannot be disabled. Changes to the audit logger code (`internal/audit/logger.go`) are tracked via Git commit history and require PR approval.

---

## CA — Security Assessment and Authorization (High Enhancements)

### CA-3(6): Transfer Authorizations

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Data transfers between Latent Archon and external systems are explicitly authorized and controlled: (1) **SCIM integration** — data transfers with customer IdPs are authorized via SCIM bearer token authentication with SHA-256 hashed tokens stored in the `scim_tokens` table, (2) **Microsoft Graph integration** — document sync with SharePoint/OneDrive is authorized via OAuth 2.0 authorization code grant with per-connection consent; refresh tokens are encrypted via Cloud KMS before database storage, (3) **Internal service-to-service** — Cloud Tasks uses OIDC tokens for authenticated task dispatch between Cloud Run services, (4) **SIEM export** — Pub/Sub export pipeline delivers security events to customer-controlled subscriptions; customers authorize and manage their subscription endpoints, (5) **Egress control** — VPC FQDN egress firewall enforces default-deny-all with explicit allowlist for authorized external endpoints (Google APIs, Microsoft Graph). No unapproved outbound data transfers are possible.

**Customer Responsibility**: Customers authorize SCIM connections, Microsoft Graph OAuth grants, and SIEM subscription endpoints for their organizations.

### CA-8: Penetration Testing

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon conducts monthly automated red team exercises (`redteam/`) comprising 99 attacks across 6 suites: authentication bypass, privilege escalation, data exfiltration, leftfield (novel attack vectors), web application, and manual tool-based testing. Attacks are mapped to the MITRE ATT&CK framework. The red team deployment guide (`compliance/red-team-deployment-guide.md`) documents test methodology and execution procedures. OWASP testing tools (`owasp/`) provide additional web application security validation using Playwright-based scanning. Test results and findings are uploaded to Drata (`compliance/drata/`) as evidence artifacts. Remediation of findings follows the Configuration Management Policy (POL-CM-001) with severity-based SLAs. Annual 3PAO penetration testing is conducted as part of the FedRAMP assessment process.

### CA-8(1): Independent Penetration Agent

- **Responsibility**: CSP
- **Status**: Partially Implemented

**Implementation**: Independence in penetration testing is achieved through: (1) **Internal separation** — the red team function operates independently from the development team, with separate test plans and findings tracked outside the development workflow, (2) **Tool-based assessment** — automated Playwright-based OWASP scanning (`owasp/`) provides tool-independent validation that does not rely on developer knowledge of the system, (3) **3PAO assessment** — the FedRAMP authorization process will include independent penetration testing by an accredited Third Party Assessment Organization (3PAO), satisfying the requirement for an independent penetration agent or team. The 3PAO assessment is pending initial authorization and will be conducted per FedRAMP 20x requirements.

---

## CM — Configuration Management (High Enhancements)

### CM-3(4): Security Representative

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Information System Security Officer (ISSO), appointed per `compliance/isso-appointment-letter.md`, serves as the security representative for all configuration change management activities. The ISSO reviews changes classified as SIGNIFICANT by the automated Security Change Notification (SCN) classifier (`compliance/classify-scn/`), which labels PRs across 6 code repositories based on security impact analysis. Security-impacting changes require ISSO acknowledgment via the `scn-acknowledged` label before merge. The ISSO participates in change review for modifications affecting: authentication/authorization logic, cryptographic configurations, network security rules, audit logging, and compliance documentation. The separation of duties matrix (`compliance/separation-of-duties-matrix.md`) documents the ISSO's role boundaries relative to development and operations personnel.

### CM-3(6): Cryptography Management

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All cryptographic key management is automated and tracked via Infrastructure as Code: (1) **Cloud KMS HSM** — CMEK keys are provisioned via Terraform (`infra/gcp/modules/`) with FIPS 140-2 Level 3 hardware-backed protection, (2) **Automated rotation** — 90-day key rotation schedules are configured in Terraform and enforced by Cloud KMS; no manual key rotation is performed, (3) **Key lifecycle monitoring** — Cloud Monitoring alerts detect KMS key state changes (disable, schedule destroy, state change) and notify security personnel, (4) **Scope** — CMEK is applied to Cloud SQL, GCS, BigQuery, Vertex AI, Artifact Registry, Cloud Logging, and Cloud Tasks, (5) **Application cryptography** — Go BoringCrypto (`GOEXPERIMENT=boringcrypto`) provides FIPS 140-2 Level 1 validated cryptographic primitives for application-layer operations. No manual key management procedures exist — all key lifecycle operations are codified in Terraform and subject to PR review.

### CM-5(1): Automated Access Enforcement/Audit

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Access to configuration change tooling is enforced and audited through automation: (1) **GitHub branch protection** — main branch requires pull request reviews, passing CI checks, and linear commit history; direct pushes are blocked, (2) **Cloud Build pipeline** — all deployments follow an automated build/scan/sign/deploy pipeline; security scans (GoSec, Semgrep, Trivy, govulncheck) run daily (`cloudbuild-security.yaml`) and Gitleaks secret detection runs on every commit, (3) **Binary Authorization** — production Cloud Run services only accept container images signed via Cosign keyless signing, verified by Binary Authorization policy, (4) **Production approval gate** — production deployments require manual approval through GitHub environment protection rules, (5) **Audit trail** — all code changes are tracked via Git commit history, Cloud Build logs, and Cloud Audit Logs; Terraform plan output is posted to PR comments for pre-apply review. No out-of-band configuration changes are possible — all infrastructure is managed via Terragrunt.

### CM-8(4): Accountability Information

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System component inventory includes accountability information mapping components to responsible individuals and teams: (1) **Terraform state** — serves as the authoritative infrastructure inventory, with each resource traceable to its defining module (`infra/gcp/modules/` — 14+ modules) and the engineer who last modified it via Git blame, (2) **Cloud Run service mapping** — each of the three services (`archon-app`, `archon-admin`, `archon-ops`) is mapped to its responsible team and service account in the Terraform configuration, (3) **Software component inventory** — daily SBOM generation (`cloudbuild-sbom.yaml`) produces CycloneDX and SPDX bills of materials cataloging all software dependencies with version, license, and supplier information, (4) **Drata asset inventory** — 30 tracked assets with assigned owners, classification, and compliance status synced weekly (`compliance/drata/`). The separation of duties matrix (`compliance/separation-of-duties-matrix.md`) documents accountability boundaries across roles.

---

## CP — Contingency Planning (High Enhancements)

### CP-2(1): Coordinate with Related Plans

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Contingency Plan (`compliance/contingency-plan.md`) is coordinated with related organizational plans: (1) **Incident Response Plan** (POL-IR-001) — contingency procedures reference IR escalation paths and the IR plan references contingency activation triggers, (2) **Configuration Management Plan** (`compliance/configuration-management-plan.md`) — recovery procedures reference IaC-based rebuild processes, (3) **Continuous Monitoring Plan** (`compliance/continuous-monitoring-plan.md`) — monitoring alerts serve as contingency activation triggers, and post-recovery verification uses the same monitoring baselines, (4) **Supply Chain Risk Management Plan** (`compliance/supply-chain-risk-management-plan.md`) — vendor contingency capabilities (GCP, Cloudflare) are assessed as part of supply chain risk. Cross-references are maintained in each plan document to ensure consistency during updates.

### CP-2(3): Resume Mission/Business Functions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Contingency Plan defines a 4-tier Recovery Time Objective (RTO) aligned with mission criticality: **Tier 1** (authentication, database) — RTO < 1 hour, achieved via Cloud SQL regional HA with automatic failover and Firebase Identity Platform's global availability; **Tier 2** (APIs, WAF) — RTO < 4 hours, achieved via Cloud Run auto-scaling with IaC-based redeployment and Cloud Armor policy restoration from Terraform state; **Tier 3** (AI/search, document processing) — RTO < 8 hours, requiring Vertex AI index rebuild and document pipeline restart; **Tier 4** (CI/CD, monitoring) — RTO < 24 hours, non-mission-critical supporting functions. IaC (Terraform/Terragrunt) enables rapid re-deployment of the entire stack to an alternate GCP region. Monthly automated contingency tests (`compliance/contingency-test/`) validate these RTOs.

### CP-2(5): Continue Mission/Business Functions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Essential mission functions continue with minimal disruption during contingency events: (1) **Authentication** — Firebase Identity Platform is a global Google-managed service with built-in redundancy, ensuring authentication continues even during regional outages, (2) **Document access** — Cloud SQL regional HA provides automatic database failover within the region; Point-in-Time Recovery (PITR) enables restoration to any point within the backup window, (3) **Cloud Run auto-scaling** — services scale across multiple zones within the region, surviving zone-level failures without manual intervention, (4) **DNS continuity** — Cloudflare DNS (independent of GCP) provides globally distributed anycast resolution, eliminating single points of failure at the DNS layer. The contingency plan prioritizes Tier 1 and Tier 2 functions for immediate recovery to maintain essential mission operations.

### CP-2(8): Associated Plans

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The following associated plans are maintained and cross-referenced with the Contingency Plan: (1) **Incident Response Plan** (POL-IR-001, `compliance/policies/incident-response.md`) — defines procedures for security incidents that may trigger contingency activation, validated via tabletop exercises (`compliance/incident-response-tabletop-exercise.md`), (2) **Configuration Management Plan** (`compliance/configuration-management-plan.md`) — documents IaC procedures used during recovery, (3) **Continuous Monitoring Plan** (`compliance/continuous-monitoring-plan.md`) — defines monitoring baselines and alert thresholds that trigger contingency assessment, (4) **Supply Chain Risk Management Plan** (`compliance/supply-chain-risk-management-plan.md`) — documents vendor contingency capabilities, (5) **Privacy Impact Assessment** (`compliance/privacy-impact-assessment.md`) — documents privacy considerations during contingency data handling, (6) **Contingency Test Plan** (`compliance/contingency-test/`) — documents monthly automated CP-4 test procedures and results. All plans are stored in the `compliance/` directory under version control.

### CP-6(1): Separation from Primary Site

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Alternate storage is geographically separated from the primary site: (1) Cloud SQL automated backups are stored in `us-central1` while the primary instance runs in `us-east4` — providing ~1,000 km geographic separation via the `backup_location` Terragrunt variable (FedRAMP High CP-6(1)); (2) GCS buckets use regional storage with multi-zone redundancy (data replicated across ≥2 zones within the region); (3) Terraform state is stored in GCS with versioning in a separate bucket; (4) Container images in Artifact Registry are regionally redundant; (5) All backup/alternate storage is within US borders per data sovereignty requirements.

### CP-6(3): Accessibility

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Backup and alternate processing site storage is accessible regardless of disruption to the primary site: (1) **Cloud-based backups** — all backups reside in GCS and Cloud SQL automated backups, accessible from any authenticated GCP session via IAM — no physical media transport is required, (2) **Geographic separation** — primary operations in GCP `us-east4`; backup storage available in `us-central1`, providing geographic separation from the primary site, (3) **IaC portability** — Terraform/Terragrunt configurations (`infra/gcp/modules/`) enable deployment to any US GCP region, with Terraform state stored in GCS with object versioning, (4) **No on-premises dependencies** — the system has zero on-premises infrastructure dependencies, ensuring that accessibility is not affected by physical site disruptions. Recovery personnel require only a web browser and valid GCP IAM credentials to access backup resources and initiate recovery procedures.

### CP-7(1): Coordination with Related Plans

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Contingency Plan (ISCP-LA-001) is coordinated with: (1) Incident Response Plan — IR activation may trigger contingency activation and vice versa; (2) Configuration Management Plan — recovery uses IaC baseline configurations; (3) Continuous Monitoring Plan — monitoring provides detection that triggers contingency activation; (4) Communication plan includes notification to FedRAMP PMO, customer agencies, and GCP Support.

### CP-7(2): Accessibility

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Alternate processing capability is accessible during disruption: (1) Terragrunt IaC enables deployment to any US GCP region — no manual console access required; (2) CI/CD pipeline (Cloud Build + GitHub Actions) operates independently of the primary region; (3) DNS failover via Cloudflare is region-independent; (4) Identity Platform is multi-regional and survives single-region outages.

### CP-7(3): Priority of Service

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Recovery priority follows the service tier model in the Contingency Plan: Tier 1 (authentication, database) RTO < 1 hour; Tier 2 (API services, WAF) RTO < 4 hours; Tier 3 (AI/search) RTO < 8 hours; Tier 4 (CI/CD, monitoring) RTO < 24 hours.

### CP-8: Telecommunications Services

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Telecommunications services are inherited from GCP's FedRAMP High authorized infrastructure. Google Cloud operates redundant global network infrastructure with diverse fiber paths, multiple peering points, and geographically distributed edge nodes. Cloud Run services are reachable via Google's global anycast network with automatic traffic routing around network failures. GCP's network is designed with no single points of failure at the telecommunications layer, with multiple independent paths between all data centers. The system's use of Cloudflare for DNS provides an additional independent telecommunications path that does not depend on GCP's network.

### CP-8(1): Priority of Service Provisions

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Priority of service provisions are inherited from GCP. GCP Premium Tier networking provides priority routing through Google's private backbone network rather than the public internet, reducing latency and improving reliability. Cloud Run services leverage Google's global load balancing with priority-based traffic management and automatic failover. GCP service level agreements (SLAs) define availability commitments: Cloud Run (99.95%), Cloud SQL (99.95% for regional HA), and Cloud Storage (99.95%). These SLAs provide contractual priority service guarantees. Latent Archon's GCP contract includes priority support provisions for incident escalation.

### CP-8(2): Single Points of Failure

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: The architecture eliminates single points of failure at the telecommunications level: (1) **GCP global network** — Google's private backbone network provides multiple redundant paths between all data centers, with automatic rerouting around failures, (2) **Cloud Run multi-zone** — services are deployed across multiple availability zones within the region, surviving zone-level network failures, (3) **Cloud SQL regional HA** — database replication across zones with automatic failover provides database connectivity resilience, (4) **DNS independence** — Cloudflare DNS operates on a globally distributed anycast network independent of GCP, ensuring DNS resolution continues even during GCP network disruptions, (5) **No single-homed connections** — all external connectivity uses Google's anycast network with multiple ingress points, eliminating single-homed telecommunications dependencies.

### CP-8(3): Separation of Primary/Alternate Providers

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Primary and alternate telecommunications providers are separated to reduce shared-fate risk: (1) **Primary compute/data** — GCP `us-east4` region serves as the primary processing and data storage location, using Google's private backbone for all internal communications, (2) **DNS provider** — Cloudflare provides DNS resolution independent of GCP infrastructure; Cloudflare operates its own global anycast network with no dependency on Google's network, (3) **Backup region** — GCP `us-central1` provides geographically separated backup storage, connected via Google's backbone but physically independent from the primary region, (4) **IaC-based failover** — Terraform/Terragrunt configurations enable redeployment to an alternate GCP region if the primary region experiences a sustained outage. The separation of DNS (Cloudflare) from compute/data (GCP) ensures that a GCP-wide network event does not prevent DNS failover to alternate infrastructure.

### CP-8(4): Provider Contingency Plan

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Contingency planning accounts for telecommunications provider contingency capabilities: (1) **GCP contingency** — Google Cloud Platform maintains its own comprehensive contingency and disaster recovery plans as part of its FedRAMP High authorization (P-ATO from JAB). GCP's contingency capabilities are reviewed as part of their annual FedRAMP assessment and continuous monitoring, (2) **Cloudflare contingency** — Cloudflare maintains disaster recovery capabilities for its DNS services, with globally distributed anycast infrastructure providing inherent resilience, (3) **Vendor assessment** — both providers' contingency capabilities are reviewed during quarterly vendor risk assessments as documented in the Supply Chain Risk Management Plan (`compliance/supply-chain-risk-management-plan.md`), (4) **Contractual provisions** — GCP and Cloudflare contracts include availability SLAs and incident notification requirements. Latent Archon's contingency plan (`compliance/contingency-plan.md`) documents provider-specific contingency procedures and escalation paths.

---

## IA — Identification and Authentication (High Enhancements)

### IA-5(2): PKI-Based Authentication

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: JWT-based authentication relies on PKI infrastructure throughout the token lifecycle. Firebase Identity Platform signs JWTs with Google-managed RSA private keys, and the backend verifies signatures against Google's published JWKS endpoint in the auth interceptor (`backend/cmd/server/connect_interceptors.go`). All client-server communication is protected by Google-managed TLS certificates with automatic renewal. Container image signing uses Cosign keyless signing via Sigstore OIDC, producing PKI-based cryptographic attestations verified by Binary Authorization at deploy time. SCIM bearer tokens (`backend/internal/sso/scim_handler.go`) are verified via SHA-256 hash comparison against stored values.

### IA-5(6): Protection of Authenticators

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: All authenticators are protected against disclosure and modification. TOTP secrets are stored exclusively within Firebase Identity Platform, encrypted at rest by Google infrastructure. SCIM bearer tokens are SHA-256 hashed before storage — plaintext tokens are never persisted in Cloud SQL. The system uses passwordless authentication (magic link + mandatory TOTP MFA), eliminating password-based attack vectors entirely. MFA enrollment requires step-up verification before binding a new TOTP device. No static service account credentials exist — Workload Identity Federation (WIF) provides ephemeral, auto-rotating tokens for all service-to-service authentication, eliminating long-lived secrets from the environment.

### IA-5(8): Multiple System Accounts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system prohibits anonymous and duplicate accounts. Each user maintains a single identity within one Firebase pool — the admin pool (Firebase project in the admin GCP project) or the app pool (Firebase project in the app GCP project). Cross-pool identity bridging is explicitly prohibited per the pool isolation design (`backend/docs/POOL_ISOLATION.md`). SCIM 2.0 provisioning (`backend/internal/sso/scim_handler.go`) creates exactly one account per user per organization, with uniqueness enforced by email address. The service account blocklist in the auth interceptor prevents system accounts from obtaining interactive sessions.

---

## IR — Incident Response (High Enhancements)

### IR-4(3): Continuity of Operations

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Incident response procedures are integrated with continuity of operations to maintain service availability during incidents. Cloud Run services deploy across multiple zones within us-east4, surviving single-zone failures without manual intervention. Cloud SQL uses regional HA with automatic failover to a standby instance. Terraform/Terragrunt IaC (100% coverage) enables rapid redeployment to the us-central1 backup region. Contingency plan activation procedures (`compliance/contingency-plan.md`) are cross-referenced in the IR plan, with automated CP-4 tests executed monthly (`compliance/contingency-test/`). IR communications plan includes notification procedures for FedRAMP PMO, customer agencies, and GCP support.

### IR-4(10): Supply Chain Coordination

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Supply chain incidents are identified and coordinated through multiple channels. GCP security bulletins are monitored via Essential Contacts configured in Terraform. GitHub security advisories trigger Dependabot alerts on all 6 classified repositories. Go vulnerability database is checked daily via govulncheck in CI (`compliance/cloudbuild.yaml`). Trivy scans container images daily for CVEs in OS packages and application dependencies. The supply chain risk management plan (`compliance/supply-chain-risk-management-plan.md`) defines escalation procedures per SR-8 vendor notification agreements. Actively exploited vulnerabilities trigger expedited remediation with a 24-hour deploy target via the CI/CD pipeline.

---

## MA — Maintenance (High Enhancements)

### MA-3(1): Inspect Tools

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Not applicable to the Latent Archon SaaS cloud deployment model. No physical maintenance tools are used within the authorization boundary. All infrastructure management is performed via Terraform/Terragrunt IaC and GCP APIs — no direct system access is available. GCP inherits physical maintenance tool inspection controls from its FedRAMP High authorization (P-ATO).

### MA-3(2): Inspect Media

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Not applicable to the Latent Archon SaaS cloud deployment model. No physical media is inserted into or removed from system components. All software delivery occurs via container images stored in Artifact Registry with integrity verification — Cosign keyless signatures provide cryptographic attestation, and all deploys use digest-pinned image references (`image@sha256:...`). Physical media inspection controls for GCP data center facilities are inherited from GCP's FedRAMP High authorization.

### MA-3(3): Prevent Unauthorized Removal

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Not applicable to the Latent Archon SaaS cloud deployment model. No physical equipment or media exists within the CSP authorization boundary to remove. Data egress is controlled via VPC FQDN egress firewall with a deny-all default rule — only explicitly allowlisted Google API domains and Microsoft Graph endpoints are reachable. GCS buckets are configured with `force_destroy = false` and WORM retention policies (7-year locked retention) preventing deletion. Physical asset removal controls are inherited from GCP's FedRAMP High authorization.

### MA-4(3): Comparable Security/Sanitization

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: All remote maintenance of the system occurs via authenticated GCP APIs requiring Google Workspace MFA — no direct SSH, VPN, or console access to infrastructure is available. Cloud console sessions are encrypted via TLS 1.2+. There is no remote diagnostic or maintenance port access to Cloud Run containers (distroless images contain no shell). Administrator workstations must meet device security requirements per physical security policy (POL-PE-001): FileVault/BitLocker full-disk encryption, 5-minute screen lock timeout, and automatic OS security updates enabled. All administrative actions are logged via Cloud Audit Logs.

---

## MP — Media Protection (High Enhancements)

### MP-4(2): Automated Restricted Access

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Access to digital media is automatically restricted through IaC-enforced IAM policies. GCS document buckets are accessible only to designated Cloud Run service accounts via Terraform-managed IAM bindings. Cloud SQL access is restricted to Cloud Run service accounts via IAM database authentication over private IP — no public IP access is enabled. Artifact Registry access is limited to Cloud Build (push) and Cloud Run (pull) service accounts. All IAM bindings are defined in Terraform (`infra/gcp/modules/`), preventing manual permission grants and ensuring access restrictions are version-controlled and auditable.

### MP-6(1): Review/Approve/Track/Document/Verify

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Media sanitization follows cloud-native cryptographic patterns. CMEK key rotation via Cloud KMS HSM (90-day rotation, FIPS 140-2 Level 3) provides cryptographic erasure capability across all encrypted services. Account closure triggers an automated 90-day data purge workflow (`internal/accountpurge/service.go`) that removes all tenant data from Cloud SQL, GCS, BigQuery, and Vertex AI vector stores. All deletion and purge actions are audit-logged to the three-store audit pipeline (`backend/internal/audit/logger.go`). Physical media sanitization for underlying storage is inherited from GCP FedRAMP High.

### MP-6(2): Equipment Testing

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP. Google verifies the effectiveness of media sanitization equipment and procedures in their data centers as part of their FedRAMP High authorization (P-ATO). Latent Archon does not operate physical storage equipment or media sanitization tools. All data is stored on GCP-managed infrastructure (Cloud SQL, GCS, BigQuery) where physical media lifecycle is managed entirely by Google.

### MP-6(3): Nondestructive Techniques

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Latent Archon employs cryptographic erasure as a nondestructive sanitization technique. CMEK key destruction via Cloud KMS renders all data encrypted under that key permanently unrecoverable without physical media destruction. This applies to Cloud SQL, GCS, BigQuery, Vertex AI, Artifact Registry, Cloud Logging, and Cloud Tasks — all services use CMEK encryption configured in Terraform. Key material is hosted in Cloud KMS HSM (FIPS 140-2 Level 3). Physical media sanitization in GCP data centers is inherited from GCP's FedRAMP High authorization.

---

## PE — Physical and Environmental Protection (High Enhancements)

### PE-3(1): Physical Access Control — Information System Access

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google data centers enforce multi-layer physical access controls for all information system components, including badge readers, biometric scanners, and escort requirements for visitors. Latent Archon does not operate physical facilities — all infrastructure runs in GCP data centers (us-east4 primary, us-central1 backup).

### PE-4: Access Control for Transmission

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google controls physical access to information system distribution and transmission lines within data center facilities, including fiber optic infrastructure and network cabling, with locked enclosures and continuous monitoring. Latent Archon has no physical transmission infrastructure.

### PE-5: Access Control for Output Devices

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. No physical output devices (printers, monitors, displays) exist within the Latent Archon authorization boundary. All system output is digital, delivered via HTTPS API responses to authenticated clients. GCP controls physical output devices in data center facilities per their FedRAMP High authorization.

### PE-9: Emergency Power — Emergency Shutoff

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google data centers provide emergency power shutoff capability for information system components in case of emergency. Latent Archon does not operate physical power infrastructure.

### PE-10: Emergency Shutoff

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google provides the capability to shut off power to information systems or individual system components in emergency situations. All power management for Latent Archon infrastructure is handled by GCP data center operations.

### PE-11: Emergency Power

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google data centers provide uninterruptible power supply (UPS) systems to facilitate transition to long-term alternate power in the event of a primary power source loss, ensuring continuous operation of Latent Archon services.

### PE-11(1): Alternate Power Supply — Long-Term

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google data centers maintain long-term alternate power supplies (diesel generators) that are self-contained, not reliant on external power generation, and capable of sustaining operations during extended power outages.

### PE-12: Emergency Lighting

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google data centers employ and maintain automatic emergency lighting systems that activate in the event of a power outage or disruption, covering emergency exits and evacuation routes.

### PE-13(1): Detection Systems — Automatic Activation and Notification

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google data centers employ fire detection and suppression systems that activate automatically and notify the organization and emergency responders in case of fire.

### PE-14(2): Monitoring with Alarms/Notifications

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google monitors temperature and humidity in data center facilities with automated environmental controls and provides alarms and notifications when conditions exceed defined operational thresholds.

### PE-15(1): Automation Support

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. Google employs automated mechanisms to detect the presence of water in data center facilities near information system components and alerts personnel for immediate response.

### PE-17: Alternate Work Site

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Latent Archon personnel operate remotely with security controls that apply regardless of work location. Device security requirements are enforced per physical security policy (POL-PE-001): FileVault/BitLocker full-disk encryption, 5-minute screen lock timeout, and automatic OS security updates. VPN is not required — all system access occurs via HTTPS with mandatory MFA (magic link + TOTP). Per-org IP allowlisting via Cloud Armor is available for customer agencies requiring network-based location restrictions. The same authentication, authorization, and audit logging controls apply at alternate work sites as at the primary work location.

### PE-18: Location of System Components

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Inherited from GCP FedRAMP High. All Latent Archon system components are deployed in United States GCP regions (us-east4 primary, us-central1 backup) per data sovereignty requirements. GCP data center facility locations are managed by Google with physical security controls per their FedRAMP High authorization. Region selection is enforced via Terraform configuration.

---

## PL — Planning (High Enhancements)

### PL-2(3): Plan/Coordinate with Other Organizational Entities

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The System Security Plan is coordinated across organizational boundaries. Customer agencies receive the shared responsibility model and customer secure configuration guide (`compliance/customer-secure-configuration-guide.md`). Inherited controls are mapped to GCP's FedRAMP High P-ATO. Internal coordination follows the separation of duties matrix (`compliance/separation-of-duties-matrix.md`) defining roles for CEO, CTO, and ISSO. The ISSO (`compliance/isso-appointment-letter.md`) participates in change management review. Security planning artifacts are maintained in Drata with weekly sync and shared with relevant stakeholders.

---

## PS — Personnel Security (High Enhancements)

### PS-3(3): Information Requiring Special Protective Measures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Personnel with access to CUI undergo additional screening appropriate for the data sensitivity level per personnel security policy (POL-PS-001). Access to production infrastructure requires documented CEO/CTO approval. Break-glass database access is restricted to security admins and triggers a CRITICAL severity alert via Cloud Monitoring (`infra/gcp/modules/monitoring/main.tf`). All personnel must acknowledge Rules of Behavior (ROB-LA-001, `compliance/rules-of-behavior.md`) with version-gated re-acceptance required when the document is updated. Data classification policy defines handling requirements for CUI, Sensitive, Internal, and Public data categories.

### PS-4(2): Automated Actions on Personnel Termination

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: SCIM 2.0 integration (`backend/internal/sso/scim_handler.go`) provides automated account deprovisioning on personnel termination. A SCIM DELETE request from the customer IdP immediately disables the user account via Firebase `DisableUser()`, which invalidates all active sessions across devices. Org admin removal via the `RemoveMember` RPC is immediate and audit-logged. For account closures, an automated 90-day data purge (`internal/accountpurge/service.go`) removes all associated data. A 24-hour maximum deprovisioning SLA is documented in the access control policy (POL-AC-001). All termination actions are logged to the three-store audit pipeline.

### PS-5(1): Access Restrictions for Personnel Transfer

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Personnel role transfers are managed through RBAC with audit enforcement. Org admins update roles via the `UpdateMemberRole` RPC, which enforces the 4-role hierarchy (master_admin, admin, editor, viewer). SCIM-enabled organizations auto-sync role changes from IdP group mappings via `backend/internal/sso/scim_handler.go`. All role changes are audit-logged with before/after values in the audit pipeline (`backend/internal/audit/logger.go`). Real-time email notifications are sent to org master_admins on any role modification. Transfer restrictions are enforced within 24 hours, with SCIM-driven changes taking effect immediately.

---

## RA — Risk Assessment (High Enhancements)

### RA-5(4): Discoverable Information

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Discoverable information is assessed through: (1) Red team manual suite (MT-001 through MT-012) includes nmap service scanning, nikto web scanning, ffuf directory brute-forcing, and nuclei vulnerability scanning against deployed endpoints; (2) Cloud Armor blocks common information disclosure paths (`.env`, `pprof`, `metrics`, `swagger`, `graphql`); (3) Error responses return generic messages without system internals; (4) HTTP security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy) prevent information leakage.

### RA-5(5): Privileged Access

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Vulnerability scanning tools operate with privileged access to maximize detection coverage. Trivy scans container images with full filesystem access to detect OS and application-layer CVEs. govulncheck analyzes Go binaries with complete source code access to identify known vulnerabilities in dependencies. GoSec and Semgrep perform static analysis with access to the full source repository. Red team exercises (`compliance/red-team-deployment-guide.md`) operate as white-box testing with knowledge of system architecture across 99 attack scenarios mapped to MITRE ATT&CK. All scanning credentials use WIF with least-privilege IAM roles scoped to the specific scanning function — no persistent credentials are stored.

---

## SA — System and Services Acquisition (High Enhancements)

### SA-4(10): Use of Approved PIV Products

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: Latent Archon supports integration with agency PIV/CAC authentication through SAML SSO federation. Firebase Identity Platform supports custom SAML configurations per tenant, enabling delegation of primary authentication to customer IdPs that enforce PIV card validation. The system does not directly process PIV credentials — authentication is federated to the agency's IdP, which is responsible for PIV/CAC card validation and certificate chain verification. This approach allows agencies to enforce their existing PIV authentication requirements without modification to the Latent Archon authentication flow.

### SA-10(1): Software/Firmware Integrity Verification

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Software integrity is cryptographically verified at every stage of the delivery pipeline. Go module checksums are verified against the Go module mirror via `go.sum`. NPM integrity hashes are validated via `package-lock.json`. Container images are signed via Cosign keyless signing (Sigstore OIDC) in Cloud Build (`compliance/cloudbuild.yaml`) — every built image receives a cryptographic attestation. Binary Authorization on Cloud Run rejects any unsigned or unattested images at deploy time. Artifact Registry enforces immutable tags preventing tag overwrites. All production deploys use digest-pinned image references (`image@sha256:...`) ensuring exact image match. CI builder images are pinned by version substitution variable, not `:latest` tags.

### SA-11(2): Threat Modeling/Vulnerability Analysis

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Systematic threat modeling and vulnerability analysis is performed through multiple complementary methods. The red team program executes 99 attack scenarios across 6 suites with MITRE ATT&CK technique mapping, run monthly. OWASP Top 10 coverage is included in the webapp attack suite. Architecture-level threat analysis is documented in the security whitepaper (`compliance/security-whitepaper.md`, 770+ lines). Attack surface analysis is performed in each red team report. GoSec and Semgrep run daily in CI for automated static vulnerability analysis. Results are uploaded to Drata evidence library for continuous monitoring.

### SA-17: Developer Security and Privacy Architecture and Design

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Developer security architecture and design principles are formally documented across multiple artifacts. The Security Architecture Whitepaper (`compliance/security-whitepaper.md`) provides a comprehensive 770+ line technical overview of the security architecture. Pool isolation design (`backend/docs/POOL_ISOLATION.md`) documents the two-project Firebase separation preventing cross-pool identity bridging. Tenant configuration (`backend/docs/TENANT_CONFIGURATION.md`) documents multi-tenant isolation patterns. The SSP includes architecture diagrams and data flow descriptions. Infrastructure modules include Terraform documentation. The architecture follows defense-in-depth with 5-layer organization isolation (subdomain, JWT pool, RLS, service account, network).

### SA-21: Developer Screening

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Developer screening is performed per personnel security policy (POL-PS-001). Background checks are conducted for all personnel with access to production systems or source code repositories. Security awareness training policy (POL-AT-001) defines training requirements tracked via the cybersecurity education tracker (`compliance/cybersecurity-education-tracker.md`). Rules of behavior acknowledgment (`compliance/rules-of-behavior.md`) is required before system access is granted. The ISSO appointment letter (`compliance/isso-appointment-letter.md`) verifies security suitability of security personnel. Access to production infrastructure requires CEO/CTO approval with documented justification per the separation of duties matrix (`compliance/separation-of-duties-matrix.md`).

---

## SC — System and Communications Protection (High Enhancements)

### SC-3: Security Function Isolation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security functions are isolated from non-security functions through: (1) **Service isolation**: Three Cloud Run services with distinct PostgreSQL roles — the auth interceptor (security function) runs in the same process but enforces checks before any business logic executes; (2) **Project isolation**: Three GCP projects with separate IAM boundaries prevent lateral movement; (3) **Database role isolation**: `archon_app_ro` (read-only), `archon_admin_rw`, `archon_ops_rw` — security-critical tables (audit_events, users, org_members) have restricted grants; (4) **Audit immutability**: The `audit_events` table is INSERT-only for non-admin roles — no application code can modify or delete audit records.

### SC-5(1): Restrict Ability to Attack Other Systems

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system is architecturally restricted from being used as a platform to attack other systems. VPC FQDN egress firewall enforces a deny-all default — only explicitly allowlisted Google API domains (e.g., `*.googleapis.com`) and Microsoft Graph endpoints are reachable from Cloud Run containers. No general outbound internet access is available from any container. Cloud Armor provides DDoS absorption at the network edge, preventing the platform from being used in reflection or amplification attacks. Rate limiting on API endpoints prevents abuse. Distroless containers with no shell or package manager prevent installation of attack tools.

### SC-7(18): Fail Secure

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: All boundary protection mechanisms fail secure (closed). Cloud Armor WAF defaults to `deny(403)` in production — if WAF policy evaluation fails, traffic is blocked rather than permitted. VPC FQDN egress firewall uses a default-deny rule — if egress rules fail to load, all outbound traffic is blocked. The auth interceptor (`backend/cmd/server/connect_interceptors.go`) is fail-closed — any exception during authentication or authorization processing results in request rejection. PostgreSQL RLS policies are fail-closed — missing session variables (org_id, workspace_id) cause queries to return zero rows rather than unscoped data.

### SC-24: Fail in Known State

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The system fails to a known secure state: (1) **RLS fail-closed**: If PostgreSQL session variables are not set, RLS policies return zero rows — no data leakage on auth failure; (2) **ClamAV fail-closed**: In production, document uploads are rejected if the ClamAV endpoint is unavailable — no unscanned files enter the system; (3) **Auth interceptor fail-closed**: Missing or invalid JWT → `Unauthenticated`; missing MFA → `Unauthenticated`; missing org membership → `PermissionDenied`; (4) **Distroless containers**: No shell or package manager — container compromise yields minimal attack surface; (5) **FQDN egress deny-all**: Default egress policy blocks all outbound — only explicitly allowlisted domains are reachable.

### SC-45: System Time Synchronization

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**: System time is synchronized via Google's internal NTP infrastructure across all components. Cloud Run instances synchronize time via Google's globally distributed NTP service. All application services use `time.Now().UTC()` for consistent UTC timestamps, avoiding timezone ambiguity. Cloud Logging adds independent ingestion timestamps for tamper-evident correlation. OpenTelemetry trace timestamps enable cross-service request correlation. PostgreSQL uses server-side `now()` for database timestamps, ensuring consistency with Cloud SQL's Google-managed time synchronization. Audit log entries (`backend/internal/audit/logger.go`) include synchronized timestamps across all three stores (Cloud SQL, BigQuery, GCS).

### SC-46: Cross-Domain Policy Enforcement

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Cross-domain access is controlled through multiple enforcement layers. Two-project Firebase Identity Platform separation (admin pool and app pool) prevents cross-pool identity bridging, as documented in `backend/docs/POOL_ISOLATION.md`. The auth interceptor (`backend/cmd/server/connect_interceptors.go`) enforces subdomain-to-organization validation via database lookup, preventing cross-org request routing. PostgreSQL RLS policies enforce workspace-scoped data access, preventing cross-workspace queries at the database layer. Vertex AI vector store token restrictions prevent cross-workspace semantic search results. CORS strict origin allowlist prevents cross-domain browser requests. These five layers collectively enforce domain separation across identity, routing, data, search, and browser contexts.

---

## SI — System and Information Integrity (High Enhancements)

### SI-4(12): Automated Organization-Generated Alerts

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Automated security alerts are generated across application and infrastructure layers. Real-time email notifications to org admins cover role changes, authentication failures, SCIM provisioning events, and member modifications. Cloud Monitoring alert policies (`infra/gcp/modules/monitoring/main.tf`) detect WAF blocks, 5xx error rate spikes (MQL-based), Cloud SQL authentication failures, rate-limit bans, Adaptive Protection events, and IAM privilege escalation (SetIamPolicy). Break-glass secret access triggers a CRITICAL severity alert. KMS key lifecycle events generate notifications. Dependabot vulnerability alerts are configured on all 6 classified repositories. All alert policies are defined in IaC and version-controlled.

### SI-4(14): Wireless Intrusion Detection

- **Responsibility**: Inherited (GCP)
- **Status**: Implemented

**Implementation**: Not applicable to the Latent Archon SaaS cloud deployment model. Latent Archon does not operate wireless networks, wireless access points, or wireless-enabled devices within its authorization boundary. All system access is via HTTPS over wired or internet connections with mandatory MFA. Wireless intrusion detection for GCP data center facilities is inherited from GCP's FedRAMP High authorization.

### SI-4(20): Privileged Users

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Privileged user actions are subject to enhanced monitoring. All master_admin operations are audit-logged via `backend/internal/audit/logger.go` with user_id, IP address, user_agent, session_id, trace_id, and action details. Role escalation events trigger real-time security email notifications to affected org admins. SCIM provisioning events for privileged accounts are logged with full detail. IAM privilege escalation alerts in Cloud Monitoring (`infra/gcp/modules/monitoring/main.tf`) detect SetIamPolicy changes at the infrastructure level. Break-glass database access triggers a CRITICAL severity alert and is restricted to security admin role holders only. All privileged actions flow to the three-store audit pipeline (Cloud SQL, BigQuery, GCS WORM).

### SI-6(3): Report Verification Results

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security function verification results are systematically reported to designated stakeholders. Red team reports (99 attack scenarios, 6 suites) are uploaded to the Drata evidence library monthly. CP-4 contingency test reports (`compliance/contingency-test/`) are uploaded to Drata monthly. Trivy scan results and SBOMs (CycloneDX + SPDX) are stored in CI/CD logs and Drata evidence. IaC drift detection results are posted as PR comments via `compliance/check-ssp-iac-drift/`. OSCAL SSP validation results (`compliance/oscal/`) are tracked in CI. Continuous monitoring status is reported via the Drata dashboard with weekly evidence sync across 13 evidence documents.

### SI-7(5): Automated Response to Integrity Violations

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Integrity violations trigger automated responses: (1) CI/CD pipeline fails and blocks deployment when `go.sum` checksum verification fails; (2) Trivy container scan findings above threshold block image push to Artifact Registry; (3) Gitleaks findings block PR merge; (4) Dependabot automatically creates remediation PRs for vulnerable dependencies; (5) Cloud Monitoring alerts fire on unexpected infrastructure drift (detected by weekly `terragrunt plan`).

### SI-7(14): Binary or Machine Executable Code

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Binary and machine executable code is strictly controlled throughout the build and deployment pipeline. Binary Authorization on Cloud Run enforces that only images with valid Cosign attestations can be deployed — unsigned images are rejected at deploy time. Container images are built exclusively in Cloud Build (trusted build environment) and never from local developer machines. Distroless base images contain no package manager, shell, or utilities that could install unauthorized binaries at runtime. CI builder images are pinned by version substitution variable (never `:latest` tags) per Atlas migration safety requirements. Go binaries are statically compiled with `CGO_ENABLED=0`, preventing dynamic library loading and ensuring the complete executable is verified at build time.
