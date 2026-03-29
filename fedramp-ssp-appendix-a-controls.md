# Appendix A: FedRAMP Security Control Implementations

> **Parent Document**: SSP-LA-001 (fedramp-ssp.md)  
> **Baseline**: NIST SP 800-53 Rev. 5 — Moderate Impact  
> **Date**: March 2026

This appendix documents the implementation narrative for each NIST 800-53 Rev. 5 Moderate baseline control. Each control includes: responsibility designation, implementation status, and a detailed narrative covering who, what, how, where, and when.

**Responsibility Key**: `CSP` = Latent Archon, `Inherited` = GCP FedRAMP High, `Shared` = Joint, `Customer` = Agency

---

## AC — Access Control

### AC-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon maintains a formal Access Control Policy (POL-AC-001, `policies/access-control.md`) that defines account management procedures, authentication requirements, authorization model, data isolation controls, and network-level access controls. The policy is reviewed annually by the Security Lead. The policy is approved by the CEO and disseminated to all personnel via the compliance document repository. Changes to the policy follow the Change Management Policy (POL-CM-001) requiring PR-based review and approval.

**Customer Responsibility**: Customer agencies are responsible for establishing complementary access control policies for their end users that align with agency-specific requirements.

### AC-2: Account Management

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**:

**(a)** Latent Archon defines four organization-level account types: `master_admin`, `admin`, `editor`, and `viewer`. Each account type has specific privileges documented in the RBAC matrix (see Section 7.3 of the SSP). Account types are enforced per-RPC in the Connect-RPC interceptor chain.

**(b)** Account managers are designated per customer organization. The `master_admin` role serves as the organization account manager with authority to create, modify, disable, and remove accounts. Latent Archon platform operations serve as the system-level account manager.

**(c)** Conditions for group and role membership are enforced by the RBAC model. Users must be explicitly invited to an organization (via invite token or SCIM provisioning) and explicitly granted workspace access. The auth interceptor enforces an **org membership gate** — users not belonging to any organization are rejected with `PermissionDenied` on all non-AuthService RPCs.

**(d)** Authorized users, group and role membership, and access authorizations are specified per-organization by the `master_admin` through the admin API (`InviteMember`, `UpdateMemberRole`, `RemoveMember` RPCs). For SCIM-enabled organizations, user lifecycle is managed automatically by the customer IdP.

**(e)** Account creation requires approval by an org admin (explicit invite) or automated provisioning via SCIM 2.0 from an authorized customer IdP. JIT (Just-In-Time) provisioning automatically creates accounts for federated users on first SSO login when an SSO configuration exists for the organization.

**(f)** Accounts are created via invite tokens (time-limited), SCIM 2.0 provisioning, or JIT provisioning. Accounts are modified via admin API RPCs. Accounts are disabled via Firebase Admin SDK `DisableUser()` or SCIM DELETE. Accounts are removed via `RemoveMember` RPC or self-service `CloseAccount` RPC (requires step-up MFA). Automated 90-day data purge runs via Cloud Scheduler for closed accounts.

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

**Implementation**: Accounts are disabled via: (1) Firebase Admin SDK `DisableUser()` called by org admins or platform operations, (2) SCIM DELETE from customer IdP, (3) self-service `CloseAccount` RPC requiring step-up MFA. Disabled accounts cannot authenticate — the Firebase Auth SDK rejects tokens from disabled accounts before they reach the application. Automated 90-day data purge via Cloud Scheduler removes personal data from closed accounts.

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
- **Project Isolation**: Two GCP projects with separate Identity Platform pools, Cloud Armor policies, and IAM configurations. Cross-pool identity bridging is explicitly prohibited (see `docs/POOL_ISOLATION.md`).
- **RBAC**: Only `master_admin` can promote others to `master_admin`. Self-MFA-reset is blocked. Last-admin guard prevents lockout.
- **CI/CD**: Production deploys require PR approval. Terraform plans are posted as PR comments for review before apply.

### AC-6: Least Privilege

- **Responsibility**: Shared
- **Status**: Implemented

**Implementation**:

- **GCP IAM**: The Terraform service account has exactly 15 specific roles (no `roles/editor` or `roles/owner`). Each Cloud Run service account has scoped permissions for only the APIs it needs. Workload Identity Federation eliminates static service account keys.
- **Database**: Four distinct PostgreSQL roles with minimum necessary grants, enforced via Atlas migration. Default `PUBLIC` privileges are revoked on all tables and sequences. `archon_app_ro` is read-only on reference data (SELECT + INSERT only for app persistence). `archon_ops_rw` is scoped to document processing tables (cannot touch org/member/invite data). Audit table is INSERT-only for non-admin roles. Schema migrations run under an `archon_migrator` role assumed via IAM auth (`SET ROLE`) — no static credentials are used in the normal migration path. A `postgres` superuser password exists in Secret Manager as a break-glass mechanism, accessible only to human security administrators and not mounted on any service or job by default.
- **Application**: RBAC enforces per-RPC authorization. Viewers cannot modify data. Editors cannot manage members. Only admins can manage workspaces.
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

**Implementation**: Privileged accounts include: (1) GCP Organization Owner — restricted to CEO, used for break-glass only; (2) Terraform service account — used only by CI/CD via WIF, 15 scoped roles; (3) `master_admin` application role — per-customer org admin. All privileged actions are audit-logged. No shared accounts are used.

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
- **Status**: Planned

**Implementation**: Currently, concurrent sessions are permitted. The per-org configurable session timeouts (idle + absolute) limit session duration. JWT-based auth means each session is independently validated on every request. _Future enhancement: configurable concurrent session limits per organization._

### AC-11: Device Lock

- **Responsibility**: Customer
- **Status**: N/A (Customer Responsibility)

**Implementation**: Device lock is the responsibility of the customer agency and end-user device management. Latent Archon's server-side session timeouts complement client-side device lock by requiring re-authentication after idle/absolute timeout expiration.

### AC-12: Session Termination

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The auth interceptor enforces two server-side session timeout checks on every request:

1. **Idle Timeout**: Calculated from JWT `auth_time` claim. Default: 30 minutes. Configurable per-org: 5-480 minutes.
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

**Implementation**: Cloud Logging provides auto-scaling log storage with no capacity limits. Application audit events are stored in the Cloud SQL `audit_events` table with no automatic expiration (indefinite retention). BigQuery audit dataset uses no table or partition expiration (CMEK-encrypted via US multi-region KMS keyring). GCS WORM audit buckets provide immutable long-term archival with locked retention policies (2 years in production). All storage uses cost-optimized tiering (STANDARD → NEARLINE → COLDLINE) with zero deletion.

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

**Implementation**: Audit records are retained indefinitely with a zero-deletion policy across all tiers: (1) Cloud Logging: 30 days in hot storage (configurable via log bucket retention); (2) Database `audit_events` table: indefinite retention (no automatic expiration); (3) BigQuery audit dataset: indefinite retention (no table or partition expiration, CMEK-encrypted); (4) GCS WORM audit buckets: 2-year locked retention in production (1-year unlocked in staging), with object versioning and 90-day soft-delete; (5) All GCS lifecycle rules tier storage class for cost optimization (NEARLINE at 90 days, COLDLINE at 365 days) but never delete objects. No automated process permanently deletes any audit data. Forensic preservation holds can additionally exempt specific data from any future policy changes.

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

**Implementation**: Internal security assessments are conducted through: (1) Red team program with 44 automated attacks mapped to MITRE ATT&CK across three suites (auth bypass, privilege escalation, data exfiltration); (2) Code review via PR-based workflow; (3) SAST pipeline (GoSec, Semgrep, Trivy, govulncheck). _Independent 3PAO assessment is pending engagement (see POA-4)._

### CA-2(1): Independent Assessors

- **Responsibility**: CSP
- **Status**: Planned

**Implementation**: _An independent Third-Party Assessment Organization (3PAO) will be engaged for the formal FedRAMP Moderate assessment. Target: Q3 2026._

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

**Implementation**: Latent Archon maintains an internal red team program (`redteam/` repository) with 44 automated attacks across 3 suites, mapped to MITRE ATT&CK tactics. The red team CLI is executed monthly against staging and can target production. Attacks cover: authentication bypass, privilege escalation, data exfiltration, and injection attacks. Results are uploaded to Drata as evidence.

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

**Implementation**: Change access is restricted through: (1) GitHub branch protection rules requiring PR review and passing CI; (2) Terraform service account with scoped IAM roles (15 specific roles, no `roles/editor`); (3) Workload Identity Federation for keyless CI/CD authentication; (4) No direct production console access — all changes via IaC pipeline; (5) Artifact Registry image push restricted to CI/CD service account.

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

**Implementation**: GCP provides automatic geographic redundancy for all storage services: Cloud SQL automated backups (cross-region), GCS multi-region storage option, and regional failover capabilities. All data resides within US regions per data sovereignty requirements.

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

- **Cloud SQL**: Automated daily backups with 30-day retention + point-in-time recovery (PITR) with < 5 minute RPO. Backups encrypted with CMEK (Cloud KMS).
- **Cloud Storage**: Object versioning enabled with 365-day retention. Soft delete with 30-day recovery window.
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

**Implementation**: Re-authentication is required: (1) After idle timeout expiration (default 30 minutes, per-org configurable); (2) After absolute session timeout (default 12 hours, per-org configurable); (3) For step-up operations (member management, document deletion, role changes) — requires MFA verification within last 5 minutes. Re-authentication forces full JWT refresh through Identity Platform.

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

**Implementation**: Incident response capabilities are tested through: (1) Red team program (44 automated attacks executed monthly) validates detection and response procedures; (2) Tabletop exercises are planned annually. _First full tabletop exercise planned for Q3 2026. See POA-6._

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

**Implementation**: GCP provides spare parts and maintenance support per their SLA. Application-level patches follow remediation timelines defined in the Vulnerability Scanning Strategy: Critical/High — 30 days, Medium — 90 days, Low — 180 days.

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

**Implementation**: All data is stored encrypted at rest using AES-256-GCM with Cloud KMS-managed keys (CMEK). Cloud Storage uses versioning with 365-day retention. Cloud SQL uses automated encrypted backups. All storage is within US regions per data sovereignty requirements.

### MP-5: Media Transport

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: All data in transit is encrypted with TLS 1.2+ (FIPS 140-2 validated modules). Internal GCP communication uses Google's encrypted inter-data-center network. Private Service Connect provides encrypted communication to Vertex AI without traversing the public internet.

### MP-6: Media Sanitization

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Physical media sanitization is inherited from GCP's FedRAMP High authorization (NIST 800-88 compliant). Application-level data sanitization includes: (1) Account closure triggers 90-day automated data purge via Cloud Scheduler; (2) Document deletion is permanent after soft-delete retention period; (3) Cryptographic erasure is supported by rotating CMEK keys to render encrypted data irrecoverable.

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

**Implementation**: Security planning is governed by the Information Security Policy (POL-IS-001, `policies/information-security.md`) which defines the overarching information security program, objectives, governance structure, and subordinate policy hierarchy. The policy references NIST SP 800-53 Moderate as the primary compliance framework.

### PL-2: System Security and Privacy Plans

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: This System Security Plan (SSP) serves as the formal security plan for the Latent Archon platform. It documents the authorization boundary, system architecture, data flows, security controls, and responsibility model. The SSP is reviewed and updated at least annually or when significant system changes occur.

### PL-4: Rules of Behavior

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Rules of behavior are documented in the Acceptable Use Policy (POL-AU-001, `policies/acceptable-use.md`). All personnel must acknowledge the rules of behavior before receiving system access. The policy covers: acceptable and prohibited system use, customer data handling, credential management, infrastructure use (IaC-only), personal device requirements, and incident reporting obligations. Violations result in tiered enforcement (warning → access suspension → termination).

### PL-4(1): Social Media and External Site/Application Usage Restrictions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Acceptable Use Policy prohibits sharing system credentials, architecture details, customer data references, or security vulnerability details on social media or external sites. CUI-related information must never be discussed in public forums.

### PL-10: Baseline Selection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The NIST SP 800-53 Rev. 5 Moderate baseline has been selected based on the FIPS 199 categorization (Moderate confidentiality, integrity, and availability). This baseline is appropriate for a system processing Controlled Unclassified Information (CUI) for government agencies.

### PL-11: Baseline Tailoring

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Moderate baseline has been tailored as follows: (1) Physical security controls (PE family) are inherited from GCP FedRAMP High authorization; (2) Maintenance controls (MA family) are largely inherited from GCP; (3) Controls are supplemented with CSP-specific implementations where the SaaS model provides additional protections beyond the baseline requirement (e.g., distroless containers for CM-7, fail-closed RLS for AC-3).

---

## PM — Program Management

### PM-1: Information Security Program Plan

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The Latent Archon information security program is governed by the Information Security Policy (POL-IS-001). The program plan encompasses: (1) security governance structure with defined roles (CEO as executive sponsor, Security Lead as program manager); (2) hierarchy of 13 subordinate security policies; (3) compliance framework alignment (NIST 800-53 Moderate, FedRAMP); (4) risk management integration; (5) continuous improvement through Drata automated monitoring.

### PM-2: Information Security Program Leadership Role

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The CEO (Andrew Hendel) serves as the executive sponsor of the information security program. The Security Lead serves as the Information System Security Officer (ISSO) responsible for day-to-day security program management, control implementation oversight, and compliance coordination. _Formal ISSO appointment letter to be issued upon agency sponsor engagement._

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

**Implementation**: The Latent Archon security architecture is integrated into the enterprise architecture through: (1) Two-project GCP architecture for blast-radius isolation; (2) Infrastructure-as-Code (Terraform/Terragrunt) ensuring security controls are embedded in infrastructure definitions; (3) Security Architecture Whitepaper documenting the complete security design; (4) Architecture decisions documented in ADRs and design docs (e.g., `POOL_ISOLATION.md`, `TENANT_CONFIGURATION.md`).

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

**Implementation**: Personnel positions are categorized by risk level: (1) **High Risk**: CEO, Security Lead, and anyone with production infrastructure access — requires comprehensive background check; (2) **Moderate Risk**: Engineers with code commit access — requires standard background check; (3) **Low Risk**: Non-technical roles without system access — requires basic identity verification. Risk designations are reviewed annually.

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

**Implementation**: All personnel must sign before receiving system access: (1) Acceptable Use Policy acknowledgment; (2) Non-Disclosure Agreement (NDA) covering customer data and system architecture; (3) Rules of Behavior acknowledgment. Access agreements are reviewed and re-signed annually. Agreements are retained in HR records.

### PS-7: External Personnel Security

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Latent Archon does not currently use external contractors for system development or operations. If contractors are engaged, they will be subject to the same background screening, access agreement, and least-privilege access requirements as employees. Third-party vendor security is governed by the Vendor Risk Management Policy (POL-VR-001).

### PS-8: Personnel Sanctions

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Personnel who violate security policies are subject to tiered sanctions as defined in the Acceptable Use Policy: (1) First offense/minor violation — written warning with mandatory remedial training; (2) Repeat offense/moderate violation — temporary access suspension with investigation; (3) Severe violation/willful misconduct — immediate access revocation and termination. Sanctions are documented and reviewed by the Security Lead.

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

**Implementation**: The system is categorized as FIPS 199 Moderate (Confidentiality: Moderate, Integrity: Moderate, Availability: Moderate). Categorization is based on the information types processed (see Section 6 of the SSP) and reviewed annually or upon significant system changes.

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
- **Monthly**: Red team attack suite execution (44 attacks, 3 suites)
- **Remediation SLAs**: Critical/High — 30 days, Medium — 90 days, Low — 180 days (per FedRAMP ConMon requirements)

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

**Implementation**: Developer configuration management includes: (1) Git version control with full commit history; (2) Branch protection rules requiring PR review and passing CI; (3) Signed commits encouraged; (4) Dependency pinning via `go.mod` + `go.sum`, `package-lock.json`; (5) Infrastructure changes tracked via Terraform state with drift detection.

### SA-11: Developer Testing and Evaluation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Developer security testing includes: (1) Unit tests for authentication, authorization, and data isolation logic; (2) GoSec static analysis for Go security vulnerabilities; (3) Semgrep pattern matching for common vulnerability patterns; (4) govulncheck for known Go dependency vulnerabilities; (5) Trivy container image scanning; (6) Gitleaks secret detection in commit history; (7) Red team attack suite (44 attacks) for integration-level security validation.

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

**Implementation**: Application and management functionality are separated through: (1) Two distinct GCP projects (app and admin) with separate Identity Platform pools; (2) Three Cloud Run services with distinct database roles (app_ro, admin_rw, ops_rw); (3) Admin operations require the `admin` or `master_admin` RBAC role, inaccessible from the app; (4) GCP management operations use separate IAM credentials from application service accounts.

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
- **Cross-project boundary**: Single narrow IAM grant (cloudsql.client) from app project to admin project database. No other cross-project access.
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

**Implementation**: Key management uses Cloud KMS: (1) CMEK keys for Cloud SQL and GCS encryption (AES-256, automatic rotation every 365 days); (2) Per-tenant CMEK anchor via `organizations.kms_key_name` column for future per-tenant encryption key isolation; (3) JWT signing keys managed by Google Identity Platform (automatic rotation); (4) SCIM tokens are random 32-byte values, SHA-256 hashed before storage; (5) No static service account keys — all service authentication uses Workload Identity Federation; (6) TLS certificate keys managed by Google Certificate Manager (automatic renewal); (7) Cloud KMS `app_secrets` key (AES-256-GCM, HSM-backed, 90-day rotation) encrypts Microsoft Graph OAuth refresh tokens before database storage. See Security Whitepaper: "Schema future-proofing".

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

**Implementation**: TLS certificates are Google-managed via Certificate Manager with automatic renewal and DNS-based domain validation. SAML IdP certificates are managed by customer agencies. DNSSEC uses Cloudflare-managed zone signing keys with DS records registered at the domain registrar.

### SC-18: Mobile Code

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: The React SPAs (app and admin) are the only mobile code executed on client devices. SPAs are served from Cloud Run containers and execute in the browser sandbox. Content Security Policy (CSP) headers restrict script sources. No Java applets, Flash, ActiveX, or other plugin-based mobile code is used.

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

**Implementation**: All data at rest is encrypted with Customer-Managed Encryption Keys (CMEK) backed by Cloud KMS HSMs (FIPS 140-2 Level 3): (1) Cloud SQL: AES-256 with CMEK (90-day auto-rotation); (2) Cloud Storage: AES-256-GCM with CMEK; (3) BigQuery audit datasets: AES-256 with CMEK via US multi-region KMS keyring (location must match dataset); (4) Vertex AI: CMEK; (5) Artifact Registry: CMEK; (6) Cloud Logging: CMEK via regional KMS keyring; (7) Terraform state: Encrypted in GCS with versioning and CMEK; (8) Microsoft Graph OAuth refresh tokens: AES-256-GCM with Cloud KMS `app_secrets` key (HSM-backed, 90-day rotation) — application-level encryption before database storage, providing defense-in-depth on top of Cloud SQL CMEK. Two KMS keyrings per project: regional (`us-east1`) for Cloud SQL/GCS/Vertex AI/AR/Logging, and multi-region (`us`) for BigQuery. All keys use HSM protection, 90-day rotation, and `prevent_destroy` lifecycle rules. Cryptographic erasure is supported by rotating CMEK keys.

### SC-28(1): Cryptographic Protection

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Cryptographic protection at rest uses AES-256 with Cloud KMS CMEK (FIPS 140-2 Level 3). Key hierarchy: Cloud KMS master key → data encryption keys (DEK) → per-object encryption. DEKs are automatically rotated. Key access is restricted to specific service accounts via IAM.

### SC-39: Process Isolation

- **Responsibility**: Inherited (GCP) + CSP
- **Status**: Implemented

**Implementation**: Process isolation operates at multiple levels: (1) **Container isolation**: Cloud Run uses gVisor sandboxing for container isolation (GCP); (2) **Service isolation**: Three separate Cloud Run services with distinct service accounts and database roles; (3) **Project isolation**: Two GCP projects with separate IAM boundaries; (4) **Data isolation**: PostgreSQL RLS provides row-level data isolation between organizations.

---

## SI — System and Information Integrity

### SI-1: Policy and Procedures

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: System integrity policies are documented across the Change Management Policy (POL-CM-001), Vulnerability Scanning Strategy (DOC-VS-001), and Security Architecture Whitepaper. These documents define vulnerability management, malware protection, software integrity verification, and monitoring requirements.

### SI-2: Flaw Remediation

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Flaw remediation follows defined SLAs: Critical/High CVSSv3 — 30 days, Medium — 90 days, Low — 180 days. Remediation sources include: Dependabot PRs (automatic), govulncheck findings, Trivy scan results, GoSec findings, red team discoveries, and customer/3PAO reports. Remediation is tracked in POA&M and Drata. Emergency patches for actively exploited vulnerabilities follow the expedited change process (deploy within 24 hours, post-hoc review).

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

**Implementation**: Automated alerts are generated for: (1) Cloud Armor WAF rule matches; (2) Cloud Monitoring metric thresholds (error rate > 5%, latency > 2s, CPU > 80%); (3) Audit events at WARN level (role escalation, cross-org attempts, auth failures); (4) Dependabot vulnerability discoveries; (5) CI/CD security scan failures. Alerts route to operations team via Cloud Monitoring notification channels.

### SI-5: Security Alerts, Advisories, and Directives

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security intelligence sources monitored: (1) CISA KEV (Known Exploited Vulnerabilities) catalog; (2) Go vulnerability database (govulncheck); (3) GitHub Advisory Database (Dependabot); (4) GCP security bulletins; (5) FedRAMP PMO directives. Critical advisories trigger immediate assessment and expedited remediation per the flaw remediation process.

### SI-6: Security and Privacy Function Verification

- **Responsibility**: CSP
- **Status**: Implemented

**Implementation**: Security function verification through: (1) Unit tests validating RBAC enforcement for each role level; (2) Integration tests validating RLS data isolation; (3) Red team suite (44 attacks) validating authentication bypass resistance, privilege escalation prevention, and data exfiltration prevention; (4) CI/CD pipeline verifying all security gates pass on every build.

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

**Implementation**: Information retention follows a zero-deletion policy for government compliance: (1) Customer documents: retained indefinitely with WORM retention policy (2-year locked in production, 1-year in staging), object versioning, and 90-day soft-delete recovery window; (2) Audit logs: indefinite retention in BigQuery (no table/partition expiration, CMEK-encrypted) + GCS WORM audit buckets (locked 2-year retention in production) + Cloud SQL `audit_events` table (no automatic expiration); (3) All GCS buckets: zero auto-delete lifecycle rules — old data tiers to NEARLINE (90 days) then COLDLINE (365 days) for cost optimization but is never deleted; (4) `force_destroy = false` on all buckets prevents accidental deletion via Terraform; (5) User PII: purged 90 days after account closure per privacy policy, with forensic preservation holds available for active investigations. No automated process permanently deletes any government record, audit trail, or document. Cryptographic erasure is available via CMEK key rotation for end-of-life data destruction when required by contract.

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

**Implementation**: Supply chain controls include: (1) `go.mod` + `go.sum` cryptographic pinning of all Go dependencies; (2) `package-lock.json` integrity verification for JavaScript dependencies; (3) Docker base images pinned by digest (distroless); (4) Terraform provider versions locked via `.terraform.lock.hcl`; (5) Dependabot automated dependency update PRs with CI validation before merge; (6) Gitleaks scanning for unauthorized credential exposure in supply chain.

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

**Total Controls Documented**: ~230+ controls across 20 families (AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR)

**Control Status Summary**:
- **Implemented**: ~215
- **Partially Implemented**: ~8 (CA-2(1), CP-4, IR-3, PM-10, PT-5, AC-10 + pending POA&M items)
- **Inherited (GCP)**: ~20+ (PE family, portions of MA, MP, CP, SC)
- **Customer Responsibility**: ~10 (AC-8, AC-11, AC-20, PT-6, PT-8, IA-2(12), IA-8(1))
