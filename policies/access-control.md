# Latent Archon — Access Control Policy

> **Policy ID**: POL-AC-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Security Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: AC-1, AC-2, AC-3, AC-5, AC-6, AC-7, AC-11, AC-12, AC-14, AC-17

---

## 1. Purpose

This policy establishes access control requirements for the Latent Archon platform, its infrastructure, and supporting systems. It ensures that access to information and system resources is granted based on the principle of least privilege, properly authorized, and continuously monitored.

---

## 2. Scope

This policy applies to:

- All Latent Archon employees, contractors, and partners with access to production systems
- All customer-facing platform access (end users, org admins)
- GCP infrastructure, CI/CD pipelines, source code repositories
- Third-party integrations and service accounts

---

## 3. Account Management

### 3.1 Account Types

| Account Type | Authorization | Provisioning | Deprovisioning |
|-------------|--------------|--------------|----------------|
| **Employee (GCP IAM)** | CEO/CTO approval | Manual via Terraform | Same-day on termination |
| **CI/CD Service Account** | Engineering lead approval | Terraform (WIF, no keys) | Terraform destroy |
| **Customer Org Admin** | Customer authorization + Latent Archon provisioning | Identity Platform tenant creation | SCIM or manual |
| **Customer End User** | Org admin invite | Magic link or SSO/SCIM JIT | SCIM DELETE or org admin removal |
| **Database Role** | Infrastructure as code | Cloud SQL IAM authentication | Terraform |

### 3.2 Provisioning Requirements

- All user accounts require a verifiable email address
- Employee accounts require management approval before provisioning
- Customer accounts require org admin authorization (invite flow)
- No shared or generic accounts are permitted
- **Every user must belong to an organization** — the auth interceptor rejects orgless users on all non-AuthService RPCs
- **Every organization must have a unique, DNS-safe slug** — validated against RFC 1123 regex (`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`) and a reserved-slug blocklist at creation time
- Service accounts use Workload Identity Federation (WIF) — no static keys
- Org policy `iam.disableServiceAccountKeyCreation` enforces this at the GCP organization level

### 3.3 Account Closure & Deprovisioning

- Employee accounts must be disabled within 4 hours of termination notification
- Customer user removal cascades: org membership removal atomically removes all workspace memberships
- SCIM DELETE immediately deprovisions federated users
- Firebase Admin SDK `DisableUser()` revokes all active sessions on deprovisioning
- **Self-service account closure**: Users may close their own account via the `CloseAccount` RPC; organization administrators may also close member accounts
- Account closure requires recent MFA verification (step-up authentication within 15 minutes)
- All Firebase authentication tokens are revoked immediately upon closure
- Data associated with closed accounts is permanently purged within 90 days via an automated daily Cloud Scheduler job, except where subject to a forensic preservation hold
- Quarterly access reviews verify all active accounts remain authorized

### 3.4 Automated Account Management

- SCIM 2.0 server enables automated provisioning/deprovisioning synced with customer IdPs
- JIT (Just-In-Time) provisioning auto-creates accounts on first federated SSO login
- IdP group-to-role mapping automates role assignment from external directory groups
- All account lifecycle events are audit-logged

---

## 4. Authentication Requirements

### 4.1 Multi-Factor Authentication

- **Requirement**: TOTP-based MFA is mandatory for all users on all data endpoints
- **Enforcement**: Server-side via `sign_in_second_factor` JWT claim in the auth interceptor chain
- **Step-Up MFA**: High-risk operations (member management, document deletion) require recent MFA re-verification
- **Admin MFA Management**: Org admins can reset member MFA; self-reset is blocked; all resets are audit-logged

### 4.2 Session Management

| Parameter | Value | NIST Control |
|-----------|-------|-------------|
| Idle timeout | 30 minutes (configurable) | AC-11, AC-12 |
| Absolute timeout | 12 hours (configurable) | AC-12 |
| Enforcement | Server-side JWT claim comparison | — |

### 4.3 Authentication Methods

| Method | Use Case | Details |
|--------|----------|---------|
| Magic link (email) | Primary passwordless auth | Time-limited, single-use |
| Password + TOTP | Traditional auth | Identity Platform password policies |
| SAML SSO | Enterprise federation | Customer IdP (Okta, Azure AD, etc.) |
| Google OIDC | Service-to-service | Cloud Tasks, Cloud Scheduler callbacks |

### 4.4 Failed Authentication

- Identity Platform provides built-in brute-force protection
- IP-based rate limiting (pre-authentication) limits login attempt volume
- Per-user rate limiting (post-authentication) limits authenticated request volume
- Failed authentication attempts are audit-logged

---

## 5. Authorization Model

### 5.1 Role-Based Access Control (RBAC)

#### Organization Roles

| Role | Capabilities |
|------|-------------|
| `master_admin` | Full org access; implicit access to all workspaces; can promote other master_admins; can reset member MFA |
| `admin` | Org management; create workspaces (auto-added as workspace admin); invite/remove members |

#### Workspace Roles

| Role | Capabilities |
|------|-------------|
| `admin` | Full workspace management; invite/remove members; upload/delete documents |
| `editor` | Document upload and metadata editing |
| `viewer` | Read-only access to documents and chat |

### 5.2 Enforcement Points

- **Org Membership Gate (interceptor-level)**: All non-AuthService RPCs require the user to belong to an organization. Users without org membership are rejected with `PermissionDenied` before reaching any handler. AuthService RPCs are exempt to allow invite acceptance.
- **Subdomain→Org DB Validation (interceptor-level)**: If the Host header contains a tenant subdomain (not a reserved infra subdomain), the slug is resolved against the `organizations` table. Unknown subdomains are rejected. Cross-tenant mismatches (user's org ≠ subdomain org) are rejected.
- Every RPC handler performs explicit authorization checks before business logic
- Organization operations require `IsOrgAdmin()` or `IsMasterAdmin()`
- Workspace operations require `CanUserAccessWorkspace()` (explicit membership OR master_admin)
- Document operations verify workspace access
- Chat/search verifies workspace access for every workspace ID in the request

### 5.3 Privilege Escalation Prevention

- Only `master_admin` can promote others to `master_admin`
- Self-MFA-reset is explicitly blocked
- Last-admin guard prevents removing the last admin from any org or workspace
- Org member removal atomically cascades to all workspace memberships (transactional)

---

## 6. Data Isolation

### 6.1 Row-Level Security (RLS)

- All workspace-scoped tables enforce RLS with `FORCE ROW LEVEL SECURITY`
- Fail-closed: if no workspace IDs are set in the session, zero rows are returned
- Three database wrappers: workspace-scoped, admin bypass, unscoped (for non-workspace tables)
- Admin bypass is only used for system operations (cron, processing)

### 6.2 Database Roles

| Role | Service | Privilege Level |
|------|---------|----------------|
| `archon_chat_ro` | Chat API | SELECT only (with INSERT for messages/searches) |
| `archon_admin_rw` | Admin API | Full CRUD |
| `archon_ops_rw` | Ops service | Processing-scoped (no org/workspace/member access) |

### 6.3 Vector Store Isolation

- Every stored embedding includes workspace_id and document_id token restrictions
- Search queries include workspace ID filters
- Cross-workspace leakage is prevented at the vector database level

---

## 7. Infrastructure Access

### 7.1 GCP IAM

- Terraform service account uses 15 specific roles (least privilege)
- Employee access via IAM with org-level `roles/owner` restricted to CEO
- No direct SSH access to any compute resources (serverless model)
- Cloud SQL access via IAM authentication only (no passwords)

### 7.2 CI/CD Access

- Workload Identity Federation (WIF) for all GitHub Actions workflows
- OIDC providers locked to `latentarchon` GitHub organization
- No secrets stored in GitHub — all authentication is keyless
- Production deployments require manual approval (GitHub environment gate)

### 7.3 Source Code Access

- GitHub organization with SSO enforcement (when available)
- Branch protection on `main` (required reviews, CI checks)
- Dependabot automated dependency scanning

---

## 8. Network-Level Access Controls

### 8.1 Per-Tenant IP Allowlisting

Organization administrators can configure CIDR-based IP allowlists enforced at the WAF layer:

- Self-service configuration via `UpdateOrganizationSettings` RPC with CIDR validation
- Allowlists synced to Cloud Armor deny rules (priority 50–99) via GCP Compute API
- CEL expressions match tenant hostname + IP range for per-tenant enforcement
- Full reconciliation logic (add/update/remove) ensures Cloud Armor rules stay in sync with database state
- Sync failure is non-fatal — database is source of truth; logged and audit-recorded
- Periodic reconciliation cron catches Cloud Armor drift

### 8.2 Remote Access

- All platform access is remote by design (cloud-native SaaS)
- TLS 1.2+ enforced on all connections
- HSTS with 2-year max-age and preload
- Cloud Armor WAF with OWASP Core Rule Set
- CORS strict origin allowlist (localhost only in development)

---

## 9. Monitoring and Review

| Activity | Frequency | Owner |
|----------|-----------|-------|
| IAM role review | Quarterly | Security Lead |
| Customer admin access review | Quarterly | Operations |
| Service account audit | Quarterly | Engineering |
| RBAC configuration review | Semi-annually | Engineering + Security |
| Failed auth monitoring | Continuous (automated alerts) | Security |
| Privilege escalation monitoring | Continuous (audit log alerts) | Security |
| Security email notifications | Real-time (async) | Automated |
| Policy review and update | Annually | Security Lead |

### 9.1 Security Email Notifications

Real-time email notifications are sent to organization administrators on security-critical access control events:

| Event | Severity |
|-------|----------|
| `admin.role_escalation` | CRITICAL |
| `admin.bootstrap` | CRITICAL |
| `auth.login_failed` | HIGH |
| `member.remove` / `org.member_remove` | HIGH |
| `member.role_change` | MEDIUM |
| `scim.user_deactivate` | HIGH |
| `scim.user_create` / `scim.user_patch` | MEDIUM |

Notifications include deduplication (5-minute window per org+action), panic recovery, timeout protection, and a configurable fallback recipient.

---

## 10. Exceptions

Exceptions to this policy require written approval from the CEO/CTO and must include:

- Business justification
- Risk assessment
- Compensating controls
- Expiration date (maximum 90 days, renewable)

All exceptions are tracked in the compliance register.

---

## 11. Enforcement

Violations of this policy may result in:

- Immediate access revocation
- Disciplinary action up to termination
- Customer notification (if customer data is affected)
- Regulatory notification (if required by applicable law)

---

*Next review date: March 2027*
