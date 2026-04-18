# Latent Archon — Access Control Policy

> **Policy ID**: POL-AC-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: AC-1, AC-2, AC-3, AC-5, AC-6, AC-7, AC-11, AC-12, AC-14, AC-17

---

> **Organizational context**: Latent Archon is a founder-led, automation-first security organization. The CEO/ISSO directs access control while automation independently enforces IAM policy, detects drift, and maintains immutable audit trails. As the team scales, role-specific duties will transfer to dedicated personnel (POA-15, POA-16). See SOD-LA-001 for the automation-first security architecture.

## 1. Purpose

This policy establishes access control requirements for the Latent Archon platform, its infrastructure, and supporting systems. It ensures that access to information and system resources is granted based on the principle of least privilege, properly authorized, and continuously monitored.

---

## 2. Scope

This policy applies to:

- All Latent Archon employees, contractors, and partners with access to production systems
- All customer-facing platform access (end users, org admins)
- Cloud infrastructure (GCP), CI/CD pipelines, source code repositories
<!-- MULTI-CLOUD: Original also listed AWS and Azure. -->
- Third-party integrations and service accounts

---

## 3. Account Management

### 3.1 Account Types

| Account Type | Authorization | Provisioning | Deprovisioning |
|-------------|--------------|--------------|----------------|
| **Employee (Cloud IAM)** | CEO/CTO approval | Manual via Terraform | Same-day on termination |
| **CI/CD Service Account** | CEO / ISSO approval | Terraform (WIF, no keys) | Terraform destroy |
| **Customer Org Admin** | Customer authorization + Latent Archon provisioning | Identity Platform tenant creation | SCIM or manual |
| **Customer End User** | Org admin invite | Magic link or SSO/SCIM JIT | SCIM DELETE or org admin removal |
| **Database Role** | Infrastructure as code | IAM-based database authentication | Terraform |

### 3.2 Provisioning Requirements

- All user accounts require a verifiable email address
- Employee accounts require management approval before provisioning
- Customer accounts require org admin authorization (invite flow)
- No shared or generic accounts are permitted
- **Every user must belong to an organization** — the auth interceptor rejects orgless users on all non-AuthService RPCs
- **Every organization must have a unique, DNS-safe slug** — validated against RFC 1123 regex (`^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$`) and a reserved-slug blocklist at creation time
- Service accounts use Workload Identity Federation (WIF) — no static keys
- Cloud-native org policies enforce keyless auth at the organization/account level
- IAM policy members restricted to `latentarchon.com` domain (`iam.allowedPolicyMemberDomains`)
- Default service accounts denied automatic Editor role (`iam.automaticIamGrantsForDefaultServiceAccounts`)
- Essential contacts restricted to `@latentarchon.com` (`essentialcontacts.allowedContactDomains`)

### 3.3 Account Closure & Deprovisioning

- Employee accounts must be disabled within 4 hours of termination notification
- Customer user removal cascades: org membership removal atomically removes all workspace memberships
- SCIM DELETE immediately deprovisions federated users
- Identity provider admin SDK revokes all active sessions on deprovisioning
- **Self-service account closure**: Users may close their own account via the `CloseAccount` RPC; organization administrators may also close member accounts
- Account closure requires recent MFA verification (step-up authentication within 15 minutes)
- All authentication tokens are revoked immediately upon closure
- Data associated with closed accounts is permanently purged within 90 days via an automated daily scheduled job, except where subject to a forensic preservation hold
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
- **Corporate 2SV**: Google Workspace 2-Step Verification is enforced for all organizational users with no grace period, providing MFA on all corporate Google services (Gmail, Drive, Admin Console, GCP Console)

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
| OIDC | Service-to-service | Task queue and scheduled job callbacks |

### 4.4 Failed Authentication

- Identity Platform provides built-in brute-force protection
- Dual-layer IP-based rate limiting (pre-authentication): Cloudflare edge rate limits + Cloud Armor origin rate limits
- Per-user rate limiting (post-authentication) limits authenticated request volume
- Failed authentication attempts are audit-logged

---

## 5. Authorization Model

### 5.1 Role-Based Access Control (RBAC)

#### Organization Roles

| Role | Capabilities |
|------|-------------|
| `master_admin` | Full org access; implicit access to all workspaces; can promote other master_admins; can reset member MFA |
| `admin` | Org management; create workspaces (auto-added as workspace admin + auto-invited to app pool); invite/remove members |

#### Workspace Roles

| Role | Capabilities |
|------|-------------|
| `admin` | Full workspace management; invite/remove members; upload/delete documents |
| `editor` | Document upload and metadata editing |
| `viewer` | Read-only access to documents and conversation |

### 5.2 Enforcement Points

- **Org Membership Gate (interceptor-level)**: All non-AuthService RPCs require the user to belong to an organization. Users without org membership are rejected with `PermissionDenied` before reaching any handler. AuthService RPCs are exempt to allow invite acceptance.
- **Subdomain→Org DB Validation (interceptor-level)**: If the Host header contains an org slug subdomain (not a reserved infra subdomain), the slug is resolved against the `organizations` table via `GetOrgIDBySlug`. Unknown subdomains are rejected. Cross-org mismatches (user's org ≠ subdomain org) are rejected.
- Every RPC handler performs explicit authorization checks before business logic
- Organization operations require `IsOrgAdmin()` or `IsMasterAdmin()`
- Workspace operations require `CanUserAccessWorkspace()` (explicit membership OR master_admin)
- Document operations verify workspace access
- Conversation/search verifies workspace access for every workspace ID in the request

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
| `archon_app_ro` | App API | SELECT only (with INSERT for messages/searches) |
| `archon_admin_rw` | Admin API | Full CRUD |
| `archon_ops_rw` | Ops service | Processing-scoped (no org/workspace/member access) |

### 6.3 Vector Store Isolation

- Every stored embedding includes workspace_id and document_id token restrictions
- Search queries include workspace ID filters
- Cross-workspace leakage is prevented at the vector database level

### 6.4 Auth Pool Isolation

The admin app and app use **separate Firebase/Identity Platform projects** with independent UID namespaces. This provides blast-radius isolation — credential compromise in one pool cannot escalate to the other.

**Prohibited**: Cross-pool identity bridging (copying memberships between pools by email matching). This would create a lateral escalation path and defeat the purpose of pool separation.

**Required**: Workspace access across pools uses the explicit invite flow only:

1. Admin creates workspace → admin UID added to `workspace_members`
2. System auto-creates a pending invite for the creator's email (app pool)
3. Creator receives sign-in link to the app
4. Creator authenticates in the app → app UID
5. Creator accepts invite → app UID added to `workspace_members`

Each pool's membership is established through that pool's own authentication, with an auditable invite record. See `backend/docs/POOL_ISOLATION.md` for the full architecture decision record.

---

## 7. Infrastructure Access

### 7.1 Cloud IAM

- Terraform service identity uses least-privilege roles per cloud provider
- Employee access via IAM with org/account-level owner restricted to CEO
- No direct SSH access to any compute resources (serverless model)
- Database access via IAM authentication only (no passwords)

### 7.2 CI/CD Access

- Workload Identity Federation (WIF) for all GitHub Actions workflows
- OIDC providers locked to `latentarchon` GitHub organization
- No secrets stored in GitHub — all authentication is keyless
- Production deployments require manual approval (GitHub environment gate)

### 7.3 Source Code Access

- GitHub organization with SSO enforcement (when available)
- Branch protection on `main` (required reviews, CI checks)
- Dependabot automated dependency scanning

### 7.4 Google Workspace Administrative Controls

Google Workspace is hardened via Admin Console with the following enforced configurations:

| Setting | Configuration | NIST Control |
|---------|--------------|-------------|
| 2-Step Verification | Enforced for all users, no grace period | IA-2 |
| Google Drive external sharing | Disabled — no sharing outside latentarchon.com | AC-4, MP-5 |
| Drive receiving external files | Enabled (required for receiving RFPs/contracts) | — |
| Drive general access default | Private to the owner | AC-3 |
| Shared Drive creation | Blocked (admin-only) | AC-3 |
| Third-party OAuth apps | Blocked by default, allowlist only (18 Google services set to Restricted) | CM-7, CM-11 |
| Google Cloud session control | 24-hour RAPT reauthentication | AC-12 |
| Endpoint Verification | Active on all personnel devices | CM-8 |
| Context-Aware Access | Blocks devices without disk encryption, current OS, or screen lock | AC-19 |

**DLP download blocking**: Google Workspace DLP rules prevent download, print, and copy of files from Google Drive, enforcing browser-only access to corporate documents. Combined with VPC Service Controls that keep CUI within the cloud boundary, this eliminates corporate data from personnel devices entirely.

Workspace security settings are audited monthly via `org/scripts/audit-workspace-security.sh`, which checks 2SV enrollment, service account keys, admin security changes, OAuth app grants, and external Drive sharing events. Settings that lack API coverage are verified manually in the Admin Console.

---

## 8. Network-Level Access Controls

### 8.1 Per-Organization IP Allowlisting

Organization administrators can configure CIDR-based IP allowlists enforced at the WAF layer:

- Self-service configuration via `UpdateOrganizationSettings` RPC with CIDR validation
- Allowlists synced to Cloud Armor WAF deny rules via cloud API
- Rules match org hostname + IP range for per-org enforcement at Cloud Armor origin layer
- Full reconciliation logic (add/update/remove) ensures WAF rules stay in sync with database state
- Sync failure is non-fatal — database is source of truth; logged and audit-recorded
- Periodic reconciliation cron catches WAF drift

### 8.2 Remote Access

- All platform access is remote by design (cloud-native SaaS)
- TLS 1.2+ enforced on all connections (Cloudflare edge + origin)
- HSTS with 2-year max-age and preload
- Dual-layer WAF: Cloudflare Edge WAF (managed rulesets, OWASP, custom firewall rules, threat score challenges, path probing protection, IP/ASN blocking) → Cloud Armor origin WAF (OWASP Core Rule Set, Cloudflare-only origin restriction)
- Cloudflare Zero Trust Access for admin endpoints (identity gate at edge)
- Tiered rate limiting at both Cloudflare edge and Cloud Armor origin
<!-- MULTI-CLOUD: Original also listed WAFv2 (AWS) and Front Door WAF (Azure). -->
- CORS strict origin allowlist (localhost only in development)

---

## 9. Monitoring and Review

| Activity | Frequency | Owner |
|----------|-----------|-------|
| IAM role review | Quarterly | CEO / ISSO |
| Customer admin access review | Quarterly | Operations |
| Service account audit | Quarterly | Engineering |
| RBAC configuration review | Semi-annually | Engineering + Security |
| Failed auth monitoring | Continuous (automated alerts) | Security |
| Privilege escalation monitoring | Continuous (audit log alerts) | Security |
| Security email notifications | Real-time (async) | Automated |
| Policy review and update | Annually | CEO / ISSO |

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
