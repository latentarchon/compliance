package main

import (
	"fmt"
	"strings"
)

// ControlDef defines a single NIST 800-53 control for SSP generation.
type ControlDef struct {
	ID             string
	ImplStatus     string // implemented, partially-implemented, planned, inherited, not-applicable
	RoleID         string
	NarrativeFn    func(f *InfraFacts) string
	Baseline       string // "moderate", "high", "il5" — minimum baseline that requires this control
	EvidenceTier   string // "verified", "templated", "manual"
	ComponentUUIDs []string
	Parameters     []ParamValue
}

type ParamValue struct {
	ParamID string
	Values  []string
}

const (
	thisSystem   = "d4e5f6a7-b8c9-4d0e-8f2a-3b4c5d6e7f80"
	gcpPlatform  = "e5f6a7b8-c9d0-4e1f-8a3b-4c5d6e7f8091"
	appAPI       = "f6a7b8c9-d0e1-4f2a-8b4c-5d6e7f809102"
	adminAPI     = "a7b8c9d0-e1f2-4a3b-8c5d-6e7f80910213"
	opsService   = "b8c9d0e1-f2a3-4b4c-8d6e-7f8091021324"
	cloudSQL     = "c9d0e1f2-a3b4-4c5d-8e7f-809102132435"
	cloudStorage = "d0e1f2a3-b4c5-4d6e-8f80-910213243546"
	edgeWAF      = "a2b3c4d5-e6f7-4a8b-9c0d-1e2f3a4b5c6d"
	cloudArmor   = "e1f2a3b4-c5d6-4e7f-8091-021324354657"
	cloudKMS     = "f2a3b4c5-d6e7-4f80-9102-132435465768"
	idPlatform   = "a3b4c5d6-e7f8-4091-8213-243546576879"
	vertexAI     = "b4c5d6e7-f809-4102-9324-35465768798a"
	ciCD         = "c5d6e7f8-0910-4213-a435-4657687989ab"
	clamAV       = "d6e7f809-1021-4324-b546-57687989abbc"
)

// verifiedControlIDs lists controls whose narratives are derived from infrastructure scanning.
var verifiedControlIDs = map[string]bool{
	"ac-2": true, "ac-3": true, "ac-4": true, "ac-5": true,
	"ac-17": true, "ac-17.1": true,
	"au-4": true, "au-9": true, "au-9.4": true, "au-11": true,
	"cm-6": true,
	"cp-2": true, "cp-6": true, "cp-9": true,
	"ia-2": true, "ia-7": true,
	"mp-2": true, "mp-4": true,
	"sc-5": true, "sc-7": true, "sc-7.4": true, "sc-8.1": true,
	"sc-12": true, "sc-13": true, "sc-28": true, "sc-28.1": true,
	"si-3": true,
	// high
	"ac-4.4": true, "cp-2.3": true, "cp-6.1": true,
	// il5
	"sc-7.24": true, "sc-28.2": true, "ac-4.21": true, "sc-13.1": true,
}

// manualControlIDs lists controls requiring human attestation (personnel, training, privacy, physical).
var manualControlIDs = map[string]bool{
	"at-1": true, "at-2": true, "at-2.2": true, "at-3": true, "at-4": true,
	"pe-3": true,
	"pl-4": true, "pl-4.1": true,
	"pm-2": true,
	"ps-1": true, "ps-2": true, "ps-3": true, "ps-4": true,
	"ps-5": true, "ps-6": true, "ps-7": true, "ps-8": true,
	"pt-1": true, "pt-2": true, "pt-3": true, "pt-4": true,
	"pt-5": true, "pt-6": true, "pt-7": true, "pt-8": true,
}

func classifyTier(id string) string {
	if verifiedControlIDs[id] {
		return "verified"
	}
	if manualControlIDs[id] {
		return "manual"
	}
	return "templated"
}

func allControls() []ControlDef {
	all := append(append(append(append(append(append(append(append(append(append(append(append(append(append(append(append(append(append(append(append(
		acControls(),
		atControls()...),
		auControls()...),
		caControls()...),
		cmControls()...),
		cpControls()...),
		iaControls()...),
		irControls()...),
		maControls()...),
		mpControls()...),
		plControls()...),
		pmControls()...),
		psControls()...),
		ptControls()...),
		raControls()...),
		saControls()...),
		scControls()...),
		siControls()...),
		srControls()...),
		highOnlyControls()...),
		il5Controls()...)

	for i := range all {
		all[i].EvidenceTier = classifyTier(all[i].ID)
	}
	return all
}

func or(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "[not configured]"
}

func boolStr(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func acControls() []ControlDef {
	return []ControlDef{
		{ID: "ac-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a formal Access Control Policy (POL-AC-001, `policies/access-control.md`) that defines account management procedures, authentication requirements, authorization model, data isolation controls, and network-level access controls. The policy is reviewed annually by the Security Lead, approved by the CEO, and disseminated to all personnel via the compliance document repository. Changes follow the Change Management Policy (POL-CM-001) requiring PR-based review and approval."
			}},
		{ID: "ac-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("(a) Latent Archon defines four organization-level account types: `master_admin`, `admin`, `editor`, and `viewer`. Each account type has specific privileges enforced per-RPC in the Connect-RPC interceptor chain. Service accounts (e.g., noreply@latentarchon.com) are a distinct non-interactive type blocked from authentication.\n(b) Account managers are designated per customer organization. The `master_admin` role serves as the organization account manager.\n(c) Conditions for group and role membership are enforced by the RBAC model. Users must be explicitly invited to an organization (via invite token or SCIM provisioning) and granted workspace access. The auth interceptor enforces an org membership gate.\n(d) Authorized users and role membership are specified per-organization by the `master_admin` through the admin API (`InviteMember`, `UpdateMemberRole`, `RemoveMember` RPCs). For SCIM-enabled organizations, user lifecycle is managed automatically by the customer IdP.\n(e) Account creation requires approval by an org admin (explicit invite) or automated provisioning via SCIM 2.0 from an authorized customer IdP. JIT provisioning auto-creates accounts on first SSO login.\n(f) Accounts are created via invite tokens (time-limited), SCIM 2.0, or JIT provisioning. Accounts are disabled via Firebase Admin SDK `DisableUser()` or SCIM DELETE. Accounts are removed via `RemoveMember` RPC or self-service `CloseAccount` RPC (requires step-up MFA). Automated 90-day data purge runs via Cloud Scheduler.\n(g) System access is monitored through comprehensive audit logging (`internal/audit/logger.go`). All authentication events, role changes, and SCIM actions are recorded with user ID, IP, user agent, timestamp, and correlation ID.\n(h) Account managers (org `master_admin`) are notified of account changes via real-time security email notifications covering: role escalation, auth failures, member changes, SCIM events, and deletions.\n(i) Authorization requires: (1) valid Firebase Auth JWT, (2) MFA verification, (3) organization membership, (4) appropriate RBAC role, and (5) workspace membership for data access.\n(j) All accounts are reviewed by the org `master_admin` through the admin dashboard. Quarterly access reviews tracked via Drata.\n(k) Role transfers handled via admin API or SCIM group-to-role mapping.\n(l) Accounts deprovisioned within 24 hours via SCIM DELETE or manual removal. Self-service closure via `CloseAccount` RPC with step-up MFA. Row-level security on %s enforces data isolation post-deprovisioning.", or(f.CloudSQLDatabaseName, "archon"))
			}},
		{ID: "ac-2.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon provides a SCIM 2.0 server (`internal/sso/scim_handler.go`) conforming to RFC 7643/7644. The SCIM server supports automated user provisioning (create), deprovisioning (delete), attribute updates (replace/patch), and group management. Customer IdPs connect via SCIM bearer token authentication with SHA-256 hashed tokens. JIT provisioning auto-creates accounts on first federated login."
			}},
		{ID: "ac-2.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system does not support anonymous or temporary accounts. All invite tokens are time-limited and single-use. Emergency access to GCP infrastructure uses IAM Conditions with time-limited grants (maximum 4 hours) and requires CEO/CTO approval documented in the incident response log."
			}},
		{ID: "ac-2.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Inactive accounts are disabled after 90 days of no successful authentication. A Cloud Scheduler cron job queries the last login timestamp from Identity Platform. Disabled accounts are automatically removed after 90 additional days. Accounts flagged for removal are logged to the audit trail with reason 'inactivity'."
			}},
		{ID: "ac-2.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated audit logging captures all account lifecycle events: creation (invite, SCIM, JIT), modification (role change, attribute update), enabling, disabling (admin action, inactivity, SCIM DELETE), and removal (admin action, self-service close). Logs include actor, target, action, timestamp, IP, user agent, and correlation ID. Logs stored in Cloud Logging with CMEK encryption."
			}},
		{ID: "ac-2.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Inactive sessions are automatically terminated after 15 minutes of inactivity. The session timeout is enforced server-side via the auth interceptor. Users must re-authenticate (including MFA) to resume. Logout is available via the `SignOut` RPC which invalidates the Firebase refresh token."
			}},
		{ID: "ac-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform, cloudSQL},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("The system enforces approved authorizations for logical access using a layered model: (1) Firebase Auth JWT validation, (2) TOTP MFA verification, (3) Organization membership gate, (4) RBAC role check per-RPC (four roles: master_admin, admin, editor, viewer), (5) PostgreSQL Row-Level Security (RLS) on database %s enforcing workspace-scoped data isolation. All authorization decisions are logged. %s",
					or(f.CloudSQLDatabaseName, "archon"),
					boolStr(f.RLSEnabled, "RLS is confirmed active in the backend codebase.", ""))
			}},
		{ID: "ac-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Information flow is controlled at multiple layers: (1) Cloudflare Edge WAF with managed rulesets, OWASP CRS, threat score challenges, path probing protection, and IP/ASN blocking %s; (2) Cloud Armor origin WAF restricts traffic to Cloudflare IPs only %s; (3) VPC egress firewall is deny-all by default with FQDN allowlist for GCP APIs only; (4) Cloud Run services configured with ingress=%s restricting to internal + load-balancer traffic; (5) Cloud SQL has no public IP (public_ip=%v, enforced by org policy sql.restrictPublicIp); (6) Vertex AI accessed via Private Service Connect (PSC) within the VPC.",
					boolStr(f.CFFirewallRulesEnabled, "(active)", "(module exists)"),
					boolStr(f.CloudArmorCFRestriction, "(Cloudflare-only rule active)", ""),
					or(f.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"),
					f.CloudSQLPublicIP)
			}},
		{ID: "ac-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Separation of duties is enforced through: (1) Three-project GCP architecture (%s for admin, %s for ops/data, %s for app) with separate IAM policies; (2) RBAC with four distinct roles — viewer cannot modify, editor cannot manage users, admin cannot change org settings, master_admin has full org scope; (3) CI/CD pipeline uses Workload Identity Federation with per-project service accounts — no single identity spans all projects; (4) KMS keys in dedicated project %s with separate IAM grants.",
					or(f.AdminProjectID), or(f.OpsProjectID), or(f.AppProjectID), or(f.KMSProjectID))
			}},
		{ID: "ac-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system employs the principle of least privilege: (1) Application RBAC restricts each role to minimum necessary functions; (2) GCP IAM uses custom roles scoped to specific APIs per service account; (3) Cloud Build SA has least-privilege IAM per project; (4) Cloud Run services run as dedicated service accounts with only required API permissions; (5) Users are assigned the `viewer` role by default and must be explicitly elevated."
			}},
		{ID: "ac-6.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privileged access to security functions is restricted: (1) `master_admin` role required for SSO/SCIM configuration, IP allowlist management, and security settings; (2) GCP IAM Conditions restrict production access to break-glass scenarios with time-limited grants (max 4 hours); (3) Terraform/Terragrunt changes require PR approval before apply; (4) Cloud Build deployment SA permissions are scoped per project."
			}},
		{ID: "ac-6.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Non-privileged accounts are used for all non-security functions. Engineers use personal accounts for development and non-privileged access. Privileged operations (infrastructure changes, production access) require separate authorization via PR approval (IaC changes) or break-glass process (emergency access). No engineer has standing privileged access to production."
			}},
		{ID: "ac-6.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privileged accounts are restricted to authorized personnel: (1) GCP organization-level roles limited to CEO/CTO; (2) Project Owner roles not assigned — Terraform SA uses custom roles; (3) `master_admin` application role assigned only to designated org administrators; (4) SCIM token management restricted to `master_admin` role."
			}},
		{ID: "ac-6.9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "All privileged function executions are logged: (1) Application audit log captures all admin mutations (role changes, member management, SSO config, IP allowlist changes) with actor, action, timestamp, IP, and correlation ID; (2) GCP Cloud Audit Logs capture all Admin Activity and Data Access events; (3) Cloudflare audit logs capture all configuration changes."
			}},
		{ID: "ac-6.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Non-privileged users cannot execute privileged functions. The Connect-RPC interceptor chain enforces RBAC checks before every RPC handler. Attempts to invoke admin-only RPCs with insufficient role are rejected with `PermissionDenied` and logged. GCP IAM prevents non-authorized identities from accessing infrastructure APIs."
			}},
		{ID: "ac-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			Parameters: []ParamValue{
				{ParamID: "ac-7_prm_1", Values: []string{"5"}},
				{ParamID: "ac-7_prm_2", Values: []string{"15 minutes"}},
				{ParamID: "ac-7_prm_3", Values: []string{"30 minutes"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return "The system enforces a limit of 5 consecutive failed login attempts within a 15-minute window. After exceeding the threshold, the account is temporarily locked for 30 minutes. Firebase Identity Platform enforces this at the authentication layer. Additionally, Cloudflare rate limiting applies tiered limits to login endpoints (10 requests/10s per IP) to prevent credential stuffing. All failed authentication attempts are logged with IP, user agent, and timestamp."
			}},
		{ID: "ac-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system displays a system use notification banner before granting access. The login page includes a DoD/Federal notice and consent banner informing users that: (1) they are accessing a U.S. Government information system, (2) usage may be monitored and recorded, (3) unauthorized use is prohibited and subject to criminal and civil penalties. Users must acknowledge the banner before proceeding to authentication."
			}},
		{ID: "ac-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			Parameters: []ParamValue{
				{ParamID: "ac-10_prm_1", Values: []string{"3"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return "The system limits concurrent sessions to 3 per user. When a fourth session is initiated, the oldest session is invalidated. Session tracking uses Firebase Auth token management with server-side session validation. Concurrent session counts are enforced in the auth interceptor."
			}},
		{ID: "ac-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			Parameters: []ParamValue{
				{ParamID: "ac-11_prm_1", Values: []string{"15 minutes"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return "The system initiates a session lock after 15 minutes of inactivity. The session lock obscures all information on the display with a re-authentication prompt. Users must provide full credentials (including MFA) to re-establish the session. The timeout is enforced both client-side (React idle detection) and server-side (JWT expiration + refresh token validation)."
			}},
		{ID: "ac-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			Parameters: []ParamValue{
				{ParamID: "ac-12_prm_1", Values: []string{"15 minutes of inactivity"}},
				{ParamID: "ac-12_prm_2", Values: []string{"12 hours maximum session duration"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return "Sessions are automatically terminated after 15 minutes of inactivity (server-side enforcement) and after a maximum session duration of 12 hours regardless of activity. Users can manually terminate sessions via the `SignOut` RPC which invalidates the Firebase refresh token. Session termination is logged."
			}},
		{ID: "ac-14", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The only actions permitted without identification and authentication are: (1) viewing the marketing site (latentarchon.com); (2) viewing the login/consent banner page. All API endpoints require authentication. The health check endpoint (`/healthz`) returns only HTTP 200 with no sensitive data."
			}},
		{ID: "ac-17", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("All access to the system is remote access — there is no physical console access. Remote access is controlled through: (1) HTTPS/TLS 1.2+ for all user-facing connections via Cloudflare and Cloud Armor; (2) Cloudflare Zero Trust Access for admin endpoints (%s); (3) GCP IAP or IAM Conditions for infrastructure access; (4) GitHub with SSO for code repository access; (5) Workload Identity Federation for CI/CD (keyless).",
					or(f.AdminDomain))
			}},
		{ID: "ac-17.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Automated monitoring of remote access is provided by: (1) Cloudflare Zero Trust Access logs all admin access attempts with identity, IP, device posture, and decision; (2) GCP Cloud Audit Logs capture all API calls; (3) Application audit logs record all authenticated actions; (4) %s provides log export to SIEM.",
					boolStr(f.CFLogpushEnabled, "Cloudflare Logpush", "Cloudflare logging"))
			}},
		{ID: "ac-17.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "All remote access sessions are encrypted using TLS 1.2+ (FIPS 140-2 validated via BoringSSL). Cloudflare enforces minimum TLS 1.2. Cloud Run services only accept HTTPS. Internal service-to-service communication within the VPC uses mTLS via Cloud Run's built-in service mesh."
			}},
		{ID: "ac-20", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "External information systems connecting to Latent Archon are limited to: (1) Customer IdPs via SAML 2.0 SSO and SCIM 2.0 — connections require explicit configuration by org admin; (2) Customer browsers via HTTPS. No direct system-to-system API access is provided to external systems without explicit authorization. All external connections traverse the full WAF stack."
			}},
		{ID: "ac-21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Information sharing decisions are enforced by workspace-level data isolation. PostgreSQL RLS ensures users can only access documents in workspaces they are members of. Cross-workspace data sharing is not supported by design. Document access requires both workspace membership and appropriate RBAC role (editor or above for upload, viewer or above for read)."
			}},
		{ID: "ac-22", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system does not make any information publicly accessible. All content is behind authentication. The marketing site (latentarchon.com) contains only public marketing material, no system data. Content designated as publicly accessible is limited to API documentation and status page."
			}},
	}
}

func atControls() []ControlDef {
	return []ControlDef{
		{ID: "at-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Security Awareness and Training Policy (POL-AT-001) requiring annual security awareness training for all personnel and role-based training for privileged users. The policy is reviewed annually and updated as needed. Training completion is tracked via Drata."
			}},
		{ID: "at-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security awareness training is provided to all personnel within 30 days of onboarding and annually thereafter. Training covers: phishing, social engineering, insider threats, CUI handling, incident reporting, password security, and secure development practices. Monthly CP-4/IR-3/AT-2 exercises are conducted via automated Cloud Build cron."
			}},
		{ID: "at-2.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Insider threat awareness is included in security awareness training. Personnel are trained to recognize indicators of insider threats including: unauthorized data exfiltration, unusual access patterns, policy violations, and social engineering targeting internal personnel."
			}},
		{ID: "at-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Role-based security training is provided to personnel with assigned security roles: (1) Developers receive secure coding training (OWASP Top 10, NIST guidelines); (2) Operations personnel receive incident response and contingency plan training; (3) Security personnel receive NIST 800-53 control assessment training. Training occurs within 30 days of role assignment and annually."
			}},
		{ID: "at-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security training records are maintained in Drata. Records include: trainee name, training date, training type, completion status, and expiration date. Records are retained for the duration of employment plus 3 years."
			}},
	}
}

func auControls() []ControlDef {
	return []ControlDef{
		{ID: "au-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains an Audit and Accountability Policy (POL-AU-001) defining audit event generation, review, analysis, and retention requirements. The policy is reviewed annually and updated as needed."
			}},
		{ID: "au-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system generates audit records for: (a) authentication events (login success/failure, MFA, SSO, logout); (b) authorization decisions (RBAC checks, RLS enforcement); (c) account lifecycle (create, modify, disable, delete, role change); (d) data access (document upload, download, search, conversation); (e) admin actions (org settings, SSO config, IP allowlist, SCIM); (f) system events (deployment, configuration change, error); (g) security events (WAF blocks, rate limit triggers, threat score challenges)."
			}},
		{ID: "au-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Audit records contain: (1) event type and subtype; (2) timestamp (UTC, millisecond precision); (3) source (component, service, API); (4) outcome (success/failure); (5) user identity (user ID, email); (6) source IP address; (7) user agent; (8) correlation ID for request tracing; (9) affected resource (document ID, workspace ID, org ID); (10) action details (before/after for mutations)."
			}},
		{ID: "au-3.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Additional audit detail is generated for privileged actions including: full request/response metadata for admin mutations, before/after state for configuration changes, IAM policy diffs for GCP changes, and file hashes for document operations."
			}},
		{ID: "au-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, gcpPlatform, cloudKMS},
			Parameters: []ParamValue{
				{ParamID: "au-4_prm_1", Values: []string{"365 days"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				retention := "365"
				if f.AuditLogRetentionDays > 0 {
					retention = fmt.Sprintf("%d", f.AuditLogRetentionDays)
				}
				return fmt.Sprintf("Audit log storage capacity is provisioned at: (1) Cloud Logging with %s-day retention and CMEK encryption; (2) GCS audit log export bucket with %s for long-term retention; (3) Application audit logs stored in Cloud SQL with partition-based retention. Storage capacity is monitored via Cloud Monitoring alerts.",
					retention,
					boolStr(f.AuditLogWORM, "locked retention policy (WORM)", "versioning enabled"))
			}},
		{ID: "au-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system alerts designated personnel in the event of audit processing failures. Cloud Monitoring alerting policies are configured for: (1) log ingestion failures; (2) audit log export failures; (3) log sink errors; (4) storage capacity thresholds. Alerts are sent via email and PagerDuty."
			}},
		{ID: "au-5.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Additional warning is provided when allocated audit log storage volume reaches 80% of capacity. Cloud Monitoring alerting policies monitor GCS bucket size and Cloud Logging ingestion rates."
			}},
		{ID: "au-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Audit records are reviewed weekly by the Security Lead for: (1) unusual access patterns; (2) failed authentication spikes; (3) privilege escalation attempts; (4) unauthorized data access attempts; (5) configuration changes outside change windows. Automated analysis via Cloud Logging queries surfaces anomalies."
			}},
		{ID: "au-6.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated analysis of audit records is performed using: (1) Cloud Logging log-based metrics for authentication failures, authorization denials, and WAF blocks; (2) Cloudflare Security Analytics for edge-layer threat detection; (3) Custom Cloud Monitoring dashboards correlating application and infrastructure events."
			}},
		{ID: "au-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Audit reduction and report generation capability is provided by: (1) Cloud Logging advanced queries with filtering by severity, resource, user, time range, and custom fields; (2) Log Analytics for SQL-based log querying; (3) Cloudflare analytics dashboard; (4) Custom compliance reporting scripts in the compliance repository."
			}},
		{ID: "au-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Timestamps in audit records use UTC with millisecond precision, synchronized to Google's internal time service (TrueTime) which provides globally consistent, GPS/atomic-clock-backed timestamps. Cloud Run containers inherit GCP's NTP configuration. Application timestamps use `time.Now().UTC()` in Go."
			}},
		{ID: "au-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, gcpPlatform, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Audit information is protected from unauthorized access, modification, and deletion: (1) Cloud Logging logs are encrypted with CMEK (Cloud KMS in %s); (2) GCS audit export bucket uses %s; (3) IAM policies restrict log access to Security Lead and authorized personnel only; (4) No application code has permission to delete or modify audit logs; (5) Cloud Audit Logs for GCP admin activity cannot be disabled.",
					or(f.KMSProjectID),
					boolStr(f.AuditLogWORM, "locked retention policy (WORM) preventing deletion", "versioning preventing accidental deletion"))
			}},
		{ID: "au-9.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Audit logs are written to a separate GCP project (%s) from the application workloads, ensuring that compromise of the application tier does not provide access to modify audit records. The ops project service accounts do not have IAM permissions on the audit log sink or export bucket.",
					or(f.OpsProjectID))
			}},
		{ID: "au-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			Parameters: []ParamValue{
				{ParamID: "au-11_prm_1", Values: []string{"365 days"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				retention := "365"
				if f.AuditLogRetentionDays > 0 {
					retention = fmt.Sprintf("%d", f.AuditLogRetentionDays)
				}
				return fmt.Sprintf("Audit records are retained for a minimum of %s days in accordance with NIST 800-53 AU-11 and FedRAMP requirements. Cloud Logging retains logs for the configured retention period. GCS audit export provides long-term archival with lifecycle rules transitioning to coldline storage after 90 days.",
					retention)
			}},
		{ID: "au-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Audit record generation is provided at: (1) Application layer via `internal/audit/logger.go` for all business logic events; (2) GCP Cloud Audit Logs for all infrastructure API calls; (3) Cloudflare audit logs for edge configuration changes; (4) Cloud Build logs for CI/CD pipeline execution. Audit generation is enabled by default and cannot be disabled by non-privileged users."
			}},
	}
}

func caControls() []ControlDef {
	return []ControlDef{
		{ID: "ca-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Security Assessment and Authorization Policy (POL-CA-001) defining assessment procedures, authorization requirements, and continuous monitoring activities. The policy is reviewed annually."
			}},
		{ID: "ca-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security assessments are conducted annually and include: (1) automated NIST control verification (`cmd/verify-controls`); (2) IaC-to-SSP drift detection (`cmd/check-ssp-iac-drift`); (3) vulnerability scanning (Trivy, GoSec, Semgrep, govulncheck); (4) penetration testing; (5) 3PAO assessment for FedRAMP authorization."
			}},
		{ID: "ca-2.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Independent assessors (3PAO) conduct annual security assessments. Automated assessment tools run continuously: daily security scans via Cloud Build, weekly KSI evidence collection, monthly contingency/incident response exercises."
			}},
		{ID: "ca-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System interconnections are authorized and documented: (1) Customer IdP connections via SAML/SCIM require explicit admin configuration; (2) GCP service interconnections managed via Terragrunt IAM modules; (3) Cloudflare-to-origin connections secured via Cloud Armor Cloudflare-only restriction; (4) GitHub-to-GCP connections via Workload Identity Federation."
			}},
		{ID: "ca-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Plan of Action and Milestones (POA&M) is maintained and tracked via Drata. POA&M items are created from: security assessment findings, vulnerability scan results, audit findings, and continuous monitoring alerts. Items include: weakness description, severity, responsible party, milestone dates, and remediation status."
			}},
		{ID: "ca-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system is pursuing FedRAMP authorization via the 20x process. The authorizing official (AO) is identified in the SSP metadata. Authorization decisions are based on: SSP, security assessment report, POA&M, and continuous monitoring evidence."
			}},
		{ID: "ca-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Continuous monitoring includes: (1) daily automated security scans (GoSec, Semgrep, Trivy, govulncheck) via Cloud Build; (2) weekly KSI evidence collection; (3) monthly CP-4/IR-3/AT-2 exercises; (4) real-time Cloud Monitoring alerts for security events; (5) automated SSP-IaC drift detection; (6) weekly audit log review; (7) automated OSCAL SSP generation from IaC."
			}},
		{ID: "ca-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Penetration testing is conducted annually by qualified assessors and includes: (1) external network penetration testing; (2) web application testing (OWASP methodology); (3) API security testing; (4) social engineering testing. An internal red team capability (`redteam/`) provides continuous adversarial testing."
			}},
		{ID: "ca-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Internal system connections are documented and authorized: (1) Cloud Run to Cloud SQL via VPC peering (private IP only); (2) Cloud Run to Vertex AI via Private Service Connect; (3) Cloud Run to GCS via GCP internal networking; (4) Cloud Run to Cloud KMS via GCP internal networking; (5) Cloud Run to Cloud Tasks via GCP internal networking. All connections defined in Terragrunt IaC."
			}},
	}
}

func cmControls() []ControlDef {
	return []ControlDef{
		{ID: "cm-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Configuration Management Policy (POL-CM-001) defining baseline configuration, change control procedures, and configuration monitoring requirements. All infrastructure is managed as code via Terragrunt."
			}},
		{ID: "cm-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Baseline configurations are established and documented in Terragrunt IaC (`infra/`) with full Git version history. The current baseline includes: (1) GCP project configurations; (2) Network architecture (VPC, firewall rules, Cloud Armor); (3) Compute configurations (Cloud Run); (4) Data tier (Cloud SQL, GCS, Vertex AI); (5) Security services (KMS, Identity Platform, ClamAV); (6) Edge services (Cloudflare WAF, DNS, Access)."
			}},
		{ID: "cm-2.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Baseline configurations are reviewed and updated: (1) with every Terragrunt apply (Git-tracked change history); (2) when system components are installed or upgraded (module version updates); (3) as part of annual security assessment. Terragrunt plan/apply workflow ensures all changes are reviewed before deployment."
			}},
		{ID: "cm-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return "Configuration changes are controlled through: (1) Git-based PR workflow requiring review and approval; (2) Terragrunt plan output reviewed before apply; (3) FedRAMP SCN classification on all PRs (GitHub Actions); (4) CI/CD pipeline validation (lint, test, security scan) before merge; (5) Cloud Build deployment with container signing (Binary Authorization on ops project)."
			}},
		{ID: "cm-3.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Changes are tested before implementation: (1) Terragrunt plan shows exact diff before apply; (2) PR CI runs format check, validation, and plan; (3) Backend PR CI runs tests, vet, vuln check, and migration validation; (4) Frontend PR CI runs typecheck and audit; (5) Staging deployment precedes production."
			}},
		{ID: "cm-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security impact analysis is conducted for all changes via: (1) FedRAMP SCN (Significant Change Notification) classifier on PRs that automatically labels changes by impact level; (2) Terragrunt plan review for infrastructure changes; (3) Security-focused code review for application changes."
			}},
		{ID: "cm-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Access restrictions for configuration changes: (1) Git repository requires PR approval before merge; (2) Terragrunt apply restricted to authorized CI/CD pipelines and designated engineers; (3) GCP IAM restricts infrastructure API access; (4) Cloudflare API access restricted to authorized accounts; (5) No direct cloud CLI mutations — all changes via IaC."
			}},
		{ID: "cm-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Configuration settings follow security hardening guidelines: (1) Cloud SQL: no public IP, SSL required, automated backups, %s availability; (2) Cloud Run: ingress restricted to %s, min/max scale %d/%d; (3) VPC: egress deny-all with FQDN allowlist; (4) KMS: %d-day rotation, %s algorithm; (5) GCS: versioning, CMEK, soft-delete; (6) All settings defined in Terragrunt and validated by drift detection.",
					or(f.CloudSQLAvailability, "REGIONAL"),
					or(f.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"),
					f.CloudRunMinScale, f.CloudRunMaxScale,
					f.KMSRotationDays, or(f.KMSAlgorithm, "GOOGLE_SYMMETRIC_ENCRYPTION"))
			}},
		{ID: "cm-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The system restricts functionality to essential capabilities: (1) Cloud Run containers run minimal Go binaries with no shell access; (2) Only required GCP APIs are enabled (managed via Terragrunt `apis/terragrunt.hcl`); (3) Assured Workloads restricts allowed GCP services to IL5-approved set; (4) VPC egress firewall blocks all outbound except FQDN-allowlisted GCP APIs."
			}},
		{ID: "cm-7.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Periodic review of unnecessary functions is performed: (1) Terragrunt `apis/terragrunt.hcl` lists all enabled APIs — reviewed quarterly; (2) IAM policy auditing identifies unused permissions; (3) Cloud Run service configurations reviewed for unnecessary environment variables or mount paths."
			}},
		{ID: "cm-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System component inventory is maintained via: (1) Terragrunt IaC as the authoritative inventory of all infrastructure components; (2) Cloud Run service revisions tracked in Artifact Registry; (3) SBOM (Software Bill of Materials) generated daily via Cloud Build (CycloneDX + SPDX formats); (4) Go module dependencies tracked in go.mod/go.sum; (5) Frontend dependencies tracked in package-lock.json."
			}},
		{ID: "cm-8.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Component inventory is updated: (1) automatically on every deployment (new container image → new SBOM); (2) daily via scheduled SBOM generation; (3) on every `go mod tidy` or `npm install` that changes dependency files."
			}},
		{ID: "cm-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Configuration management plan defines: (1) IaC tool chain (Terraform + Terragrunt); (2) branching strategy (staging → production promotion); (3) PR review requirements; (4) CI/CD pipeline stages; (5) rollback procedures (redeploy previous Cloud Run revision). Plan documented in CLAUDE.md and infra/CLAUDE.md."
			}},
		{ID: "cm-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Software usage restrictions: (1) All dependencies are open-source with compatible licenses (checked via `go-licenses`); (2) No proprietary software installed on infrastructure; (3) GCP services are commercially licensed through the Google Cloud agreement; (4) Cloudflare services are commercially licensed."
			}},
		{ID: "cm-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "User-installed software is not applicable — the system is a SaaS platform. Users interact via web browser only and cannot install software on the system. Cloud Run containers are immutable — runtime modifications are not possible."
			}},
	}
}

func cpControls() []ControlDef {
	return []ControlDef{
		{ID: "cp-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Contingency Planning Policy (POL-CP-001) and Information System Contingency Plan (ISCP) defining recovery strategies, roles, and procedures. The policy and plan are reviewed annually and after significant system changes."
			}},
		{ID: "cp-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("The contingency plan addresses: (1) essential missions and business functions; (2) recovery objectives (RTO < 1 hour for Tier 1, < 4 hours for Tier 2); (3) recovery strategies per component (Cloud SQL PITR, Cloud Run redeploy, GCS version restore, Vertex AI index rebuild); (4) roles and responsibilities; (5) communication procedures. All infrastructure recoverable via Terragrunt from Git in region %s.",
					or(f.Region, "us-east4"))
			}},
		{ID: "cp-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Contingency plan training is provided: (1) within 30 days of role assignment; (2) annually thereafter; (3) via monthly automated exercises (CP-4 via Cloud Build cron). Training covers: backup restoration, Cloud Run rollback, incident communication, and Terragrunt disaster recovery."
			}},
		{ID: "cp-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Contingency plan testing is conducted monthly via automated Cloud Build exercises (`cloudbuild-monthly.yaml`). Tests include: (1) Cloud SQL backup restoration; (2) Cloud Run service redeploy from Artifact Registry; (3) GCS object recovery from versions; (4) Terragrunt plan validation for disaster recovery. Results uploaded to Drata."
			}},
		{ID: "cp-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Alternate storage is provided by: (1) Cloud SQL automated backups stored within the %s region; (2) GCS cross-region replication available for critical buckets; (3) Git repository (GitHub) serves as configuration backup with geographic redundancy; (4) Container images stored in Artifact Registry with multi-zone availability.",
					or(f.Region, "us-east4"))
			}},
		{ID: "cp-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Alternate processing is available via: (1) Cloud Run auto-scales across zones within the region; (2) Terragrunt configs can deploy to alternate US regions for disaster recovery; (3) Cloudflare provides edge caching and DDoS protection independent of origin region. Regional failover procedure documented in ISCP."
			}},
		{ID: "cp-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Telecommunications services for the system are provided by: (1) Google Cloud's global network (redundant fiber, peering); (2) Cloudflare's edge network (300+ cities, anycast routing); (3) Multiple ISP paths to GCP regions. No single telecommunications provider failure affects system availability."
			}},
		{ID: "cp-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudSQL, cloudStorage, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Backup strategy by component:\n- Cloud SQL (%s): Automated daily backups (14 retained) + point-in-time recovery (PITR) with 7-day transaction log retention. Backups encrypted with CMEK (Cloud KMS in %s). Availability type: %s.\n- Cloud Storage (%s): Object versioning enabled (all versions preserved indefinitely). Soft delete with 90-day recovery window. CMEK encryption.\n- Terraform State: Stored in GCS with versioning.\n- Vertex AI Indexes: Rebuilt from source documents via ops service.\n- Configuration: All configuration in Git with full version history.",
					or(f.CloudSQLDatabaseName, "archon"),
					or(f.KMSProjectID),
					or(f.CloudSQLAvailability, "REGIONAL"),
					or(f.GCSDocumentsBucket))
			}},
		{ID: "cp-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Recovery procedures documented for five failure scenarios: (1) Database failure → Cloud SQL PITR; (2) Cloud Run failure → redeploy from Artifact Registry; (3) GCS failure → restore from versioned objects; (4) Vector Search failure → rebuild from source documents; (5) Regional failure → redeploy to alternate US region via Terragrunt. Target RTOs: Tier 1 < 1 hour, Tier 2 < 4 hours."
			}},
	}
}

func iaControls() []ControlDef {
	return []ControlDef{
		{ID: "ia-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains an Identification and Authentication Policy (POL-IA-001) defining authenticator requirements, identity proofing, and credential management procedures. The policy is reviewed annually."
			}},
		{ID: "ia-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("All users are uniquely identified and authenticated via Firebase Identity Platform. Authentication methods: (1) Email + password with mandatory TOTP MFA; (2) SAML 2.0 SSO via customer IdP with MFA enforced at the IdP; (3) Magic link (passwordless) with TOTP MFA. User accounts are identified by a globally unique Firebase UID. %s",
					boolStr(f.CFAccessEnabled, "Admin endpoints additionally protected by Cloudflare Zero Trust Access.", ""))
			}},
		{ID: "ia-2.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Multi-factor authentication (MFA) is required for all privileged and non-privileged network access. TOTP-based MFA (RFC 6238) is enforced at the application layer via the auth interceptor. Users who have not enrolled in MFA are blocked from accessing any functionality. MFA enrollment is mandatory during first login."
			}},
		{ID: "ia-2.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "MFA is required for all non-privileged network access. The same TOTP MFA requirement applies to all user roles (viewer through master_admin). No exemptions are granted."
			}},
		{ID: "ia-2.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Replay-resistant authentication is implemented via: (1) TOTP codes are time-based (30-second window) with server-side used-code tracking to prevent replay; (2) Firebase Auth JWTs include `iat` (issued-at) and `exp` (expiry) claims; (3) SAML assertions include `NotOnOrAfter` conditions. All authentication tokens are transmitted over TLS."
			}},
		{ID: "ia-2.12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "PIV/CAC authentication is accepted via SAML federation. Customer agencies configure their IdP to perform certificate-based authentication (PIV/CAC) and federate to Latent Archon via SAML 2.0. The system accepts the IdP's authentication assertion without requiring direct certificate validation."
			}},
		{ID: "ia-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Device identification and authentication: (1) Cloudflare Zero Trust Access enforces device posture checks for admin access; (2) Service-to-service authentication within GCP uses Workload Identity (automatic mTLS); (3) CI/CD uses Workload Identity Federation with GitHub OIDC tokens — no long-lived credentials."
			}},
		{ID: "ia-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Identifier management: (1) User identifiers are globally unique Firebase UIDs (128-bit); (2) Organization IDs and workspace IDs are UUIDs generated server-side; (3) GCP service account identifiers follow naming convention `{service}@{project}.iam.gserviceaccount.com`; (4) Identifiers are never reused — deleted users' UIDs are retired."
			}},
		{ID: "ia-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Authenticator management: (1) Passwords hashed with scrypt (Firebase default, FIPS-compatible); (2) TOTP secrets encrypted at rest in Identity Platform; (3) SCIM bearer tokens hashed with SHA-256 before storage; (4) GCP service account keys not used — Workload Identity Federation provides keyless auth; (5) API tokens are never logged or exposed in responses."
			}},
		{ID: "ia-5.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			Parameters: []ParamValue{
				{ParamID: "ia-5.1_prm_1", Values: []string{"12"}},
				{ParamID: "ia-5.1_prm_2", Values: []string{"1 uppercase, 1 lowercase, 1 digit, 1 special"}},
				{ParamID: "ia-5.1_prm_3", Values: []string{"12"}},
				{ParamID: "ia-5.1_prm_4", Values: []string{"90 days"}},
				{ParamID: "ia-5.1_prm_5", Values: []string{"1 day"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return "Password-based authentication enforces: (1) minimum 12 characters; (2) at least one uppercase, one lowercase, one digit, one special character; (3) password history (last 12 passwords); (4) maximum age 90 days; (5) minimum age 1 day; (6) passwords checked against breached password database (Have I Been Pwned k-anonymity API). Firebase Identity Platform enforces these policies."
			}},
		{ID: "ia-5.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "PKI-based authentication is supported via SAML federation (customer IdP performs certificate validation for PIV/CAC). TLS certificates for the system are managed by: (1) Cloudflare for edge certificates (automatic renewal, CT logging); (2) Google-managed SSL certificates for Cloud Run/Load Balancer."
			}},
		{ID: "ia-5.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Authenticators are protected commensurate with the security category of the information: (1) TOTP secrets stored in Identity Platform with CMEK encryption; (2) SCIM tokens hashed (SHA-256) — plaintext never stored; (3) Firebase refresh tokens are opaque and revocable; (4) Session tokens transmitted only over TLS."
			}},
		{ID: "ia-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Authentication feedback is obscured: (1) Login errors return generic 'Invalid credentials' without specifying whether email or password was incorrect; (2) Password fields are masked in the UI; (3) TOTP codes are masked after entry; (4) Failed login attempts are logged server-side but error details are not returned to the client."
			}},
		{ID: "ia-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic module authentication uses FIPS 140-2 validated modules: (1) %s in the Go backend (BoringCrypto/BoringSSL); (2) GCP services use FIPS 140-2 Level 3 HSMs for KMS operations; (3) Cloudflare uses FIPS 140-2 validated TLS implementation.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto is enabled", "BoringCrypto should be enabled"))
			}},
		{ID: "ia-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Non-organizational users (agency end users) are identified and authenticated through: (1) Firebase Identity Platform with mandatory MFA; (2) SAML SSO federation with customer IdP; (3) SCIM 2.0 automated provisioning from customer IdP. All non-org users must belong to a customer organization."
			}},
		{ID: "ia-8.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "PIV credentials from other agencies are accepted via SAML federation. Customer agencies perform PIV/CAC authentication at their IdP and federate to Latent Archon via SAML 2.0 assertions."
			}},
		{ID: "ia-8.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "FICAM-approved third-party credentials are accepted via SAML 2.0 federation. The system supports any FICAM-approved credential provider that implements SAML 2.0."
			}},
		{ID: "ia-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Re-authentication is required for: (1) session timeout (15 minutes inactivity); (2) privilege escalation (step-up MFA for sensitive operations like account closure, SSO configuration changes); (3) maximum session duration (12 hours); (4) accessing admin endpoints protected by Cloudflare Zero Trust Access."
			}},
	}
}

func irControls() []ControlDef {
	return []ControlDef{
		{ID: "ir-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains an Incident Response Policy (POL-IR-001) and Incident Response Plan defining incident categories, severity levels, response procedures, escalation paths, and reporting requirements. The policy is reviewed annually."
			}},
		{ID: "ir-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Incident response training is provided: (1) within 30 days of role assignment; (2) annually thereafter; (3) via monthly automated exercises (IR-3 via Cloud Build cron). Training covers: incident detection, classification, containment, eradication, recovery, and post-incident activities."
			}},
		{ID: "ir-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Incident response exercises are conducted monthly via automated Cloud Build exercises (`cloudbuild-monthly.yaml`). Exercises include tabletop scenarios and simulated incident handling. Exercise results are documented and uploaded to Drata."
			}},
		{ID: "ir-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Incident handling includes: (1) preparation — monitoring dashboards, runbooks, communication templates; (2) detection — automated alerts via Cloud Monitoring, Cloudflare security events, audit log analysis; (3) analysis — log correlation, impact assessment; (4) containment — WAF rule updates, service isolation via Cloud Armor, account disabling; (5) eradication — root cause analysis, vulnerability remediation; (6) recovery — service restoration, verification; (7) post-incident — lessons learned, control updates."
			}},
		{ID: "ir-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Incidents are tracked from detection through resolution. Each incident is assigned a unique ID, severity level, and tracked with: timeline, responders, actions taken, evidence collected, resolution, and lessons learned. Incident records maintained in the incident log with minimum 3-year retention."
			}},
		{ID: "ir-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Incident reporting follows: (1) internal escalation within 1 hour of detection; (2) US-CERT notification within 1 hour for significant incidents per FedRAMP requirements; (3) customer notification within 24 hours; (4) FedRAMP PMO notification within 72 hours; (5) monthly incident summary in continuous monitoring deliverables."
			}},
		{ID: "ir-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Incident response assistance is provided via: (1) documented runbooks for common incident types; (2) automated incident detection and alerting; (3) log analysis tools (Cloud Logging queries, Cloudflare analytics); (4) communication channels (PagerDuty, email, Slack)."
			}},
		{ID: "ir-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The Incident Response Plan is reviewed annually and updated after: (1) significant incidents; (2) exercise findings; (3) organizational changes; (4) system architecture changes. The plan is distributed to all incident response personnel and available in the compliance repository."
			}},
	}
}

func maControls() []ControlDef {
	return []ControlDef{
		{ID: "ma-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a System Maintenance Policy (POL-MA-001) defining maintenance procedures for cloud-based systems. Physical maintenance is inherited from GCP. Logical maintenance is performed via CI/CD pipeline and Terragrunt IaC."
			}},
		{ID: "ma-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Controlled maintenance activities include: (1) dependency updates via PR-reviewed `go mod` and `npm` changes; (2) infrastructure updates via Terragrunt plan/apply; (3) security patching via automated vulnerability scans triggering PRs; (4) database maintenance via Cloud SQL automated maintenance windows (Sunday 04:00 UTC). All maintenance is logged and trackable via Git history."
			}},
		{ID: "ma-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance tools are controlled: (1) all maintenance performed via approved tools (Terragrunt, GitHub, Cloud Console read-only); (2) no direct SSH or console access to compute instances (Cloud Run is serverless); (3) database maintenance via Cloud SQL Admin API only; (4) maintenance tool access controlled via IAM."
			}},
		{ID: "ma-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "All maintenance is performed remotely — there is no physical access to infrastructure (cloud-native). Remote maintenance sessions are: (1) authenticated via GCP IAM; (2) encrypted via TLS/SSH; (3) logged via Cloud Audit Logs; (4) time-limited for break-glass access (max 4 hours)."
			}},
		{ID: "ma-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance personnel are authorized before access: (1) engineers require PR approval for IaC changes; (2) break-glass production access requires CEO/CTO approval with documented justification; (3) GCP support cases require explicit consent before Google personnel access any resources. Non-escorted maintenance is not applicable (no physical access)."
			}},
		{ID: "ma-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Timely maintenance is ensured by: (1) automated vulnerability scanning (daily) surfaces required patches; (2) dependency update PRs created within 7 days of CVE publication; (3) critical patches applied within 24 hours; (4) Cloud SQL maintenance windows ensure database patches applied automatically."
			}},
	}
}

func mpControls() []ControlDef {
	return []ControlDef{
		{ID: "mp-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Media Protection Policy (POL-MP-001). Physical media controls are inherited from GCP's FedRAMP High authorization. Digital media (data at rest) is protected via CMEK encryption."
			}},
		{ID: "mp-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Access to digital media is restricted: (1) Cloud SQL data encrypted with CMEK via Cloud KMS (%s); (2) GCS objects encrypted with CMEK; (3) IAM policies restrict access to authorized service accounts only; (4) No data is stored on removable media; (5) Laptop full-disk encryption required for all personnel.",
					or(f.KMSProjectID))
			}},
		{ID: "mp-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "CUI marking: (1) all data at rest is treated as CUI per the SSP security categorization; (2) GCS bucket names include environment identifier for classification; (3) OSCAL SSP metadata includes `marking: CUI`; (4) system use notification banner indicates CUI handling requirements."
			}},
		{ID: "mp-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Digital media storage is controlled: (1) all data stored within GCP %s region; (2) Assured Workloads %s enforces data residency; (3) CMEK encryption for all data at rest; (4) no data exported to removable media; (5) GCS versioning preserves all versions.",
					or(f.Region, "us-east4"),
					boolStr(f.AWSComplianceRegime != "", "("+f.AWSComplianceRegime+")", ""))
			}},
		{ID: "mp-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Media transport is controlled: (1) all data in transit encrypted with TLS 1.2+; (2) no physical media transport — all data movement is network-based; (3) data exports (if any) require admin authorization and are encrypted; (4) GCP handles physical media transport/disposal under their FedRAMP authorization."
			}},
		{ID: "mp-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Media sanitization is inherited from GCP's FedRAMP High authorization for physical media. Digital sanitization: (1) account closure triggers 90-day automated data purge; (2) document deletion removes from GCS and purges embeddings; (3) Cloud SQL row-level deletion with vacuum for space reclamation; (4) KMS key destruction after data retention period."
			}},
		{ID: "mp-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Media use restrictions: (1) no removable media can be connected to system components (serverless architecture); (2) data download restricted by RBAC role; (3) DLP scanning prevents sensitive data exfiltration; (4) no USB, CD/DVD, or other removable media interfaces exist on Cloud Run containers."
			}},
	}
}

func plControls() []ControlDef {
	return []ControlDef{
		{ID: "pl-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Security Planning Policy (POL-PL-001) and this System Security Plan (SSP). The SSP is auto-generated from infrastructure-as-code configurations and reviewed annually."
			}},
		{ID: "pl-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "This System Security Plan (SSP) is maintained in OSCAL format (`compliance/oscal/ssp.json`), auto-generated from Terragrunt IaC configurations by `cmd/generate-ssp`. The SSP describes: (1) authorization boundary; (2) system architecture; (3) security controls; (4) responsible roles. The SSP is consistent with the system architecture because it is derived from the same IaC source of truth."
			}},
		{ID: "pl-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Rules of behavior are established for all personnel: (1) acceptable use of system resources; (2) CUI handling requirements; (3) security incident reporting obligations; (4) consequences of non-compliance. All personnel acknowledge rules of behavior before being granted system access."
			}},
		{ID: "pl-4.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Rules of behavior include social media and networking restrictions: personnel are prohibited from posting CUI, system architecture details, security configurations, or vulnerability information on social media or public forums."
			}},
		{ID: "pl-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Baseline security configuration is established via Terragrunt IaC — all security-relevant settings are codified and version-controlled. Changes require PR review, CI validation, and plan approval before apply."
			}},
		{ID: "pl-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privacy plan integration: the system protects PII in accordance with NIST SP 800-122 and handles CUI per 32 CFR 2002. Privacy controls are implemented through: (1) data minimization (collect only necessary PII); (2) purpose limitation; (3) encryption at rest and in transit; (4) access controls (RBAC + RLS); (5) data retention and disposal policies."
			}},
	}
}

func pmControls() []ControlDef {
	return []ControlDef{
		{ID: "pm-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains an Information Security Program Plan documenting: (1) security program structure; (2) roles and responsibilities; (3) management commitment; (4) coordination among organizational entities; (5) compliance requirements. The plan is reviewed annually."
			}},
		{ID: "pm-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "The CEO serves as the Senior Information Security Officer (SISO) responsible for: (1) security program oversight; (2) risk management decisions; (3) authorization decisions; (4) resource allocation for security activities."
			}},
		{ID: "pm-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security and privacy resources are allocated through: (1) dedicated compliance infrastructure (compliance repo, automated tools); (2) engineering time for security controls; (3) third-party security assessment budget; (4) security tooling budget (Drata, scanning tools)."
			}},
		{ID: "pm-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "POA&M is maintained in Drata and updated continuously as vulnerabilities are discovered, assessed, and remediated. POA&M items include milestones and completion dates."
			}},
		{ID: "pm-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System inventory: Latent Archon maintains a single system boundary documented in this SSP. The system inventory is maintained in Terragrunt IaC (infrastructure components) and SBOM generation (software components)."
			}},
		{ID: "pm-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Risk management is measured through: (1) security scan results trending; (2) POA&M age and closure rates; (3) incident frequency and severity trending; (4) control assessment pass rates (via `cmd/verify-controls`); (5) time-to-remediate metrics."
			}},
		{ID: "pm-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Enterprise architecture is aligned with security requirements: (1) three-project GCP isolation; (2) defense-in-depth WAF (edge + origin); (3) zero-trust networking (deny-all egress, private IPs only); (4) CMEK encryption; (5) IaC for all infrastructure. Security is a foundational architectural principle, not an afterthought."
			}},
		{ID: "pm-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Critical infrastructure plan: the system supports federal agency document intelligence capabilities. Business continuity is maintained through: (1) multi-zone Cloud Run deployment; (2) automated backups and recovery; (3) Terragrunt-based disaster recovery to alternate regions."
			}},
		{ID: "pm-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Risk management strategy: (1) risk assessment conducted annually and on significant changes; (2) risks tracked in risk register; (3) risk acceptance documented by AO; (4) continuous monitoring for emerging risks."
			}},
		{ID: "pm-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security authorization process follows FedRAMP 20x methodology: (1) automated evidence collection; (2) machine-readable SSP (OSCAL); (3) automated control verification; (4) continuous monitoring deliverables; (5) annual reassessment."
			}},
		{ID: "pm-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Risk management process is defined and includes: risk identification (threat modeling, vulnerability scanning), risk analysis (likelihood × impact), risk response (mitigate, accept, transfer), and risk monitoring (continuous)."
			}},
		{ID: "pm-14", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Insider threat testing is conducted through: (1) monthly red team exercises (`redteam/`); (2) RBAC permission boundary testing; (3) RLS data isolation verification; (4) audit log completeness testing."
			}},
		{ID: "pm-15", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security contacts and groups are established: (1) security@latentarchon.com for vulnerability reports; (2) PagerDuty for on-call escalation; (3) incident response team distribution list; (4) FedRAMP PMO contact for authorization matters."
			}},
		{ID: "pm-16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Threat awareness program includes: (1) subscription to US-CERT advisories; (2) monitoring NIST NVD for relevant CVEs; (3) automated govulncheck for Go vulnerability detection; (4) Trivy container scanning for OS-level vulnerabilities; (5) threat intelligence from Cloudflare threat analytics."
			}},
	}
}

func psControls() []ControlDef {
	return []ControlDef{
		{ID: "ps-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Personnel Security Policy (POL-PS-001) defining screening requirements, access agreements, and termination procedures. The policy is reviewed annually."
			}},
		{ID: "ps-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Position risk designations are assigned based on the level of system access: (1) engineers with infrastructure access — high risk; (2) support personnel with limited access — moderate risk; (3) all positions are reviewed annually for appropriate risk designation."
			}},
		{ID: "ps-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Personnel screening includes background investigations appropriate to position risk level. Screening is completed before granting system access. Rescreening occurs every 5 years for high-risk positions."
			}},
		{ID: "ps-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Personnel termination procedures: (1) system access disabled within 4 hours of termination notification; (2) GCP IAM permissions revoked; (3) GitHub organization access removed; (4) Cloudflare access revoked; (5) exit interview conducted covering security obligations; (6) all company equipment collected."
			}},
		{ID: "ps-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Personnel transfer procedures: (1) access reviewed within 24 hours of transfer; (2) IAM permissions adjusted to new role requirements; (3) unnecessary access revoked; (4) transfer documented in personnel records."
			}},
		{ID: "ps-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Access agreements are signed by all personnel before system access is granted. Agreements cover: (1) acceptable use; (2) CUI handling obligations; (3) security incident reporting; (4) non-disclosure; (5) consequences of non-compliance. Agreements are reviewed and re-signed annually."
			}},
		{ID: "ps-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Third-party personnel security requirements: (1) all contractors subject to same screening requirements as employees; (2) third-party access limited to minimum necessary; (3) third-party access monitored and audited; (4) third-party access agreements required."
			}},
		{ID: "ps-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Personnel sanctions for non-compliance include: (1) verbal warning; (2) written warning; (3) access suspension; (4) termination. Sanctions are applied based on severity and frequency of the violation. All sanctions are documented."
			}},
	}
}

func ptControls() []ControlDef {
	return []ControlDef{
		{ID: "pt-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Privacy Policy that governs the collection, use, retention, and disclosure of PII. The policy is published on the company website and reviewed annually."
			}},
		{ID: "pt-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Authority to collect PII is established through: (1) customer service agreements; (2) terms of service; (3) privacy policy; (4) applicable federal regulations (32 CFR 2002 for CUI). Collection is limited to what is necessary for system functionality."
			}},
		{ID: "pt-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Purpose specification: PII is collected and processed solely for: (1) user authentication and account management; (2) audit logging; (3) customer support. PII is not used for marketing, profiling, or purposes beyond the stated scope."
			}},
		{ID: "pt-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Consent for PII processing is obtained through: (1) terms of service acceptance; (2) system use notification banner acknowledgment; (3) privacy policy acceptance. Users are informed of data processing purposes before providing PII."
			}},
		{ID: "pt-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privacy notice: users are provided with clear, accessible information about: (1) what PII is collected; (2) why it is collected; (3) how it is used; (4) with whom it may be shared; (5) how long it is retained; (6) how to exercise privacy rights."
			}},
		{ID: "pt-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System of records: PII is maintained in: (1) Firebase Identity Platform (auth data); (2) Cloud SQL (user profiles, org memberships); (3) audit logs (user actions). Each store has defined retention periods and access controls."
			}},
		{ID: "pt-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Data minimization: the system collects only the minimum PII necessary: (1) email address (authentication); (2) display name (UI); (3) IP address (security logging). No SSN, date of birth, or other unnecessary PII is collected."
			}},
		{ID: "pt-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Accuracy of PII: (1) users can update their display name and email via account settings; (2) SCIM synchronization keeps user attributes current with the authoritative IdP; (3) stale accounts are disabled after 90 days of inactivity."
			}},
	}
}

func raControls() []ControlDef {
	return []ControlDef{
		{ID: "ra-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Risk Assessment Policy (POL-RA-001) defining risk assessment methodology, frequency, and reporting requirements. Risk assessments are conducted annually and on significant system changes."
			}},
		{ID: "ra-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security categorization follows FIPS 199 and NIST SP 800-60: the system is categorized as Moderate impact for confidentiality, integrity, and availability. Information types include CUI documents, conversation data, user PII, and audit logs. Categorization documented in this SSP."
			}},
		{ID: "ra-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Risk assessments identify threats, vulnerabilities, and likelihood/impact of exploitation. Risk assessment results are documented in the risk register and inform security control selection and POA&M prioritization."
			}},
		{ID: "ra-3.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Supply chain risk assessment is conducted for all critical dependencies: (1) GCP services (covered by GCP's FedRAMP High authorization); (2) Go module dependencies (vulnerability scanning, license checking); (3) npm dependencies (audit, license checking); (4) container base images (Trivy scanning)."
			}},
		{ID: "ra-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Vulnerability scanning is automated and continuous: (1) daily GoSec + Semgrep + Trivy + govulncheck via Cloud Build scheduled job; (2) daily SBOM generation (CycloneDX + SPDX); (3) PR-time scanning (test, vet, vuln, gitleaks) via Cloud Build; (4) npm audit on frontend PRs; (5) container image scanning via Trivy."
			}},
		{ID: "ra-5.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Vulnerability scanning tools are updated: (1) Trivy database updates automatically on each scan; (2) govulncheck uses the Go vulnerability database (updated continuously); (3) Semgrep rules updated with each release; (4) GoSec rules updated with each release."
			}},
		{ID: "ra-5.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privileged access for vulnerability scanning: (1) Cloud Build SA has read access to source code and container images; (2) security scanning runs in isolated Cloud Build workers; (3) scan results are not exposed to non-privileged users."
			}},
		{ID: "ra-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Risk response: identified risks are responded to by: (1) mitigate — implement additional controls; (2) accept — document risk acceptance with AO approval; (3) transfer — leverage GCP's FedRAMP authorization for inherited controls; (4) avoid — eliminate the risk source."
			}},
		{ID: "ra-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Criticality analysis: system components are classified by criticality: (1) Tier 1 (critical) — authentication, database, encryption; (2) Tier 2 (important) — document processing, search, AI services; (3) Tier 3 (supporting) — monitoring, logging, admin UI. Recovery priorities follow tier classification."
			}},
	}
}

func saControls() []ControlDef {
	return []ControlDef{
		{ID: "sa-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a System and Services Acquisition Policy (POL-SA-001) defining secure development practices, acquisition requirements, and third-party service evaluation criteria."
			}},
		{ID: "sa-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security resources are allocated: (1) dedicated compliance tooling and automation; (2) engineering time for security controls; (3) budget for third-party assessments; (4) security scanning infrastructure (Cloud Build scheduled jobs)."
			}},
		{ID: "sa-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System development lifecycle: (1) planning — requirements include security controls; (2) development — secure coding standards (OWASP, Go security best practices); (3) testing — automated security scanning, peer review; (4) deployment — CI/CD with container signing; (5) operations — continuous monitoring; (6) disposal — data purge procedures."
			}},
		{ID: "sa-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Acquisition requirements include security specifications: (1) GCP services selected from FedRAMP High authorized services; (2) Cloudflare selected based on FedRAMP Moderate authorization; (3) open-source dependencies evaluated for security posture, maintenance status, and license compatibility."
			}},
		{ID: "sa-4.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Functional security properties are documented: (1) OSCAL SSP describes security functions of all components; (2) component security capabilities are verified via `cmd/verify-controls`; (3) design documentation includes security architecture diagrams."
			}},
		{ID: "sa-4.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Design and implementation information: (1) infrastructure defined in Terragrunt (full source available); (2) application source code in Go (auditable); (3) security-relevant design decisions documented in ADRs and CLAUDE.md files."
			}},
		{ID: "sa-4.9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Functions, ports, protocols, and services in use are documented in the SSP network architecture and data flow sections. Only HTTPS (443) is exposed externally. All internal communication uses GCP private networking."
			}},
		{ID: "sa-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System documentation includes: (1) architecture documentation (SSP, ADRs); (2) API documentation; (3) operational runbooks; (4) security configuration guides (Terragrunt modules); (5) user guides for admin and app interfaces."
			}},
		{ID: "sa-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security engineering principles: (1) defense in depth (dual WAF, RBAC + RLS, CMEK + TLS); (2) least privilege (per-service IAM, RBAC roles); (3) fail secure (ClamAV fail-closed, auth interceptor deny-by-default); (4) separation of duties (three-project architecture); (5) zero trust (private IPs, CF Access, mTLS)."
			}},
		{ID: "sa-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "External system services: (1) GCP — FedRAMP High authorized, IL5 available; (2) Cloudflare — FedRAMP Moderate authorized; (3) GitHub — used for source control and CI/CD, no CUI stored; (4) Drata — used for compliance tracking, no CUI stored. All external services evaluated for security posture before adoption."
			}},
		{ID: "sa-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Configuration management in development: (1) all code in Git with full history; (2) PR-based workflow with required reviews; (3) branch protection rules; (4) CI/CD pipeline validates all changes; (5) infrastructure changes require Terragrunt plan review."
			}},
		{ID: "sa-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Developer security testing: (1) SAST via GoSec and Semgrep (daily + PR-time); (2) dependency scanning via govulncheck and npm audit; (3) container scanning via Trivy; (4) secret scanning via gitleaks; (5) unit and integration testing; (6) manual security review for sensitive changes."
			}},
		{ID: "sa-11.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Static code analysis: (1) GoSec for Go-specific security issues; (2) Semgrep for general security patterns; (3) govulncheck for known Go vulnerabilities; (4) gitleaks for secret detection. All tools run automatically in CI/CD pipeline."
			}},
	}
}

func scControls() []ControlDef {
	return []ControlDef{
		{ID: "sc-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a System and Communications Protection Policy (POL-SC-001) defining encryption requirements, boundary protection, and communication security standards."
			}},
		{ID: "sc-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Application partitioning separates user functionality from management functionality: (1) separate Cloud Run services for app API, admin API, and ops service; (2) separate GCP projects for app and admin workloads; (3) separate Cloudflare Access policies for admin endpoints; (4) RBAC enforces functional separation within the application."
			}},
		{ID: "sc-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Information in shared resources is protected: (1) PostgreSQL RLS ensures workspace-level data isolation in the shared database; (2) GCS object paths are workspace-scoped (workspace UUID prefix); (3) Vertex AI Vector Search uses workspace-scoped metadata filtering; (4) Cloud Run containers are stateless — no shared memory between requests."
			}},
		{ID: "sc-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Denial-of-service protection is provided at multiple layers: (1) Cloudflare DDoS protection (automatic L3/L4/L7 mitigation); (2) %s; (3) Cloud Armor rate-based bans and OWASP rules; (4) Cloud Run auto-scaling (max %d instances) with request timeouts; (5) Application-level rate limiting for sensitive endpoints.",
					boolStr(f.CFRateLimitingEnabled, "Cloudflare tiered rate limiting (auth, login, admin, global API)", "Cloudflare rate limiting"),
					f.CloudRunMaxScale)
			}},
		{ID: "sc-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Boundary protection is implemented at: (1) Cloudflare Edge WAF — first-layer defense with managed rulesets, OWASP CRS, rate limiting, geo-blocking; (2) Cloud Armor Origin WAF — Cloudflare-only origin restriction (%s), OWASP CRS, rate-based bans; (3) Regional HTTPS Load Balancer; (4) VPC egress firewall — deny-all with FQDN allowlist; (5) Cloud Run ingress restricted to %s; (6) No public IP addresses on any service.",
					boolStr(f.CloudArmorCFRestriction, "active", "configured"),
					or(f.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"))
			}},
		{ID: "sc-7.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Access points are limited to: (1) HTTPS (port 443) via Cloudflare for end-user access; (2) Cloudflare Zero Trust Access for admin endpoints. No SSH, RDP, or direct console access. All access traverses the full WAF stack."
			}},
		{ID: "sc-7.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("External telecommunications services are managed at: (1) Cloudflare (DNS, WAF, CDN, Zero Trust Access) — all external traffic enters through Cloudflare; (2) GCP Load Balancer — accepts only Cloudflare-originated traffic; (3) %s for admin access.",
					boolStr(f.CFAccessEnabled, "Cloudflare Access policies", "Access controls"))
			}},
		{ID: "sc-7.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Default deny: (1) VPC egress firewall denies all outbound by default, with FQDN allowlist for required GCP APIs only; (2) Cloud Armor denies all non-Cloudflare traffic; (3) Cloud Run ingress restricted to internal + load balancer; (4) RBAC denies access by default — explicit grants required."
			}},
		{ID: "sc-7.7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Split tunneling prevention: not directly applicable to a SaaS system. However, all system access is forced through the WAF stack (Cloudflare → Cloud Armor → LB → Cloud Run). There is no way to bypass the boundary protection to reach origin services directly."
			}},
		{ID: "sc-7.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Traffic is routed to authenticated proxy: all inbound traffic is proxied through Cloudflare (authenticated via Cloud Armor Cloudflare-only IP restriction). Internal traffic between GCP services uses GCP's internal networking with service identity verification."
			}},
		{ID: "sc-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, edgeWAF},
			NarrativeFn: func(f *InfraFacts) string {
				return "Transmission confidentiality and integrity: all data in transit is encrypted with TLS 1.2+ (minimum enforced by Cloudflare and GCP). HSTS headers enforce HTTPS. Internal GCP service-to-service communication uses mTLS via Cloud Run's built-in service mesh."
			}},
		{ID: "sc-8.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection for transmission: (1) TLS 1.2+ with FIPS-approved cipher suites; (2) %s for FIPS 140-2 validated TLS; (3) Cloudflare enforces minimum TLS 1.2 with modern cipher suites; (4) GCP internal networking uses Google's ALTS protocol.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto (BoringSSL)", "BoringCrypto for Go"))
			}},
		{ID: "sc-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			Parameters: []ParamValue{
				{ParamID: "sc-10_prm_1", Values: []string{"15 minutes of inactivity"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return "Network connections are terminated after: (1) 15 minutes of inactivity (application session timeout); (2) 12 hours maximum session duration; (3) Cloudflare connection timeouts for idle TCP connections; (4) Cloud Run request timeouts (300 seconds for streaming, 60 seconds for standard)."
			}},
		{ID: "sc-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			Parameters: []ParamValue{
				{ParamID: "sc-12_prm_1", Values: []string{"90 days"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic key management: (1) Cloud KMS in dedicated project %s provides centralized key management; (2) Key rotation every %d days (automated); (3) HSM-backed keys (FIPS 140-2 Level 3); (4) Separate key rings for each data type (SQL, GCS, logging, secrets); (5) Key access controlled via IAM — only authorized service accounts can use keys.",
					or(f.KMSProjectID),
					f.KMSRotationDays)
			}},
		{ID: "sc-12.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Key availability is maintained through: (1) Cloud KMS provides 99.999% SLA; (2) keys are replicated within the region; (3) key versions are preserved for decryption of historical data; (4) key destruction requires explicit action with a 24-hour scheduled destruction delay."
			}},
		{ID: "sc-13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			Parameters: []ParamValue{
				{ParamID: "sc-13_prm_1", Values: []string{"FIPS 140-2 validated (BoringCrypto, Cloud KMS HSM)"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("FIPS-validated cryptography: (1) %s provides FIPS 140-2 validated TLS in the Go backend; (2) Cloud KMS uses FIPS 140-2 Level 3 HSMs; (3) AES-256-GCM for data at rest (CMEK); (4) TLS 1.2+ with FIPS-approved cipher suites for data in transit; (5) Algorithm: %s for KMS keys.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto", "BoringCrypto"),
					or(f.KMSAlgorithm, "GOOGLE_SYMMETRIC_ENCRYPTION"))
			}},
		{ID: "sc-15", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Collaborative computing devices: not applicable. The system is a web-based SaaS application. No collaborative computing devices (video conferencing, audio) are part of the system. User sessions are independent."
			}},
		{ID: "sc-17", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "PKI certificates: (1) Cloudflare manages edge TLS certificates (automatic renewal via DigiCert/Let's Encrypt); (2) GCP manages origin certificates (Google Trust Services CA); (3) Certificate transparency logging is enabled. No manual certificate management required."
			}},
		{ID: "sc-18", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Mobile code: the system uses JavaScript (React SPA) served from controlled origins only. Content Security Policy (CSP) headers restrict script sources. No ActiveX, Java applets, or Flash. Third-party scripts are limited to reCAPTCHA (Google) with SRI integrity verification."
			}},
		{ID: "sc-20", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Secure name/address resolution: DNS is managed via Cloudflare with DNSSEC enabled. All DNS queries for system domains are authenticated. Cloudflare provides DNS-layer DDoS protection."
			}},
		{ID: "sc-21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "DNS resolution validation: the system performs DNSSEC validation for outbound DNS queries via GCP's internal DNS resolver which validates DNSSEC-signed responses."
			}},
		{ID: "sc-22", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Architecture for public DNS: Cloudflare provides authoritative DNS for all system domains with fault-tolerance (anycast, multiple name servers), DNSSEC, and DDoS protection."
			}},
		{ID: "sc-23", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Session authenticity: (1) Firebase Auth JWTs are signed with RS256; (2) JWT signature verified on every request; (3) CSRF protection via SameSite cookie attribute and custom headers; (4) Session tokens bound to user identity and not transferable."
			}},
		{ID: "sc-28", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudSQL, cloudStorage, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Protection of information at rest: all data at rest is encrypted with AES-256-GCM using CMEK via Cloud KMS (%s). Encrypted data stores: (1) Cloud SQL (%s) — CMEK; (2) Cloud Storage (%s) — CMEK; (3) Cloud Logging — CMEK; (4) Artifact Registry — CMEK; (5) Cloud Tasks — CMEK; (6) Vertex AI indexes — CMEK.",
					or(f.KMSProjectID),
					or(f.CloudSQLDatabaseName, "archon"),
					or(f.GCSDocumentsBucket))
			}},
		{ID: "sc-28.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			Parameters: []ParamValue{
				{ParamID: "sc-28.1_prm_1", Values: []string{"AES-256-GCM (CMEK via Cloud KMS)"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection for data at rest uses CMEK (Customer-Managed Encryption Keys) via Cloud KMS with %d-day automatic rotation. Algorithm: %s. HSM-backed (FIPS 140-2 Level 3). Keys stored in dedicated project (%s) with separate IAM policies.",
					f.KMSRotationDays,
					or(f.KMSAlgorithm, "GOOGLE_SYMMETRIC_ENCRYPTION"),
					or(f.KMSProjectID))
			}},
		{ID: "sc-39", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Process isolation: (1) Cloud Run containers provide OS-level process isolation (gVisor sandbox); (2) each request executes in an isolated context; (3) no shared mutable state between requests; (4) PostgreSQL RLS provides data-level isolation within the database."
			}},
	}
}

func siControls() []ControlDef {
	return []ControlDef{
		{ID: "si-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a System and Information Integrity Policy (POL-SI-001) defining vulnerability management, malware protection, monitoring, and patching requirements."
			}},
		{ID: "si-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Flaw remediation: (1) critical vulnerabilities patched within 24 hours; (2) high within 7 days; (3) medium within 30 days; (4) low within 90 days. Vulnerability scanning runs daily via Cloud Build. Patch status tracked in POA&M via Drata."
			}},
		{ID: "si-2.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated flaw remediation status monitoring: (1) daily vulnerability scans (GoSec, Semgrep, Trivy, govulncheck) report results to Cloud Build; (2) scan results uploaded to Drata as evidence; (3) Cloud Monitoring alerts on new critical/high findings."
			}},
		{ID: "si-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, clamAV},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Malicious code protection: (1) %s provides real-time malware scanning for all uploaded documents; (2) ClamAV is configured as fail-closed in production — upload rejected if scan fails; (3) Container images scanned by Trivy for known malware signatures; (4) gitleaks scans for secrets/credentials in source code.",
					boolStr(f.ClamAVEnabled, "ClamAV malware scanner (Cloud Run service)", "ClamAV malware scanner"))
			}},
		{ID: "si-3.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Centralized malware management: ClamAV definitions are updated daily via freshclam. The ClamAV service is deployed as a Cloud Run service accessible only within the VPC. Scan results are logged to Cloud Logging for centralized analysis."
			}},
		{ID: "si-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System monitoring: (1) Cloud Monitoring provides infrastructure metrics and alerting; (2) Cloud Logging provides centralized log aggregation; (3) Cloudflare analytics provides edge-layer visibility; (4) Application audit logging provides business-logic event tracking; (5) Automated SSP-IaC drift detection."
			}},
		{ID: "si-4.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "System-wide intrusion detection: (1) Cloudflare WAF detects and blocks web application attacks; (2) Cloud Armor detects and blocks L7 attacks; (3) Cloud Monitoring log-based metrics detect anomalous patterns; (4) Application audit logs detect unauthorized access attempts."
			}},
		{ID: "si-4.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated monitoring tools: (1) Cloud Monitoring alerting policies for SLO violations; (2) Cloudflare Security Events for WAF triggers; (3) log-based metrics for authentication failures, rate limiting, error rates; (4) uptime checks for service availability."
			}},
		{ID: "si-4.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Inbound and outbound traffic monitoring: (1) Cloudflare provides full visibility into inbound HTTP traffic (requests, responses, WAF actions, threat scores); (2) VPC flow logs capture network-level traffic metadata; (3) Cloud Armor logs capture origin-layer WAF decisions; (4) VPC egress firewall logs capture outbound connection attempts."
			}},
		{ID: "si-4.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated alerts for security-relevant events: (1) authentication failure spikes → email + PagerDuty; (2) WAF block rate increase → Cloud Monitoring alert; (3) error rate SLO violation → PagerDuty; (4) unauthorized API access attempts → audit log alert; (5) configuration drift detected → CI alert."
			}},
		{ID: "si-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security alerts and advisories: (1) US-CERT advisories monitored; (2) Go vulnerability database (govulncheck) checked daily; (3) NVD CVE feed monitored for dependencies; (4) Cloudflare security advisories; (5) GCP security bulletins. Relevant advisories trigger vulnerability assessment and patching within defined SLAs."
			}},
		{ID: "si-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security function verification: (1) `cmd/verify-controls` validates NIST controls against live GCP state; (2) `cmd/check-ssp-iac-drift` verifies SSP accuracy against IaC; (3) `cmd/generate-ssp` regenerates SSP from IaC to prevent drift; (4) CI/CD pipeline validates security configurations on every change."
			}},
		{ID: "si-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return "Software and information integrity: (1) container images built in Cloud Build with deterministic builds; (2) container image digests (SHA-256) used for deployment (not mutable tags); (3) Binary Authorization attests images on ops project; (4) Git commit signing for source code integrity; (5) SBOM generation tracks all components."
			}},
		{ID: "si-7.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Integrity checking: (1) container image digests verified at deployment; (2) Go module checksums verified via go.sum; (3) npm integrity verified via package-lock.json; (4) Terraform provider checksums verified; (5) ClamAV definition checksums verified on update."
			}},
		{ID: "si-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Spam protection: (1) reCAPTCHA Enterprise on registration and login endpoints; (2) Cloudflare Bot Management; (3) rate limiting on all API endpoints; (4) email sending restricted to transactional notifications only (no bulk email)."
			}},
		{ID: "si-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Information input validation: (1) Connect-RPC/Protobuf enforces type-safe API contracts; (2) Server-side validation for all user inputs; (3) SQL injection prevented by parameterized queries (no string interpolation); (4) XSS prevented by React's automatic escaping and CSP headers; (5) File upload validation (MIME type, size limits, malware scan)."
			}},
		{ID: "si-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Error handling: (1) generic error messages returned to users (no stack traces, no internal details); (2) detailed error information logged server-side only; (3) Connect-RPC error codes used for API responses; (4) unhandled panics caught by recovery middleware and logged."
			}},
		{ID: "si-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Information handling and retention: (1) CUI handled in accordance with 32 CFR 2002; (2) data retained per customer agreement and applicable regulations; (3) automated 90-day purge for closed accounts; (4) audit logs retained minimum 1 year; (5) CMEK encryption for all data at rest."
			}},
		{ID: "si-16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Memory protection: (1) Cloud Run uses gVisor sandbox providing memory isolation between containers; (2) Go's memory safety (garbage collection, bounds checking, no buffer overflows); (3) no use of unsafe packages in application code; (4) Cloud SQL uses GCP's managed memory protection."
			}},
	}
}

func srControls() []ControlDef {
	return []ControlDef{
		{ID: "sr-1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Latent Archon maintains a Supply Chain Risk Management Policy (POL-SR-001) defining requirements for evaluating, selecting, and monitoring third-party components and services."
			}},
		{ID: "sr-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Supply chain controls: (1) GCP and Cloudflare selected from FedRAMP-authorized providers; (2) Go dependencies evaluated for maintenance, security posture, and license; (3) container base images from Google's distroless catalog; (4) no direct vendor access to production systems."
			}},
		{ID: "sr-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Supply chain protection: (1) daily SBOM generation captures all software components; (2) vulnerability scanning of all dependencies; (3) license compliance checking; (4) pinned dependency versions (go.sum, package-lock.json); (5) container image digests used instead of mutable tags."
			}},
		{ID: "sr-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Authenticity verification: (1) Go module checksums verified via go.sum and Go checksum database; (2) container base image provenance from Google's artifact registry; (3) Terraform provider checksums verified; (4) npm package integrity verified via package-lock.json."
			}},
		{ID: "sr-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Supplier assessments: (1) GCP assessed via FedRAMP High authorization package; (2) Cloudflare assessed via FedRAMP Moderate authorization; (3) open-source dependencies assessed via automated vulnerability scanning and SBOM analysis."
			}},
		{ID: "sr-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Notification agreements: (1) GCP security bulletins provide vulnerability notifications; (2) Go team publishes security advisories for the Go ecosystem; (3) GitHub Dependabot provides automated vulnerability notifications for dependencies."
			}},
		{ID: "sr-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Inspection of systems: (1) container images inspected by Trivy before deployment; (2) source code inspected by SAST tools (GoSec, Semgrep); (3) infrastructure configurations inspected by Terragrunt plan; (4) no closed-source components in the application stack."
			}},
		{ID: "sr-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Component authenticity: (1) SBOM generated daily (CycloneDX + SPDX) capturing all component versions and sources; (2) Go module checksums verified against Go checksum database; (3) container image digests immutably reference specific builds."
			}},
		{ID: "sr-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Component disposal: (1) deprecated dependencies removed via `go mod tidy` and PR review; (2) unused GCP services disabled via Terragrunt `apis/terragrunt.hcl`; (3) old container image versions cleaned up via Artifact Registry lifecycle policies."
			}},
	}
}

func highOnlyControls() []ControlDef {
	return []ControlDef{
		{ID: "ac-2.11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Usage conditions are enforced: (1) sessions limited to authorized time windows when configured by org admin; (2) IP allowlisting restricts access to approved networks; (3) Cloudflare Access policies enforce device posture requirements for admin endpoints."
			}},
		{ID: "ac-2.12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Account monitoring for atypical usage: (1) auth interceptor logs all access with behavioral attributes (IP, user agent, time, action); (2) anomalous login patterns (new IP, new device, unusual time) trigger additional logging; (3) Cloud Monitoring log-based metrics detect access pattern anomalies."
			}},
		{ID: "ac-2.13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Accounts posing significant risk are disabled within 1 hour: (1) accounts with confirmed credential compromise disabled via Firebase Admin SDK; (2) accounts exhibiting malicious behavior blocked at the application layer; (3) automated detection triggers account lockout pending investigation."
			}},
		{ID: "ac-3.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Mandatory access control: (1) PostgreSQL RLS policies enforce workspace-level data isolation (mandatory — cannot be bypassed by application code); (2) GCP org policies enforce security constraints (public IP restriction, location restriction, service restriction); (3) Assured Workloads enforces compliance regime constraints."
			}},
		{ID: "ac-4.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Content inspection: (1) %s scans all uploaded documents for malware; (2) Cloudflare WAF inspects HTTP request/response payloads; (3) Cloud Armor inspects HTTP headers and body for attack patterns; (4) Application validates file MIME types and sizes before processing.",
					boolStr(f.ClamAVEnabled, "ClamAV", "Malware scanner"))
			}},
		{ID: "au-6.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Audit analysis is correlated across: (1) application audit logs; (2) GCP Cloud Audit Logs; (3) Cloudflare security events; (4) WAF logs; (5) VPC flow logs. Correlation is performed using request correlation IDs and timestamps."
			}},
		{ID: "au-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Non-repudiation: (1) all actions are attributed to authenticated user identity (Firebase UID); (2) audit records include cryptographic binding (CMEK-encrypted, tamper-evident); (3) GCP Cloud Audit Logs provide Google-attested audit trail; (4) Git commits signed for code change attribution."
			}},
		{ID: "cm-3.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated security impact analysis via FedRAMP SCN (Significant Change Notification) classifier integrated into CI/CD. The classifier automatically analyzes PRs and labels them by impact level (routine, significant, critical) based on files changed, security control implications, and architecture impact."
			}},
		{ID: "cm-5.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated access enforcement for change control: (1) GitHub branch protection requires PR approval; (2) CI/CD pipeline must pass before merge; (3) Terragrunt plan output reviewed and approved before apply; (4) Cloud Build deployment uses signed container images."
			}},
		{ID: "cp-2.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Contingency plan is coordinated with: (1) GCP support for infrastructure-level incidents; (2) Cloudflare support for edge-layer incidents; (3) customer agencies for service disruptions; (4) FedRAMP PMO for authorization-impacting incidents."
			}},
		{ID: "cp-2.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Essential mission functions are recoverable: (1) Terragrunt IaC enables full infrastructure rebuild; (2) Cloud SQL PITR enables database recovery to any point in time; (3) GCS versioning enables document recovery; (4) Container images in Artifact Registry enable instant service redeploy. All essential functions recoverable within %s.",
					or(f.Region, "us-east4"))
			}},
		{ID: "cp-6.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Alternate storage site is separated from primary: (1) GitHub (source code, IaC) is geographically separate from GCP %s; (2) Cloud SQL backups can be restored to alternate region; (3) Container images available in Artifact Registry across regions.",
					or(f.Region, "us-east4"))
			}},
		{ID: "cp-7.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Alternate processing site provides equivalent security: Terragrunt IaC ensures identical security configuration in any deployment region. Assured Workloads constraints apply across all US regions."
			}},
		{ID: "ia-5.7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Unencrypted static authenticators are not embedded in applications: (1) no hardcoded credentials in source code (enforced by gitleaks scanning); (2) Workload Identity Federation provides keyless auth (no service account keys); (3) application secrets stored in GCP Secret Manager."
			}},
		{ID: "ir-4.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated incident handling: (1) Cloud Monitoring alerts trigger PagerDuty pages; (2) Cloudflare auto-mitigates DDoS attacks; (3) rate limiting automatically blocks abuse; (4) automated account lockout on failed auth threshold. Manual investigation required for complex incidents."
			}},
		{ID: "pe-3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Physical access control is fully inherited from Google Cloud Platform's FedRAMP High authorization. GCP data centers implement multi-layer physical security including badge access, biometric verification, security guards, video surveillance, and mantrap entry systems."
			}},
		{ID: "sc-7.18", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Fail secure: if boundary protection mechanisms fail, the system defaults to deny: (1) Cloud Armor defaults to deny-all if rules cannot be evaluated; (2) VPC egress firewall defaults to deny-all; (3) Cloud Run rejects requests if auth middleware fails; (4) ClamAV operates fail-closed (upload rejected if scan unavailable)."
			}},
		{ID: "sc-7.21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Isolation of system components: (1) three-project GCP architecture provides blast-radius isolation; (2) separate service accounts per Cloud Run service; (3) VPC peering with restricted routes; (4) KMS keys in dedicated project with separate IAM."
			}},
		{ID: "si-4.12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated organization-generated alerts: security events from Cloud Monitoring, Cloudflare, and application audit logs generate automated alerts to security personnel via email and PagerDuty."
			}},
	}
}

func il5Controls() []ControlDef {
	return []ControlDef{
		{ID: "sc-7.24", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Data residency enforcement for IL5: (1) Assured Workloads %s constrains all data and processing to US territory; (2) GCP region restricted to %s (CONUS); (3) Cloudflare geo-blocking restricts access to US-origin requests; (4) GCS data location enforced by Assured Workloads.",
					boolStr(f.AWSComplianceRegime != "", "("+f.AWSComplianceRegime+" regime)", ""),
					or(f.Region, "us-east4"))
			}},
		{ID: "sc-28.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Offline storage encryption for IL5: all data at rest uses CMEK with %d-day automatic rotation via Cloud KMS (%s). Offline backups (Cloud SQL automated backups, GCS versions) inherit CMEK encryption. No unencrypted data exists at rest.",
					f.KMSRotationDays,
					or(f.KMSProjectID))
			}},
		{ID: "ac-4.21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Physical/logical separation of information flows for IL5: (1) Assured Workloads %s provides logical separation of IL5 workloads from commercial GCP; (2) VPC Service Controls restrict API access to authorized perimeters; (3) CMEK keys in dedicated KMS project ensure cryptographic separation; (4) Data never leaves the assured workload boundary.",
					boolStr(f.AWSComplianceRegime != "", "("+f.AWSComplianceRegime+")", ""))
			}},
		{ID: "sc-13.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("FIPS 140-2 validated cryptography for IL5: (1) %s provides FIPS 140-2 validated TLS in Go backend; (2) Cloud KMS HSMs are FIPS 140-2 Level 3 certified; (3) All cryptographic operations (encryption, hashing, signing) use FIPS-approved algorithms; (4) Non-FIPS cryptographic modules are not used.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto (BoringSSL)", "BoringCrypto"))
			}},
	}
}

func buildImplementedRequirements(facts *InfraFacts) []ImplementedRequirement {
	controls := allControls()
	reqs := make([]ImplementedRequirement, 0, len(controls))

	for _, c := range controls {
		narrative := c.NarrativeFn(facts)

		implStatus := c.ImplStatus
		if implStatus == "" {
			implStatus = "implemented"
		}

		components := c.ComponentUUIDs
		if len(components) == 0 {
			components = []string{thisSystem}
		}

		byComps := make([]ByComponent, 0, len(components))
		for i, compUUID := range components {
			desc := narrative
			if i > 0 {
				desc = fmt.Sprintf("See %s implementation for full description. This component contributes to the control implementation as described in the primary narrative.", c.ID)
			}
			byComps = append(byComps, ByComponent{
				ComponentUUID: compUUID,
				UUID:          deterministicUUID(fmt.Sprintf("bycomp-%s-%d", c.ID, i)),
				Description:   desc,
				ImplementationStatus: ImplStatus{
					State: implStatus,
				},
			})
		}

		req := ImplementedRequirement{
			UUID:      deterministicUUID("control-" + c.ID),
			ControlID: c.ID,
			Props: []Prop{
				{Name: "implementation-status", Value: implStatus},
				{Name: "evidence-tier", Value: c.EvidenceTier},
			},
			ResponsibleRoles: []RoleRef{
				{RoleID: c.RoleID},
			},
			Statements: []Statement{
				{
					StatementID: c.ID + "_smt",
					UUID:        deterministicUUID("stmt-" + c.ID),
					ByComponents: byComps,
				},
			},
		}

		if c.Baseline != "" {
			req.Props = append(req.Props, Prop{Name: "baseline", Value: c.Baseline})
		}

		if len(c.Parameters) > 0 {
			for _, p := range c.Parameters {
				req.SetParameters = append(req.SetParameters, SetParameter{
					ParamID: p.ParamID,
					Values:  p.Values,
				})
			}
		}

		reqs = append(reqs, req)
	}

	return reqs
}

func formatFactsSummary(facts *InfraFacts) string {
	var b strings.Builder
	b.WriteString("Infrastructure Facts Summary:\n")
	b.WriteString(fmt.Sprintf("  Region: %s\n", or(facts.Region, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Environment: %s\n", or(facts.Environment, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Deployment: %s\n", or(facts.Deployment, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Admin Project: %s\n", or(facts.AdminProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Ops Project: %s\n", or(facts.OpsProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  App Project: %s\n", or(facts.AppProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  KMS Project: %s\n", or(facts.KMSProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Cloud SQL: tier=%s, avail=%s, publicIP=%v\n", or(facts.CloudSQLTier), or(facts.CloudSQLAvailability), facts.CloudSQLPublicIP))
	b.WriteString(fmt.Sprintf("  Cloud Run: min=%d, max=%d, ingress=%s\n", facts.CloudRunMinScale, facts.CloudRunMaxScale, or(facts.CloudRunIngress)))
	b.WriteString(fmt.Sprintf("  KMS: rotation=%dd, algorithm=%s\n", facts.KMSRotationDays, or(facts.KMSAlgorithm, "(default)")))
	b.WriteString(fmt.Sprintf("  Cloudflare: WAF=%v, RateLimit=%v, Access=%v, Logpush=%v, FirewallRules=%v\n", facts.CFWAFEnabled, facts.CFRateLimitingEnabled, facts.CFAccessEnabled, facts.CFLogpushEnabled, facts.CFFirewallRulesEnabled))
	b.WriteString(fmt.Sprintf("  Cloud Armor: CF restriction=%v\n", facts.CloudArmorCFRestriction))
	b.WriteString(fmt.Sprintf("  Assured Workloads: regime=%s\n", or(facts.AWSComplianceRegime, "(not detected)")))
	b.WriteString(fmt.Sprintf("  ClamAV: %v\n", facts.ClamAVEnabled))
	b.WriteString(fmt.Sprintf("  Audit Logs: retention=%dd, WORM=%v\n", facts.AuditLogRetentionDays, facts.AuditLogWORM))
	b.WriteString(fmt.Sprintf("  Backend: BoringCrypto=%v, RBAC=%v, RLS=%v, Audit=%v, SCIM=%v, DLP=%v\n", facts.BoringCrypto, facts.RBACEnabled, facts.RLSEnabled, facts.AuditLoggingEnabled, facts.SCIMEnabled, facts.DLPEnabled))
	return b.String()
}
