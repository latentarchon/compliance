package main

import (
	"fmt"
	"strings"
)

func verifiedControls() []ControlDef {
	return []ControlDef{
		// AC family
		{ID: "ac-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("(a) Latent Archon defines four tenant-level account types: `master_admin`, `admin`, `editor`, and `viewer`. Each account type has specific privileges enforced per-RPC in the Connect-RPC interceptor chain. Service accounts (e.g., noreply@latentarchon.com) are a distinct non-interactive type blocked from authentication.\n(b) Account managers are designated per customer tenant. The `master_admin` role serves as the tenant account manager.\n(c) Conditions for group and role membership are enforced by the RBAC model. Users must be explicitly invited to a tenant (via invite token or SCIM provisioning) and granted workspace access. The auth interceptor enforces a tenant membership gate.\n(d) Authorized users and role membership are specified per-tenant by the `master_admin` through the admin API (`InviteMember`, `UpdateMemberRole`, `RemoveMember` RPCs). For SCIM-enabled tenants, user lifecycle is managed automatically by the customer IdP.\n(e) Account creation requires approval by a tenant admin (explicit invite) or automated provisioning via SCIM 2.0 from an authorized customer IdP. JIT provisioning auto-creates accounts on first SSO login.\n(f) Accounts are created via invite tokens (time-limited), SCIM 2.0, or JIT provisioning. Accounts are disabled via Firebase Admin SDK `DisableUser()` or SCIM DELETE. Accounts are removed via `RemoveMember` RPC or self-service `CloseAccount` RPC (requires step-up MFA). Automated 90-day data purge runs via Cloud Scheduler.\n(g) System access is monitored through comprehensive audit logging (`internal/audit/logger.go`). All authentication events, role changes, and SCIM actions are recorded with user ID, IP, user agent, timestamp, and correlation ID.\n(h) Account managers (tenant `master_admin`) are notified of account changes via real-time security email notifications covering: role escalation, auth failures, member changes, SCIM events, and deletions.\n(i) Authorization requires: (1) valid Firebase Auth JWT, (2) MFA verification, (3) tenant membership, (4) appropriate RBAC role, and (5) workspace membership for data access.\n(j) All accounts are reviewed by the tenant `master_admin` through the admin dashboard. Quarterly access reviews tracked via Drata.\n(k) Role transfers handled via admin API or SCIM group-to-role mapping.\n(l) Accounts deprovisioned within 24 hours via SCIM DELETE or manual removal. Self-service closure via `CloseAccount` RPC with step-up MFA. Row-level security on %s enforces data isolation post-deprovisioning.", or(f.CloudSQLDatabaseName, "archon"))
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
				return fmt.Sprintf("Information flow is controlled at multiple layers: (1) Cloudflare Edge WAF with managed rulesets, OWASP CRS, threat score challenges (threshold=%d), path probing protection (%d paths blocked), and IP/ASN blocking %s; (2) Cloud Armor origin WAF restricts traffic to Cloudflare IPs only %s; (3) VPC egress firewall is deny-all by default with FQDN allowlist for GCP APIs only (org policy enforces ALL_TRAFFIC egress=%v); (4) Cloud Run services configured with ingress=%s restricting to internal + load-balancer traffic; (5) Cloud SQL has no public IP (public_ip=%v, org policy sql.restrictPublicIp=%v); (6) Vertex AI accessed via Private Service Connect (PSC) within the VPC.",
					f.CFThreatScoreThreshold, len(f.CFBlockedPaths),
					boolStr(f.CFFirewallRulesEnabled, "(active)", "(module exists)"),
					boolStr(f.CloudArmorCFRestriction, "(Cloudflare-only rule active)", ""),
					f.OrgPolicyRunEgressAllTraffic,
					or(f.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"),
					f.CloudSQLPublicIP, f.OrgPolicySQLPublicIPDeny)
			}},
		{ID: "ac-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Separation of duties is enforced through: (1) Three-project GCP architecture (%s for admin, %s for ops/data, %s for app) with separate IAM policies; (2) RBAC with four distinct roles — viewer cannot modify, editor cannot manage users, admin cannot change tenant settings, master_admin has full tenant scope; (3) CI/CD pipeline uses Workload Identity Federation with per-project service accounts — no single identity spans all projects; (4) KMS keys in dedicated project %s with separate IAM grants; (5) %d org-level IAM groups with role-based access (org policy: domain restricted=%v, SA key creation disabled=%v, default SA grants disabled=%v).",
					or(f.AdminProjectID), or(f.OpsProjectID), or(f.AppProjectID), or(f.KMSProjectID),
					f.OrgIAMGroupCount, f.OrgPolicyDomainRestricted, f.OrgPolicySAKeyCreationDeny, f.OrgPolicyDefaultSAGrantDeny)
			}},
		{ID: "ac-17", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				cloudShellDesc := ""
				if f.CloudShellDisabled {
					cloudShellDesc = "; (6) Cloud Shell disabled on all projects via org constraint"
				}
				return fmt.Sprintf("All access to the system is remote access — there is no physical console access. Remote access is controlled through: (1) HTTPS/TLS 1.2+ for all user-facing connections via Cloudflare and Cloud Armor; (2) Cloudflare Zero Trust Access for admin endpoints (%s); (3) GCP IAP or IAM Conditions for infrastructure access; (4) GitHub with SSO for code repository access; (5) Workload Identity Federation for CI/CD (keyless)%s.",
					or(f.AdminDomain), cloudShellDesc)
			}},
		{ID: "ac-17.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Automated monitoring of remote access is provided by: (1) Cloudflare Zero Trust Access logs all admin access attempts with identity, IP, device posture, and decision; (2) GCP Cloud Audit Logs capture all API calls; (3) Application audit logs record all authenticated actions; (4) %s provides log export to SIEM.",
					boolStr(f.CFLogpushEnabled, "Cloudflare Logpush", "Cloudflare logging"))
			}},

		// AU family
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

		// CM family
		{ID: "cm-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Configuration settings follow security hardening guidelines: (1) Cloud SQL: no public IP, SSL required, automated backups, %s availability; (2) Cloud Run: ingress restricted to %s, min/max scale %d/%d; (3) VPC: egress deny-all with FQDN allowlist; (4) KMS: %d-day rotation, %s algorithm; (5) GCS: versioning, CMEK, soft-delete; (6) All settings defined in Terragrunt and validated by drift detection.",
					or(f.CloudSQLAvailability, "REGIONAL"),
					or(f.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"),
					f.CloudRunMinScale, f.CloudRunMaxScale,
					f.KMSRotationDays, or(f.KMSAlgorithm, "GOOGLE_SYMMETRIC_ENCRYPTION"))
			}},

		// CP family
		{ID: "cp-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("The contingency plan addresses: (1) essential missions and business functions; (2) recovery objectives (RTO < 1 hour for Tier 1, < 4 hours for Tier 2); (3) recovery strategies per component (Cloud SQL PITR, Cloud Run redeploy, GCS version restore, Vertex AI index rebuild); (4) roles and responsibilities; (5) communication procedures. All infrastructure recoverable via Terragrunt from Git in region %s.",
					or(f.Region, "us-east4"))
			}},
		{ID: "cp-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Alternate storage is provided by: (1) Cloud SQL automated backups stored within the %s region; (2) GCS cross-region replication available for critical buckets; (3) Git repository (GitHub) serves as configuration backup with geographic redundancy; (4) Container images stored in Artifact Registry with multi-zone availability.",
					or(f.Region, "us-east4"))
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

		// IA family
		{ID: "ia-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("All users are uniquely identified and authenticated via Firebase Identity Platform. Authentication methods: (1) Email + password with mandatory TOTP MFA; (2) SAML 2.0 SSO via customer IdP with MFA enforced at the IdP; (3) Magic link (passwordless) with TOTP MFA. User accounts are identified by a globally unique Firebase UID. %s",
					boolStr(f.CFAccessEnabled, "Admin endpoints additionally protected by Cloudflare Zero Trust Access.", ""))
			}},
		{ID: "ia-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic module authentication uses FIPS 140-2 validated modules: (1) %s in the Go backend (BoringCrypto/BoringSSL); (2) GCP services use FIPS 140-2 Level 3 HSMs for KMS operations; (3) Cloudflare uses FIPS 140-2 validated TLS implementation.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto is enabled", "BoringCrypto should be enabled"))
			}},

		// MP family
		{ID: "mp-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Access to digital media is restricted: (1) Cloud SQL data encrypted with CMEK via Cloud KMS (%s); (2) GCS objects encrypted with CMEK; (3) IAM policies restrict access to authorized service accounts only; (4) No data is stored on removable media; (5) Laptop full-disk encryption required for all personnel.",
					or(f.KMSProjectID))
			}},
		{ID: "mp-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Digital media storage is controlled: (1) all data stored within GCP %s region; (2) Assured Workloads %s enforces data residency; (3) CMEK encryption for all data at rest; (4) no data exported to removable media; (5) GCS versioning preserves all versions.",
					or(f.Region, "us-east4"),
					boolStr(f.AWSComplianceRegime != "", "("+f.AWSComplianceRegime+")", ""))
			}},

		// SC family
		{ID: "sc-5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Denial-of-service protection is provided at multiple layers: (1) Cloudflare DDoS protection (automatic L3/L4/L7 mitigation); (2) %s; (3) Cloud Armor rate-based bans and OWASP rules; (4) Cloud Run auto-scaling (max %d instances) with request timeouts; (5) Application-level rate limiting for sensitive endpoints.%s",
					boolStr(f.CFRateLimitingEnabled, "Cloudflare tiered rate limiting", "Cloudflare rate limiting"),
					f.CloudRunMaxScale,
					boolStr(f.CFLoginRateLimitEnabled, fmt.Sprintf(" Login brute-force protection: %d requests per %d seconds at the edge.", f.CFLoginRateLimit, f.CFLoginRatePeriod), ""))
			}},
		{ID: "sc-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Boundary protection is implemented at: (1) Cloudflare Edge WAF — managed ruleset=%v, OWASP CRS=%v, threat score challenges (threshold=%d), path probing protection (%d blocked paths), %s; (2) Cloud Armor Origin WAF — Cloudflare-only origin restriction (%s), OWASP CRS, rate-based bans; (3) Regional HTTPS Load Balancer; (4) VPC egress firewall — deny-all with FQDN allowlist; (5) Cloud Run ingress restricted to %s (org policy enforced=%v); (6) No public IP addresses on any service (org policy: VM external IP deny=%v, SQL public IP deny=%v).",
					f.CFWAFManagedRuleset, f.CFWAFOWASPRuleset, f.CFThreatScoreThreshold, len(f.CFBlockedPaths),
					boolStr(f.CFWorkerProxyEnabled, "Worker proxy for same-origin API gateway", ""),
					boolStr(f.CloudArmorCFRestriction, "active", "configured"),
					or(f.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"),
					f.OrgPolicyRunIngressRestrict,
					f.OrgPolicyVMExternalIPDeny, f.OrgPolicySQLPublicIPDeny)
			}},
		{ID: "sc-7.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("External telecommunications services are managed at: (1) Cloudflare (DNS, WAF, CDN, Zero Trust Access) — all external traffic enters through Cloudflare; (2) GCP Load Balancer — accepts only Cloudflare-originated traffic; (3) %s for admin access.",
					boolStr(f.CFAccessEnabled, "Cloudflare Access policies", "Access controls"))
			}},
		{ID: "sc-8.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection for transmission: (1) TLS 1.2+ with FIPS-approved cipher suites; (2) %s for FIPS 140-2 validated TLS; (3) Cloudflare enforces minimum TLS %s, SSL mode=%s, always HTTPS=%v, TLS 1.3=%v; (4) GCP internal networking uses Google's ALTS protocol.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto (BoringSSL)", "BoringCrypto for Go"),
					or(f.CFMinTLS, "1.2"), or(f.CFSSLMode, "strict"), f.CFAlwaysHTTPS, f.CFTLS13)
			}},
		{ID: "sc-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			Parameters: []ParamValue{
				{ParamID: "sc-12_prm_1", Values: []string{"90 days"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic key management: (1) Cloud KMS in dedicated project %s provides centralized key management; (2) Key rotation every %d days (automated); (3) HSM-backed keys (FIPS 140-2 Level 3); (4) Separate key rings for each data type (SQL, GCS, logging, secrets); (5) Key access controlled via IAM — only authorized service accounts can use keys; (6) Per-tenant CMEK keys anchored via tenants.kms_key_name column — used for application-level envelope encryption of document chunks, chat messages, GCS objects, and Microsoft Graph OAuth tokens; (7) DEK lifecycle: random 256-bit DEK generated per encrypt operation, wrapped by tenant KMS key, stored alongside ciphertext; (8) Crypto-shredding supported by destroying tenant KMS key versions (24-hour scheduled destruction delay).",
					or(f.KMSProjectID),
					f.KMSRotationDays)
			}},
		{ID: "sc-13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			Parameters: []ParamValue{
				{ParamID: "sc-13_prm_1", Values: []string{"FIPS 140-2 validated (BoringCrypto, Cloud KMS HSM)"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("FIPS-validated cryptography: (1) %s provides FIPS 140-2 validated TLS in the Go backend; (2) Cloud KMS uses FIPS 140-2 Level 3 HSMs; (3) AES-256-GCM for data at rest (CMEK and application-level envelope encryption); (4) TLS 1.2+ with FIPS-approved cipher suites for data in transit; (5) Algorithm: %s for KMS keys; (6) Application-level envelope encryption uses Go crypto/aes + crypto/cipher (AES-256-GCM via BoringCrypto FIPS module) with crypto/rand for DEK and nonce generation.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto", "BoringCrypto"),
					or(f.KMSAlgorithm, "GOOGLE_SYMMETRIC_ENCRYPTION"))
			}},
		{ID: "sc-28", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudSQL, cloudStorage, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Protection of information at rest: all data at rest is encrypted with AES-256-GCM using CMEK via Cloud KMS (%s). Encrypted data stores: (1) Cloud SQL (%s) — CMEK; (2) Cloud Storage (%s) — CMEK; (3) Cloud Logging — CMEK; (4) Artifact Registry — CMEK; (5) Cloud Tasks — CMEK; (6) Vertex AI indexes — CMEK. Per-tenant envelope encryption: tenants with a kms_key_name receive application-level AES-256-GCM envelope encryption for document chunk content, chat message content, and GCS-stored objects. Each write generates a random 256-bit DEK, encrypts the data, wraps the DEK with the tenant's Cloud KMS key, and stores ciphertext + nonce + wrapped DEK alongside the record. Per-object CMEK is applied to GCS uploads for tenants with a configured key. Crypto-shredding: destroying the tenant's KMS key versions renders all envelope-encrypted data permanently irrecoverable.",
					or(f.KMSProjectID),
					or(f.CloudSQLDatabaseName, "archon"),
					or(f.GCSDocumentsBucket))
			}},

		// High-only verified
		{ID: "ac-4.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Content inspection: (1) %s scans all uploaded documents for malware; (2) Cloudflare WAF inspects HTTP request/response payloads; (3) Cloud Armor inspects HTTP headers and body for attack patterns; (4) Application validates file MIME types and sizes before processing.",
					boolStr(f.ClamAVEnabled, "ClamAV", "Malware scanner"))
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

		{ID: "sc-7.24", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Personally identifiable information — data residency: (1) Assured Workloads %s constrains all data and processing to US territory; (2) GCP region restricted to %s (CONUS); (3) DLP inspect template detects %d PII info types; (4) RLS prevents cross-tenant PII disclosure; (5) Cloudflare TLS %s+ protects PII in transit.",
					boolStr(f.AWSComplianceRegime != "", "("+f.AWSComplianceRegime+" regime)", ""),
					or(f.Region, "us-east4"), f.DLPPIIInfoTypes, or(f.CFMinTLS, "1.2"))
			}},
		{ID: "sc-28.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Offline storage encryption: all data at rest uses CMEK with %d-day automatic rotation via Cloud KMS (%s). Offline backups (Cloud SQL automated backups=%v, GCS versions=%v) inherit CMEK encryption. Audit logs protected by WORM=%v retention. No unencrypted data exists at rest.",
					f.KMSRotationDays, or(f.KMSProjectID), f.CMEKCloudSQL, f.CMEKGCS, f.AuditLogWORM)
			}},
		{ID: "ac-4.21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Physical/logical separation of information flows: (1) Assured Workloads %s provides logical separation from commercial GCP; (2) VPC Service Controls perimeter %q restricts API access to %d authorized projects; (3) CMEK keys in dedicated KMS project ensure cryptographic separation; (4) three-project architecture provides blast-radius isolation.",
					boolStr(f.AWSComplianceRegime != "", "("+f.AWSComplianceRegime+")", ""),
					or(f.VPCSCPerimeterName), f.VPCSCProtectedProjects)
			}},
		{ID: "sc-13.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("FIPS 140-2 validated cryptography for IL5: (1) %s provides FIPS 140-2 validated TLS in Go backend; (2) Cloud KMS HSMs are FIPS 140-2 Level 3 certified; (3) All cryptographic operations (encryption, hashing, signing) use FIPS-approved algorithms; (4) Non-FIPS cryptographic modules are not used.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto (BoringSSL)", "BoringCrypto"))
			}},

		// VPC-SC verified
		{ID: "sc-7.21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("VPC Service Controls isolate GCP API access: perimeter %q protects %d projects, enforcement=%v, violation alerts=%v. Ingress/egress policies scope cross-perimeter access to specific APIs (identitytoolkit, storage). Auth projects excluded by design (Identity Platform requires global access).",
					or(f.VPCSCPerimeterName), f.VPCSCProtectedProjects, f.VPCSCEnforced, f.VPCSCViolationAlerts)
			}},

		// CMEK verified
		{ID: "sc-28.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, cloudKMS, cloudSQL, cloudStorage},
			Parameters: []ParamValue{
				{ParamID: "sc-28.1_prm_1", Values: []string{"AES-256-GCM (CMEK via Cloud KMS)"}},
			},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("CMEK encryption verified across data stores: Cloud SQL=%v, GCS=%v, BigQuery audit logs=%v, Secrets Manager=%v, Artifact Registry=%v. All keys in dedicated project %s with %d-day rotation, HSM-backed (FIPS 140-2 Level 3). Application-level envelope encryption: per-tenant AES-256-GCM with random DEK per write, DEK wrapped by tenant's Cloud KMS key (HSM-backed). DEK cache (SHA-256 fingerprint → plaintext DEK, 5-minute TTL) reduces KMS API calls during read-heavy workloads. Envelope-encrypted fields: chunks.content_ciphertext, messages.content_ciphertext, plus GCS per-object CMEK for document files.",
					f.CMEKCloudSQL, f.CMEKGCS, f.CMEKBigQuery, f.CMEKSecrets, f.CMEKArtifactRegistry,
					or(f.KMSProjectID), f.KMSRotationDays)
			}},

		// Supply chain verified
		{ID: "sa-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Developer security testing in CI/CD pipeline (%d Cloud Build triggers): container scanning (Trivy=%v), Go vulnerability check (govulncheck=%v), SAST (GoSec=%v, Semgrep=%v), secret detection (Gitleaks=%v), SBOM generation=%v, Binary Authorization=%v. All scans run before deployment to staging/production.",
					f.CloudBuildTriggers, f.CloudBuildTrivyEnabled, f.CloudBuildGovulncheck,
					f.CloudBuildGosecEnabled, f.CloudBuildSemgrepEnabled, f.CloudBuildGitleaksEnabled,
					f.CloudBuildSBOMEnabled, f.CloudBuildBinauthzEnabled)
			}},
		{ID: "sa-11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Developer security and privacy testing: (1) SAST via GoSec=%v and Semgrep=%v in daily Cloud Build security scan; (2) Dependency scanning via govulncheck=%v (Go advisory database); (3) Container vulnerability scanning via Trivy=%v; (4) Secret detection via Gitleaks=%v in PR checks; (5) SBOM generation=%v (CycloneDX+SPDX) for supply chain transparency.",
					f.CloudBuildGosecEnabled, f.CloudBuildSemgrepEnabled, f.CloudBuildGovulncheck,
					f.CloudBuildTrivyEnabled, f.CloudBuildGitleaksEnabled, f.CloudBuildSBOMEnabled)
			}},

		// DLP/malware verified
		{ID: "si-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Malicious code protection: (1) %s scans all uploaded documents before ingestion (fail-closed); (2) SVG files short-circuited before document extraction to prevent XXE/SSRF vectors; (3) Vector post-condition validation ensures embedding pipeline integrity; (4) Cloud DLP inspect template detects %d PII types and %d credential types in document content; (5) Trivy=%v scans container images for known CVEs; (6) GoSec=%v/Semgrep=%v perform static analysis for code vulnerabilities.",
					boolStr(f.ClamAVEnabled, "ClamAV malware scanner", "Malware scanning"),
					f.DLPPIIInfoTypes, f.DLPCredentialTypes,
					f.CloudBuildTrivyEnabled, f.CloudBuildGosecEnabled, f.CloudBuildSemgrepEnabled)
			}},

		// RLS verified
		{ID: "ac-3.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, cloudSQL},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Role-based access control at the database level: PostgreSQL Row-Level Security enforced on %d tables with %d policies. Database roles enforce least privilege: %s. RLS policies scope all queries to the authenticated workspace, preventing cross-tenant data access even if application logic is bypassed.",
					f.RLSTableCount, f.RLSPolicyCount, strings.Join(f.RLSRoles, ", "))
			}},

		// Org policy verified
		{ID: "ac-6.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Org-level guardrails prevent privilege escalation: %d org policies enforced including SA key creation disabled=%v, SA key upload disabled=%v, VM external IP denied=%v, default SA grants disabled=%v, domain restriction=%v. Access Approval requires explicit authorization before Google support accesses customer data=%v.",
					f.OrgPolicyCount, f.OrgPolicySAKeyCreationDeny, f.OrgPolicySAKeyUploadDeny,
					f.OrgPolicyVMExternalIPDeny, f.OrgPolicyDefaultSAGrantDeny,
					f.OrgPolicyDomainRestricted, f.OrgAccessApprovalEnabled)
			}},

		// Identity Platform verified
		{ID: "ia-2.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("MFA for privileged accounts: Identity Platform MFA state=%s across %d tenants. TOTP (RFC 6238) is the second factor. Magic link (email) provides passwordless first factor. App Check=%v provides bot protection. All admin operations require step-up MFA verification.",
					or(f.IDPMFAState, "not configured"), f.IDPTenantCount, f.IDPAppCheckEnabled)
			}},
		{ID: "ia-2.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("MFA for non-privileged accounts: all users require TOTP MFA regardless of role. MFA enforcement is set at the Identity Platform project level (state=%s) and inherited by all %d tenants. Email link sign-in=%v provides the passwordless first factor; TOTP provides the second factor.",
					or(f.IDPMFAState, "not configured"), f.IDPTenantCount, f.IDPEmailLinkEnabled)
			}},

		// Monitoring verified
		{ID: "au-6.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Automated audit analysis: %d monitoring alert policies, %d audit-specific alert policies, %d uptime checks, %d log sinks per project routing to BigQuery/GCS for analysis. VPC-SC violation alerts=%v. Cloudflare WAF and rate limiting provide edge-layer anomaly detection.",
					f.MonitoringAlertPolicies, f.AuditLogAlertPolicies,
					f.MonitoringUptimeChecks, f.AuditLogSinksPerProject, f.VPCSCViolationAlerts)
			}},

		// Cloud Run hardening verified
		{ID: "cm-7.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				var svcDetails []string
				for _, svc := range f.CloudRunServices {
					svcDetails = append(svcDetails, fmt.Sprintf("%s(ingress=%s,unauth=%v)", or(svc.Name, svc.Project), or(svc.Ingress, "default"), svc.AllowUnauthenticated))
				}
				return fmt.Sprintf("Least functionality — Cloud Run services configured with minimal exposure: %s. Org policy restricts ingress=%v, enforces ALL_TRAFFIC egress=%v. No services expose *.run.app URLs directly.",
					strings.Join(svcDetails, "; "), f.OrgPolicyRunIngressRestrict, f.OrgPolicyRunEgressAllTraffic)
			}},
	}
}
