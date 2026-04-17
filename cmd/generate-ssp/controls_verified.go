package main

import "fmt"

func verifiedControls() []ControlDef {
	return []ControlDef{
		// AC family
		{ID: "ac-2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("(a) Latent Archon defines four organization-level account types: `master_admin`, `admin`, `editor`, and `viewer`. Each account type has specific privileges enforced per-RPC in the Connect-RPC interceptor chain. Service accounts (e.g., noreply@latentarchon.com) are a distinct non-interactive type blocked from authentication.\n(b) Account managers are designated per customer organization. The `master_admin` role serves as the organization account manager.\n(c) Conditions for group and role membership are enforced by the RBAC model. Users must be explicitly invited to an organization (via invite token or SCIM provisioning) and granted workspace access. The auth interceptor enforces an org membership gate.\n(d) Authorized users and role membership are specified per-organization by the `master_admin` through the admin API (`InviteMember`, `UpdateMemberRole`, `RemoveMember` RPCs). For SCIM-enabled organizations, user lifecycle is managed automatically by the customer IdP.\n(e) Account creation requires approval by an org admin (explicit invite) or automated provisioning via SCIM 2.0 from an authorized customer IdP. JIT provisioning auto-creates accounts on first SSO login.\n(f) Accounts are created via invite tokens (time-limited), SCIM 2.0, or JIT provisioning. Accounts are disabled via Firebase Admin SDK `DisableUser()` or SCIM DELETE. Accounts are removed via `RemoveMember` RPC or self-service `CloseAccount` RPC (requires step-up MFA). Automated 90-day data purge runs via Cloud Scheduler.\n(g) System access is monitored through comprehensive audit logging (`internal/audit/logger.go`). All authentication events, role changes, and SCIM actions are recorded with user ID, IP, user agent, timestamp, and correlation ID.\n(h) Account managers (org `master_admin`) are notified of account changes via real-time security email notifications covering: role escalation, auth failures, member changes, SCIM events, and deletions.\n(i) Authorization requires: (1) valid Firebase Auth JWT, (2) MFA verification, (3) organization membership, (4) appropriate RBAC role, and (5) workspace membership for data access.\n(j) All accounts are reviewed by the org `master_admin` through the admin dashboard. Quarterly access reviews tracked via Drata.\n(k) Role transfers handled via admin API or SCIM group-to-role mapping.\n(l) Accounts deprovisioned within 24 hours via SCIM DELETE or manual removal. Self-service closure via `CloseAccount` RPC with step-up MFA. Row-level security on %s enforces data isolation post-deprovisioning.", or(f.CloudSQLDatabaseName, "archon"))
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
				return fmt.Sprintf("Information flow is controlled at multiple layers: (1) Cloudflare Edge WAF enforces geo-blocking (US-only) %s; (2) Cloud Armor origin WAF restricts traffic to Cloudflare IPs only %s; (3) VPC egress firewall is deny-all by default with FQDN allowlist for GCP APIs only; (4) Cloud Run services configured with ingress=%s restricting to internal + load-balancer traffic; (5) Cloud SQL has no public IP (public_ip=%v, enforced by org policy sql.restrictPublicIp); (6) Vertex AI accessed via Private Service Connect (PSC) within the VPC.",
					boolStr(f.CFGeoBlockingEnabled, "(active)", "(module exists)"),
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
		{ID: "sc-7.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("External telecommunications services are managed at: (1) Cloudflare (DNS, WAF, CDN, Zero Trust Access) — all external traffic enters through Cloudflare; (2) GCP Load Balancer — accepts only Cloudflare-originated traffic; (3) %s for admin access.",
					boolStr(f.CFAccessEnabled, "Cloudflare Access policies", "Access controls"))
			}},
		{ID: "sc-8.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection for transmission: (1) TLS 1.2+ with FIPS-approved cipher suites; (2) %s for FIPS 140-2 validated TLS; (3) Cloudflare enforces minimum TLS 1.2 with modern cipher suites; (4) GCP internal networking uses Google's ALTS protocol.",
					boolStr(f.BoringCrypto, "GOEXPERIMENT=boringcrypto (BoringSSL)", "BoringCrypto for Go"))
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

		// SI family
		{ID: "si-3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{thisSystem, clamAV},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Malicious code protection: (1) %s provides real-time malware scanning for all uploaded documents; (2) ClamAV is configured as fail-closed in production — upload rejected if scan fails; (3) Container images scanned by Trivy for known malware signatures; (4) gitleaks scans for secrets/credentials in source code.",
					boolStr(f.ClamAVEnabled, "ClamAV malware scanner (Cloud Run service)", "ClamAV malware scanner"))
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

		// IL5 verified
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
