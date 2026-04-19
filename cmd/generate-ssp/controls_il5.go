package main

import "fmt"

func il5Controls() []ControlDef {
	return []ControlDef{
		// ── AC — IL5 overlay ──────────────────────────────────────────────
		{ID: "ac-2.7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Privileged role-based access scheme: (1) four application roles (master_admin, admin, editor, viewer) with per-RPC enforcement; (2) three database roles (%s) enforce least-privilege at the PostgreSQL layer; (3) GCP IAM custom roles scoped per service account; (4) no shared or group privileged accounts.",
					joinOr(f.RLSRoles))
			}},
		{ID: "ac-3.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudSQL},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Discretionary access control: workspace owners (master_admin role) control access to their workspace data. PostgreSQL RLS (%d tables, %d policies) enforces workspace-scoped access. Members are granted access via admin invite or SCIM provisioning — the workspace owner controls the membership list.",
					f.RLSTableCount, f.RLSPolicyCount)
			}},
		{ID: "ac-3.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return "Audited override of access control mechanisms: (1) break-glass access to production GCP requires CEO/CTO approval with time-limited IAM Conditions (max 4 hours); (2) all overrides logged in GCP Cloud Audit Logs and application audit log; (3) break-glass events trigger immediate security notification email; (4) post-incident review required."
			}},
		{ID: "ac-4.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Security policy filters on data flows: (1) Cloudflare WAF (managed=%v, OWASP=%v) filters inbound HTTP; (2) Cloud Armor enforces origin restriction and OWASP CRS; (3) DLP inspect template filters %d PII types and %d credential types from document content; (4) ClamAV filters malware from uploads; (5) VPC egress firewall filters outbound to allowlisted FQDNs only.",
					f.CFWAFManagedRuleset, f.CFWAFOWASPRuleset, f.DLPPIIInfoTypes, f.DLPCredentialTypes)
			}},
		{ID: "ac-6.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privilege levels for code execution: (1) Cloud Run containers execute as non-root with read-only filesystem; (2) gVisor sandbox restricts syscall surface; (3) application code runs under a dedicated service account per service with least-privilege IAM; (4) no privileged containers or host-level access."
			}},
		{ID: "ac-16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security and privacy attributes: (1) Firebase JWTs carry user identity, tenant ID, MFA verification status, and custom claims; (2) GCP resource labels carry project tier (admin/ops/app), environment, compliance regime; (3) Assured Workloads labels mark IL5 resources; (4) audit log entries carry security context (IP, user agent, role, action)."
			}},
		{ID: "ac-16.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Dynamic attribute association: (1) Firebase ID tokens dynamically include tenant membership, MFA status, and custom claims per authentication event; (2) SCIM synchronization dynamically updates user role attributes from authoritative IdP; (3) Cloudflare Access JWT attributes reflect real-time device posture. %d IDP tenants with dynamic attribute binding.",
					f.IDPTenantCount)
			}},

		// ── AU — IL5 overlay ──────────────────────────────────────────────
		{ID: "au-3.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Centralized analysis of problematic events: Cloud Logging aggregates events from all sources. %d audit alert policies detect problematic patterns (auth failures, privilege escalation, data exfiltration attempts). %d monitoring alert policies cover infrastructure anomalies. Alerts trigger PagerDuty for immediate investigation.",
					f.AuditLogAlertPolicies, f.MonitoringAlertPolicies)
			}},
		{ID: "au-5.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Real-time alerts for audit event failures: %d monitoring alert policies and %d audit alert policies configured in Cloud Monitoring. Alerts fire within minutes of detection and page on-call via PagerDuty. Log sink failures generate GCP-level alerts.",
					f.MonitoringAlertPolicies, f.AuditLogAlertPolicies)
			}},

		// ── IA — IL5 overlay ──────────────────────────────────────────────
		{ID: "ia-2.13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Out-of-band authentication: magic link email serves as an out-of-band authentication channel separate from the browser session. The email link is sent to the user's verified email address and must be opened to complete authentication. TOTP MFA provides a second independent channel via authenticator app."
			}},
		{ID: "ia-3.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return "Cryptographic bidirectional authentication: (1) TLS provides mutual cryptographic authentication between client and server; (2) Cloudflare Access JWT provides cryptographic service-to-service authentication (ECDSA-signed); (3) GCP service account identity tokens provide cryptographic inter-service authentication; (4) SAML assertions use XML signatures for bidirectional trust."
			}},
		{ID: "ia-5.13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return "Expiration of cached authenticators: (1) Firebase ID tokens expire after 1 hour; (2) Firebase refresh tokens can be revoked server-side via Admin SDK; (3) JWKS cache expires after 5 minutes, forcing re-fetch from Cloudflare; (4) session cookies have explicit expiration; (5) SCIM bearer tokens do not expire but can be rotated on demand."
			}},

		// ── SC — IL5 overlay ──────────────────────────────────────────────
		{ID: "sc-7.9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Restrict threatening outgoing communications: (1) VPC egress firewall deny-all default with FQDN-based allowlist; (2) Cloud Run VPC egress configured for controlled outbound; (3) Cloudflare rate limiting (login=%v, %d req/%ds) blocks outbound abuse; (4) DLP scanning prevents data exfiltration via uploaded content.",
					f.CFLoginRateLimitEnabled, f.CFLoginRateLimit, f.CFLoginRatePeriod)
			}},
		{ID: "sc-7.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Prevent exfiltration: (1) VPC Service Controls perimeter %q prevents unauthorized API-level data extraction from %d projects; (2) DLP inspect template detects %d PII types in document content; (3) VPC egress firewall blocks all non-allowlisted outbound; (4) Cloud Storage has no public access; (5) audit logging tracks all data access.",
					or(f.VPCSCPerimeterName), f.VPCSCProtectedProjects, f.DLPPIIInfoTypes)
			}},
		{ID: "sc-8.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Pre/post transmission handling: (1) data encrypted at rest with CMEK before transmission (AES-256-GCM); (2) TLS %s+ protects data in transit; (3) data re-encrypted at rest at destination; (4) no cleartext data exists at any point — encryption is continuous from upload through storage through retrieval.",
					or(f.CFMinTLS, "1.2"))
			}},
		{ID: "sc-12.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Symmetric key management: Cloud KMS manages symmetric CMEK keys (AES-256-GCM) with %d-day automatic rotation, HSM-backed (FIPS 140-2 Level 3). Keys stored in dedicated project %s with independent IAM. Key versions retained for decryption of historical data.",
					f.KMSRotationDays, or(f.KMSProjectID))
			}},
		{ID: "sc-12.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Asymmetric key management: Cloud KMS manages asymmetric signing keys for Binary Authorization attestations. HSM-backed (FIPS 140-2 Level 3). Asymmetric keys do not rotate automatically (by design — attestation verification requires stable public keys). Keys in project %s.",
					or(f.KMSProjectID))
			}},
		{ID: "sc-12.6", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Physical control of cryptographic keys: inherited from GCP. Cloud KMS HSMs are physically secured within Google data centers. FIPS 140-2 Level 3 certification requires physical tamper evidence and tamper response mechanisms. Key material never leaves the HSM boundary in plaintext."
			}},
		{ID: "sc-23.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Allowed certificate authorities: (1) Cloudflare uses DigiCert, Let's Encrypt, and Google Trust Services as CAs (configurable per zone); (2) GCP-managed certificates use Google Trust Services; (3) HSTS (always_https=%v) prevents downgrade attacks; (4) Certificate Transparency logs provide public auditability.",
					f.CFAlwaysHTTPS)
			}},
		// ── SI — IL5 overlay ──────────────────────────────────────────────
		{ID: "si-4.14", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Wireless intrusion detection: inherited from GCP. Google monitors wireless access within data center facilities. Not applicable at the SaaS layer — Latent Archon has no organization-controlled wireless infrastructure."
			}},
		{ID: "si-7.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection of integrity: (1) CMEK encryption (AES-256-GCM) provides authenticated encryption with integrity verification; (2) Binary Authorization uses KMS-signed attestations; (3) TLS provides integrity protection in transit; (4) all keys HSM-backed (FIPS 140-2 Level 3) in project %s.",
					or(f.KMSProjectID))
			}},
		{ID: "si-7.15", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Code authentication: (1) Binary Authorization=%v verifies cryptographic attestations before deploying container images to Cloud Run; (2) Go modules authenticated via checksum database (sum.golang.org); (3) npm packages authenticated via package-lock.json integrity hashes; (4) Gitleaks=%v prevents credential leakage in code.",
					f.CloudBuildBinauthzEnabled, f.CloudBuildGitleaksEnabled)
			}},
	}
}
