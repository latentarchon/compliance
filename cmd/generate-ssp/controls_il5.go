package main

import "fmt"

func il5Controls() []ControlDef {
	return []ControlDef{
		// ── AC — IL5 overlay ──────────────────────────────────────────────
		{ID: "ac-2.7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
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
		{ID: "ac-6.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
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
		{ID: "au-5.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
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
		{ID: "ia-5.13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
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
		{ID: "sc-7.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
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
		{ID: "sc-12.6", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
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
		{ID: "si-4.14", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
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
		{ID: "si-7.15", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Code authentication: (1) Binary Authorization=%v verifies cryptographic attestations before deploying container images to Cloud Run; (2) Go modules authenticated via checksum database (sum.golang.org); (3) npm packages authenticated via package-lock.json integrity hashes; (4) Gitleaks=%v prevents credential leakage in code.",
					f.CloudBuildBinauthzEnabled, f.CloudBuildGitleaksEnabled)
			}},

		// ── AC — IL5 overlay (additional) ─────────────────────────────────
		{ID: "ac-12.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("User-initiated logouts: the application provides an explicit logout capability that terminates the authenticated session. Session timeout is configured at %d minutes. On logout, the Firebase ID token is revoked server-side via Admin SDK and the client clears all cached tokens.",
					f.SessionTimeoutMinutes)
			}},
		{ID: "ac-12.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI},
			NarrativeFn: func(f *InfraFacts) string {
				return "Termination message: the application displays an explicit logout confirmation message to the user upon session termination. The UI redirects to a dedicated logout page that confirms the session has ended and provides a link to re-authenticate."
			}},
		{ID: "ac-16.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Maintenance of attribute association by authorized personnel: (1) workspace administrators maintain role assignments within their tenant; (2) SCIM provisioning from customer IdP maintains user-to-group attribute bindings; (3) %d IdP tenants enforce authoritative attribute sources; (4) attribute changes are audit-logged.",
					f.IDPTenantCount)
			}},
		{ID: "ac-16.7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Consistent attribute interpretation: (1) JWT claims (tenant_id, role, mfa_verified) are interpreted identically across all distributed services (app-api, admin-api, ops-service); (2) OIDC standard claim semantics enforced; (3) protobuf message definitions ensure type-safe attribute transmission; (4) centralized JWKS validation guarantees consistent trust."
			}},
		{ID: "ac-17.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF},
			NarrativeFn: func(f *InfraFacts) string {
				return "Protection of remote access mechanism information: (1) Cloudflare Access policies and configuration are managed via IaC (Terraform) with restricted access; (2) service tokens are stored in GCP Secret Manager with CMEK encryption; (3) access mechanism details are not exposed to end users; (4) administrative access to remote access configuration requires MFA and break-glass approval."
			}},
		{ID: "ac-17.9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Disconnect or disable remote access: (1) Cloudflare Access applications (%d configured) can be individually disabled to immediately terminate remote access; (2) service tokens can be revoked; (3) Firebase user sessions can be revoked server-side; (4) GCP IAM bindings can be removed to disable administrative access.",
					f.CFAccessApps)
			}},
		{ID: "ac-17.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Authentication of remote commands: (1) all API requests require a valid Firebase ID token (ECDSA-signed JWT); (2) Cloudflare Access JWT validates service identity for inter-service calls; (3) %d Cloudflare Access service tokens authenticate automated commands; (4) GCP service account identity tokens authenticate Cloud Run-to-Cloud Run calls.",
					f.CFAccessServiceTokens)
			}},
		{ID: "ac-20.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Restricted use of non-organizationally owned systems: (1) org policy denies SA key creation=%v, preventing external system credential issuance; (2) domain-restricted sharing=%v limits IAM grants to organizational domains; (3) VPC Service Controls perimeter %q blocks API access from non-approved networks; (4) Cloudflare Access restricts application access to managed devices.",
					f.OrgPolicySAKeyCreationDeny, f.OrgPolicyDomainRestricted, or(f.VPCSCPerimeterName))
			}},
		{ID: "ac-23", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudSQL, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Data mining protection: (1) DLP scanning detects %d PII info types and %d credential types in uploaded content; (2) PostgreSQL RLS (%d tables, %d policies) prevents cross-tenant data aggregation; (3) VPC Service Controls (enforced=%v) prevent bulk API-level data extraction; (4) no direct database access — all queries pass through application-layer authorization.",
					f.DLPPIIInfoTypes, f.DLPCredentialTypes, f.RLSTableCount, f.RLSPolicyCount, f.VPCSCEnforced)
			}},

		// ── AU — IL5 overlay (additional) ─────────────────────────────────
		{ID: "au-9.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudStorage},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Dual authorization for audit movement/deletion: (1) audit log WORM protection=%v prevents deletion during retention period; (2) audit log sink deletion requires org-level IAM (logging.admin) plus resource-level permission — no single principal can unilaterally modify or delete audit data; (3) %d sinks per project route logs to immutable destinations.",
					f.AuditLogWORM, f.AuditLogSinksPerProject)
			}},
		{ID: "au-9.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudStorage},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Read-only access to audit information: (1) audit log WORM=%v enforces write-once-read-many semantics — logs cannot be modified after ingestion; (2) %d log sinks per project export to locked Cloud Storage buckets; (3) IAM roles grant logging.viewer (read-only) to security personnel; (4) no principal has logging.buckets.delete on audit sinks.",
					f.AuditLogWORM, f.AuditLogSinksPerProject)
			}},
		{ID: "au-14", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Session audit: (1) Cloud Logging captures all authenticated session activity including API calls, data access, and admin actions; (2) audit log retention is %d days; (3) session events include user identity, IP address, action, resource, and timestamp; (4) %d alert policies monitor session anomalies.",
					f.AuditLogRetentionDays, f.AuditLogAlertPolicies)
			}},
		{ID: "au-14.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Session audit at system startup: Cloud Run services initiate audit logging at container startup. GCP Cloud Audit Logs capture all API activity from the moment the service begins accepting traffic. No user-configurable delay — audit begins before the readiness probe passes."
			}},
		{ID: "au-14.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Remote viewing of session content: Cloud Logging provides real-time remote viewing of audit records via the GCP Console Logs Explorer. Authorized personnel can view live session audit data, filter by user identity, and correlate events across services. No direct session replay — audit records capture API-level activity."
			}},
		{ID: "au-16.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Identity preservation in cross-organizational audit trails: (1) GCP Cloud Audit Logs preserve the original caller identity (principalEmail) across all cross-project API calls; (2) Firebase user UID is carried through all application-layer audit entries; (3) Cloudflare Access JWT subject is logged at the edge layer; (4) no identity translation occurs — original identity is preserved end-to-end."
			}},
		{ID: "au-16.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Sharing of audit information: (1) audit log sinks (%d per project) can export to customer-designated Cloud Storage buckets for cross-organizational sharing; (2) WORM protection=%v ensures shared audit data integrity; (3) audit data is available in structured JSON format for automated consumption; (4) VPC SC violation alerts=%v notify of boundary events.",
					f.AuditLogSinksPerProject, f.AuditLogWORM, f.VPCSCViolationAlerts)
			}},

		// ── CM — IL5 overlay ──────────────────────────────────────────────
		{ID: "cm-3.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Automated security response to unauthorized changes: (1) %d Cloud Build triggers enforce pipeline-only deployment — manual changes are blocked by IAM; (2) %d monitoring alert policies detect configuration drift; (3) Terraform state drift is detected on each plan; (4) unauthorized baseline changes trigger alerts and are automatically reverted by the next pipeline run.",
					f.CloudBuildTriggers, f.MonitoringAlertPolicies)
			}},
		{ID: "cm-5.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Limit library privileges: (1) Artifact Registry stores all container images and is the sole allowed registry for Cloud Run deployments; (2) Artifact Registry is CMEK-encrypted=%v; (3) write access restricted to Cloud Build service accounts only; (4) developers have read-only access; (5) no direct docker push — all images flow through CI pipeline.",
					f.CMEKArtifactRegistry)
			}},
		{ID: "cm-7.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Registration compliance for ports/protocols/services: (1) Cloud Run ingress=%s restricts inbound to authorized sources; (2) only HTTPS (443) is exposed externally via Cloudflare; (3) VPC firewall rules enforce deny-all-ingress default with explicit allowlist; (4) no SSH, RDP, or other administrative ports are exposed; (5) internal services communicate over private VPC only.",
					or(f.CloudRunIngress, "internal-and-cloud-load-balancing"))
			}},
		{ID: "cm-7.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Binary/executable code restrictions: (1) Binary Authorization=%v requires cryptographic attestation before container execution; (2) Trivy scanning=%v checks for known vulnerabilities in binary dependencies; (3) only code built by the organization's CI pipeline is permitted; (4) no third-party binary uploads accepted without source review.",
					f.CloudBuildBinauthzEnabled, f.CloudBuildTrivyEnabled)
			}},
		{ID: "cm-7.9", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Prohibiting use of unauthorized hardware: inherited from GCP. The system is a SaaS application running on GCP Cloud Run — no organization-controlled hardware exists. GCP manages all physical hardware inventory, tracking, and authorization within its data centers per FedRAMP High authorization."
			}},
		{ID: "cm-10.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Open-source software restrictions: (1) Go modules verified via go.sum checksum database (sum.golang.org); (2) govulncheck=%v scans Go dependencies for known vulnerabilities; (3) npm packages verified via package-lock.json integrity hashes; (4) SBOM generation=%v documents all open-source components; (5) no unapproved open-source frameworks permitted.",
					f.CloudBuildGovulncheck, f.CloudBuildSBOMEnabled)
			}},
		{ID: "cm-11.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Software installation with privileged status: (1) Cloud Run containers use a read-only filesystem — no runtime software installation is possible; (2) gVisor sandbox restricts syscall surface preventing privilege escalation; (3) all software is installed at build time via Cloud Build pipeline only; (4) container runs as non-root with no CAP_SYS_ADMIN."
			}},

		// ── IA — IL5 overlay (additional) ─────────────────────────────────
		{ID: "ia-4.9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Attribute maintenance and protection in central storage: (1) Firebase Authentication serves as the central identity store with %d tenants; (2) user attributes (email, MFA status, custom claims) are maintained in protected Firebase project; (3) SCIM synchronization keeps attributes current with authoritative IdP; (4) attribute storage is CMEK-encrypted.",
					f.IDPTenantCount)
			}},
		{ID: "ia-5.14", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("PKI trust store management: (1) Cloudflare manages TLS certificates with minimum TLS version %s and SSL mode %s; (2) GCP-managed certificates use Google Trust Services CA; (3) TLS 1.3=%v enforced at the edge; (4) certificate transparency logs provide public audit trail; (5) trust stores are managed via IaC — no manual certificate installation.",
					or(f.CFMinTLS, "1.2"), or(f.CFSSLMode, "full"), f.CFTLS13)
			}},
		{ID: "ia-5.16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "In-person or trusted external party authenticator issuance: (1) SCIM provisioning from customer IdP serves as the trusted external party for initial authenticator binding; (2) IdP federation delegates authenticator issuance to the customer's vetted identity provider; (3) magic link email to verified address provides out-of-band verification; (4) MFA enrollment requires possession of the registered email account."
			}},
		{ID: "ia-12.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Supervisor authorization for account registration: (1) workspace creation requires an existing master_admin to invite new members; (2) admin invite flow ensures supervisor authorization before account provisioning; (3) SCIM provisioning inherits authorization from the customer IdP administrator; (4) self-registration is disabled — all accounts require explicit organizational authorization."
			}},

		// ── SC — IL5 overlay (additional) ─────────────────────────────────
		{ID: "sc-7.11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Restrict incoming communications to authorized sources: (1) Cloudflare proxy filters all inbound traffic (WAF managed=%v, OWASP=%v); (2) Cloud Armor restricts origin to Cloudflare IPs only (CF restriction=%v); (3) Cloud Run ingress=%s blocks direct access bypassing the proxy chain; (4) only HTTPS on port 443 is accepted.",
					f.CFWAFManagedRuleset, f.CFWAFOWASPRuleset, f.CloudArmorCFRestriction, or(f.CloudRunIngress, "internal-and-cloud-load-balancing"))
			}},
		{ID: "sc-7.13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Isolation of security tools: security tools are deployed in separate GCP projects — admin project (%s) for IAM and org policy management, ops project (%s) for monitoring/logging/alerting, app project (%s) for workloads. Each project has independent IAM, VPC, and audit logging. No co-mingling of security tool and application workloads.",
					or(f.AdminProjectID), or(f.OpsProjectID), or(f.AppProjectID))
			}},
		{ID: "sc-7.14", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Protection against unauthorized physical connections: inherited from GCP. All physical network infrastructure is managed by Google within FedRAMP-authorized data centers. No organization-controlled physical network connections exist. GCP enforces physical security controls per its FedRAMP High authorization."
			}},
		{ID: "sc-7.15", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Networked privileged accesses through dedicated interface: (1) Cloudflare Access (%d applications) provides a dedicated authenticated interface for privileged administrative access; (2) administrative APIs (admin-api) are separated from application APIs (app-api); (3) privileged GCP access requires break-glass approval and is routed through IAM Conditions with time limits.",
					f.CFAccessApps)
			}},
		{ID: "sc-7.25", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Connections to unclassified national security systems: (1) all external connections pass through Cloudflare proxy with WAF inspection (action=%s); (2) Cloud Armor enforces origin restriction=%v; (3) VPC Service Controls perimeter %q provides API-level boundary protection; (4) no direct connections to NSS without boundary protection.",
					or(f.CFWAFAction, "block"), f.CloudArmorCFRestriction, or(f.VPCSCPerimeterName))
			}},
		{ID: "sc-7.28", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, edgeWAF, cloudArmor},
			NarrativeFn: func(f *InfraFacts) string {
				return "Connections to public networks: (1) no direct connection to public networks — all inbound traffic is proxied through Cloudflare; (2) Cloud Run services have no public IP addresses; (3) outbound traffic is routed through VPC with egress firewall deny-all default; (4) only allowlisted FQDNs are reachable from application workloads."
			}},
		{ID: "sc-16.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Integrity verification of transmitted security attributes: (1) Firebase ID tokens are ECDSA-signed JWTs — signature verification ensures attribute integrity; (2) Cloudflare Access JWTs are verified against published JWKS endpoints; (3) SAML assertions use XML digital signatures; (4) any token with an invalid signature is rejected before attribute extraction."
			}},
		{ID: "sc-16.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform, edgeWAF},
			NarrativeFn: func(f *InfraFacts) string {
				return "Anti-spoofing for security attributes: (1) JWKS validation ensures only tokens signed by the trusted issuer are accepted; (2) Cloudflare Access JWT includes audience claim restricting token to specific application; (3) Firebase ID tokens are bound to the specific project; (4) replay protection via token expiration (1 hour) and nonce validation; (5) token substitution prevented by audience binding."
			}},
		{ID: "sc-16.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic binding of attributes to transmitted information: (1) TLS (min version %s) provides channel-level cryptographic binding; (2) JWT claims are cryptographically bound to the token via ECDSA signature — attributes cannot be modified without invalidating the signature; (3) CMEK encryption binds data attributes at the storage layer.",
					or(f.CFMinTLS, "1.2"))
			}},
		{ID: "sc-18.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI},
			NarrativeFn: func(f *InfraFacts) string {
				return "Identify unacceptable mobile code and take corrective actions: (1) Content-Security-Policy headers restrict JavaScript execution to same-origin and explicitly allowlisted sources; (2) frontend build process bundles all JavaScript — no runtime code loading from external sources; (3) CSP violation reports are logged for review; (4) inline script execution is blocked by CSP."
			}},
		{ID: "sc-18.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI},
			NarrativeFn: func(f *InfraFacts) string {
				return "Prevent downloading and execution of unacceptable mobile code: (1) Content-Security-Policy headers prevent loading scripts from unauthorized origins; (2) Subresource Integrity (SRI) hashes verify third-party resource integrity; (3) X-Content-Type-Options: nosniff prevents MIME-type sniffing attacks; (4) uploaded files are scanned by ClamAV before serving."
			}},
		{ID: "sc-18.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI},
			NarrativeFn: func(f *InfraFacts) string {
				return "Prevent automatic execution of mobile code: (1) CSP script-src directive prevents automatic script execution from untrusted sources; (2) no auto-run plugins or ActiveX controls are used; (3) all JavaScript is explicitly loaded via application bundle; (4) user-uploaded content is served with Content-Disposition: attachment to prevent in-browser execution."
			}},
		{ID: "sc-23.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Invalidate session identifiers at logout: (1) Firebase ID token is revoked server-side via Admin SDK revokeRefreshTokens on logout; (2) client-side tokens are cleared from memory and storage; (3) revoked tokens are rejected on subsequent API calls even if not yet expired; (4) session cookie is cleared with Max-Age=0."
			}},
		{ID: "sc-23.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Unique system-generated session identifiers: (1) Firebase generates cryptographically random unique session tokens using secure PRNG; (2) session identifiers are never derived from user input or predictable values; (3) each authentication event produces a new unique token; (4) token uniqueness is guaranteed by Firebase's globally distributed identity platform."
			}},
		{ID: "sc-28.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudKMS},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Protected storage for cryptographic keys: (1) Cloud KMS HSM (FIPS 140-2 Level 3) stores all CMEK keys in dedicated project %s; (2) key material never leaves the HSM boundary in plaintext; (3) algorithm=%s with %d-day automatic rotation; (4) IAM restricts key access to specific service accounts; (5) key usage is audit-logged.",
					or(f.KMSProjectID), or(f.KMSAlgorithm, "GOOGLE_SYMMETRIC_ENCRYPTION"), f.KMSRotationDays)
			}},

		// ── SI — IL5 overlay (additional) ─────────────────────────────────
		{ID: "si-2.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Automated patch management: (1) Trivy vulnerability scanning=%v runs on every build; (2) govulncheck=%v detects Go-specific vulnerabilities; (3) Semgrep=%v performs static analysis for security patterns; (4) Cloud Run base images are rebuilt regularly to incorporate OS-level patches; (5) Dependabot alerts notify of dependency vulnerabilities.",
					f.CloudBuildTrivyEnabled, f.CloudBuildGovulncheck, f.CloudBuildSemgrepEnabled)
			}},
		{ID: "si-2.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Removal of previous versions after update: (1) Cloud Run retains only a limited number of revisions — previous revisions are automatically cleaned up; (2) Artifact Registry lifecycle policies remove old container images after retention period; (3) each deployment fully replaces the previous version with no side-by-side execution; (4) rollback is achieved by redeploying a known-good image, not by retaining old versions."
			}},
		{ID: "si-3.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, clamAV},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Malicious code analysis: (1) ClamAV=%v scans uploaded files for malware signatures and behavioral patterns; (2) DLP template scans %d PII info types and %d credential types to detect data exfiltration payloads; (3) suspicious files are quarantined and logged; (4) malware detection events trigger alerts.",
					f.ClamAVEnabled, f.DLPPIIInfoTypes, f.DLPCredentialTypes)
			}},
		{ID: "si-4.15", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Wireless to wireline communications monitoring: inherited from GCP. The system has no organization-controlled wireless infrastructure. All communications are wireline (internet-based) through Cloudflare and GCP networking. GCP monitors wireless access within its data centers per FedRAMP High authorization."
			}},
		{ID: "si-4.24", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform, opsService},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Indicators of compromise: (1) %d audit log alert policies detect authentication anomalies, privilege escalation, and data exfiltration patterns; (2) %d monitoring alert policies detect infrastructure-level IoCs (resource exhaustion, unexpected scaling); (3) VPC SC violation alerts=%v detect perimeter breach attempts; (4) alerts distributed via PagerDuty for immediate response.",
					f.AuditLogAlertPolicies, f.MonitoringAlertPolicies, f.VPCSCViolationAlerts)
			}},
		{ID: "si-4.25", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform, opsService},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Optimize network traffic analysis: (1) VPC flow logs capture all network traffic metadata for analysis; (2) Cloud Logging aggregates flow logs with application logs for correlation; (3) %d monitoring alert policies detect traffic anomalies; (4) %d uptime checks verify endpoint availability; (5) Cloudflare analytics provide edge-layer traffic visibility.",
					f.MonitoringAlertPolicies, f.MonitoringUptimeChecks)
			}},
		{ID: "si-6.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, opsService},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Report verification results: (1) the generate-ssp compliance scanner outputs structured verification results for all controls; (2) %d monitoring alert policies report security function status; (3) Cloud Build pipeline reports scan results (Trivy, gosec, Semgrep) as structured output; (4) verification results are stored in audit logs for review.",
					f.MonitoringAlertPolicies)
			}},
		{ID: "si-7.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Auditing capability for significant integrity events: (1) Binary Authorization=%v logs all attestation verification results; (2) %d monitoring alert policies detect integrity violations (deployment failures, unauthorized image attempts); (3) Cloud Audit Logs capture all resource modifications; (4) integrity events trigger immediate PagerDuty notifications.",
					f.CloudBuildBinauthzEnabled, f.MonitoringAlertPolicies)
			}},
		{ID: "si-7.9", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Verify boot process: inherited from GCP. Cloud Run containers execute within gVisor sandbox on GCP-managed infrastructure. GCP verifies the boot process of underlying compute nodes using Shielded VM with Secure Boot, vTPM, and integrity monitoring. The application layer does not control the boot process."
			}},
		{ID: "si-7.10", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Protection of boot firmware: inherited from GCP. All boot firmware on GCP compute infrastructure is managed and protected by Google. Titan security chips verify firmware integrity at boot. The SaaS application layer has no access to or control over boot firmware."
			}},
		{ID: "si-7.17", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Runtime application self-protection: (1) comprehensive input validation on all API endpoints with strict type checking; (2) BoringCrypto=%v provides FIPS-validated cryptographic primitives at runtime; (3) gVisor sandbox restricts syscall surface preventing runtime exploitation; (4) Cloud Run read-only filesystem prevents runtime binary modification.",
					f.BoringCrypto)
			}},
		{ID: "si-10.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI},
			NarrativeFn: func(f *InfraFacts) string {
				return "Predictable behavior on invalid input: (1) API endpoints return well-defined error responses (gRPC status codes) for all invalid input; (2) protobuf/gRPC type safety ensures predictable deserialization behavior; (3) invalid requests are logged with error details for audit; (4) no undefined behavior — all error paths are explicitly handled with structured responses."
			}},
		{ID: "si-10.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI, edgeWAF, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Restrict inputs to trusted sources and formats: (1) Cloudflare Access authenticates all inbound requests from trusted sources; (2) API authentication requires valid Firebase ID token from %d authorized tenants; (3) protobuf schemas enforce strict input format validation; (4) file uploads restricted to allowlisted MIME types with content-type verification.",
					f.IDPTenantCount)
			}},
		{ID: "si-10.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI, cloudSQL},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Injection prevention: (1) all database queries use parameterized SQL — no string concatenation in queries; (2) PostgreSQL RLS (%d policies) provides defense-in-depth against injection-based data access; (3) protobuf serialization prevents injection in inter-service communication; (4) CSP headers prevent client-side injection attacks.",
					f.RLSPolicyCount)
			}},
		{ID: "si-12.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, cloudStorage, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Information disposal: (1) Cloud Storage lifecycle policies automatically delete objects after the defined retention period; (2) audit logs are retained for %d days with WORM=%v then disposed via lifecycle policy; (3) CMEK key versions can be destroyed to render encrypted data unrecoverable; (4) Cloud SQL automated backups expire per retention configuration.",
					f.AuditLogRetentionDays, f.AuditLogWORM)
			}},
		{ID: "si-15", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, appAPI},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Information output filtering: (1) DLP scanning validates document output against %d PII info types before delivery to users; (2) API responses are filtered through protobuf serialization ensuring only defined fields are returned; (3) error responses are sanitized to prevent information leakage; (4) file download responses include content-type validation.",
					f.DLPPIIInfoTypes)
			}},
		{ID: "si-21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Information refresh at defined frequencies: (1) JWKS cache refreshes every 5 minutes from Cloudflare and Firebase endpoints; (2) Firebase ID tokens refresh every 1 hour via refresh token exchange; (3) Cloudflare Access JWT re-evaluates device posture at each refresh; (4) ClamAV virus definitions update daily; (5) DLP templates are refreshed on deployment."
			}},

		// ── SR — Supply Chain ─────────────────────────────────────────────
		{ID: "sr-3.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform, edgeWAF},
			NarrativeFn: func(f *InfraFacts) string {
				return "Diverse supply base: (1) multi-provider architecture uses GCP for compute/storage and Cloudflare for edge/WAF, avoiding single-vendor dependency; (2) TLS certificates sourced from multiple CAs (DigiCert, Let's Encrypt, Google Trust Services); (3) DNS resolution uses Cloudflare DNS independent of GCP; (4) monitoring spans both GCP Cloud Monitoring and Cloudflare analytics."
			}},
		{ID: "sr-3.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Limitation of harm from supply chain compromise: (1) VPC Service Controls (enforced=%v) limit blast radius of compromised components; (2) least-privilege IAM ensures compromised service accounts have minimal access; (3) separate GCP projects (%s, %s, %s) isolate supply chain impact; (4) Binary Authorization prevents deployment of tampered images.",
					f.VPCSCEnforced, or(f.AdminProjectID), or(f.OpsProjectID), or(f.AppProjectID))
			}},
		{ID: "sr-3.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem},
			NarrativeFn: func(f *InfraFacts) string {
				return "Sub-tier flow down of supply chain controls: (1) all third-party SaaS dependencies (Cloudflare, GCP) maintain FedRAMP authorizations; (2) open-source dependencies are vetted via vulnerability scanning and checksum verification; (3) supply chain security requirements are documented in vendor agreements; (4) sub-processor compliance is verified during vendor assessments."
			}},
		{ID: "sr-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Provenance documentation and monitoring: (1) SBOM generation=%v documents all software components and their origins; (2) go.sum provides cryptographic verification of Go module provenance; (3) package-lock.json records exact versions and integrity hashes for npm packages; (4) Cloud Build logs record the complete build provenance chain from source commit to deployed image.",
					f.CloudBuildSBOMEnabled)
			}},
		{ID: "sr-5.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Adequate supply of critical components: (1) GCP provides multi-region availability in region %s with automatic failover capabilities; (2) infrastructure is defined as Terraform IaC enabling rapid re-provisioning; (3) Cloud Run auto-scales between %d and %d instances; (4) Cloudflare provides globally distributed edge infrastructure with inherent redundancy.",
					or(f.Region), f.CloudRunMinScale, f.CloudRunMaxScale)
			}},
		{ID: "sr-5.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Assessments prior to selection: (1) Trivy=%v scans all container image dependencies for vulnerabilities before deployment; (2) govulncheck=%v assesses Go dependencies against known vulnerability databases; (3) new dependencies require review of license, maintenance status, and security posture; (4) only FedRAMP-authorized cloud services are selected.",
					f.CloudBuildTrivyEnabled, f.CloudBuildGovulncheck)
			}},
		{ID: "sr-6.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Testing and analysis of supply chain components: (1) CI pipeline runs %d build triggers with comprehensive scanning; (2) Trivy=%v for container vulnerability analysis; (3) gosec=%v for Go security analysis; (4) Semgrep=%v for pattern-based vulnerability detection; (5) Gitleaks=%v prevents secrets in supply chain artifacts.",
					f.CloudBuildTriggers, f.CloudBuildTrivyEnabled, f.CloudBuildGosecEnabled, f.CloudBuildSemgrepEnabled, f.CloudBuildGitleaksEnabled)
			}},
		{ID: "sr-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{thisSystem, gcpPlatform, ciCD},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Supply chain operations security: (1) private Artifact Registry stores all container images — no public registry access at runtime; (2) VPC Service Controls (enforced=%v) perimeter %q prevents unauthorized access to supply chain artifacts; (3) build pipeline secrets stored in Secret Manager with CMEK encryption; (4) source code in private repositories with branch protection.",
					f.VPCSCEnforced, or(f.VPCSCPerimeterName))
			}},

		// ── PE — IL5 overlay (GCP inherited) ─────────────────────────────
		{ID: "pe-8.3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Visitor access records — limit PII elements: inherited from GCP. Google limits PII in visitor access records to name, organization, and badge number. Latent Archon has no physical facilities — all data center visitor management is handled by Google per FedRAMP High authorization."
			}},
		{ID: "pe-22", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Component marking: inherited from GCP. Google marks hardware components within data centers indicating permitted impact levels. Assured Workloads regime %q enforces IL5 data residency and handling labels at the logical layer. Latent Archon has no organization-owned hardware to mark.",
					or(f.AWSComplianceRegime, "IL5"))
			}},

		// ── MA — IL5 overlay (GCP inherited) ─────────────────────────────
		{ID: "ma-3.4", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance tools — restricted tool use: inherited from GCP. Google restricts the use of maintenance tools within data center facilities to authorized personnel only. Not applicable at the SaaS layer — Latent Archon has no physical infrastructure requiring maintenance tools."
			}},
		{ID: "ma-3.5", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance tools — execution with privilege: inherited from GCP. Google monitors the use of privileged maintenance tools within data center facilities. Not applicable at the SaaS layer."
			}},
		{ID: "ma-3.6", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance tools — software updates and patches: inherited from GCP. Google ensures maintenance tools are updated with the latest patches. Not applicable at the SaaS layer."
			}},
		{ID: "ma-4.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Nonlocal maintenance — logging and review: inherited from GCP. Google logs all nonlocal maintenance sessions and reviews audit records for anomalous behavior. At the SaaS layer, all infrastructure management occurs through Terragrunt IaC with full audit trails in Cloud Audit Logs."
			}},
		{ID: "ma-4.4", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Nonlocal maintenance — authentication and separation: inherited from GCP. Google employs replay-resistant authentication and separated maintenance sessions. At the SaaS layer, all administrative access requires MFA and uses separate Cloudflare Access-protected admin endpoints."
			}},
		{ID: "ma-4.6", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Nonlocal maintenance — cryptographic protection: inherited from GCP. Google uses cryptographic mechanisms to protect integrity and confidentiality of nonlocal maintenance communications. At the SaaS layer, all administrative access is over TLS 1.2+ with CMEK-encrypted data at rest."
			}},
		{ID: "ma-4.7", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il5",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Nonlocal maintenance — disconnect verification: inherited from GCP. Google verifies session and network connection termination after nonlocal maintenance. At the SaaS layer, Cloudflare Access sessions have explicit expiration and IAM Conditions enforce time-limited access."
			}},
	}
}
