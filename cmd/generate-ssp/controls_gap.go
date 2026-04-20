package main

import "fmt"

func gapControls() []ControlDef {
	var controls []ControlDef
	controls = append(controls, gapACControls()...)
	controls = append(controls, gapAUControls()...)
	controls = append(controls, gapCAControls()...)
	controls = append(controls, gapCMControls()...)
	controls = append(controls, gapCPControls()...)
	controls = append(controls, gapIAControls()...)
	controls = append(controls, gapIRControls()...)
	controls = append(controls, gapPLControls()...)
	controls = append(controls, gapPMControls()...)
	controls = append(controls, gapPSControls()...)
	controls = append(controls, gapPTControls()...)
	controls = append(controls, gapRAControls()...)
	controls = append(controls, gapSAControls()...)
	controls = append(controls, gapSCControls()...)
	controls = append(controls, gapSIControls()...)
	controls = append(controls, gapSRControls()...)
	return controls
}

func gapACControls() []ControlDef {
	return []ControlDef{
		{ID: "ac-6.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Network access to privileged commands is restricted: (1) GCP IAM restricts administrative API access to authorized service accounts and break-glass personnel; (2) Cloudflare Access enforces identity-based access to admin endpoints; (3) no SSH/RDP access to production — Cloud Run is serverless; (4) database access restricted to VPC-peered service accounts only."
			}},
		{ID: "ac-6.7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Review of user privileges: (1) quarterly access reviews via automated access-review tool; (2) GCP IAM Recommender identifies excess permissions; (3) application RBAC roles reviewed by org master_admin; (4) SCIM-managed accounts automatically reflect IdP group changes."
			}},
		{ID: "ac-11.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Session lock — pattern-hiding displays: the SPA renders a full-screen re-authentication overlay when a session times out, hiding all previously displayed CUI content. The session state is cleared client-side; resumption requires full re-authentication including MFA."
			}},
		{ID: "ac-18", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Wireless access: not applicable — Latent Archon is a SaaS platform hosted entirely on GCP Cloud Run (serverless). There are no organization-controlled wireless access points. End-user wireless connectivity is the responsibility of the customer agency. GCP data center wireless controls are inherited."
			}},
		{ID: "ac-19", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Access control for mobile devices: (1) Cloudflare Access device posture checks enforce OS version, disk encryption, and screen lock for admin access; (2) application enforces session timeouts and re-authentication on all devices; (3) no organization-issued mobile devices — access is via standard web browser with MFA required."
			}},
		{ID: "ac-20.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Limits on authorized use of external systems: (1) the system does not permit connections from external information systems to process, store, or transmit CUI; (2) external system access is limited to API integrations authenticated via SCIM tokens or SAML/OIDC federation; (3) all external integrations documented and reviewed quarterly."
			}},
	}
}

func gapAUControls() []ControlDef {
	return []ControlDef{
		{ID: "au-6.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Integrated analysis of audit records: audit logs from application (%d alert policies), GCP Cloud Audit Logs, and Cloudflare security events are aggregated in Cloud Logging (%d log sinks/project). Cross-source correlation uses request IDs and timestamps for unified analysis.",
					f.MonitoringAlertPolicies, f.AuditLogSinksPerProject)
			}},
		{ID: "au-6.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Correlation with physical monitoring: not applicable for SaaS — physical monitoring is inherited from GCP. Application-level correlation integrates: (1) authentication events with IP geolocation; (2) Cloudflare threat scores with access patterns; (3) rate limiting triggers with user accounts."
			}},
		{ID: "au-9.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Audit logs stored in separate system: audit logs are exported to a dedicated logging project via %d log sinks per project. Log buckets use CMEK encryption and are in a separate GCP project from the application workloads, with independent IAM policies preventing application service accounts from modifying audit records.",
					f.AuditLogSinksPerProject)
			}},
		{ID: "au-9.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Cryptographic protection of audit information: (1) audit logs encrypted at rest with CMEK via Cloud KMS; (2) audit logs encrypted in transit with TLS 1.2+; (3) WORM (Write Once Read Many) retention prevents deletion or modification of audit records."
			}},
		{ID: "au-12.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "System-wide audit trail compiled from individual records: Cloud Logging aggregates audit records from all Cloud Run services, Cloud SQL, Cloud Storage, Identity Platform, and application audit logs into a unified, time-ordered trail queryable via Cloud Logging API and BigQuery."
			}},
		{ID: "au-12.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Changes to logging configuration require privileged access and are logged: (1) Cloud Logging sink configuration managed exclusively via Terragrunt; (2) changes require PR approval; (3) GCP Admin Activity audit logs capture all logging configuration changes; (4) org policies prevent service accounts from modifying org-level sinks."
			}},
		{ID: "au-16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Cross-organizational audit logging: (1) Cloudflare provides edge-layer audit events (WAF, rate limiting, Access) via Logpush; (2) GCP Cloud Audit Logs provide infrastructure events; (3) application audit logs provide business-logic events. All three sources are aggregated in Cloud Logging for cross-organizational audit trail."
			}},
	}
}

func gapCAControls() []ControlDef {
	return []ControlDef{
		{ID: "ca-7.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Independent assessor for continuous monitoring: automated monitoring tools (Cloud Monitoring, Cloudflare analytics, OSCAL SSP-IaC drift detection) provide independent assessment data. 3PAO engagement planned for initial authorization assessment."
			}},
	}
}

func gapCMControls() []ControlDef {
	return []ControlDef{
		{ID: "cm-3.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Automated change control: (1) GitHub PR-based workflow with required approvals; (2) CI/CD pipeline automatically runs tests, security scans, and Terragrunt plan; (3) %d Cloud Build triggers enforce automated build/deploy pipeline; (4) FedRAMP SCN classifier labels PRs by security impact.",
					f.CloudBuildTriggers)
			}},
		{ID: "cm-3.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security representative for change control: FedRAMP SCN classifier automatically flags security-impacting changes. Critical/significant changes require explicit security review documented in PR comments."
			}},
		{ID: "cm-3.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				binauthzStep := "Cosign-signed container image digests verify provenance"
				if f.CloudBuildBinauthzEnabled {
					binauthzStep = "Binary Authorization verifies cryptographic attestations before deployment"
				}
				return fmt.Sprintf("Cryptographic integrity verification: (1) Go module checksums verified via go.sum; (2) container image digests ensure immutable references; (3) %s; (4) Terraform provider checksums verified by HashiCorp's registry.", binauthzStep)
			}},
		{ID: "cm-3.7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Changes reviewed and approved before implementation: (1) Terragrunt plan output must be reviewed before apply; (2) GitHub branch protection enforces PR approvals; (3) CI pipeline must pass before merge is allowed; (4) no direct pushes to staging or main branches."
			}},
		{ID: "cm-3.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Prevent or restrict unverified changes: (1) branch protection prevents direct commits; (2) all changes must pass CI pipeline; (3) Terragrunt apply requires prior plan approval; (4) org policies prevent console-based infrastructure changes for restricted resources."
			}},
		{ID: "cm-7.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Authorized software allowlisting: (1) %d org policies restrict which GCP services can be used; (2) Cloud Run only executes container images from authorized Artifact Registry repositories; (3) Binary Authorization (binauthz=%v) enforces attestation-based image allowlisting; (4) Go module proxy and checksum database verify authorized packages.",
					f.OrgPolicyCount, f.CloudBuildBinauthzEnabled)
			}},
		{ID: "cm-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Information location: CUI is stored exclusively within: (1) Cloud SQL PostgreSQL (structured data, CMEK-encrypted); (2) Cloud Storage (documents, CMEK-encrypted); (3) Vertex AI Vector Search (embeddings, no raw CUI). All storage within US regions enforced by Assured Workloads location constraints."
			}},
		{ID: "cm-14", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				signingDesc := "container images signed via Cosign with digest pinning"
				if f.CloudBuildBinauthzEnabled {
					signingDesc = "container images signed via Binary Authorization attestation"
				}
				return fmt.Sprintf("Signed components: (1) %s; (2) Go binaries built with verified module checksums; (3) Terraform providers verified via HashiCorp GPG signatures; (4) SBOMs generated for component provenance.", signingDesc)
			}},
	}
}

func gapCPControls() []ControlDef {
	return []ControlDef{
		{ID: "cp-2.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Contingency plan continues essential missions: Terragrunt IaC enables full environment rebuild in an alternate GCP region within hours. Assured Workloads constraints apply to all US regions. Cloud SQL automated backups and Cloud Storage multi-region replication ensure data availability."
			}},
		{ID: "cp-2.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Identify critical assets: critical assets documented in SSP authorization boundary: Cloud SQL (CUI data), Cloud Storage (CUI documents), Cloud KMS (encryption keys), Identity Platform (authentication). Recovery priority: (1) auth, (2) database, (3) storage, (4) application services."
			}},
		{ID: "cp-4.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Contingency plan testing coordination: monthly automated CP-4 exercises run via Cloud Build cron. Tests coordinate recovery of Cloud SQL, Cloud Storage, and Cloud Run services. Results uploaded to Drata as evidence."
			}},
		{ID: "cp-4.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Alternate processing site testing: Terragrunt IaC supports deployment to any US GCP region. Contingency plan testing includes validation that IaC applies cleanly to alternate regions with Assured Workloads compliance constraints."
			}},
		{ID: "cp-6.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Recovery time and consistency objectives for alternate storage: Cloud SQL automated backups provide RPO < 24 hours. Cloud Storage objects replicated with versioning. Backup encryption uses same CMEK keys (Cloud KMS in %s). RTO target: 4 hours for full service restoration.",
					or(f.KMSProjectID))
			}},
		{ID: "cp-6.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Accessibility of alternate storage site: Cloud SQL backups and Cloud Storage objects accessible from any authorized GCP region via IAM. No physical access required. Assured Workloads ensures alternate storage remains within US boundaries."
			}},
		{ID: "cp-9.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Testing backups: monthly CP-4 exercises include backup restoration verification: (1) Cloud SQL backup restored to test instance; (2) Cloud Storage objects verified for integrity; (3) results documented and uploaded to Drata."
			}},
		{ID: "cp-9.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Transfer to alternate storage: Cloud SQL automated backups stored in GCP-managed backup infrastructure. Cloud Storage objects can be replicated to alternate regions via gsutil. All backups encrypted with CMEK from %s.",
					or(f.KMSProjectID))
			}},
		{ID: "cp-9.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Cryptographic protection of backup information: all backups encrypted at rest with AES-256 via CMEK (Cloud KMS). Backup transmission encrypted with TLS 1.2+. KMS keys for backup encryption stored in dedicated project with independent IAM."
			}},
		{ID: "cp-10.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Transaction recovery: Cloud SQL supports point-in-time recovery (PITR) using write-ahead logs. Application uses database transactions with rollback on failure. No partial transaction commits reach persistent state."
			}},
		{ID: "cp-10.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Restore within time period: RTO target is 4 hours. Terragrunt IaC enables infrastructure rebuild. Cloud SQL PITR enables database recovery to any point within the backup window. Cloud Storage versioning enables document recovery. Monthly CP-4 exercises validate recovery time."
			}},
	}
}

func gapIAControls() []ControlDef {
	return []ControlDef{
		{ID: "ia-2.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Group authentication — individual identification first: all authentication is individual (no shared accounts). Firebase Identity Platform issues per-user JWTs with unique UID. TOTP MFA bound to individual user accounts. MFA state: %s across %d tenants.",
					or(f.IDPMFAState, "not configured"), f.IDPTenantCount)
			}},
		{ID: "ia-2.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{thisSystem, idPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Multi-factor authentication for network access to privileged accounts: (1) all admin API access requires MFA (magic link + TOTP); (2) GCP console access requires Google MFA; (3) Cloudflare Access enforces MFA for admin dashboard; (4) GitHub requires 2FA for repository access."
			}},
		{ID: "ia-8.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Use of defined profiles for identity verification: customer agencies use SAML/OIDC federation with their authoritative IdP (Okta, Azure AD, ADFS, PingFederate). Identity assertions conform to SAML 2.0 and OpenID Connect profiles. Latent Archon does not issue credentials — relies on customer IdP assertions."
			}},
		{ID: "ia-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Service identification and authentication: (1) Cloud Run services authenticate to each other via GCP service account identity tokens; (2) SCIM clients authenticate via SHA-256 hashed bearer tokens; (3) Cloudflare Workers authenticate to origin via CF Access JWT; (4) Cloud Build authenticates via Workload Identity Federation (keyless)."
			}},
		{ID: "ia-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Adaptive authentication: the system adjusts authentication requirements based on context: (1) new device/IP triggers additional logging and security notification; (2) admin operations require step-up MFA re-verification; (3) account closure requires explicit MFA confirmation; (4) Cloudflare Access enforces device posture checks for admin endpoints."
			}},
		{ID: "ia-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Identity proofing: for federated users, identity proofing is delegated to the customer agency's IdP which performs initial identity verification. For direct users, identity is established through organizational email verification (magic link to verified domain email) and admin-approved invitations."
			}},
		{ID: "ia-12.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Identity evidence validation: identity evidence is validated through: (1) SAML/OIDC assertions from trusted customer IdPs with verified metadata; (2) email domain verification via magic link; (3) SCIM provisioning from authoritative HR/IdP systems with pre-established trust."
			}},
		{ID: "ia-12.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Identity evidence verification: for federated authentication, the customer IdP serves as the authoritative identity source. SAML assertions and OIDC tokens are cryptographically verified against the IdP's published certificates/JWKS. For direct accounts, email link verification serves as identity evidence."
			}},
		{ID: "ia-12.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "In-person identity proofing: not applicable — Latent Archon is a SaaS platform. In-person identity proofing is performed by the customer agency as part of their personnel security process before users are provisioned via SCIM or admin invite."
			}},
		{ID: "ia-12.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Address confirmation: identity address confirmation is delegated to the customer agency's personnel security process. The system confirms organizational email addresses via magic link verification to the registered email domain."
			}},
	}
}

func gapIRControls() []ControlDef {
	return []ControlDef{
		{ID: "ir-4.11", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Integrated incident response team: the same engineering team handles development, operations, and security incident response. Incident handling procedures include coordination with GCP support (infrastructure), Cloudflare support (edge-layer), and customer agency POCs (data breach)."
			}},
		{ID: "ir-6.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Automated incident reporting: (1) Cloud Monitoring alerts automatically page on-call via PagerDuty; (2) Cloudflare security events trigger notifications; (3) application security events (auth failures, rate limit triggers) generate automated alerts; (4) FedRAMP incident reporting to CISA within required timeframes."
			}},
		{ID: "ir-6.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Vulnerabilities related to incidents: security vulnerabilities discovered during incident investigation are documented, tracked, and remediated. Post-incident reviews identify root causes and drive security improvements documented in incident response reports."
			}},
	}
}

func gapPLControls() []ControlDef {
	return []ControlDef{
		{ID: "pl-8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security and privacy architecture: the system follows a zero-trust architecture with defense-in-depth: (1) edge WAF (Cloudflare) → origin WAF (Cloud Armor) → application auth → RBAC → RLS; (2) CMEK encryption at rest; (3) TLS 1.2+ in transit; (4) VPC Service Controls for API isolation; (5) separate GCP projects for blast-radius containment."
			}},
	}
}

func gapPMControls() []ControlDef {
	return []ControlDef{
		{ID: "pm-12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Insider threat program: (1) principle of least privilege limits blast radius of insider actions; (2) comprehensive audit logging tracks all privileged operations; (3) no standing production access — break-glass only; (4) code changes require PR review; (5) infrastructure changes require Terragrunt plan review."
			}},
		{ID: "pm-13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security and privacy workforce: engineering team maintains security skills through: (1) annual security awareness training; (2) secure coding training (OWASP Top 10); (3) hands-on incident response exercises (monthly automated CP-4/IR-3/AT-2); (4) FedRAMP-specific training for compliance personnel."
			}},
		{ID: "pm-17", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Protecting CUI on external systems: CUI is not permitted on external systems. All CUI processing occurs within the FedRAMP-authorized boundary (GCP + Cloudflare). External system access is limited to authenticated API integrations that do not transfer CUI outside the boundary."
			}},
		{ID: "pm-18", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privacy program plan: Latent Archon maintains a privacy program including: (1) Privacy Policy published and reviewed annually; (2) Privacy Impact Assessment (PIA) for CUI handling; (3) data minimization practices; (4) DLP scanning for PII detection; (5) automated data retention and purge policies."
			}},
		{ID: "pm-20", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Dissemination of privacy program information: privacy program information disseminated through: (1) published Privacy Policy; (2) system use notification banner; (3) personnel onboarding materials; (4) privacy training integrated into security awareness training."
			}},
		{ID: "pm-21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Accounting of disclosures: the system maintains records of CUI disclosures through: (1) comprehensive audit logging of all data access; (2) RLS-enforced workspace isolation prevents unauthorized cross-tenant disclosure; (3) API access logs track all data retrieval with user identity and timestamp."
			}},
		{ID: "pm-22", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Personally identifiable information quality: (1) SCIM 2.0 synchronization ensures user attributes reflect authoritative IdP data; (2) email verification via magic link validates contact information; (3) users can update their own profile attributes; (4) stale accounts flagged after 90 days of inactivity."
			}},
		{ID: "pm-23", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Data governance body: the CEO serves as data governance authority responsible for PII handling decisions, privacy policy approval, and data retention decisions. Security Lead serves as operational privacy officer."
			}},
		{ID: "pm-24", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Data integrity board: data integrity is maintained through: (1) PostgreSQL ACID transactions; (2) Cloud SQL automated consistency checks; (3) application-level validation on all inputs; (4) CMEK encryption prevents tampering; (5) audit log integrity protected by WORM retention."
			}},
		{ID: "pm-25", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Minimization of PII: the system collects minimum necessary PII: email address (authentication), display name (UI), IP address (security logging). No SSN, date of birth, or demographic data collected. Customer documents (CUI) are the customer's data — the platform processes but does not extract PII from documents except for DLP scanning."
			}},
		{ID: "pm-26", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Complaint management: privacy complaints are handled through: (1) support email published in Privacy Policy; (2) complaints logged and tracked; (3) response within 30 days; (4) escalation path to CEO for unresolved complaints."
			}},
		{ID: "pm-27", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privacy reporting: privacy metrics reported quarterly including: (1) number of privacy incidents; (2) PII breach notifications issued; (3) privacy complaints received and resolved; (4) DLP scan results summary; (5) data retention compliance status."
			}},
		{ID: "pm-28", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Risk framing: risk management approach aligned with NIST RMF. Risk assessment considers: (1) CUI confidentiality (high impact); (2) system availability for mission-critical operations; (3) supply chain risks (mitigated by FedRAMP-authorized providers). %d org policies enforce risk boundaries.",
					f.OrgPolicyCount)
			}},
		{ID: "pm-30", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Supply chain risk management plan: documented in SCRMP (supply-chain-risk-management-plan.md). Key elements: (1) use only FedRAMP-authorized IaaS; (2) open-source dependency scanning; (3) SBOM generation for supply chain transparency; (4) container image provenance verification."
			}},
		{ID: "pm-31", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Continuous monitoring strategy: documented in ConMon plan. Automated monitoring includes: (1) daily vulnerability scans; (2) OSCAL SSP-IaC drift detection; (3) Cloud Monitoring infrastructure alerts; (4) Cloudflare security event monitoring; (5) monthly compliance exercises. Results reported to AO monthly."
			}},
		{ID: "pm-32", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "moderate",
			NarrativeFn: func(f *InfraFacts) string {
				return "Purposing: all system components are dedicated to their authorized purpose. GCP projects scoped to specific functions (admin, ops, app, KMS). No shared-purpose infrastructure. Assured Workloads enforces compliance regime on all resources within the boundary."
			}},
	}
}

func gapPSControls() []ControlDef {
	return []ControlDef{
		{ID: "ps-9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Position descriptions: all positions with system access have documented security responsibilities: (1) engineers responsible for secure coding, PR review, incident response; (2) CEO/CTO responsible for authorization decisions, risk acceptance; (3) Security Lead responsible for control implementation and assessment."
			}},
	}
}

func gapPTControls() []ControlDef {
	return []ControlDef{
		{ID: "pt-5.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Privacy Act statements: system use notification banner includes privacy notice informing users of: (1) authority for data collection; (2) purpose of collection; (3) routine uses; (4) consequences of not providing information. Published in Privacy Policy and displayed at login."
			}},
	}
}

func gapRAControls() []ControlDef {
	return []ControlDef{
		{ID: "ra-5.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Discoverable information: (1) Cloudflare proxying hides origin IP addresses; (2) Cloud Run services have no public IP; (3) server headers stripped by Cloud Run; (4) error messages return generic responses (no stack traces); (5) security scanning tools (GoSec=%v, Semgrep=%v) identify information leakage in source code.",
					f.CloudBuildGosecEnabled, f.CloudBuildSemgrepEnabled)
			}},
		{ID: "ra-10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Threat hunting: (1) Cloud Logging aggregates all security events for proactive analysis; (2) audit log alert policies detect anomalous patterns; (3) Cloudflare threat intelligence provides real-time threat data; (4) monthly security review includes threat hunting across audit logs and WAF events."
			}},
	}
}

func gapSAControls() []ControlDef {
	return []ControlDef{
		{ID: "sa-15", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Development process, standards, and tools: (1) Go backend built with BoringCrypto=%v (FIPS 140-2 validated); (2) security scanning integrated into CI/CD (GoSec=%v, Semgrep=%v, Trivy=%v, govulncheck=%v, Gitleaks=%v); (3) SBOM generation=%v for provenance; (4) PR-based development workflow with required reviews.",
					f.BoringCrypto, f.CloudBuildGosecEnabled, f.CloudBuildSemgrepEnabled,
					f.CloudBuildTrivyEnabled, f.CloudBuildGovulncheck, f.CloudBuildGitleaksEnabled,
					f.CloudBuildSBOMEnabled)
			}},
		{ID: "sa-16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Developer-provided training resources: (1) Go official documentation and security guidelines; (2) OWASP Top 10 reference in secure coding training; (3) internal CLAUDE.md files document security requirements and patterns; (4) PR review process provides ongoing peer training."
			}},
		{ID: "sa-17", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Developer security and privacy architecture and design: (1) zero-trust architecture documented in SSP; (2) defense-in-depth with multiple WAF layers; (3) multi-tenant isolation via RLS and per-tenant auth pools; (4) CMEK encryption for all data stores; (5) VPC Service Controls for API isolation."
			}},
		{ID: "sa-20", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Customized development of critical components: all application code is custom-developed by Latent Archon. No COTS components process CUI. Open-source dependencies (Go modules, npm packages) are scanned for vulnerabilities and license compliance before inclusion."
			}},
		{ID: "sa-21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Developer screening: all developers undergo background screening per PS-3 requirements before receiving repository or infrastructure access. Access to production systems requires additional authorization. SBOM=%v provides transparency into developer-selected components.",
					f.CloudBuildSBOMEnabled)
			}},
		{ID: "sa-22", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Unsupported system components: (1) Go version tracked and updated regularly; (2) container base images use Google's distroless (minimal, maintained); (3) npm dependencies audited for end-of-life status; (4) GCP services used are all Generally Available and fully supported; (5) govulncheck identifies components with known vulnerabilities."
			}},
	}
}

func gapSCControls() []ControlDef {
	return []ControlDef{
		{ID: "sc-7.29", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Separate subnets for connecting to different security domains: (1) three-project GCP architecture separates admin, ops, and app tiers; (2) VPC peering with restricted routes limits cross-project connectivity; (3) Private Service Connect endpoints for Vertex AI eliminate public network traversal."
			}},
		{ID: "sc-16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Transmission of security and privacy attributes: (1) Firebase JWTs carry user identity, tenant, MFA status, and custom claims; (2) Cloudflare Access JWTs carry identity and device posture; (3) GCP service account tokens carry IAM identity and scopes; (4) all security attributes transmitted via cryptographically signed tokens."
			}},
		{ID: "sc-24", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Fail in known state: (1) Cloud Run services restart automatically on failure in a known-good state from the immutable container image; (2) Cloud SQL maintains ACID consistency through crash recovery; (3) auth middleware fails closed (rejects requests on error); (4) ClamAV fails closed (rejects uploads on scan failure)."
			}},
		{ID: "sc-25", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Thin nodes: Cloud Run containers are stateless thin nodes — all persistent state in Cloud SQL and Cloud Storage. Containers rebuilt from scratch on each deployment. No local persistent storage. Container images use distroless base (minimal OS surface)."
			}},
		{ID: "sc-38", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Operations security: (1) infrastructure-as-code prevents configuration knowledge from being a single point of failure; (2) Terragrunt modules are version-controlled and auditable; (3) no undocumented production changes — all changes via PR; (4) security configurations are deterministic and reproducible."
			}},
	}
}

func gapSIControls() []ControlDef {
	return []ControlDef{
		{ID: "si-4.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Visibility of encrypted communications: (1) TLS terminated at Cloudflare edge and GCP load balancer — application sees decrypted traffic for inspection; (2) Cloud Armor WAF inspects decrypted HTTP traffic; (3) application-level audit logging captures business-logic events from decrypted request content."
			}},
		{ID: "si-4.22", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Unauthorized network services: (1) Cloud Run only exposes configured ports (8080 for HTTP); (2) VPC firewall deny-all default prevents unauthorized network services; (3) org policies restrict which GCP services can be enabled; (4) Cloud Run ingress restricted to internal + load balancer only."
			}},
	}
}

func gapSRControls() []ControlDef {
	return []ControlDef{
		{ID: "sr-2.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return "Establish SCRM team: supply chain risk management responsibilities assigned to the engineering team. CEO provides oversight. Security Lead evaluates new dependencies and infrastructure providers for supply chain risk."
			}},
		{ID: "sr-11.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Component authenticity — public registry verification: (1) Go modules verified against Go checksum database (sum.golang.org); (2) npm packages verified via package-lock.json integrity hashes; (3) container base images from Google's Artifact Registry; (4) SBOM generation=%v captures component provenance.",
					f.CloudBuildSBOMEnabled)
			}},
		{ID: "sr-11.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "high",
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Component authenticity — component disposal: deprecated or vulnerable components are removed through: (1) `go mod tidy` removes unused modules; (2) npm audit identifies deprecated packages; (3) Trivy=%v flags vulnerable container layers; (4) Artifact Registry lifecycle policies remove old image versions.",
					f.CloudBuildTrivyEnabled)
			}},
	}
}
