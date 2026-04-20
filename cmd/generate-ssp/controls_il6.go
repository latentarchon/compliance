package main

import "fmt"

// il6Controls returns IL6/Secret overlay controls for GDC air-gapped deployments.
// These controls reference GDC infrastructure (AlloyDB Omni, GDC Object Storage,
// GKE Gateway API, Kubernetes NetworkPolicy, physical air-gap) instead of GCP
// services (Cloud Run, Cloud SQL, Cloud Armor, VPC SC, Assured Workloads).
//
// Inherited controls come from the GDC platform authorization, not GCP FedRAMP High.
// The baseline for CNSSI 1253 Secret aligns with NIST 800-53 Rev 5 High + Secret overlay.
func il6Controls() []ControlDef {
	return []ControlDef{
		// ── AC — IL6/GDC overlay ──────────────────────────────────────────

		{ID: "ac-3.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, alloyDBOmni},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Discretionary access control on GDC: workspace owners (master_admin role) control access to their workspace data. AlloyDB Omni with pgvector enforces workspace-scoped RLS (%d tables, %d policies). Members are granted access via admin invite or SCIM provisioning.",
					f.RLSTableCount, f.RLSPolicyCount)
			}},
		{ID: "ac-3.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			NarrativeFn: func(f *InfraFacts) string {
				return "Audited override of access control on GDC: (1) break-glass access to the GDC cluster requires dual authorization from CEO/CTO with time-limited RBAC bindings; (2) all overrides logged in Kubernetes audit logs and application audit log; (3) break-glass events trigger immediate security notification; (4) post-incident review required. Physical air-gap prevents remote unauthorized access."
			}},
		{ID: "ac-4.8", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Security policy filters on GDC data flows: (1) GKE Gateway API (%s) enforces mTLS=%v with DoD root CA client certificate verification; (2) Kubernetes NetworkPolicy (enabled=%v) restricts pod-to-pod communication to authorized paths only; (3) regex-based DLP scanner filters PII from document content; (4) ClamAV filters malware from uploads; (5) air-gapped network eliminates all unauthorized egress.",
					or(f.GDCGatewayClassName), f.GDCGatewayMTLS, f.GDCNetworkPolicyEnabled)
			}},
		{ID: "ac-4.21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Physical/logical separation of information flows on GDC: (1) air-gapped GDC cluster provides physical network isolation — no internet connectivity; (2) Kubernetes NetworkPolicy enforces logical separation between app, admin, ops, and worker pods; (3) GKE Gateway separates app (%s) and admin (%s) traffic via distinct HTTPRoute resources; (4) AlloyDB Omni RLS enforces tenant-level data flow separation.",
					or(f.GDCAppHost), or(f.GDCAdminHost))
			}},
		{ID: "ac-16", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			NarrativeFn: func(f *InfraFacts) string {
				return "Security and privacy attributes on GDC: (1) CAC/PKI certificates carry user identity, clearance level, and organization via X.509 subject DN; (2) Kubernetes labels carry component role (app/admin/ops/worker) and environment; (3) audit log entries carry security context (IP, user agent, role, action, CAC subject DN); (4) GDC platform labels mark IL6/Secret resources."
			}},
		{ID: "ac-16.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return "Dynamic attribute association on GDC: (1) CAC/PKI client certificates dynamically carry user identity and clearance attributes per mTLS handshake; (2) SCIM synchronization dynamically updates user role attributes from authoritative IdP; (3) X-Forwarded-Client-Cert header propagates dynamic client identity from gateway to backend pods."
			}},

		// ── AU — IL6/GDC overlay ──────────────────────────────────────────

		{ID: "au-3.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Centralized analysis on GDC: Kubernetes audit logs and application-level audit logs are aggregated within the air-gapped cluster. Application audit events capture authentication, authorization, data access, and admin operations. GDC platform audit logging captures infrastructure-level events."
			}},
		{ID: "au-9.5", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcObjStorage},
			NarrativeFn: func(f *InfraFacts) string {
				return "Dual authorization for audit movement/deletion on GDC: (1) Kubernetes RBAC requires cluster-admin plus namespace-admin to modify audit log storage; (2) GDC Object Storage access controls prevent single-principal deletion; (3) air-gap prevents exfiltration of audit data; (4) physical security controls on GDC hardware provide additional protection."
			}},
		{ID: "au-14", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Session audit on GDC: (1) Kubernetes audit logs capture all API server operations; (2) application audit log records all authenticated session activity including API calls, data access, and admin actions; (3) session events include CAC subject DN, IP address, action, resource, and timestamp; (4) mTLS gateway logs capture TLS handshake events for session establishment."
			}},

		// ── IA — IL6/GDC overlay ──────────────────────────────────────────

		{ID: "ia-2.12", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("PIV-compliant authentication on GDC: (1) GKE Gateway (class=%s) requires CAC/PIV client certificates for all connections (mTLS=%v); (2) DoD root CA bundle mounted from Kubernetes Secret validates CAC certificate chain; (3) backend extracts identity from X-Forwarded-Client-Cert header; (4) certificate revocation checked against DoD CRL/OCSP within the air-gapped environment.",
					or(f.GDCGatewayClassName), f.GDCGatewayMTLS)
			}},
		{ID: "ia-3.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic bidirectional authentication on GDC: (1) mTLS via GKE Gateway provides mutual cryptographic authentication — server presents TLS cert, client presents CAC/PIV cert; (2) DoD CA bundle (mounted=%v) validates client certificate chain; (3) Kubernetes service accounts provide cryptographic inter-pod authentication; (4) all authentication is certificate-based — no password-based auth paths exist.",
					f.GDCDoDCAMounted)
			}},
		{ID: "ia-5.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return "PKI-based authentication on GDC: (1) CAC/PIV certificates are issued by DoD PKI infrastructure; (2) certificates are validated against DoD root CA chain at the gateway; (3) certificate-to-identity mapping uses X.509 subject DN; (4) private keys are stored in CAC hardware token (FIPS 140-2 Level 2); (5) certificate revocation is enforced via CRL distribution within the air-gapped environment."
			}},

		// ── SC — IL6/GDC overlay ──────────────────────────────────────────

		{ID: "sc-7.9", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Restrict threatening outgoing communications on GDC: (1) air-gapped GDC cluster has no internet connectivity — all outbound is blocked by physical isolation; (2) Kubernetes NetworkPolicy (enabled=%v) restricts inter-pod communication to authorized paths; (3) pods have no egress to external networks; (4) DLP scanning prevents sensitive data from leaving authorized boundaries.",
					f.GDCNetworkPolicyEnabled)
			}},
		{ID: "sc-7.10", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Prevent exfiltration on GDC: (1) physical air-gap provides absolute network-level exfiltration prevention — no internet connectivity exists; (2) AlloyDB Omni RLS (%d tables, %d policies) prevents cross-tenant data aggregation; (3) GDC Object Storage access controls prevent unauthorized bulk data extraction; (4) Kubernetes RBAC restricts data access to authorized service accounts.",
					f.RLSTableCount, f.RLSPolicyCount)
			}},
		{ID: "sc-7.21", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Isolation of system components on GDC: (1) separate Kubernetes Deployments isolate app, admin, ops, and worker components; (2) Kubernetes NetworkPolicy enforces component-level network isolation — worker has zero ingress, ops only accepts from worker; (3) separate service accounts per pod provide IAM-level isolation; (4) PodDisruptionBudgets ensure component availability during maintenance."
			}},
		{ID: "sc-8.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway, alloyDBOmni},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Pre/post transmission handling on GDC: (1) data encrypted at rest in AlloyDB Omni (ssl_mode=%s) and GDC Object Storage; (2) mTLS protects data in transit between client and gateway, gateway and pods; (3) GDC platform provides FIPS 140-2 validated encryption for storage layer; (4) no cleartext data exists at any point — encryption is continuous from upload through storage through retrieval. Air-gap eliminates transit exposure to untrusted networks.",
					or(f.GDCAlloyDBSSLMode, "require"))
			}},
		{ID: "sc-12.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Symmetric key management on GDC: GDC platform manages encryption keys for storage-layer encryption (FIPS 140-2 validated). Application-layer envelope encryption uses AES-256-GCM with random 256-bit DEKs for per-tenant document encryption. The GDC platform's key management service handles key lifecycle, rotation, and HSM-backed storage within the air-gapped boundary."
			}},
		{ID: "sc-12.3", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Asymmetric key management on GDC: (1) CAC/PIV certificates use RSA-2048 or ECDSA asymmetric keys stored in hardware tokens (FIPS 140-2 Level 2); (2) TLS server certificates managed within the GDC platform; (3) container image signing uses asymmetric keys for deployment provenance verification; (4) all asymmetric key operations occur within the air-gapped boundary."
			}},
		{ID: "sc-28.1", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, alloyDBOmni, gdcObjStorage},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection of data at rest on GDC: (1) AlloyDB Omni (%s) provides FIPS-validated encryption for database storage; (2) GDC Object Storage (%s) encrypts objects at rest; (3) Kubernetes Secrets storing credentials and CA bundles are encrypted at rest by etcd encryption; (4) GDC platform provides FIPS 140-2 validated encryption for all persistent storage.",
					or(f.GDCAlloyDBHost), or(f.GDCStorageBucket))
			}},

		// ── CM — IL6/GDC overlay ──────────────────────────────────────────

		{ID: "cm-2.2", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Automation support for accuracy and currency on GDC: (1) Helm chart (deploy/gdc/) defines the complete system configuration as code — %d Deployments, %d Services; (2) values.yaml provides single source of truth for all configurable parameters; (3) `helm diff` detects configuration drift before applying changes; (4) Makefile provides repeatable deployment automation.",
					f.GDCDeploymentCount, f.GDCServiceCount)
			}},
		{ID: "cm-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Configuration settings on GDC: (1) Helm values.yaml defines all security-relevant settings: session timeouts (idle=%dmin, absolute=%dmin), max concurrent sessions=%d, CAC enforcement, database SSL mode=%s; (2) Kubernetes SecurityContext enforces runAsNonRoot=%v, readOnlyRootFilesystem, drop ALL capabilities; (3) NetworkPolicy enabled=%v; (4) PodDisruptionBudget enabled=%v.",
					f.GDCSessionIdleTimeout, f.GDCSessionAbsTimeout, f.GDCMaxConcurrentSess,
					or(f.GDCAlloyDBSSLMode, "require"), f.GDCSecurityContext,
					f.GDCNetworkPolicyEnabled, f.GDCPDBEnabled)
			}},

		// ── CP — IL6/GDC overlay ──────────────────────────────────────────

		{ID: "cp-6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Alternate storage site on GDC: (1) AlloyDB Omni provides built-in replication and backup within the GDC cluster; (2) GDC Object Storage (%s) provides durable object storage with platform-managed redundancy; (3) Kubernetes PersistentVolumes are managed by the GDC storage subsystem; (4) WWT partner manages physical storage infrastructure and disaster recovery.",
					or(f.GDCStorageBucket))
			}},

		// ── PE — IL6/GDC overlay (inherited from GDC platform) ────────────

		{ID: "pe-3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Physical access control: inherited from GDC platform. GDC air-gapped infrastructure is hosted in SCIF/SAPF or equivalent IL6-authorized facility managed by WWT. Physical access requires appropriate clearance and need-to-know authorization. Badge readers, mantraps, and escort procedures enforced per ICD 705."
			}},
		{ID: "pe-5", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Access control for output devices: inherited from GDC platform. All output devices (monitors, printers) are within the physically secured facility. No output devices are accessible outside the IL6 boundary. GDC platform team (WWT) manages physical output device inventory and access."
			}},
		{ID: "pe-18", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Location of system components: inherited from GDC platform. All GDC hardware is located within IL6-authorized facilities. Physical isolation from unclassified networks is enforced at the facility level. No system components exist outside the secured boundary."
			}},
		{ID: "pe-19", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Information leakage: inherited from GDC platform. TEMPEST controls and emissions security (EMSEC) are implemented at the facility level per CNSSAM TEMPEST/01-13. GDC hardware is rated for operation in IL6-authorized spaces. No electromagnetic emanation controls are required at the application layer."
			}},

		// ── MA — IL6/GDC overlay (inherited) ──────────────────────────────

		{ID: "ma-5.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance personnel with appropriate clearance: inherited from GDC platform. WWT partner personnel maintaining GDC hardware hold appropriate clearances for IL6 operations. Maintenance within the air-gapped boundary does not expose the system to uncleared personnel. All maintenance is logged."
			}},
		{ID: "ma-4.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Cryptographic protection of maintenance sessions on GDC: (1) all administrative access to the cluster uses mTLS with CAC/PIV certificates; (2) kubectl access requires client certificate authentication; (3) Helm operations execute over the same mTLS-protected channel; (4) air-gap ensures maintenance traffic never traverses untrusted networks."
			}},

		// ── SI — IL6/GDC overlay ──────────────────────────────────────────

		{ID: "si-4.14", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Wireless intrusion detection: inherited from GDC platform. The IL6-authorized facility prohibits wireless devices per ICD 705. GDC air-gapped cluster has no wireless interfaces. TEMPEST monitoring at the facility level detects unauthorized wireless emissions."
			}},
		{ID: "si-7.6", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection of integrity on GDC: (1) container images are pre-loaded into GDC local registry (%s) with digest verification; (2) AlloyDB Omni encryption provides authenticated encryption with integrity verification; (3) mTLS provides integrity protection for all in-cluster communication; (4) GDC platform provides FIPS 140-2 validated integrity protection for storage.",
					or(f.GDCRegistryHost))
			}},
		{ID: "si-7.9", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Verify boot process: inherited from GDC platform. GDC bare-metal nodes use Titan security chips for hardware root-of-trust boot verification. Secure Boot and measured boot ensure firmware and OS integrity. The application layer runs in Kubernetes containers on verified nodes."
			}},
		{ID: "si-7.17", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcAppServer},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Runtime application self-protection on GDC: (1) comprehensive input validation on all API endpoints with strict type checking; (2) BoringCrypto=%v provides FIPS-validated cryptographic primitives at runtime; (3) Kubernetes SecurityContext (hardened=%v) enforces non-root execution, read-only filesystem, dropped capabilities; (4) no runtime binary modification possible.",
					f.BoringCrypto, f.GDCSecurityContext)
			}},

		// ── SR — Supply Chain (IL6/GDC specific) ──────────────────────────

		{ID: "sr-4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Provenance on GDC: (1) container images are built in an authorized CI environment and transferred to GDC local registry (%s) via approved media; (2) SBOM=%v documents all software components and their origins; (3) go.sum provides cryptographic verification of Go module provenance; (4) image digests are verified on load into the air-gapped registry.",
					or(f.GDCRegistryHost), f.CloudBuildSBOMEnabled)
			}},
		{ID: "sr-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Supply chain operations security on GDC: (1) air-gapped cluster has no access to public registries — all images pre-loaded into %s; (2) image transfer follows approved media handling procedures for IL6 data; (3) no runtime dependency fetching — all code is bundled at build time; (4) source code reviewed and built in authorized environment before transfer.",
					or(f.GDCRegistryHost))
			}},

		// ── Infrastructure description controls ───────────────────────────

		{ID: "sc-7", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Boundary protection on GDC: (1) physical air-gap provides the primary boundary — no internet connectivity exists; (2) GKE Gateway API (class=%s) with mTLS=%v enforces application-layer boundary at ingress; (3) Kubernetes NetworkPolicy (enabled=%v) enforces internal boundaries between components; (4) separate Kubernetes namespaces isolate application from platform services; (5) %d pods across %d Deployments with individual NetworkPolicy rules.",
					or(f.GDCGatewayClassName), f.GDCGatewayMTLS, f.GDCNetworkPolicyEnabled,
					f.GDCAppReplicas+f.GDCAdminReplicas+f.GDCOpsReplicas+f.GDCWorkerReplicas, f.GDCDeploymentCount)
			}},
		{ID: "sc-7.4", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcGateway},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("External telecommunications on GDC: (1) no external telecommunications exist — air-gapped cluster has zero internet connectivity; (2) all communication is within the physically secured boundary; (3) GKE Gateway manages internal-only HTTPS endpoints: app=%s, admin=%s; (4) no VPN, dial-up, or other external connection paths exist.",
					or(f.GDCAppHost), or(f.GDCAdminHost))
			}},
		{ID: "sc-13", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, gdcPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Cryptographic protection on GDC: (1) BoringCrypto=%v provides FIPS 140-2 validated cryptographic module in application binary; (2) GDC platform provides FIPS 140-2 validated encryption for storage and network layers; (3) mTLS with CAC/PIV certificates (DoD PKI) for all client-server communication; (4) AlloyDB Omni SSL mode=%s for database connections.",
					f.BoringCrypto, or(f.GDCAlloyDBSSLMode, "require"))
			}},
		{ID: "sc-28", ImplStatus: "implemented", RoleID: "system-owner", Baseline: "il6",
			ComponentUUIDs: []string{thisSystem, alloyDBOmni, gdcObjStorage},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Protection of information at rest on GDC: (1) AlloyDB Omni (%s) encrypts data at rest with FIPS-validated encryption; (2) GDC Object Storage (%s) encrypts stored objects; (3) Kubernetes Secrets are encrypted at rest by etcd encryption; (4) GDC platform provides full-disk encryption on bare-metal nodes. Physical air-gap and facility security provide additional protection against unauthorized physical access to storage media.",
					or(f.GDCAlloyDBHost), or(f.GDCStorageBucket))
			}},
	}
}
