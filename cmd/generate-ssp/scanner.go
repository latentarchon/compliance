package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// InfraFacts holds security-relevant facts extracted from IaC configs.
type InfraFacts struct {
	// Deployment
	Region      string
	Environment string
	Deployment  string
	Tier        string

	// Project IDs
	AdminProjectID string
	OpsProjectID   string
	AppProjectID   string
	KMSProjectID   string

	// Domains
	AppDomain      string
	AdminDomain    string
	APIAppDomain   string
	APIAdminDomain string

	// Cloud SQL
	CloudSQLTier              string
	CloudSQLDiskSize          int
	CloudSQLAvailability      string
	CloudSQLPublicIP          bool
	CloudSQLConnectionName    string
	CloudSQLDatabaseName      string

	// Cloud Run
	CloudRunMinScale int
	CloudRunMaxScale int
	CloudRunIngress  string

	// GCS
	GCSDocumentsBucket string

	// KMS
	KMSRotationDays int
	KMSAlgorithm    string

	// Vertex AI
	GeminiModel         string
	EmbeddingModel      string
	EmbeddingDimensions int
	EmbeddingRegion     string

	// Cloudflare — presence
	CFAccessTeamDomain     string
	CFWAFEnabled           bool
	CFRateLimitingEnabled  bool
	CFAccessEnabled        bool
	CFLogpushEnabled       bool
	CFFirewallRulesEnabled bool
	CFIPRangesConfigured   bool

	// Cloudflare — WAF details
	CFWAFManagedRuleset bool
	CFWAFOWASPRuleset   bool
	CFWAFAction         string

	// Cloudflare — rate limiting details
	CFLoginRateLimitEnabled bool
	CFLoginRateLimit        int
	CFLoginRatePeriod       int

	// Cloudflare — firewall rules details
	CFThreatScoreEnabled   bool
	CFThreatScoreThreshold int
	CFPathProtectionEnabled bool
	CFBlockedPaths          []string

	// Cloudflare — Access details
	CFAccessApps         int
	CFAccessServiceTokens int

	// Cloudflare — zone settings
	CFSSLMode       string
	CFMinTLS        string
	CFTLS13         bool
	CFAlwaysHTTPS   bool
	CFSecurityLevel string

	// Cloudflare — Worker proxy
	CFWorkerProxyEnabled bool

	// Cloud Armor
	CloudArmorCFRestriction bool

	// Assured Workloads
	AWSComplianceRegime  string
	AWSAllowedServices   []string
	AWSCMEKKeyProjects   []string
	AWSCMEKRestricted    []string

	// Identity Platform
	MFAEnabled       bool
	SAMLOnly         bool
	RequireIDPPool   bool
	IDPTenantCount   int
	IDPMFAState      string
	IDPAppCheckEnabled bool
	IDPEmailLinkEnabled bool

	// ClamAV
	ClamAVEnabled bool

	// VPC
	VPCEgressPolicy string

	// VPC-SC
	VPCSCEnabled        bool
	VPCSCEnforced       bool
	VPCSCPerimeterName  string
	VPCSCProtectedProjects int
	VPCSCIngressPolicies int
	VPCSCEgressPolicies  int
	VPCSCViolationAlerts bool

	// Audit Logs
	AuditLogRetentionDays int
	AuditLogWORM          bool
	AuditLogSinksPerProject int
	AuditLogAlertPolicies int

	// Monitoring
	MonitoringUptimeChecks int
	MonitoringAlertPolicies int
	MonitoringNotificationChannels int

	// Cloud Build
	CloudBuildEnabled         bool
	CloudBuildTriggers        int
	CloudBuildBinauthzEnabled bool
	CloudBuildTrivyEnabled    bool
	CloudBuildGovulncheck     bool
	CloudBuildSBOMEnabled     bool
	CloudBuildGosecEnabled    bool
	CloudBuildSemgrepEnabled  bool
	CloudBuildGitleaksEnabled bool

	// DLP
	DLPTemplateEnabled   bool
	DLPPIIInfoTypes      int
	DLPCredentialTypes   int

	// CMEK
	CMEKCloudSQL  bool
	CMEKGCS       bool
	CMEKBigQuery  bool
	CMEKLogging   bool
	CMEKSecrets   bool
	CMEKArtifactRegistry bool

	// VPC — flow logs and shell
	FlowLogSampling    float64
	CloudShellDisabled bool

	// Artifact Registry
	ImmutableTags bool

	// Email
	EmailProvider string

	// Cloud Run per-service
	CloudRunServices []CloudRunServiceFacts

	// GDC (air-gapped IL6)
	GDCPlatform             bool
	GDCProject              string
	GDCLocation             string
	GDCRegistryHost         string
	GDCAppReplicas          int
	GDCAdminReplicas        int
	GDCOpsReplicas          int
	GDCWorkerReplicas       int
	GDCWorkerEnabled        bool
	GDCGatewayEnabled       bool
	GDCGatewayMTLS          bool
	GDCGatewayClassName     string
	GDCAppHost              string
	GDCAdminHost            string
	GDCNetworkPolicyEnabled bool
	GDCPDBEnabled           bool
	GDCDoDCAMounted         bool
	GDCStorageBucket        string
	GDCEmbeddingModel       string
	GDCEmbeddingDimensions  int
	GDCExtractorModel       string
	GDCAlloyDBHost          string
	GDCAlloyDBSSLMode       string
	GDCSessionIdleTimeout   int
	GDCSessionAbsTimeout    int
	GDCMaxConcurrentSess    int
	GDCSecurityContext      bool // runAsNonRoot + readOnlyRootFilesystem + drop ALL
	GDCDeploymentCount      int
	GDCServiceCount         int

	// RLS
	RLSTableCount  int
	RLSPolicyCount int
	RLSRoles       []string

	// Backend code
	BoringCrypto         bool
	SessionTimeoutMinutes int
	CFAccessMiddleware   bool
	RBACEnabled          bool
	AuditLoggingEnabled  bool
	RLSEnabled           bool
	SCIMEnabled          bool
	DLPEnabled           bool

	// Org policies (from org repo)
	OrgPolicyCount              int
	OrgPolicySAKeyCreationDeny  bool
	OrgPolicySAKeyUploadDeny    bool
	OrgPolicyVMExternalIPDeny   bool
	OrgPolicySQLPublicIPDeny    bool
	OrgPolicyRunIngressRestrict bool
	OrgPolicyRunEgressAllTraffic bool
	OrgPolicyResourceLocations  []string
	OrgPolicyShieldedVM         bool
	OrgPolicyUniformBucketAccess bool
	OrgPolicyStoragePublicDeny  bool
	OrgPolicyDefaultSAGrantDeny bool
	OrgPolicyDomainRestricted   bool
	OrgAccessApprovalEnabled    bool
	OrgIAMGroupCount            int
}

type CloudRunServiceFacts struct {
	Name                string
	Project             string
	Ingress             string
	AllowUnauthenticated bool
	UseSharedVPC        bool
	ServerMode          string
	RequireIDPPool      bool
	RequireMFA          bool
	SAMLOnly            bool
}

func scanInfrastructure(infraRoot, backendRoot, orgRoot string) (*InfraFacts, error) {
	facts := &InfraFacts{}

	scanDeploymentHCL(infraRoot, facts)
	scanCloudRunAdmin(infraRoot, facts)
	scanCloudRunAllServices(infraRoot, facts)
	scanCloudSQLModule(infraRoot, facts)
	scanKMSModule(infraRoot, facts)
	scanGCSModule(infraRoot, facts)
	scanVPCModule(infraRoot, facts)
	scanVPCSC(infraRoot, facts)
	scanCloudArmorModule(infraRoot, facts)
	scanAssuredWorkloads(infraRoot, facts)
	scanArtifactRegistry(infraRoot, facts)
	scanCloudflareModules(infraRoot, facts)
	scanCloudflareConfigs(infraRoot, facts)
	scanAuditLogs(infraRoot, facts)
	scanMonitoring(infraRoot, facts)
	scanClamAV(infraRoot, facts)
	scanCloudBuild(infraRoot, facts)
	scanDLP(infraRoot, facts)
	scanCMEK(infraRoot, facts)
	scanIdentityPlatform(infraRoot, facts)

	if backendRoot != "" {
		scanBackendCode(backendRoot, facts)
		scanRLS(backendRoot, facts)
		scanCICD(backendRoot, facts)
		scanGDCDeployment(backendRoot, facts)
	}

	if orgRoot != "" {
		scanOrgPolicies(orgRoot, facts)
	}

	return facts, nil
}

func scanDeploymentHCL(infraRoot string, facts *InfraFacts) {
	// Try staging first, then fed
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "gcp/environments", env, "deployment.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		facts.Region = hclLocalValue(content, "region")
		facts.Environment = hclLocalValue(content, "environment")
		facts.Deployment = hclLocalValue(content, "deployment")
		facts.Tier = hclLocalValue(content, "tier")

		facts.AdminProjectID = hclLocalValue(content, "admin_project_id")
		facts.OpsProjectID = hclLocalValue(content, "ops_project_id")
		facts.AppProjectID = hclLocalValue(content, "app_project_id")
		facts.KMSProjectID = hclLocalValue(content, "kms_project_id")

		facts.AppDomain = hclLocalValue(content, "app_domain")
		facts.AdminDomain = hclLocalValue(content, "admin_domain")
		facts.APIAppDomain = hclLocalValue(content, "api_app_domain")
		facts.APIAdminDomain = hclLocalValue(content, "api_admin_domain")

		facts.CloudSQLConnectionName = hclLocalValue(content, "cloud_sql_connection_name")
		facts.CloudSQLDatabaseName = hclLocalValue(content, "cloud_sql_database_name")
		facts.CloudSQLTier = hclLocalValue(content, "cloud_sql_tier")
		facts.CloudSQLAvailability = hclLocalValue(content, "cloud_sql_availability_type")
		facts.CloudSQLPublicIP = hclLocalValue(content, "cloud_sql_enable_public_ip") == "true"
		facts.CloudSQLDiskSize, _ = strconv.Atoi(hclLocalValue(content, "cloud_sql_disk_size"))

		facts.CloudRunMinScale, _ = strconv.Atoi(hclLocalValue(content, "cloud_run_min_scale"))
		facts.CloudRunMaxScale, _ = strconv.Atoi(hclLocalValue(content, "cloud_run_max_scale"))

		facts.GCSDocumentsBucket = hclLocalValue(content, "gcs_documents_bucket")
		facts.GeminiModel = hclLocalValue(content, "gemini_model")
		facts.EmbeddingModel = hclLocalValue(content, "embedding_model")
		facts.EmbeddingDimensions, _ = strconv.Atoi(hclLocalValue(content, "embedding_vector_dimensions"))
		facts.EmbeddingRegion = hclLocalValue(content, "embedding_region")
		facts.CFAccessTeamDomain = hclLocalValue(content, "cf_access_team_domain")
		break
	}
}

func scanCloudRunAdmin(infraRoot string, facts *InfraFacts) {
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "gcp/environments", env, "admin/cloud-run-admin/terragrunt.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		facts.CloudRunIngress = hclInputValueFromContent(content, "ingress")
		if strings.Contains(content, "CF_ACCESS_AUD") {
			facts.CFAccessMiddleware = true
		}
		if strings.Contains(content, "vpc_egress") {
			facts.VPCEgressPolicy = hclInputValueFromContent(content, "vpc_egress")
		}
		break
	}
}

func scanCloudSQLModule(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/cloud-sql/variables.tf")
	if _, err := os.Stat(path); err == nil {
		if v, ok := hclVarDefault(path, "backup_enabled"); ok && v == "true" {
			// default is backup enabled
		}
		if v, ok := hclVarDefault(path, "ssl_mode"); ok {
			_ = v
		}
	}
}

func scanKMSModule(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/kms-central/variables.tf")
	if _, err := os.Stat(path); err == nil {
		if v, ok := hclVarDefault(path, "rotation_period"); ok {
			facts.KMSRotationDays = parseRotationDays(v)
		}
		if v, ok := hclVarDefault(path, "algorithm"); ok {
			facts.KMSAlgorithm = v
		}
	}
	// Also check the kms module
	path = filepath.Join(infraRoot, "gcp/modules/kms/variables.tf")
	if _, err := os.Stat(path); err == nil {
		if facts.KMSRotationDays == 0 {
			if v, ok := hclVarDefault(path, "rotation_period"); ok {
				facts.KMSRotationDays = parseRotationDays(v)
			}
		}
		if facts.KMSAlgorithm == "" {
			if v, ok := hclVarDefault(path, "algorithm"); ok {
				facts.KMSAlgorithm = v
			}
		}
	}
}

func scanGCSModule(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/gcs/variables.tf")
	if _, err := os.Stat(path); err == nil {
		if v, ok := hclVarDefault(path, "versioning"); ok {
			_ = v
		}
		if v, ok := hclVarDefault(path, "soft_delete_retention_seconds"); ok {
			_ = v
		}
	}
}

func scanVPCModule(infraRoot string, facts *InfraFacts) {
	for _, env := range []string{"staging", "fed"} {
		for _, proj := range []string{"admin/vpc", "app/vpc", "ops/vpc", "ops/shared-vpc"} {
			path := filepath.Join(infraRoot, "gcp/environments", env, proj, "terragrunt.hcl")
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)

			if v := hclInputValueFromContent(content, "flow_log_sampling"); v != "" {
				if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > facts.FlowLogSampling {
					facts.FlowLogSampling = parsed
				}
			}

			if v := hclInputValueFromContent(content, "enable_cloud_shell_access"); v == "false" {
				facts.CloudShellDisabled = true
			}
		}
		if facts.FlowLogSampling > 0 {
			break
		}
	}
}

func scanArtifactRegistry(infraRoot string, facts *InfraFacts) {
	varPath := filepath.Join(infraRoot, "gcp/modules/artifact-registry/variables.tf")
	if v, ok := hclVarDefault(varPath, "immutable_tags"); ok {
		facts.ImmutableTags = v == "true"
	}
	for _, env := range []string{"staging", "fed"} {
		for _, proj := range []string{"admin", "app", "ops"} {
			path := filepath.Join(infraRoot, "gcp/environments", env, proj, "artifact-registry/terragrunt.hcl")
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)
			if v := hclInputValueFromContent(content, "immutable_tags"); v == "false" {
				facts.ImmutableTags = false
			}
		}
		break
	}
}

func scanCloudArmorModule(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/cloud-armor/main.tf")
	if data, err := os.ReadFile(path); err == nil {
		content := string(data)
		if strings.Contains(content, "cloudflare") || strings.Contains(content, "cf_ip") {
			facts.CloudArmorCFRestriction = true
		}
	}
}

func scanAssuredWorkloads(infraRoot string, facts *InfraFacts) {
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "gcp/environments", env, "assured-workloads-il5/terragrunt.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "IL5") || strings.Contains(content, "il5") {
			facts.AWSComplianceRegime = "IL5"
		}
		// Extract allowed services
		if strings.Contains(content, "allowed_services") {
			facts.AWSAllowedServices = extractHCLList(content, "allowed_services")
		}
		break
	}
}

func scanCloudflareModules(infraRoot string, facts *InfraFacts) {
	cfModules := filepath.Join(infraRoot, "cloudflare/modules")

	if _, err := os.Stat(filepath.Join(cfModules, "waf")); err == nil {
		facts.CFWAFEnabled = true
	}
	if _, err := os.Stat(filepath.Join(cfModules, "rate-limiting")); err == nil {
		facts.CFRateLimitingEnabled = true
	}
	if _, err := os.Stat(filepath.Join(cfModules, "access")); err == nil {
		facts.CFAccessEnabled = true
	}
	if _, err := os.Stat(filepath.Join(cfModules, "logpush")); err == nil {
		facts.CFLogpushEnabled = true
	}
	if _, err := os.Stat(filepath.Join(cfModules, "firewall-rules/main.tf")); err == nil {
		if data, err := os.ReadFile(filepath.Join(cfModules, "firewall-rules/main.tf")); err == nil {
			content := string(data)
			if strings.Contains(content, "threat_score") || strings.Contains(content, "blocked_paths") || strings.Contains(content, "blocked_ips") {
				facts.CFFirewallRulesEnabled = true
			}
		}
	}
	if _, err := os.Stat(filepath.Join(cfModules, "ip-ranges")); err == nil {
		facts.CFIPRangesConfigured = true
	}
}

func scanAuditLogs(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/audit-logs/variables.tf")
	if _, err := os.Stat(path); err == nil {
		if v, ok := hclVarDefault(path, "gcs_audit_retention_days"); ok {
			facts.AuditLogRetentionDays, _ = strconv.Atoi(v)
		}
	}
	// Check for WORM/locked retention
	mainPath := filepath.Join(infraRoot, "gcp/modules/audit-logs/main.tf")
	if data, err := os.ReadFile(mainPath); err == nil {
		if strings.Contains(string(data), "retention_policy") || strings.Contains(string(data), "locked") {
			facts.AuditLogWORM = true
		}
	}
}

func scanClamAV(infraRoot string, facts *InfraFacts) {
	if _, err := os.Stat(filepath.Join(infraRoot, "gcp/modules/clamav")); err == nil {
		facts.ClamAVEnabled = true
	}
}

func scanBackendCode(backendRoot string, facts *InfraFacts) {
	// Check for BoringCrypto (FIPS) in build configs
	for _, name := range []string{"cloudbuild.yaml", "Dockerfile", "Makefile"} {
		path := filepath.Join(backendRoot, name)
		if data, err := os.ReadFile(path); err == nil {
			if strings.Contains(string(data), "boringcrypto") || strings.Contains(string(data), "GOEXPERIMENT=boringcrypto") {
				facts.BoringCrypto = true
			}
		}
	}

	// Check for CF Access middleware
	cfAccessPath := filepath.Join(backendRoot, "shared-go/transport/cfaccess.go")
	if _, err := os.Stat(cfAccessPath); err == nil {
		facts.CFAccessMiddleware = true
	}

	// Check for RBAC
	if containsPattern(backendRoot, "shared-go/auth", "rbac", "Role", "role") ||
		containsPattern(backendRoot, "internal/auth", "rbac", "role") {
		facts.RBACEnabled = true
	}

	// Check for audit logging
	if _, err := os.Stat(filepath.Join(backendRoot, "internal/audit")); err == nil {
		facts.AuditLoggingEnabled = true
	}

	// Check for RLS
	if containsPattern(backendRoot, "shared-go/postgres/migrations", "rls", "RLS", "row_level_security") ||
		containsPattern(backendRoot, "shared-go/postgres", "SetWorkspace", "rls") {
		facts.RLSEnabled = true
	}

	// Check for SCIM
	if containsPattern(backendRoot, "internal/sso", "scim", "SCIM") {
		facts.SCIMEnabled = true
	}

	// Check for DLP
	if _, err := os.Stat(filepath.Join(backendRoot, "internal/dlp")); err == nil {
		facts.DLPEnabled = true
	}

	// Check for session management
	if containsPattern(backendRoot, "shared-go/auth", "SessionTimeout", "session_timeout") ||
		containsPattern(backendRoot, "internal/auth", "session_timeout", "SessionTimeout") {
		facts.SessionTimeoutMinutes = 15
	}
}

// containsPattern checks if any file under dir contains any of the patterns.
func containsPattern(root, subdir string, patterns ...string) bool {
	dir := filepath.Join(root, subdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		content := string(data)
		for _, p := range patterns {
			if strings.Contains(content, p) {
				return true
			}
		}
	}
	return false
}

func scanCloudRunAllServices(infraRoot string, facts *InfraFacts) {
	type serviceDir struct {
		project string
		path    string
	}
	dirs := []serviceDir{
		{"admin", "admin/cloud-run-admin"},
		{"admin", "admin/cloud-run-spa"},
		{"app", "app/cloud-run"},
		{"app", "app/cloud-run-spa"},
		{"ops", "ops/cloud-run-ops"},
		{"ops", "ops/cloud-run-jobs"},
		{"ops", "ops/clamav"},
	}

	for _, env := range []string{"staging", "fed"} {
		found := false
		for _, d := range dirs {
			path := filepath.Join(infraRoot, "gcp/environments", env, d.path, "terragrunt.hcl")
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			found = true
			content := string(data)
			svc := CloudRunServiceFacts{
				Project: d.project,
				Ingress: hclInputValueFromContent(content, "ingress"),
			}
			svc.Name = hclInputValueFromContent(content, "service_name")
			svc.AllowUnauthenticated = hclInputValueFromContent(content, "allow_unauthenticated") == "true"
			svc.UseSharedVPC = strings.Contains(content, "use_shared_vpc")

			if envVars := extractBlock(content, "env_vars"); envVars != "" {
				svc.ServerMode = hclInputValueFromContent(envVars, "SERVER_MODE")
				svc.RequireIDPPool = hclInputValueFromContent(envVars, "REQUIRE_IDP_POOL") == "true"
				svc.SAMLOnly = hclInputValueFromContent(envVars, "AUTH_SAML_ONLY") == "true"
				if ep := hclInputValueFromContent(envVars, "EMAIL_PROVIDER"); ep != "" && facts.EmailProvider == "" {
					facts.EmailProvider = ep
				}
			}
			facts.CloudRunServices = append(facts.CloudRunServices, svc)
		}
		if found {
			break
		}
	}
}

func scanVPCSC(infraRoot string, facts *InfraFacts) {
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "gcp/environments", env, "vpc-service-controls/terragrunt.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		facts.VPCSCEnabled = true
		facts.VPCSCEnforced = hclInputValueFromContent(content, "dry_run_mode") == "false"
		facts.VPCSCPerimeterName = hclInputValueFromContent(content, "perimeter_name")
		facts.VPCSCProtectedProjects = len(extractHCLList(content, "protected_project_ids"))
		facts.VPCSCViolationAlerts = hclInputValueFromContent(content, "enable_violation_alerts") == "true"

		facts.VPCSCIngressPolicies = strings.Count(content, "service_name")
		facts.VPCSCEgressPolicies = len(extractHCLList(content, "egress_policies"))
		break
	}
}

func scanMonitoring(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/monitoring/main.tf")
	if data, err := os.ReadFile(path); err == nil {
		content := string(data)
		facts.MonitoringAlertPolicies = strings.Count(content, "google_monitoring_alert_policy")
		facts.MonitoringUptimeChecks = strings.Count(content, "google_monitoring_uptime_check")
	}

	ncPath := filepath.Join(infraRoot, "gcp/modules/notification-channels/main.tf")
	if data, err := os.ReadFile(ncPath); err == nil {
		facts.MonitoringNotificationChannels = strings.Count(string(data), "google_monitoring_notification_channel")
	}

	auditPath := filepath.Join(infraRoot, "gcp/modules/audit-logs/main.tf")
	if data, err := os.ReadFile(auditPath); err == nil {
		content := string(data)
		facts.AuditLogAlertPolicies = strings.Count(content, "google_monitoring_alert_policy")
		facts.AuditLogSinksPerProject = strings.Count(content, "google_logging_project_sink")
	}
}

func scanCloudBuild(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/cloud-build/main.tf")
	if data, err := os.ReadFile(path); err == nil {
		content := string(data)
		facts.CloudBuildEnabled = true
		facts.CloudBuildTriggers = strings.Count(content, "google_cloudbuild_trigger")
	}

	// Check actual terragrunt configs for enable_binary_authorization
	for _, env := range []string{"staging", "fed"} {
		for _, proj := range []string{"admin", "app", "ops"} {
			path := filepath.Join(infraRoot, "gcp/environments", env, proj, "cloud-build/terragrunt.hcl")
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if hclInputValueFromContent(string(data), "enable_binary_authorization") == "true" {
				facts.CloudBuildBinauthzEnabled = true
			}
		}
		break
	}
}

func scanDLP(infraRoot string, facts *InfraFacts) {
	path := filepath.Join(infraRoot, "gcp/modules/dlp/variables.tf")
	if data, err := os.ReadFile(path); err == nil {
		content := string(data)
		facts.DLPTemplateEnabled = true
		facts.DLPPIIInfoTypes = len(extractHCLList(content, "pii_info_types"))
		facts.DLPCredentialTypes = len(extractHCLList(content, "credential_info_types"))
	}
}

func scanCMEK(infraRoot string, facts *InfraFacts) {
	// Check which consumer modules reference KMS keys
	for _, mod := range []struct {
		path string
		flag *bool
	}{
		{"gcp/modules/cloud-sql/main.tf", &facts.CMEKCloudSQL},
		{"gcp/modules/gcs/main.tf", &facts.CMEKGCS},
		{"gcp/modules/audit-logs/main.tf", &facts.CMEKBigQuery},
		{"gcp/modules/secrets/main.tf", &facts.CMEKSecrets},
	} {
		p := filepath.Join(infraRoot, mod.path)
		if data, err := os.ReadFile(p); err == nil {
			content := string(data)
			if strings.Contains(content, "kms_key") || strings.Contains(content, "cmek") || strings.Contains(content, "encryption_key") || strings.Contains(content, "crypto_key") {
				*mod.flag = true
			}
		}
	}

	// Check logging for CMEK
	logVars := filepath.Join(infraRoot, "gcp/modules/audit-logs/variables.tf")
	if data, err := os.ReadFile(logVars); err == nil {
		if strings.Contains(string(data), "cmek") || strings.Contains(string(data), "kms_key") {
			facts.CMEKLogging = true
		}
	}

	// Check Artifact Registry
	arPath := filepath.Join(infraRoot, "gcp/modules/artifact-registry/main.tf")
	if data, err := os.ReadFile(arPath); err == nil {
		if strings.Contains(string(data), "kms_key") {
			facts.CMEKArtifactRegistry = true
		}
	}
}

func scanIdentityPlatform(infraRoot string, facts *InfraFacts) {
	for _, env := range []string{"staging", "fed"} {
		for _, proj := range []string{"auth-admin", "auth-app"} {
			path := filepath.Join(infraRoot, "gcp/environments", env, proj, "identity-platform/terragrunt.hcl")
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := string(data)

			mfa := hclInputValueFromContent(content, "mfa_state")
			if mfa != "" {
				facts.IDPMFAState = mfa
				facts.MFAEnabled = mfa == "ENABLED" || mfa == "MANDATORY"
			}

			appCheck := hclInputValueFromContent(content, "app_check_enabled")
			if appCheck == "true" {
				facts.IDPAppCheckEnabled = true
			}

			tenants := extractBlock(content, "identity_platform_tenants")
			if tenants != "" {
				facts.IDPTenantCount += strings.Count(tenants, "display_name")
				if strings.Contains(tenants, "enable_email_link_signin") {
					facts.IDPEmailLinkEnabled = true
				}
			}

			if strings.Contains(content, "REQUIRE_IDP_POOL") {
				facts.RequireIDPPool = true
			}
		}
		if facts.IDPMFAState != "" {
			break
		}
	}
}

func scanRLS(backendRoot string, facts *InfraFacts) {
	schemaPath := filepath.Join(backendRoot, "shared-go/postgres/schema.sql")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		return
	}
	content := string(data)
	facts.RLSTableCount = strings.Count(content, "ENABLE ROW LEVEL SECURITY")
	facts.RLSPolicyCount = strings.Count(content, "CREATE POLICY")

	for _, role := range []string{"archon_app_ro", "archon_admin_rw", "archon_ops_rw"} {
		if strings.Contains(content, role) {
			facts.RLSRoles = append(facts.RLSRoles, role)
		}
	}
}

func scanCICD(backendRoot string, facts *InfraFacts) {
	for _, name := range []string{"cloudbuild.yaml", "cloudbuild-security.yaml", "cloudbuild-sbom.yaml", "cloudbuild-pr.yaml"} {
		path := filepath.Join(backendRoot, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if strings.Contains(content, "trivy") {
			facts.CloudBuildTrivyEnabled = true
		}
		if strings.Contains(content, "govulncheck") {
			facts.CloudBuildGovulncheck = true
		}
		if strings.Contains(content, "sbom") || strings.Contains(content, "cyclonedx") || strings.Contains(content, "spdx") {
			facts.CloudBuildSBOMEnabled = true
		}
		if strings.Contains(content, "gosec") {
			facts.CloudBuildGosecEnabled = true
		}
		if strings.Contains(content, "semgrep") {
			facts.CloudBuildSemgrepEnabled = true
		}
		if strings.Contains(content, "gitleaks") {
			facts.CloudBuildGitleaksEnabled = true
		}
	}
}

func extractBlock(content, blockName string) string {
	idx := strings.Index(content, blockName)
	if idx == -1 {
		return ""
	}
	rest := content[idx:]
	braceStart := strings.Index(rest, "{")
	if braceStart == -1 {
		return ""
	}
	depth := 0
	for i := braceStart; i < len(rest); i++ {
		if rest[i] == '{' {
			depth++
		} else if rest[i] == '}' {
			depth--
			if depth == 0 {
				return rest[:i+1]
			}
		}
	}
	return rest
}

func scanCloudflareConfigs(infraRoot string, facts *InfraFacts) {
	// Scan WAF terragrunt configs for detailed settings
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "cloudflare/environments", env, "waf/terragrunt.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if hclInputValueFromContent(content, "enable_managed_ruleset") == "true" {
			facts.CFWAFManagedRuleset = true
		}
		if hclInputValueFromContent(content, "enable_owasp_ruleset") == "true" {
			facts.CFWAFOWASPRuleset = true
		}
		facts.CFWAFAction = hclInputValueFromContent(content, "waf_action")
		break
	}

	// Scan rate limiting configs
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "cloudflare/environments", env, "rate-limiting/terragrunt.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if hclInputValueFromContent(content, "enable_login_rate_limit") == "true" {
			facts.CFLoginRateLimitEnabled = true
			facts.CFLoginRateLimit, _ = strconv.Atoi(hclInputValueFromContent(content, "login_requests_per_period"))
			facts.CFLoginRatePeriod, _ = strconv.Atoi(hclInputValueFromContent(content, "login_period"))
		}
		break
	}

	// Scan firewall rules configs
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "cloudflare/environments", env, "firewall-rules/terragrunt.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		if hclInputValueFromContent(content, "enable_threat_score_challenge") == "true" {
			facts.CFThreatScoreEnabled = true
			facts.CFThreatScoreThreshold, _ = strconv.Atoi(hclInputValueFromContent(content, "threat_score_threshold"))
		}
		if hclInputValueFromContent(content, "enable_path_protection") == "true" {
			facts.CFPathProtectionEnabled = true
			facts.CFBlockedPaths = extractHCLList(content, "blocked_paths")
		}
		break
	}

	// Scan Access configs
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "cloudflare/environments", env, "access/terragrunt.hcl")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)
		facts.CFAccessApps = strings.Count(content, "name                      =")
		facts.CFAccessServiceTokens = strings.Count(content, "min_days_for_renewal")
		break
	}

	// Scan zone settings
	path := filepath.Join(infraRoot, "cloudflare/environments/zone/zone-settings/terragrunt.hcl")
	if data, err := os.ReadFile(path); err == nil {
		content := string(data)
		facts.CFSSLMode = hclInputValueFromContent(content, "ssl_mode")
		facts.CFMinTLS = hclInputValueFromContent(content, "min_tls_version")
		facts.CFTLS13 = hclInputValueFromContent(content, "tls_1_3") != ""
		facts.CFAlwaysHTTPS = hclInputValueFromContent(content, "always_use_https") == "on"
		facts.CFSecurityLevel = hclInputValueFromContent(content, "security_level")
	}

	// Check for Worker proxy
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "cloudflare/environments", env, "worker-proxy/terragrunt.hcl")
		if _, err := os.Stat(path); err == nil {
			facts.CFWorkerProxyEnabled = true
			break
		}
	}
}

func scanOrgPolicies(orgRoot string, facts *InfraFacts) {
	path := filepath.Join(orgRoot, "org-policy.tf")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	facts.OrgPolicyCount = strings.Count(content, "resource \"google_org_policy_policy\"")

	facts.OrgPolicySAKeyCreationDeny = strings.Contains(content, "iam.disableServiceAccountKeyCreation")
	facts.OrgPolicySAKeyUploadDeny = strings.Contains(content, "iam.disableServiceAccountKeyUpload")
	facts.OrgPolicyVMExternalIPDeny = strings.Contains(content, "compute.vmExternalIpAccess")
	facts.OrgPolicySQLPublicIPDeny = strings.Contains(content, "sql.restrictPublicIp")
	facts.OrgPolicyRunIngressRestrict = strings.Contains(content, "run.allowedIngress")
	facts.OrgPolicyRunEgressAllTraffic = strings.Contains(content, "run.allowedVPCEgress")
	facts.OrgPolicyShieldedVM = strings.Contains(content, "compute.requireShieldedVm")
	facts.OrgPolicyUniformBucketAccess = strings.Contains(content, "storage.uniformBucketLevelAccess")
	facts.OrgPolicyStoragePublicDeny = strings.Contains(content, "storage.publicAccessPrevention")
	facts.OrgPolicyDefaultSAGrantDeny = strings.Contains(content, "iam.automaticIamGrantsForDefaultServiceAccounts")
	facts.OrgPolicyDomainRestricted = strings.Contains(content, "iam.allowedPolicyMemberDomains")

	facts.OrgPolicyResourceLocations = extractHCLList(content, "allowed_values")

	// Access Approval
	aaPath := filepath.Join(orgRoot, "access-approval.tf")
	if _, err := os.Stat(aaPath); err == nil {
		facts.OrgAccessApprovalEnabled = true
	}

	// IAM groups
	groupsPath := filepath.Join(orgRoot, "groups.tf")
	if gdata, err := os.ReadFile(groupsPath); err == nil {
		facts.OrgIAMGroupCount = strings.Count(string(gdata), "@${local.domain}")
	}
}

// --- HCL parsing helpers ---

func hclLocalValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key) && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if idx := strings.Index(val, "#"); idx > 0 {
					val = strings.TrimSpace(val[:idx])
				}
				val = strings.Trim(val, `"`)
				return val
			}
		}
	}
	return ""
}

func hclInputValueFromContent(content, key string) string {
	inputsIdx := strings.Index(content, "inputs")
	if inputsIdx == -1 {
		return ""
	}
	rest := content[inputsIdx:]
	for _, line := range strings.Split(rest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key) && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if idx := strings.Index(val, "#"); idx > 0 {
					val = strings.TrimSpace(val[:idx])
				}
				val = strings.Trim(val, `"`)
				return val
			}
		}
	}
	return ""
}

func hclVarDefault(path, varName string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	p := hclparse.NewParser()
	f, diags := p.ParseHCLFile(path)
	if diags.HasErrors() {
		return hclVarDefaultRaw(string(data), varName)
	}

	content, _, diags := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "variable", LabelNames: []string{"name"}},
		},
	})
	if diags.HasErrors() {
		return hclVarDefaultRaw(string(data), varName)
	}

	for _, block := range content.Blocks {
		if len(block.Labels) > 0 && block.Labels[0] == varName {
			attrs, _ := block.Body.JustAttributes()
			if def, ok := attrs["default"]; ok {
				val, vDiags := def.Expr.Value(nil)
				if !vDiags.HasErrors() {
					switch val.Type() {
					case cty.String:
						return val.AsString(), true
					case cty.Number:
						bf := val.AsBigFloat()
						if bf.IsInt() {
							i, _ := bf.Int64()
							return strconv.FormatInt(i, 10), true
						}
						f, _ := bf.Float64()
						return strconv.FormatFloat(f, 'f', -1, 64), true
					case cty.Bool:
						return strconv.FormatBool(val.True()), true
					}
				}
			}
		}
	}
	return "", false
}

func hclVarDefaultRaw(content, varName string) (string, bool) {
	marker := fmt.Sprintf(`variable "%s"`, varName)
	idx := strings.Index(content, marker)
	if idx == -1 {
		return "", false
	}
	block := content[idx:]
	if len(block) > 500 {
		block = block[:500]
	}
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "default") && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, `"`)
				return val, true
			}
		}
	}
	return "", false
}

func extractHCLList(content, key string) []string {
	idx := strings.Index(content, key)
	if idx == -1 {
		return nil
	}
	rest := content[idx:]
	start := strings.Index(rest, "[")
	end := strings.Index(rest, "]")
	if start == -1 || end == -1 || end <= start {
		return nil
	}
	listContent := rest[start+1 : end]
	var items []string
	for _, line := range strings.Split(listContent, "\n") {
		trimmed := strings.TrimSpace(line)
		trimmed = strings.Trim(trimmed, `",`)
		trimmed = strings.TrimSpace(trimmed)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			items = append(items, trimmed)
		}
	}
	return items
}

func parseRotationDays(v string) int {
	v = strings.TrimSpace(v)
	if strings.HasSuffix(v, "s") {
		v = strings.TrimSuffix(v, "s")
		seconds, err := strconv.Atoi(v)
		if err == nil {
			return seconds / 86400
		}
	}
	days, _ := strconv.Atoi(v)
	return days
}
