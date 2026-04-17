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

	// Cloudflare
	CFAccessTeamDomain     string
	CFWAFEnabled           bool
	CFRateLimitingEnabled  bool
	CFAccessEnabled        bool
	CFLogpushEnabled       bool
	CFFirewallRulesEnabled bool
	CFIPRangesConfigured   bool

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

	// ClamAV
	ClamAVEnabled bool

	// VPC
	VPCEgressPolicy string

	// Audit Logs
	AuditLogRetentionDays int
	AuditLogWORM          bool

	// Cloud Build
	CloudBuildEnabled bool

	// Backend code
	BoringCrypto         bool
	SessionTimeoutMinutes int
	CFAccessMiddleware   bool
	RBACEnabled          bool
	AuditLoggingEnabled  bool
	RLSEnabled           bool
	SCIMEnabled          bool
	DLPEnabled           bool
}

func scanInfrastructure(infraRoot, backendRoot string) (*InfraFacts, error) {
	facts := &InfraFacts{}

	scanDeploymentHCL(infraRoot, facts)
	scanCloudRunAdmin(infraRoot, facts)
	scanCloudSQLModule(infraRoot, facts)
	scanKMSModule(infraRoot, facts)
	scanGCSModule(infraRoot, facts)
	scanVPCModule(infraRoot, facts)
	scanCloudArmorModule(infraRoot, facts)
	scanAssuredWorkloads(infraRoot, facts)
	scanCloudflareModules(infraRoot, facts)
	scanAuditLogs(infraRoot, facts)
	scanClamAV(infraRoot, facts)

	if backendRoot != "" {
		scanBackendCode(backendRoot, facts)
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
	// Check for FQDN egress firewall
	for _, env := range []string{"staging", "fed"} {
		path := filepath.Join(infraRoot, "gcp/environments", env, "admin/vpc/terragrunt.hcl")
		if data, err := os.ReadFile(path); err == nil {
			if strings.Contains(string(data), "egress") {
				// VPC egress controls exist
			}
			break
		}
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
