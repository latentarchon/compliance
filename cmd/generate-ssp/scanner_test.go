package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHclLocalValue(t *testing.T) {
	content := `locals {
  region         = "us-east4"
  environment    = "staging"
  deployment     = "staging"
  tier           = "fed"
  admin_project_id = "archon-fed-admin-staging"
  ops_project_id   = "archon-fed-ops-staging"
  cloud_sql_enable_public_ip  = false  # org policy enforces this
  cloud_sql_disk_size         = 10
  cloud_run_min_scale = 0
  cloud_run_max_scale = 3
}`
	tests := []struct {
		key  string
		want string
	}{
		{"region", "us-east4"},
		{"environment", "staging"},
		{"tier", "fed"},
		{"admin_project_id", "archon-fed-admin-staging"},
		{"ops_project_id", "archon-fed-ops-staging"},
		{"cloud_sql_enable_public_ip", "false"},
		{"cloud_sql_disk_size", "10"},
		{"cloud_run_min_scale", "0"},
		{"cloud_run_max_scale", "3"},
		{"nonexistent_key", ""},
	}
	for _, tt := range tests {
		got := hclLocalValue(content, tt.key)
		if got != tt.want {
			t.Errorf("hclLocalValue(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestHclLocalValueWithComments(t *testing.T) {
	content := `locals {
  public_ip = false  # enforced by org policy
  domain    = "app.fed.staging.latentarchon.com" # cloud-neutral
}`
	if got := hclLocalValue(content, "public_ip"); got != "false" {
		t.Errorf("got %q, want %q", got, "false")
	}
	if got := hclLocalValue(content, "domain"); got != "app.fed.staging.latentarchon.com" {
		t.Errorf("got %q, want %q", got, "app.fed.staging.latentarchon.com")
	}
}

func TestHclInputValueFromContent(t *testing.T) {
	content := `include "root" {
  path = find_in_parent_folders()
}

inputs = {
  ingress        = "internal-and-cloud-load-balancing"
  min_instances  = 1
  vpc_egress     = "all-traffic"
  some_flag      = true  # important
}`
	tests := []struct {
		key  string
		want string
	}{
		{"ingress", "internal-and-cloud-load-balancing"},
		{"min_instances", "1"},
		{"vpc_egress", "all-traffic"},
		{"some_flag", "true"},
		{"nonexistent", ""},
	}
	for _, tt := range tests {
		got := hclInputValueFromContent(content, tt.key)
		if got != tt.want {
			t.Errorf("hclInputValueFromContent(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestHclInputValueNoInputsBlock(t *testing.T) {
	content := `include "root" {
  path = find_in_parent_folders()
}`
	if got := hclInputValueFromContent(content, "ingress"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestParseRotationDays(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"7776000s", 90},
		{"2592000s", 30},
		{"86400s", 1},
		{"90", 90},
		{"365", 365},
		{"", 0},
		{"invalid", 0},
	}
	for _, tt := range tests {
		got := parseRotationDays(tt.input)
		if got != tt.want {
			t.Errorf("parseRotationDays(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestExtractHCLList(t *testing.T) {
	content := `inputs = {
  allowed_services = [
    "compute.googleapis.com",
    "storage.googleapis.com",
    # disabled for now
    # "bigquery.googleapis.com",
    "kms.googleapis.com",
  ]
}`
	got := extractHCLList(content, "allowed_services")
	want := []string{"compute.googleapis.com", "storage.googleapis.com", "kms.googleapis.com"}
	if len(got) != len(want) {
		t.Fatalf("extractHCLList: got %d items, want %d: %v", len(got), len(want), got)
	}
	for i, g := range got {
		if g != want[i] {
			t.Errorf("extractHCLList[%d] = %q, want %q", i, g, want[i])
		}
	}
}

func TestExtractHCLListEmpty(t *testing.T) {
	got := extractHCLList("no list here", "allowed_services")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestHclVarDefaultRaw(t *testing.T) {
	content := `variable "rotation_period" {
  description = "Key rotation period"
  type        = string
  default     = "7776000s"
}

variable "algorithm" {
  description = "Algorithm"
  type        = string
  default     = "GOOGLE_SYMMETRIC_ENCRYPTION"
}

variable "enabled" {
  type    = bool
  default = true
}

variable "count" {
  type    = number
  default = 42
}`
	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{"rotation_period", "7776000s", true},
		{"algorithm", "GOOGLE_SYMMETRIC_ENCRYPTION", true},
		{"enabled", "true", true},
		{"count", "42", true},
		{"nonexistent", "", false},
	}
	for _, tt := range tests {
		got, ok := hclVarDefaultRaw(content, tt.name)
		if ok != tt.ok {
			t.Errorf("hclVarDefaultRaw(%q): ok=%v, want %v", tt.name, ok, tt.ok)
		}
		if got != tt.want {
			t.Errorf("hclVarDefaultRaw(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestContainsPattern(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "auth")
	os.MkdirAll(subdir, 0755)

	os.WriteFile(filepath.Join(subdir, "rbac.go"), []byte(`
package auth

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)
`), 0644)

	os.WriteFile(filepath.Join(subdir, "session.go"), []byte(`
package auth

const SessionTimeout = 15 * time.Minute
`), 0644)

	if !containsPattern(dir, "auth", "Role", "rbac") {
		t.Error("expected containsPattern to find Role/rbac in auth/")
	}
	if !containsPattern(dir, "auth", "SessionTimeout") {
		t.Error("expected containsPattern to find SessionTimeout in auth/")
	}
	if containsPattern(dir, "auth", "NonexistentPattern12345") {
		t.Error("did not expect containsPattern to match NonexistentPattern12345")
	}
	if containsPattern(dir, "nonexistent-dir", "anything") {
		t.Error("did not expect containsPattern to match nonexistent dir")
	}
}

func TestContainsPatternSkipsSubdirs(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "parent")
	nested := filepath.Join(subdir, "child")
	os.MkdirAll(nested, 0755)

	os.WriteFile(filepath.Join(nested, "deep.go"), []byte("package deep\nvar RLS = true"), 0644)

	if containsPattern(dir, "parent", "RLS") {
		t.Error("containsPattern should not recurse into child dirs")
	}
}

func TestDeterministicUUID(t *testing.T) {
	uuid1 := deterministicUUID("test-input")
	uuid2 := deterministicUUID("test-input")
	if uuid1 != uuid2 {
		t.Errorf("deterministic UUID not stable: %s != %s", uuid1, uuid2)
	}

	uuid3 := deterministicUUID("different-input")
	if uuid1 == uuid3 {
		t.Errorf("different inputs produced same UUID: %s", uuid1)
	}

	if len(uuid1) != 36 {
		t.Errorf("UUID wrong length: %d (want 36): %s", len(uuid1), uuid1)
	}
	if uuid1[8] != '-' || uuid1[13] != '-' || uuid1[18] != '-' || uuid1[23] != '-' {
		t.Errorf("UUID wrong format: %s", uuid1)
	}
	if uuid1[14] != '4' {
		t.Errorf("UUID version not 4: %s", uuid1)
	}
	if uuid1[19] != '8' {
		t.Errorf("UUID variant not 8: %s", uuid1)
	}
}

func TestDeterministicUUIDNamespaceIsolation(t *testing.T) {
	orig := uuidNamespace
	defer func() { uuidNamespace = orig }()

	uuidNamespace = "system-A"
	uuidA := deterministicUUID("control-ac-1")

	uuidNamespace = "system-B"
	uuidB := deterministicUUID("control-ac-1")

	if uuidA == uuidB {
		t.Errorf("UUIDs should differ across namespaces: both got %s", uuidA)
	}
}

func TestScanDeploymentHCL(t *testing.T) {
	dir := t.TempDir()
	envDir := filepath.Join(dir, "gcp/environments/staging")
	os.MkdirAll(envDir, 0755)

	os.WriteFile(filepath.Join(envDir, "deployment.hcl"), []byte(`locals {
  deployment     = "staging"
  tier           = "fed"
  environment    = "staging"
  region         = "us-east4"
  admin_project_id = "test-admin"
  ops_project_id   = "test-ops"
  app_project_id   = "test-app"
  kms_project_id   = "test-kms"
  cloud_sql_tier   = "db-f1-micro"
  cloud_sql_availability_type = "ZONAL"
  cloud_sql_enable_public_ip  = false
  cloud_sql_disk_size         = 10
  cloud_run_min_scale = 0
  cloud_run_max_scale = 5
  gemini_model = "gemini-3.1-pro"
}`), 0644)

	facts := &InfraFacts{}
	scanDeploymentHCL(dir, facts)

	if facts.Region != "us-east4" {
		t.Errorf("Region = %q, want us-east4", facts.Region)
	}
	if facts.AdminProjectID != "test-admin" {
		t.Errorf("AdminProjectID = %q, want test-admin", facts.AdminProjectID)
	}
	if facts.KMSProjectID != "test-kms" {
		t.Errorf("KMSProjectID = %q, want test-kms", facts.KMSProjectID)
	}
	if facts.CloudRunMaxScale != 5 {
		t.Errorf("CloudRunMaxScale = %d, want 5", facts.CloudRunMaxScale)
	}
	if facts.CloudSQLPublicIP {
		t.Error("CloudSQLPublicIP should be false")
	}
	if facts.GeminiModel != "gemini-3.1-pro" {
		t.Errorf("GeminiModel = %q, want gemini-3.1-pro", facts.GeminiModel)
	}
}

func TestScanCloudflareModules(t *testing.T) {
	dir := t.TempDir()
	cfModules := filepath.Join(dir, "cloudflare/modules")
	for _, mod := range []string{"waf", "rate-limiting", "access", "logpush", "firewall-rules", "ip-ranges"} {
		os.MkdirAll(filepath.Join(cfModules, mod), 0755)
	}
	os.WriteFile(filepath.Join(cfModules, "firewall-rules/main.tf"), []byte(`
resource "cloudflare_ruleset" "custom_firewall" {
  dynamic "rules" {
    for_each = var.enable_threat_score_challenge ? [1] : []
    content {
      expression = "cf.threat_score gt 14"
    }
  }
  dynamic "rules" {
    for_each = var.enable_path_protection ? [1] : []
    content {
      expression = join(" or ", [for p in var.blocked_paths : "http.request.uri.path contains p"])
    }
  }
}
`), 0644)

	facts := &InfraFacts{}
	scanCloudflareModules(dir, facts)

	if !facts.CFWAFEnabled {
		t.Error("CFWAFEnabled should be true")
	}
	if !facts.CFRateLimitingEnabled {
		t.Error("CFRateLimitingEnabled should be true")
	}
	if !facts.CFAccessEnabled {
		t.Error("CFAccessEnabled should be true")
	}
	if !facts.CFLogpushEnabled {
		t.Error("CFLogpushEnabled should be true")
	}
	if !facts.CFFirewallRulesEnabled {
		t.Error("CFFirewallRulesEnabled should be true")
	}
	if !facts.CFIPRangesConfigured {
		t.Error("CFIPRangesConfigured should be true")
	}
}

func TestScanCloudflareModulesPartial(t *testing.T) {
	dir := t.TempDir()
	cfModules := filepath.Join(dir, "cloudflare/modules")
	os.MkdirAll(filepath.Join(cfModules, "waf"), 0755)
	os.MkdirAll(filepath.Join(cfModules, "dns"), 0755)

	facts := &InfraFacts{}
	scanCloudflareModules(dir, facts)

	if !facts.CFWAFEnabled {
		t.Error("CFWAFEnabled should be true")
	}
	if facts.CFRateLimitingEnabled {
		t.Error("CFRateLimitingEnabled should be false")
	}
	if facts.CFAccessEnabled {
		t.Error("CFAccessEnabled should be false")
	}
}

func TestScanClamAV(t *testing.T) {
	dir := t.TempDir()

	facts := &InfraFacts{}
	scanClamAV(dir, facts)
	if facts.ClamAVEnabled {
		t.Error("ClamAVEnabled should be false when module absent")
	}

	os.MkdirAll(filepath.Join(dir, "gcp/modules/clamav"), 0755)
	scanClamAV(dir, facts)
	if !facts.ClamAVEnabled {
		t.Error("ClamAVEnabled should be true when module exists")
	}
}

func TestScanCloudArmorModule(t *testing.T) {
	dir := t.TempDir()
	modDir := filepath.Join(dir, "gcp/modules/cloud-armor")
	os.MkdirAll(modDir, 0755)

	os.WriteFile(filepath.Join(modDir, "main.tf"), []byte(`
resource "google_compute_security_policy" "default" {
  rule {
    match {
      expr {
        expression = "origin.ip in cloudflare_ip_ranges"
      }
    }
  }
}`), 0644)

	facts := &InfraFacts{}
	scanCloudArmorModule(dir, facts)

	if !facts.CloudArmorCFRestriction {
		t.Error("CloudArmorCFRestriction should be true")
	}
}

func TestBuildImplementedRequirements(t *testing.T) {
	facts := &InfraFacts{
		Region:           "us-east4",
		AdminProjectID:   "test-admin",
		OpsProjectID:     "test-ops",
		AppProjectID:     "test-app",
		KMSProjectID:     "test-kms",
		KMSRotationDays:  90,
		BoringCrypto:     true,
		RBACEnabled:      true,
		RLSEnabled:       true,
		ClamAVEnabled:    true,
		AuditLogRetentionDays: 365,
	}
	reqs := buildImplementedRequirements(facts)

	if len(reqs) == 0 {
		t.Fatal("expected controls, got none")
	}

	controlMap := map[string]ImplementedRequirement{}
	for _, r := range reqs {
		controlMap[r.ControlID] = r
	}

	// Verify ac-7 has parameters
	ac7, ok := controlMap["ac-7"]
	if !ok {
		t.Fatal("ac-7 not found")
	}
	if len(ac7.SetParameters) != 3 {
		t.Errorf("ac-7: expected 3 set-parameters, got %d", len(ac7.SetParameters))
	}

	// Verify sc-28 has multiple by-components
	sc28, ok := controlMap["sc-28"]
	if !ok {
		t.Fatal("sc-28 not found")
	}
	if len(sc28.Statements) == 0 {
		t.Fatal("sc-28: no statements")
	}
	if len(sc28.Statements[0].ByComponents) < 2 {
		t.Errorf("sc-28: expected multiple by-components, got %d", len(sc28.Statements[0].ByComponents))
	}

	// Verify UUIDs are deterministic
	reqs2 := buildImplementedRequirements(facts)
	for i, r := range reqs {
		if r.UUID != reqs2[i].UUID {
			t.Errorf("control %s: UUID not deterministic: %s vs %s", r.ControlID, r.UUID, reqs2[i].UUID)
			break
		}
	}

	// Verify no duplicate control IDs
	seen := map[string]bool{}
	for _, r := range reqs {
		if seen[r.ControlID] {
			t.Errorf("duplicate control ID: %s", r.ControlID)
		}
		seen[r.ControlID] = true
	}
}

func TestFilterByBaseline(t *testing.T) {
	facts := &InfraFacts{Region: "us-east4"}
	reqs := buildImplementedRequirements(facts)

	moderate := filterByBaseline(reqs, "moderate")
	high := filterByBaseline(reqs, "high")
	il5 := filterByBaseline(reqs, "il5")

	if len(moderate) >= len(high) {
		t.Errorf("high (%d) should have more controls than moderate (%d)", len(high), len(moderate))
	}
	if len(high) >= len(il5) {
		t.Errorf("il5 (%d) should have more controls than high (%d)", len(il5), len(high))
	}
}
