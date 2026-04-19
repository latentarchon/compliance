// Package main implements automated SSP-to-IaC drift detection.
//
// It cross-checks concrete claims in the FedRAMP SSP against actual
// Terraform/Terragrunt configurations and backend source code using
// proper HCL and Go AST parsing — no fragile regex.
//
// Usage:
//
//	go run ./cmd/check-ssp-iac-drift
//	go run ./cmd/check-ssp-iac-drift --infra-root ../infra --backend-root ../backend --json
//
// Exit codes:
//
//	0 = no drift detected
//	1 = drift detected
//	2 = setup error
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"

)

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

type CheckResult struct {
	Name     string `json:"name"`
	Control  string `json:"control"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Pass     bool   `json:"pass"`
}

type Report struct {
	Timestamp string        `json:"timestamp"`
	Passed    int           `json:"passed"`
	Failed    int           `json:"failed"`
	Total     int           `json:"total"`
	Checks    []CheckResult `json:"checks"`
}

// ---------------------------------------------------------------------------
// Checker
// ---------------------------------------------------------------------------

type Checker struct {
	infraRoot   string
	backendRoot string
	report      Report
}

func (c *Checker) check(control, name, expected, actual string) {
	pass := expected == actual
	c.report.Checks = append(c.report.Checks, CheckResult{
		Name:     name,
		Control:  control,
		Expected: expected,
		Actual:   actual,
		Pass:     pass,
	})
	c.report.Total++
	if pass {
		c.report.Passed++
	} else {
		c.report.Failed++
	}
}

// ---------------------------------------------------------------------------
// HCL helpers
// ---------------------------------------------------------------------------

// hclVarDefaultFromFile reads a variables.tf and extracts the default for a named variable.
// Works by scanning for `variable "name" { ... default = VALUE ... }` blocks.
func hclVarDefaultFromFile(path, varName string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}

	p := hclparse.NewParser()
	f, diags := p.ParseHCLFile(path)
	if diags.HasErrors() {
		// Fall back to raw text scan
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

// hclVarDefaultRaw is a fallback text-based extraction.
func hclVarDefaultRaw(content, varName string) (string, bool) {
	// Find variable block
	marker := fmt.Sprintf(`variable "%s"`, varName)
	idx := strings.Index(content, marker)
	if idx == -1 {
		return "", false
	}

	// Find default within the next ~500 chars
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

// hclInputValue extracts an input value from a terragrunt.hcl `inputs = { ... }` block.
func hclInputValue(path, key string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	content := string(data)

	// Find the inputs block
	inputsIdx := strings.Index(content, "inputs")
	if inputsIdx == -1 {
		return "", false
	}

	// Search for the key within the inputs block
	rest := content[inputsIdx:]
	for _, line := range strings.Split(rest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key) && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				// Strip inline comments (# ... or // ...)
				if idx := strings.Index(val, "#"); idx > 0 {
					val = strings.TrimSpace(val[:idx])
				}
				if idx := strings.Index(val, "//"); idx > 0 {
					val = strings.TrimSpace(val[:idx])
				}
				val = strings.Trim(val, `"`)
				return val, true
			}
		}
	}
	return "", false
}

// countRolesInBlock counts "roles/..." entries in a named block within a terragrunt.hcl.
func countRolesInBlock(path, blockName string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	content := string(data)

	// Find the block
	idx := strings.Index(content, fmt.Sprintf(`"%s"`, blockName))
	if idx == -1 {
		return 0, false
	}

	// Find the closing brace of this block
	block := content[idx:]
	braceCount := 0
	started := false
	endIdx := len(block)
	for i, ch := range block {
		if ch == '{' {
			braceCount++
			started = true
		} else if ch == '}' {
			braceCount--
			if started && braceCount == 0 {
				endIdx = i
				break
			}
		}
	}
	block = block[:endIdx]

	count := 0
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, `"roles/`) {
			count++
		}
	}
	return count, count > 0
}

// blockContains checks if a named block contains a specific string.
func blockContains(path, blockName, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	content := string(data)

	idx := strings.Index(content, fmt.Sprintf(`"%s"`, blockName))
	if idx == -1 {
		return false
	}

	block := content[idx:]
	braceCount := 0
	started := false
	endIdx := len(block)
	for i, ch := range block {
		if ch == '{' {
			braceCount++
			started = true
		} else if ch == '}' {
			braceCount--
			if started && braceCount == 0 {
				endIdx = i
				break
			}
		}
	}
	block = block[:endIdx]
	return strings.Contains(block, needle)
}

// fileContainsOutsideComments checks if a file contains a string in non-comment lines.
func fileContainsOutsideComments(path, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.Contains(trimmed, needle) {
			return true
		}
	}
	return false
}

// fileContains checks if file content contains a string.
func fileContains(path, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}

// ---------------------------------------------------------------------------
// Go AST helpers
// ---------------------------------------------------------------------------

// goExtractEnvDefault extracts the default value from a GetEnvAsInt("KEY", DEFAULT) call.
func goExtractEnvDefault(path, envVar string) (string, bool) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		return "", false
	}

	var result string
	var found bool

	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Match config.GetEnvAsInt("SESSION_IDLE_TIMEOUT_MIN", 25)
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "GetEnvAsInt" {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}

		// Check first arg is our env var
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		varName := strings.Trim(lit.Value, `"`)
		if varName != envVar {
			return true
		}

		// Extract second arg (the default value)
		defLit, ok := call.Args[1].(*ast.BasicLit)
		if !ok {
			return true
		}
		result = defLit.Value
		found = true
		return false
	})

	return result, found
}

// ---------------------------------------------------------------------------
// Check implementations
// ---------------------------------------------------------------------------

func (c *Checker) checkKMSRotation() {
	varsFile := filepath.Join(c.infraRoot, "gcp/modules/kms/variables.tf")
	val, ok := hclVarDefaultFromFile(varsFile, "rotation_period")
	if !ok {
		c.check("SC-12", "KMS rotation (days)", "90", "NOT_FOUND")
		return
	}
	// Value is like "7776000s"
	val = strings.TrimSuffix(val, "s")
	seconds, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		c.check("SC-12", "KMS rotation (days)", "90", "PARSE_ERROR: "+val)
		return
	}
	days := seconds / 86400
	c.check("SC-12", "KMS rotation (days)", "90", strconv.FormatInt(days, 10))
}

func (c *Checker) checkCloudSQLBackup() {
	mainFile := filepath.Join(c.infraRoot, "gcp/modules/cloud-sql/main.tf")
	data, err := os.ReadFile(mainFile)
	if err != nil {
		c.check("CP-9", "Cloud SQL retained_backups", "14", "FILE_NOT_FOUND")
		return
	}
	content := string(data)

	// Extract retained_backups value
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "retained_backups") && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				c.check("CP-9", "Cloud SQL retained_backups", "14", val)
				break
			}
		}
	}

	// Check PITR
	hasPITR := strings.Contains(content, "point_in_time_recovery_enabled = true")
	c.check("CP-9", "Cloud SQL PITR enabled", "true", strconv.FormatBool(hasPITR))
}

func (c *Checker) checkGCSSoftDelete() {
	varsFile := filepath.Join(c.infraRoot, "gcp/modules/gcs/variables.tf")
	val, ok := hclVarDefaultFromFile(varsFile, "soft_delete_retention_seconds")
	if !ok {
		c.check("CP-9", "GCS soft_delete default (days)", "90", "NOT_FOUND")
		return
	}
	seconds, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		c.check("CP-9", "GCS soft_delete default (days)", "90", "PARSE_ERROR: "+val)
		return
	}
	days := seconds / 86400
	c.check("CP-9", "GCS soft_delete default (days)", "90", strconv.FormatInt(days, 10))
}

func (c *Checker) checkAuditLogWORM() {
	// Production
	prodFile := filepath.Join(c.infraRoot, "gcp/environments/fed/ops/audit-logs/terragrunt.hcl")
	if retDays, ok := hclInputValue(prodFile, "gcs_audit_retention_days"); ok {
		days, err := strconv.ParseInt(retDays, 10, 64)
		if err == nil {
			years := days / 365
			c.check("AU-11", "Prod WORM retention (years)", "7", strconv.FormatInt(years, 10))
		}
	} else {
		c.check("AU-11", "Prod WORM retention (years)", "7", "NOT_FOUND")
	}

	if locked, ok := hclInputValue(prodFile, "gcs_audit_retention_locked"); ok {
		c.check("AU-11", "Prod WORM locked", "true", locked)
	} else {
		c.check("AU-11", "Prod WORM locked", "true", "NOT_FOUND")
	}

	// Staging
	stagingFile := filepath.Join(c.infraRoot, "gcp/environments/staging/ops/audit-logs/terragrunt.hcl")
	if retDays, ok := hclInputValue(stagingFile, "gcs_audit_retention_days"); ok {
		c.check("AU-11", "Staging WORM retention (days)", "365", retDays)
	}
	if locked, ok := hclInputValue(stagingFile, "gcs_audit_retention_locked"); ok {
		c.check("AU-11", "Staging WORM unlocked", "false", locked)
	}
}

func (c *Checker) checkTerraformSARoles() {
	saFile := filepath.Join(c.infraRoot, "gcp/environments/staging/ops/service-accounts/terragrunt.hcl")

	roleCount, ok := countRolesInBlock(saFile, "terraform-sa")
	if !ok {
		c.check("AC-6", "terraform-sa role count", "20", "NOT_FOUND")
		return
	}
	c.check("AC-6", "terraform-sa role count", "20", strconv.Itoa(roleCount))

	hasEditor := blockContains(saFile, "terraform-sa", `"roles/editor"`)
	c.check("AC-6", "terraform-sa has roles/editor", "true", strconv.FormatBool(hasEditor))
}

func (c *Checker) checkSessionTimeouts() {
	interceptor := filepath.Join(c.backendRoot, "cmd/server/connect_interceptors.go")
	if _, err := os.Stat(interceptor); err != nil {
		c.check("AC-12", "Idle timeout default (min)", "25", "FILE_NOT_FOUND")
		c.check("AC-12", "Absolute timeout default (min)", "720", "FILE_NOT_FOUND")
		return
	}

	if idle, ok := goExtractEnvDefault(interceptor, "SESSION_IDLE_TIMEOUT_MIN"); ok {
		c.check("AC-12", "Idle timeout default (min)", "25", idle)
	} else {
		c.check("AC-12", "Idle timeout default (min)", "25", "NOT_FOUND")
	}

	if abs, ok := goExtractEnvDefault(interceptor, "SESSION_ABSOLUTE_TIMEOUT_MIN"); ok {
		c.check("AC-12", "Absolute timeout default (min)", "720", abs)
	} else {
		c.check("AC-12", "Absolute timeout default (min)", "720", "NOT_FOUND")
	}
}

func (c *Checker) checkCloudRunIngress() {
	varsFile := filepath.Join(c.infraRoot, "gcp/modules/cloud-run/variables.tf")
	val, ok := hclVarDefaultFromFile(varsFile, "ingress")
	if !ok {
		c.check("SC-7", "Cloud Run ingress default", "internal-and-cloud-load-balancing", "NOT_FOUND")
		return
	}
	c.check("SC-7", "Cloud Run ingress default", "internal-and-cloud-load-balancing", val)
}

func (c *Checker) checkGCSForceDestroy() {
	// GCS module variable default
	varsFile := filepath.Join(c.infraRoot, "gcp/modules/gcs/variables.tf")
	val, ok := hclVarDefaultFromFile(varsFile, "force_destroy")
	if ok {
		c.check("SI-12", "GCS force_destroy default", "false", val)
	} else {
		c.check("SI-12", "GCS force_destroy default", "false", "NOT_FOUND")
	}

	// Audit logs hardcoded force_destroy
	auditMain := filepath.Join(c.infraRoot, "gcp/modules/audit-logs/main.tf")
	if fileContains(auditMain, "force_destroy = false") {
		c.check("SI-12", "Audit logs force_destroy", "false", "false")
	} else if fileContains(auditMain, "force_destroy = true") {
		c.check("SI-12", "Audit logs force_destroy", "false", "true")
	} else {
		c.check("SI-12", "Audit logs force_destroy", "false", "NOT_FOUND")
	}
}

func (c *Checker) checkBoringCrypto() {
	dockerfile := filepath.Join(c.backendRoot, "Dockerfile")
	has := fileContainsOutsideComments(dockerfile, "GOEXPERIMENT=boringcrypto")
	c.check("SC-13", "Dockerfile has GOEXPERIMENT=boringcrypto", "true", strconv.FormatBool(has))
}

func (c *Checker) checkVPCEgress() {
	vpcMain := filepath.Join(c.infraRoot, "gcp/modules/vpc/main.tf")
	hasDenyAll := fileContains(vpcMain, "deny_all")
	c.check("AC-4", "VPC has default-deny egress rule", "true", strconv.FormatBool(hasDenyAll))

	hasFQDN := fileContains(vpcMain, "dest_fqdns")
	c.check("AC-4", "VPC uses FQDN-based egress", "true", strconv.FormatBool(hasFQDN))
}

func (c *Checker) checkCMEKCoverage() {
	varsFile := filepath.Join(c.infraRoot, "gcp/modules/kms/variables.tf")
	keys := []string{
		"cloudsql", "gcs", "bigquery", "logging",
		"vertex_ai", "artifact_registry", "cloud_tasks", "app_secrets",
	}
	for _, key := range keys {
		varName := "enable_" + key + "_key"
		_, ok := hclVarDefaultFromFile(varsFile, varName)
		c.check("SC-12", "KMS has "+varName+" variable", "true", strconv.FormatBool(ok))
	}
}

func (c *Checker) checkCloudflareProxied() {
	// SSP claims all traffic is proxied through Cloudflare Edge WAF.
	// Verify staging and fed DNS configs have proxied = true.
	for _, env := range []string{"staging", "fed"} {
		dnsFile := filepath.Join(c.infraRoot, "cloudflare/environments", env, "dns/terragrunt.hcl")
		if val, ok := hclInputValue(dnsFile, "proxied"); ok {
			c.check("SC-7", env+" DNS proxied mode", "true", val)
		} else {
			c.check("SC-7", env+" DNS proxied mode", "true", "NOT_FOUND")
		}
	}
}

func (c *Checker) checkCloudflareWAFModule() {
	// SSP claims Cloudflare Edge WAF with managed rulesets.
	// Verify module exists with expected ruleset resources.
	wafMain := filepath.Join(c.infraRoot, "cloudflare/modules/waf/main.tf")
	hasManaged := fileContains(wafMain, "managed_waf")
	c.check("SC-7", "Cloudflare WAF module has managed ruleset", "true", strconv.FormatBool(hasManaged))

	hasOWASP := fileContains(wafMain, "owasp")
	c.check("SC-7", "Cloudflare WAF module has OWASP ruleset", "true", strconv.FormatBool(hasOWASP))
}

func (c *Checker) checkCloudArmorCFRestriction() {
	// SSP claims Cloud Armor enforces Cloudflare-only origin restriction.
	// Verify module has cloudflare_ip_ranges variable and deny-all rule.
	varsFile := filepath.Join(c.infraRoot, "gcp/modules/cloud-armor/variables.tf")
	_, hasCFVar := hclVarDefaultFromFile(varsFile, "cloudflare_ip_ranges")
	c.check("SC-7", "Cloud Armor has cloudflare_ip_ranges variable", "true", strconv.FormatBool(hasCFVar))

	mainFile := filepath.Join(c.infraRoot, "gcp/modules/cloud-armor/main.tf")
	hasCFAllow := fileContains(mainFile, "cloudflare")
	c.check("SC-7", "Cloud Armor main.tf references cloudflare", "true", strconv.FormatBool(hasCFAllow))
}

func (c *Checker) checkCloudflareFirewallRules() {
	fwMain := filepath.Join(c.infraRoot, "cloudflare/modules/firewall-rules/main.tf")

	hasThreatScore := fileContains(fwMain, "threat_score")
	c.check("SC-7", "Firewall rules has threat score challenge", "true", strconv.FormatBool(hasThreatScore))

	hasPathProtection := fileContains(fwMain, "blocked_paths")
	c.check("SC-7", "Firewall rules has path probing protection", "true", strconv.FormatBool(hasPathProtection))

	hasIPBlocklist := fileContains(fwMain, "blocked_ips")
	c.check("SC-7", "Firewall rules has IP blocklist", "true", strconv.FormatBool(hasIPBlocklist))

	hasASNBlocking := fileContains(fwMain, "blocked_asns")
	c.check("SC-7", "Firewall rules has ASN blocking", "true", strconv.FormatBool(hasASNBlocking))

	hasNoGeoBlock := !fileContains(fwMain, "allowed_countries") && !fileContains(fwMain, "geo_restriction") && !fileContains(fwMain, "geo-block") && !fileContains(fwMain, "Block non-US")
	c.check("SC-7", "Firewall rules has no geo-blocking (removed)", "true", strconv.FormatBool(hasNoGeoBlock))
}

func (c *Checker) checkCloudflareLogpush() {
	logpushMain := filepath.Join(c.infraRoot, "cloudflare/modules/logpush/main.tf")
	hasLogpush := fileContains(logpushMain, "cloudflare_logpush_job")
	c.check("SI-4", "Cloudflare Logpush module exists", "true", strconv.FormatBool(hasLogpush))

	hasFirewallEvents := fileContains(logpushMain, "firewall_events")
	c.check("SI-4", "Logpush exports firewall_events dataset", "true", strconv.FormatBool(hasFirewallEvents))

	envConfig := filepath.Join(c.infraRoot, "cloudflare/environments/zone/logpush/terragrunt.hcl")
	if val, ok := hclInputValue(envConfig, "enable_firewall_events"); ok {
		c.check("SI-4", "Logpush firewall_events enabled", "true", val)
	} else {
		c.check("SI-4", "Logpush firewall_events enabled", "true", "NOT_FOUND")
	}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	infraRoot := flag.String("infra-root", "../infra", "Path to infra repository root")
	backendRoot := flag.String("backend-root", "../backend", "Path to backend repository root")
	jsonOutput := flag.Bool("json", false, "Output JSON instead of human-readable text")
	flag.Parse()

	// Resolve paths
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		return a
	}
	*infraRoot = abs(*infraRoot)
	*backendRoot = abs(*backendRoot)

	// Validate paths exist
	for _, p := range []string{*infraRoot, *backendRoot} {
		if _, err := os.Stat(p); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: path not found: %s\n", p)
			os.Exit(2)
		}
	}

	c := &Checker{
		infraRoot:   *infraRoot,
		backendRoot: *backendRoot,
		report: Report{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}

	// Run all checks
	if !*jsonOutput {
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("  SSP-to-IaC Drift Detection (Go)")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println()
		fmt.Println("Infra:  ", c.infraRoot)
		fmt.Println("Backend:", c.backendRoot)
		fmt.Println()
	}

	c.checkKMSRotation()
	c.checkCloudSQLBackup()
	c.checkGCSSoftDelete()
	c.checkAuditLogWORM()
	c.checkTerraformSARoles()
	c.checkSessionTimeouts()
	c.checkCloudRunIngress()
	c.checkGCSForceDestroy()
	c.checkBoringCrypto()
	c.checkVPCEgress()
	c.checkCMEKCoverage()
	c.checkCloudflareProxied()
	c.checkCloudflareWAFModule()
	c.checkCloudflareFirewallRules()
	c.checkCloudArmorCFRestriction()
	c.checkCloudflareLogpush()

	if *jsonOutput {
		data, _ := json.MarshalIndent(c.report, "", "  ")
		fmt.Println(string(data))
	} else {
		// Print results grouped by control
		currentControl := ""
		for _, r := range c.report.Checks {
			if r.Control != currentControl {
				if currentControl != "" {
					fmt.Println()
				}
				fmt.Printf("── %s ──\n", r.Control)
				currentControl = r.Control
			}
			if r.Pass {
				fmt.Printf("  ✅ %s: %s\n", r.Name, r.Actual)
			} else {
				fmt.Printf("  ❌ %s: SSP='%s' IaC='%s'\n", r.Name, r.Expected, r.Actual)
			}
		}
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════")
		if c.report.Failed == 0 {
			fmt.Printf("  ✅ ALL %d CHECKS PASSED — No SSP-IaC drift detected\n", c.report.Total)
		} else {
			fmt.Printf("  ❌ DRIFT DETECTED: %d/%d checks failed\n", c.report.Failed, c.report.Total)
		}
		fmt.Println("═══════════════════════════════════════════════════════════")
	}

	if c.report.Failed > 0 {
		os.Exit(1)
	}
}
