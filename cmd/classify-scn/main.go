// Package main implements the FedRAMP Significant Change Notification (SCN) classifier.
//
// It analyzes git diffs to determine whether a change is "significant" (requires
// SCN filing with FedRAMP PMO) or "routine" (no notification needed).
//
// Usage:
//
//	go run ./cmd/classify-scn --base origin/main --head HEAD
//	go run ./cmd/classify-scn --base HEAD~1 --head HEAD --json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// significantPatterns defines path patterns that indicate a security-critical change.
// A change touching any of these paths requires an SCN filing with FedRAMP PMO.
var significantPatterns = []struct {
	Pattern string
	Reason  string
}{
	// Authentication & authorization
	{"cmd/server/connect_interceptors.go", "Auth interceptor (authentication/authorization boundary)"},
	{"internal/auth/", "Authentication service"},
	{"internal/sso/", "SSO/SCIM identity federation"},
	{"internal/cloudarmor/", "Cloud Armor WAF rules"},
	{"modules/identity-platform/", "Identity Platform configuration"},
	{"modules/firebase/", "Firebase authentication"},

	// Cryptography & key management
	{"modules/kms/", "Encryption key management"},
	{"crypto", "Cryptographic operations"},
	{"encrypt", "Encryption configuration"},
	{"tls", "TLS configuration"},
	{"certificate", "Certificate management"},

	// Network architecture
	{"modules/vpc/", "VPC network architecture"},
	{"modules/cloud-armor/", "WAF/DDoS protection"},
	{"modules/load-balancer/", "Load balancer configuration"},
	{"firewall", "Firewall rules"},
	{"cloud-nat", "NAT gateway"},
	{"red-infra/", "Red team infrastructure"},
	{"vpc/", "VPC configuration"},

	// Data storage & processing
	{"modules/cloud-sql/", "Database configuration"},
	{"modules/gcs/", "Object storage configuration"},
	{"modules/vertex-ai/", "AI/ML pipeline"},
	{"modules/document-ai/", "Document processing"},
	{"postgres/migrations/", "Database schema migration"},
	{"postgres/schema.sql", "Database schema"},

	// IAM & service accounts
	{"modules/service-accounts/", "Service account IAM"},
	{"iam", "IAM policy change"},
	{"org/", "Organization-level configuration"},

	// Audit & logging
	{"modules/audit-logs/", "Audit logging configuration"},
	{"internal/audit/", "Application audit logging"},

	// Infrastructure core
	{"terragrunt.hcl", "Terragrunt root config"},
	{"env.hcl", "Environment variables"},

	// Compliance documents (SSP changes = significant)
	{"fedramp-ssp.md", "System Security Plan"},
	{"fedramp-ssp-appendix-a-controls.md", "Control implementations"},

	// Proto definitions (API contract changes)
	{".proto", "API contract (protobuf)"},

	// Container base images
	{"Dockerfile", "Container image definition"},
}

// Classification represents the result of the SCN analysis.
type Classification struct {
	Result           string   `json:"classification"`
	Timestamp        string   `json:"timestamp"`
	BaseRef          string   `json:"base_ref"`
	HeadRef          string   `json:"head_ref"`
	TotalChanged     int      `json:"total_files_changed"`
	SignificantCount int      `json:"significant_files_count"`
	RoutineCount     int      `json:"routine_files_count"`
	SignificantFiles []Match  `json:"significant_files"`
	RoutineFiles     []string `json:"routine_files"`
}

// Match represents a file that matched a significant pattern.
type Match struct {
	File    string `json:"file"`
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
}

func getChangedFiles(baseRef, headRef string) ([]string, error) {
	// Try three-dot diff first (PR-style), fall back to two-dot
	out, err := exec.Command("git", "diff", "--name-only", baseRef+"..."+headRef).Output()
	if err != nil {
		out, err = exec.Command("git", "diff", "--name-only", baseRef, headRef).Output()
		if err != nil {
			return nil, fmt.Errorf("git diff failed: %w", err)
		}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var files []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			files = append(files, l)
		}
	}
	return files, nil
}

func classifyFile(file string) *Match {
	normalized := filepath.ToSlash(file)
	for _, p := range significantPatterns {
		if strings.Contains(normalized, p.Pattern) {
			return &Match{
				File:    file,
				Pattern: p.Pattern,
				Reason:  p.Reason,
			}
		}
	}
	return nil
}

func main() {
	baseRef := flag.String("base", "origin/main", "Base git ref for comparison")
	headRef := flag.String("head", "HEAD", "Head git ref for comparison")
	jsonOutput := flag.Bool("json", false, "Output JSON instead of human-readable text")
	flag.Parse()

	files, err := getChangedFiles(*baseRef, *headRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	result := Classification{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		BaseRef:      *baseRef,
		HeadRef:      *headRef,
		TotalChanged: len(files),
	}

	for _, f := range files {
		if m := classifyFile(f); m != nil {
			result.SignificantFiles = append(result.SignificantFiles, *m)
			result.SignificantCount++
		} else {
			result.RoutineFiles = append(result.RoutineFiles, f)
			result.RoutineCount++
		}
	}

	if result.SignificantCount > 0 {
		result.Result = "SIGNIFICANT"
	} else {
		result.Result = "ROUTINE"
	}

	if *jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Println("=== FedRAMP SCN Classification ===")
		fmt.Printf("Base: %s\n", *baseRef)
		fmt.Printf("Head: %s\n", *headRef)
		fmt.Printf("Changed files: %d\n\n", result.TotalChanged)

		if result.SignificantCount > 0 {
			fmt.Printf("--- Significant files (%d) ---\n", result.SignificantCount)
			for _, m := range result.SignificantFiles {
				fmt.Printf("  ⚠  %s\n     → %s\n", m.File, m.Reason)
			}
			fmt.Println()
		}

		if result.RoutineCount > 0 {
			fmt.Printf("--- Routine files (%d) ---\n", result.RoutineCount)
			for _, f := range result.RoutineFiles {
				fmt.Printf("  ✓  %s\n", f)
			}
			fmt.Println()
		}

		if result.Result == "SIGNIFICANT" {
			fmt.Println("╔══════════════════════════════════════════════════════════════╗")
			fmt.Println("║  CLASSIFICATION: SIGNIFICANT CHANGE                         ║")
			fmt.Println("║                                                             ║")
			fmt.Println("║  This PR modifies security-critical components.             ║")
			fmt.Println("║  A Significant Change Notification (SCN) must be filed      ║")
			fmt.Println("║  with the FedRAMP PMO before merging.                       ║")
			fmt.Println("║                                                             ║")
			fmt.Println("║  Contact: security@latentarchon.com                         ║")
			fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		} else {
			fmt.Println("Classification: ROUTINE — no SCN required.")
		}
	}

	if result.Result == "SIGNIFICANT" {
		os.Exit(1)
	}
}
