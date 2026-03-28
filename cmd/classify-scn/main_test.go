package main

import (
	"testing"
)

func TestClassifyFile_Significant(t *testing.T) {
	tests := []struct {
		file       string
		wantMatch  bool
		wantReason string
	}{
		// Auth boundary
		{"cmd/server/connect_interceptors.go", true, "Auth interceptor (authentication/authorization boundary)"},
		{"internal/auth/firebase.go", true, "Authentication service"},
		{"internal/sso/scim_handler.go", true, "SSO/SCIM identity federation"},

		// Crypto
		{"modules/kms/main.tf", true, "Encryption key management"},
		{"internal/crypto/encrypt.go", true, "Cryptographic operations"},

		// Network
		{"modules/vpc/main.tf", true, "VPC network architecture"},
		{"modules/cloud-armor/main.tf", true, "WAF/DDoS protection"},
		{"modules/load-balancer/main.tf", true, "Load balancer configuration"},
		{"vpc/main.tf", true, "VPC configuration"},

		// Data
		{"modules/cloud-sql/main.tf", true, "Database configuration"},
		{"modules/gcs/main.tf", true, "Object storage configuration"},
		{"postgres/migrations/001_init.sql", true, "Database schema migration"},

		// IAM
		{"modules/service-accounts/main.tf", true, "Service account IAM"},
		{"org/projects.tf", true, "Organization-level configuration"},

		// Compliance docs
		{"fedramp-ssp.md", true, "System Security Plan"},
		{"fedramp-ssp-appendix-a-controls.md", true, "Control implementations"},

		// Containers & protos
		{"backend/Dockerfile", true, "Container image definition"},
		{"proto/conversation.proto", true, "API contract (protobuf)"},

		// Infrastructure config
		{"terragrunt.hcl", true, "Terragrunt root config"},
		{"environments/staging/env.hcl", true, "Environment variables"},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			m := classifyFile(tt.file)
			if !tt.wantMatch {
				if m != nil {
					t.Errorf("expected no match, got pattern=%q reason=%q", m.Pattern, m.Reason)
				}
				return
			}
			if m == nil {
				t.Fatalf("expected match with reason %q, got nil", tt.wantReason)
			}
			if m.Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", m.Reason, tt.wantReason)
			}
		})
	}
}

func TestClassifyFile_Routine(t *testing.T) {
	routineFiles := []string{
		"README.md",
		"compliance/scripts/verify-compliance-tooling.sh",
		"docs/api-reference.md",
		".github/workflows/ci.yml",
		"internal/gentext/service.go",
		"cmd/server/main.go",
		"shared-go/postgres/queries.sql",
		"frontend/src/App.tsx",
		"package.json",
		"go.mod",
		"sales/pipeline-targets.md",
		"policies/information-security.md",
	}

	for _, f := range routineFiles {
		t.Run(f, func(t *testing.T) {
			m := classifyFile(f)
			if m != nil {
				t.Errorf("expected routine (nil), got pattern=%q reason=%q", m.Pattern, m.Reason)
			}
		})
	}
}

func TestClassification_Result(t *testing.T) {
	// If any file is significant, result should be SIGNIFICANT
	files := []string{
		"README.md",
		"modules/kms/main.tf", // significant
		"docs/api.md",
	}

	var sigCount int
	for _, f := range files {
		if classifyFile(f) != nil {
			sigCount++
		}
	}

	if sigCount != 1 {
		t.Errorf("expected 1 significant file, got %d", sigCount)
	}
}
