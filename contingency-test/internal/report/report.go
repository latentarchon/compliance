// Package report generates FedRAMP-ready markdown reports from contingency test results.
package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/latentarchon/compliance/contingency-test/internal/checks"
)

// Input contains all data needed to generate a report.
type Input struct {
	Timestamp      time.Time
	AdminProjectID string
	AppProjectID   string
	Region         string
	Results        []checks.Result
}

// Generate creates a markdown report from test results.
func Generate(in Input) string {
	var b strings.Builder

	passed, failed, skipped := 0, 0, 0
	for _, r := range in.Results {
		switch r.Status {
		case checks.StatusPass:
			passed++
		case checks.StatusFail:
			failed++
		case checks.StatusSkip:
			skipped++
		}
	}
	total := len(in.Results)

	overallStatus := "PASS"
	if failed > 0 {
		overallStatus = "FAIL"
	}

	// Header
	b.WriteString("# CP-4 Contingency Plan Test Report\n\n")
	b.WriteString("> **Document ID**: CP4-TEST-" + in.Timestamp.Format("20060102") + "  \n")
	b.WriteString("> **Test Date**: " + in.Timestamp.Format("January 2, 2006 15:04 UTC") + "  \n")
	b.WriteString("> **Test Type**: Automated Monthly Backup Verification (ISCP-LA-001 §7.1)  \n")
	b.WriteString("> **Overall Result**: **" + overallStatus + "**  \n")
	b.WriteString("> **Controls Tested**: CP-2, CP-4, CP-9, CP-10, SC-12  \n")
	b.WriteString("> **Parent Plan**: ISCP-LA-001 (contingency-plan.md)  \n")
	b.WriteString("> **System**: Latent Archon Document Intelligence Platform  \n")
	b.WriteString("\n---\n\n")

	// Executive Summary
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(fmt.Sprintf("This automated contingency plan test verified %d infrastructure components ", total))
	b.WriteString("across the Latent Archon authorization boundary. The test validates backup ")
	b.WriteString("configuration, recovery capabilities, and service health as required by ")
	b.WriteString("NIST SP 800-53 Rev. 5 control CP-4 (Contingency Plan Testing).\n\n")

	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(fmt.Sprintf("| **Total Checks** | %d |\n", total))
	b.WriteString(fmt.Sprintf("| **Passed** | %d |\n", passed))
	b.WriteString(fmt.Sprintf("| **Failed** | %d |\n", failed))
	b.WriteString(fmt.Sprintf("| **Skipped** | %d |\n", skipped))
	b.WriteString(fmt.Sprintf("| **Admin Project** | `%s` |\n", in.AdminProjectID))
	if in.AppProjectID != "" {
		b.WriteString(fmt.Sprintf("| **App Project** | `%s` |\n", in.AppProjectID))
	}
	b.WriteString(fmt.Sprintf("| **Region** | `%s` |\n", in.Region))
	b.WriteString("\n---\n\n")

	// Results by Category
	b.WriteString("## Detailed Results\n\n")

	categories := orderCategories(in.Results)
	for _, cat := range categories {
		b.WriteString("### " + cat + "\n\n")
		for _, r := range in.Results {
			if r.Category != cat {
				continue
			}
			icon := statusIcon(r.Status)
			b.WriteString(fmt.Sprintf("#### %s %s\n\n", icon, r.Name))
			b.WriteString(fmt.Sprintf("- **Control**: %s\n", r.Control))
			b.WriteString(fmt.Sprintf("- **Description**: %s\n", r.Description))
			b.WriteString(fmt.Sprintf("- **Status**: %s\n", r.Status))
			b.WriteString(fmt.Sprintf("- **Duration**: %s\n", r.Duration.Round(time.Millisecond)))
			b.WriteString("\n**Findings**:\n\n```\n")
			b.WriteString(r.Details)
			b.WriteString("\n```\n\n")
		}
	}

	// Findings Summary (only if failures)
	if failed > 0 {
		b.WriteString("---\n\n## Findings Requiring Remediation\n\n")
		b.WriteString("| # | Category | Check | Control | Issue |\n")
		b.WriteString("|---|----------|-------|---------|-------|\n")
		n := 1
		for _, r := range in.Results {
			if r.Status == checks.StatusFail {
				// Extract first failure line from details
				firstFail := extractFirstFailure(r.Details)
				b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n", n, r.Category, r.Name, r.Control, firstFail))
				n++
			}
		}
		b.WriteString("\n")
	}

	// Compliance Mapping
	b.WriteString("---\n\n## NIST 800-53 Control Mapping\n\n")
	b.WriteString("| Control | Title | Test Coverage |\n")
	b.WriteString("|---------|-------|---------------|\n")
	b.WriteString("| CP-2 | Contingency Plan | Cloud Run service health, rollback capability |\n")
	b.WriteString("| CP-4 | Contingency Plan Testing | This test execution |\n")
	b.WriteString("| CP-9 | System Backup | Cloud SQL backup/PITR, GCS versioning |\n")
	b.WriteString("| CP-10 | System Recovery and Reconstitution | Artifact Registry image availability |\n")
	b.WriteString("| SC-12 | Cryptographic Key Establishment and Management | KMS key accessibility and rotation |\n")
	b.WriteString("\n---\n\n")

	// Footer
	b.WriteString("## Test Methodology\n\n")
	b.WriteString("This test was executed by the `contingency-test` automated tool using GCP client ")
	b.WriteString("libraries with Workload Identity Federation authentication. All checks are read-only ")
	b.WriteString("— no infrastructure was modified during testing.\n\n")
	b.WriteString("The test validates the following contingency plan capabilities:\n\n")
	b.WriteString("1. **Backup Integrity** (CP-9): Cloud SQL automated backups and PITR are enabled with recent successful backups\n")
	b.WriteString("2. **Data Protection** (CP-9): GCS object versioning provides document recovery capability\n")
	b.WriteString("3. **Service Continuity** (CP-2): Cloud Run services are healthy with rollback-capable revisions\n")
	b.WriteString("4. **Encryption Continuity** (SC-12): KMS keys are accessible with rotation configured\n")
	b.WriteString("5. **Recovery Capability** (CP-10): Container images available in Artifact Registry for redeployment\n\n")
	b.WriteString("---\n\n")
	b.WriteString("_End of CP-4 Contingency Plan Test Report_\n")

	return b.String()
}

// orderCategories returns categories in a logical order, deduped.
func orderCategories(results []checks.Result) []string {
	order := []string{"Cloud SQL", "Cloud Storage", "Cloud Run", "Cloud KMS", "Artifact Registry"}
	seen := map[string]bool{}
	for _, r := range results {
		seen[r.Category] = true
	}
	var out []string
	for _, cat := range order {
		if seen[cat] {
			out = append(out, cat)
			delete(seen, cat)
		}
	}
	// Append any remaining categories not in the predefined order
	for _, r := range results {
		if seen[r.Category] {
			out = append(out, r.Category)
			delete(seen, r.Category)
		}
	}
	return out
}

func statusIcon(s checks.Status) string {
	switch s {
	case checks.StatusPass:
		return "✅"
	case checks.StatusFail:
		return "❌"
	case checks.StatusSkip:
		return "⏭️"
	default:
		return "❓"
	}
}

func extractFirstFailure(details string) string {
	for _, line := range strings.Split(details, "\n") {
		if strings.HasPrefix(line, "❌") {
			return strings.TrimPrefix(line, "❌ ")
		}
	}
	return "See details"
}
