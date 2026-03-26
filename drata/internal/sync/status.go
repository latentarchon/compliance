package sync

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/latentarchon/compliance/drata/internal/client"
)

// StatusReporter generates a compliance readiness summary from Drata.
type StatusReporter struct {
	client *client.Client
	logger *slog.Logger
}

// NewStatusReporter creates a new status reporter.
func NewStatusReporter(c *client.Client, logger *slog.Logger) *StatusReporter {
	return &StatusReporter{client: c, logger: logger}
}

// Report runs all status checks and prints a summary.
func (s *StatusReporter) Report(ctx context.Context) error {
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  Latent Archon — Drata Compliance Readiness Report")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()

	// Frameworks
	frameworks, err := s.client.ListFrameworks(ctx)
	if err != nil {
		s.logger.Warn("could not fetch frameworks", "error", err)
	} else {
		fmt.Printf("📋 Frameworks (%d enabled)\n", len(frameworks))
		for _, f := range frameworks {
			if f.IsEnabled {
				readyPct := 0
				if f.NumInScopeRequirements > 0 {
					readyPct = (f.NumReadyInScopeRequirements * 100) / f.NumInScopeRequirements
				}
				status := "❌"
				if f.IsReady {
					status = "✅"
				} else if readyPct > 50 {
					status = "🟡"
				}
				fmt.Printf("  %s %s: %d/%d requirements ready (%d%%)\n",
					status, f.Name, f.NumReadyInScopeRequirements, f.NumInScopeRequirements, readyPct)
			}
		}
		fmt.Println()
	}

	// Controls
	controls, err := s.client.ListControls(ctx)
	if err != nil {
		s.logger.Warn("could not fetch controls", "error", err)
	} else {
		ready := 0
		withEvidence := 0
		withPolicy := 0
		monitored := 0
		for _, c := range controls {
			if c.Flags.IsReady {
				ready++
			}
			if c.Flags.HasEvidence {
				withEvidence++
			}
			if c.Flags.HasPolicy {
				withPolicy++
			}
			if c.Flags.IsMonitored {
				monitored++
			}
		}
		total := len(controls)
		fmt.Printf("🛡️  Controls (%d total)\n", total)
		fmt.Printf("  Ready:          %d/%d (%d%%)\n", ready, total, pct(ready, total))
		fmt.Printf("  With Evidence:  %d/%d (%d%%)\n", withEvidence, total, pct(withEvidence, total))
		fmt.Printf("  With Policy:    %d/%d (%d%%)\n", withPolicy, total, pct(withPolicy, total))
		fmt.Printf("  Monitored:      %d/%d (%d%%)\n", monitored, total, pct(monitored, total))
		fmt.Println()
	}

	// Personnel
	personnel, err := s.client.ListPersonnel(ctx)
	if err != nil {
		s.logger.Warn("could not fetch personnel", "error", err)
	} else {
		active := 0
		compliant := 0
		mfaOK := 0
		trainingOK := 0
		bgCheckOK := 0
		for _, p := range personnel {
			if p.EmploymentStatus == "CURRENT_EMPLOYEE" || p.EmploymentStatus == "CURRENT_CONTRACTOR" {
				active++
				allPassing := true
				for _, cc := range p.ComplianceChecks {
					switch cc.Type {
					case "IDENTITY_MFA":
						if cc.Status == "PASSED" {
							mfaOK++
						} else {
							allPassing = false
						}
					case "SECURITY_TRAINING":
						if cc.Status == "PASSED" {
							trainingOK++
						} else {
							allPassing = false
						}
					case "BACKGROUND_CHECK":
						if cc.Status == "PASSED" {
							bgCheckOK++
						} else {
							allPassing = false
						}
					default:
						if cc.Status != "PASSED" {
							allPassing = false
						}
					}
				}
				if allPassing && len(p.ComplianceChecks) > 0 {
					compliant++
				}
			}
		}
		fmt.Printf("👥 Personnel (%d active)\n", active)
		fmt.Printf("  Fully Compliant: %d/%d (%d%%)\n", compliant, active, pct(compliant, active))
		fmt.Printf("  MFA Verified:    %d/%d\n", mfaOK, active)
		fmt.Printf("  Training Done:   %d/%d\n", trainingOK, active)
		fmt.Printf("  BG Check Done:   %d/%d\n", bgCheckOK, active)
		fmt.Println()
	}

	// Evidence
	evidence, err := s.client.ListEvidence(ctx)
	if err != nil {
		s.logger.Warn("could not fetch evidence", "error", err)
	} else {
		fmt.Printf("📁 Evidence Library: %d items\n", len(evidence))
		fmt.Println()
	}

	// Vendors
	vendors, err := s.client.ListVendors(ctx)
	if err != nil {
		s.logger.Warn("could not fetch vendors", "error", err)
	} else {
		fmt.Printf("🏢 Vendors: %d registered\n", len(vendors))
		for _, v := range vendors {
			fmt.Printf("  • %s (%s) — %s\n", v.Name, v.RiskLevel, v.Status)
		}
		fmt.Println()
	}

	// Risks
	risks, err := s.client.ListRisks(ctx)
	if err != nil {
		s.logger.Warn("could not fetch risks", "error", err)
	} else {
		fmt.Printf("⚠️  Risk Register: %d entries\n", len(risks))
		fmt.Println()
	}

	// Monitoring Tests
	tests, err := s.client.ListMonitoringTests(ctx)
	if err != nil {
		s.logger.Warn("could not fetch monitoring tests", "error", err)
	} else {
		passed := 0
		failed := 0
		for _, t := range tests {
			if t.CheckResultStatus == "PASSED" {
				passed++
			} else {
				failed++
			}
		}
		fmt.Printf("🔍 Monitoring Tests: %d passed, %d failed (%d total)\n", passed, failed, len(tests))
		fmt.Println()
	}

	fmt.Println("═══════════════════════════════════════════════════════════")
	return nil
}

func pct(n, total int) int {
	if total == 0 {
		return 0
	}
	return (n * 100) / total
}
