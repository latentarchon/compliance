// Package checks implements GCP infrastructure verification checks for CP-4
// contingency plan testing. Each check verifies a specific DR/backup capability.
package checks

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Status represents the outcome of a check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusSkip Status = "SKIP"
)

// Result captures the outcome of a single contingency check.
type Result struct {
	Category    string        // e.g., "Cloud SQL", "GCS", "Cloud Run"
	Name        string        // Human-readable check name
	Description string        // What was verified
	Status      Status        // PASS, FAIL, SKIP
	Details     string        // Detailed findings
	Duration    time.Duration // How long the check took
	Control     string        // NIST 800-53 control reference
}

// Check is the interface all contingency checks implement.
type Check interface {
	Run(ctx context.Context) Result
}

// Runner executes a collection of checks.
type Runner struct {
	logger *slog.Logger
	checks []Check
}

// NewRunner creates a new check runner.
func NewRunner(logger *slog.Logger) *Runner {
	return &Runner{logger: logger}
}

// Add registers a check with the runner.
func (r *Runner) Add(c Check) {
	r.checks = append(r.checks, c)
}

// Execute runs all registered checks and returns results.
func (r *Runner) Execute(ctx context.Context) []Result {
	results := make([]Result, 0, len(r.checks))
	for _, c := range r.checks {
		r.logger.Info("running check", "type", fmt.Sprintf("%T", c))
		start := time.Now()
		result := c.Run(ctx)
		result.Duration = time.Since(start)
		results = append(results, result)

		logLevel := slog.LevelInfo
		if result.Status == StatusFail {
			logLevel = slog.LevelError
		}
		r.logger.Log(ctx, logLevel, "check complete",
			"category", result.Category,
			"name", result.Name,
			"status", result.Status,
			"duration", result.Duration.Round(time.Millisecond),
		)
	}
	return results
}
