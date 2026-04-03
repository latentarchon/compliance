// contingency-test runs automated CP-4 contingency plan verification checks
// against GCP infrastructure and produces a FedRAMP-ready evidence report.
//
// Usage:
//
//	contingency-test [flags]
//
// Flags:
//
//	--project-id       GCP project ID (admin project)
//	--app-project-id   GCP project ID (app project)
//	--region           GCP region (default: us-east4)
//	--db-instance      Cloud SQL instance name
//	--documents-bucket GCS documents bucket name
//	--kms-keyring      KMS key ring name
//	--kms-key          KMS crypto key name
//	--output-dir       Directory for report output (default: ./reports)
//	--services         Comma-separated Cloud Run service names to check
//	--dry-run          Print checks without executing (for CI validation)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/latentarchon/compliance/contingency-test/internal/checks"
	"github.com/latentarchon/compliance/contingency-test/internal/report"
)

func main() {
	projectID := flag.String("project-id", os.Getenv("PROJECT_ID"), "GCP admin project ID")
	appProjectID := flag.String("app-project-id", os.Getenv("APP_PROJECT_ID"), "GCP app project ID")
	region := flag.String("region", envOrDefault("REGION", "us-east4"), "GCP region")
	dbInstance := flag.String("db-instance", os.Getenv("DB_INSTANCE"), "Cloud SQL instance name")
	documentsBucket := flag.String("documents-bucket", os.Getenv("GCS_DOCUMENTS_BUCKET"), "GCS documents bucket")
	kmsKeyring := flag.String("kms-keyring", os.Getenv("KMS_KEYRING"), "KMS key ring name")
	kmsKey := flag.String("kms-key", os.Getenv("KMS_KEY"), "KMS crypto key name")
	outputDir := flag.String("output-dir", envOrDefault("OUTPUT_DIR", "./reports"), "Report output directory")
	services := flag.String("services", envOrDefault("CLOUD_RUN_SERVICES", "archon-admin,archon-app,archon-ops,admin-spa,app-spa,clamav"), "Cloud Run services to check")
	dryRun := flag.Bool("dry-run", false, "Print checks without executing")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *projectID == "" {
		logger.Error("--project-id is required")
		os.Exit(1)
	}

	if *dryRun {
		logger.Info("[DRY RUN] would execute contingency plan checks",
			"admin_project", *projectID,
			"app_project", *appProjectID,
			"region", *region,
			"db_instance", *dbInstance,
			"documents_bucket", *documentsBucket,
			"kms_keyring", *kmsKeyring,
			"services", *services,
		)
		fmt.Println("Dry run complete — all checks would be executed.")
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Parse service lists per project
	adminServices := []string{}
	appServices := []string{}
	for _, s := range strings.Split(*services, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// App project services
		if s == "archon-app" || s == "app-spa" {
			appServices = append(appServices, s)
		} else {
			adminServices = append(adminServices, s)
		}
	}

	runner := checks.NewRunner(logger)

	// ── 1. Cloud SQL Backup Verification ──
	if *dbInstance != "" {
		runner.Add(checks.NewCloudSQLCheck(*projectID, *region, *dbInstance))
	} else {
		logger.Warn("skipping Cloud SQL checks — no --db-instance provided")
	}

	// ── 2. GCS Versioning & Lifecycle ──
	if *documentsBucket != "" {
		runner.Add(checks.NewGCSCheck(*projectID, *documentsBucket))
	} else {
		logger.Warn("skipping GCS checks — no --documents-bucket provided")
	}

	// ── 3. Cloud Run Service Health (admin project) ──
	for _, svc := range adminServices {
		runner.Add(checks.NewCloudRunCheck(*projectID, *region, svc))
	}

	// ── 4. Cloud Run Service Health (app project) ──
	if *appProjectID != "" {
		for _, svc := range appServices {
			runner.Add(checks.NewCloudRunCheck(*appProjectID, *region, svc))
		}
	}

	// ── 5. KMS Key Accessibility ──
	if *kmsKeyring != "" && *kmsKey != "" {
		runner.Add(checks.NewKMSCheck(*projectID, *region, *kmsKeyring, *kmsKey))
	} else {
		logger.Warn("skipping KMS checks — no --kms-keyring/--kms-key provided")
	}

	// ── 6. Artifact Registry Image Verification ──
	runner.Add(checks.NewArtifactRegistryCheck(*projectID, *region))
	if *appProjectID != "" {
		runner.Add(checks.NewArtifactRegistryCheck(*appProjectID, *region))
	}

	// ── Execute all checks ──
	results := runner.Execute(ctx)

	// ── Generate report ──
	rpt := report.Generate(report.Input{
		Timestamp:      time.Now().UTC(),
		AdminProjectID: *projectID,
		AppProjectID:   *appProjectID,
		Region:         *region,
		Results:        results,
	})

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		logger.Error("failed to create output directory", "error", err)
		os.Exit(1)
	}

	filename := fmt.Sprintf("contingency-test-%s.md", time.Now().UTC().Format("2006-01-02"))
	outPath := filepath.Join(*outputDir, filename)

	if err := os.WriteFile(outPath, []byte(rpt), 0o644); err != nil {
		logger.Error("failed to write report", "error", err)
		os.Exit(1)
	}

	// Summary
	passed, failed, skipped := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case checks.StatusPass:
			passed++
		case checks.StatusFail:
			failed++
		case checks.StatusSkip:
			skipped++
		}
	}

	logger.Info("contingency plan test complete",
		"report", outPath,
		"passed", passed,
		"failed", failed,
		"skipped", skipped,
	)

	if failed > 0 {
		os.Exit(1)
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
