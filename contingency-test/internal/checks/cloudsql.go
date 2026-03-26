package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

// CloudSQLCheck verifies Cloud SQL backup and PITR configuration.
type CloudSQLCheck struct {
	projectID  string
	region     string
	instanceID string
}

// NewCloudSQLCheck creates a Cloud SQL backup verification check.
func NewCloudSQLCheck(projectID, region, instanceID string) *CloudSQLCheck {
	return &CloudSQLCheck{
		projectID:  projectID,
		region:     region,
		instanceID: instanceID,
	}
}

// Run executes the Cloud SQL backup verification.
func (c *CloudSQLCheck) Run(ctx context.Context) Result {
	svc, err := sqladmin.NewService(ctx)
	if err != nil {
		return Result{
			Category:    "Cloud SQL",
			Name:        "Backup Configuration",
			Description: "Verify Cloud SQL automated backups and PITR are enabled",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to create SQL Admin client: %v", err),
			Control:     "CP-9",
		}
	}

	instance, err := svc.Instances.Get(c.projectID, c.instanceID).Context(ctx).Do()
	if err != nil {
		return Result{
			Category:    "Cloud SQL",
			Name:        "Backup Configuration",
			Description: "Verify Cloud SQL automated backups and PITR are enabled",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to get instance %s: %v", c.instanceID, err),
			Control:     "CP-9",
		}
	}

	var findings []string
	allPassed := true

	// Check automated backups
	if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
		bc := instance.Settings.BackupConfiguration
		if bc.Enabled {
			findings = append(findings, "✅ Automated backups: ENABLED")
		} else {
			findings = append(findings, "❌ Automated backups: DISABLED")
			allPassed = false
		}

		if bc.PointInTimeRecoveryEnabled {
			findings = append(findings, "✅ Point-in-time recovery (PITR): ENABLED")
		} else {
			findings = append(findings, "❌ Point-in-time recovery (PITR): DISABLED")
			allPassed = false
		}

		if bc.TransactionLogRetentionDays > 0 {
			findings = append(findings, fmt.Sprintf("✅ Transaction log retention: %d days", bc.TransactionLogRetentionDays))
		}

		if bc.BackupRetentionSettings != nil {
			findings = append(findings, fmt.Sprintf("✅ Backup retention: %d backups", bc.BackupRetentionSettings.RetainedBackups))
		}
	} else {
		findings = append(findings, "❌ No backup configuration found")
		allPassed = false
	}

	// Check latest backup
	backups, err := svc.BackupRuns.List(c.projectID, c.instanceID).MaxResults(5).Context(ctx).Do()
	if err != nil {
		findings = append(findings, fmt.Sprintf("⚠️ Could not list backup runs: %v", err))
	} else if len(backups.Items) == 0 {
		findings = append(findings, "❌ No backup runs found")
		allPassed = false
	} else {
		latest := backups.Items[0]
		findings = append(findings, fmt.Sprintf("✅ Latest backup: %s (status: %s, type: %s)",
			latest.EndTime, latest.Status, latest.Type))

		// Check if latest backup is within 24 hours
		if latest.EndTime != "" {
			endTime, parseErr := time.Parse(time.RFC3339, latest.EndTime)
			if parseErr == nil {
				age := time.Since(endTime)
				if age > 24*time.Hour {
					findings = append(findings, fmt.Sprintf("❌ Latest backup is %.0f hours old (>24h)", age.Hours()))
					allPassed = false
				} else {
					findings = append(findings, fmt.Sprintf("✅ Latest backup age: %.1f hours (<24h)", age.Hours()))
				}
			}
		}

		if latest.Status != "SUCCESSFUL" {
			findings = append(findings, fmt.Sprintf("❌ Latest backup status: %s (expected SUCCESSFUL)", latest.Status))
			allPassed = false
		}
	}

	// Check HA configuration
	if instance.Settings != nil && instance.Settings.AvailabilityType == "REGIONAL" {
		findings = append(findings, "✅ High availability: REGIONAL (automatic failover)")
	} else {
		findings = append(findings, "⚠️ High availability: ZONAL (no automatic failover)")
	}

	// Check encryption
	if instance.DiskEncryptionConfiguration != nil && instance.DiskEncryptionConfiguration.KmsKeyName != "" {
		findings = append(findings, "✅ Encryption: CMEK enabled")
	} else {
		findings = append(findings, "✅ Encryption: Google-managed (default)")
	}

	status := StatusPass
	if !allPassed {
		status = StatusFail
	}

	return Result{
		Category:    "Cloud SQL",
		Name:        fmt.Sprintf("Backup Configuration (%s)", c.instanceID),
		Description: "Verify Cloud SQL automated backups, PITR, retention, and latest backup recency",
		Status:      status,
		Details:     strings.Join(findings, "\n"),
		Control:     "CP-9",
	}
}
