package checks

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
)

// GCSCheck verifies Cloud Storage versioning and lifecycle configuration.
type GCSCheck struct {
	projectID  string
	bucketName string
}

// NewGCSCheck creates a GCS versioning/lifecycle verification check.
func NewGCSCheck(projectID, bucketName string) *GCSCheck {
	return &GCSCheck{
		projectID:  projectID,
		bucketName: bucketName,
	}
}

// Run executes the GCS verification.
func (c *GCSCheck) Run(ctx context.Context) Result {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return Result{
			Category:    "Cloud Storage",
			Name:        fmt.Sprintf("Bucket Configuration (%s)", c.bucketName),
			Description: "Verify GCS object versioning, lifecycle rules, and encryption",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to create GCS client: %v", err),
			Control:     "CP-9",
		}
	}
	defer client.Close()

	bucket := client.Bucket(c.bucketName)
	attrs, err := bucket.Attrs(ctx)
	if err != nil {
		return Result{
			Category:    "Cloud Storage",
			Name:        fmt.Sprintf("Bucket Configuration (%s)", c.bucketName),
			Description: "Verify GCS object versioning, lifecycle rules, and encryption",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to get bucket attrs: %v", err),
			Control:     "CP-9",
		}
	}

	var findings []string
	allPassed := true

	// Check versioning
	if attrs.VersioningEnabled {
		findings = append(findings, "✅ Object versioning: ENABLED")
	} else {
		findings = append(findings, "❌ Object versioning: DISABLED")
		allPassed = false
	}

	// Check lifecycle rules
	if len(attrs.Lifecycle.Rules) > 0 {
		findings = append(findings, fmt.Sprintf("✅ Lifecycle rules: %d rules configured", len(attrs.Lifecycle.Rules)))
		for i, rule := range attrs.Lifecycle.Rules {
			action := string(rule.Action.Type)
			conditions := []string{}
			if rule.Condition.AgeInDays > 0 {
				conditions = append(conditions, fmt.Sprintf("age>%dd", rule.Condition.AgeInDays))
			}
			if rule.Condition.NumNewerVersions > 0 {
				conditions = append(conditions, fmt.Sprintf("newerVersions>%d", rule.Condition.NumNewerVersions))
			}
			findings = append(findings, fmt.Sprintf("  Rule %d: %s when %s", i+1, action, strings.Join(conditions, " AND ")))
		}
	} else {
		findings = append(findings, "⚠️ No lifecycle rules configured")
	}

	// Check encryption
	if attrs.Encryption != nil && attrs.Encryption.DefaultKMSKeyName != "" {
		findings = append(findings, "✅ Encryption: CMEK enabled")
	} else {
		findings = append(findings, "✅ Encryption: Google-managed (default AES-256)")
	}

	// Check location
	findings = append(findings, fmt.Sprintf("✅ Location: %s (type: %s)", attrs.Location, attrs.LocationType))

	// Check uniform bucket-level access
	if attrs.UniformBucketLevelAccess.Enabled {
		findings = append(findings, "✅ Uniform bucket-level access: ENABLED")
	} else {
		findings = append(findings, "⚠️ Uniform bucket-level access: DISABLED (fine-grained ACLs)")
	}

	// Check public access prevention
	if attrs.PublicAccessPrevention == storage.PublicAccessPreventionEnforced {
		findings = append(findings, "✅ Public access prevention: ENFORCED")
	} else {
		findings = append(findings, "⚠️ Public access prevention: NOT ENFORCED")
	}

	status := StatusPass
	if !allPassed {
		status = StatusFail
	}

	return Result{
		Category:    "Cloud Storage",
		Name:        fmt.Sprintf("Bucket Configuration (%s)", c.bucketName),
		Description: "Verify GCS object versioning, lifecycle rules, encryption, and access controls",
		Status:      status,
		Details:     strings.Join(findings, "\n"),
		Control:     "CP-9",
	}
}
