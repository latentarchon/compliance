package checks

import (
	"context"
	"fmt"
	"strings"

	run "cloud.google.com/go/run/apiv2"
	runpb "cloud.google.com/go/run/apiv2/runpb"
)

// CloudRunCheck verifies a Cloud Run service exists and has healthy revisions.
type CloudRunCheck struct {
	projectID   string
	region      string
	serviceName string
}

// NewCloudRunCheck creates a Cloud Run service health check.
func NewCloudRunCheck(projectID, region, serviceName string) *CloudRunCheck {
	return &CloudRunCheck{
		projectID:   projectID,
		region:      region,
		serviceName: serviceName,
	}
}

// Run executes the Cloud Run service verification.
func (c *CloudRunCheck) Run(ctx context.Context) Result {
	client, err := run.NewServicesClient(ctx)
	if err != nil {
		return Result{
			Category:    "Cloud Run",
			Name:        fmt.Sprintf("Service Health (%s/%s)", c.projectID, c.serviceName),
			Description: "Verify Cloud Run service exists with healthy revision and rollback capability",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to create Cloud Run client: %v", err),
			Control:     "CP-2",
		}
	}
	defer client.Close()

	name := fmt.Sprintf("projects/%s/locations/%s/services/%s", c.projectID, c.region, c.serviceName)
	svc, err := client.GetService(ctx, &runpb.GetServiceRequest{Name: name})
	if err != nil {
		return Result{
			Category:    "Cloud Run",
			Name:        fmt.Sprintf("Service Health (%s/%s)", c.projectID, c.serviceName),
			Description: "Verify Cloud Run service exists with healthy revision and rollback capability",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to get service: %v", err),
			Control:     "CP-2",
		}
	}

	var findings []string
	allPassed := true

	// Check service exists and has a URI
	if svc.Uri != "" {
		findings = append(findings, fmt.Sprintf("✅ Service URI: %s", svc.Uri))
	} else {
		findings = append(findings, "❌ Service has no URI (not serving traffic)")
		allPassed = false
	}

	// Check reconciling status
	if svc.Reconciling {
		findings = append(findings, "⚠️ Service is currently reconciling")
	}

	// Check conditions
	for _, cond := range svc.Conditions {
		if cond.Type == "Ready" {
			if cond.State == runpb.Condition_CONDITION_SUCCEEDED {
				findings = append(findings, "✅ Ready condition: SUCCEEDED")
			} else {
				findings = append(findings, fmt.Sprintf("❌ Ready condition: %s (message: %s)", cond.State, cond.Message))
				allPassed = false
			}
		}
	}

	// Check latest revision
	if svc.LatestReadyRevision != "" {
		findings = append(findings, fmt.Sprintf("✅ Latest ready revision: %s", svc.LatestReadyRevision))
	} else {
		findings = append(findings, "❌ No ready revision available")
		allPassed = false
	}

	// Check traffic routing
	if len(svc.Traffic) > 0 {
		for _, t := range svc.Traffic {
			if t.Revision != "" {
				findings = append(findings, fmt.Sprintf("✅ Traffic: %d%% → %s", t.Percent, t.Revision))
			} else if t.Type == runpb.TrafficTargetAllocationType_TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST {
				findings = append(findings, fmt.Sprintf("✅ Traffic: %d%% → LATEST", t.Percent))
			}
		}
	}

	// Check container image
	if svc.Template != nil && len(svc.Template.Containers) > 0 {
		img := svc.Template.Containers[0].Image
		findings = append(findings, fmt.Sprintf("✅ Container image: %s", img))

		// Check if image uses digest (immutable) vs tag (mutable)
		if strings.Contains(img, "@sha256:") {
			findings = append(findings, "✅ Image pinned by digest (immutable)")
		} else {
			findings = append(findings, "⚠️ Image uses tag (mutable) — consider pinning by digest for DR")
		}
	}

	status := StatusPass
	if !allPassed {
		status = StatusFail
	}

	return Result{
		Category:    "Cloud Run",
		Name:        fmt.Sprintf("Service Health (%s/%s)", c.projectID, c.serviceName),
		Description: "Verify Cloud Run service exists with healthy revision and rollback capability",
		Status:      status,
		Details:     strings.Join(findings, "\n"),
		Control:     "CP-2",
	}
}
