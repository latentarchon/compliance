package checks

import (
	"context"
	"fmt"
	"strings"

	artifactregistry "google.golang.org/api/artifactregistry/v1"
)

// ArtifactRegistryCheck verifies container images exist in Artifact Registry.
type ArtifactRegistryCheck struct {
	projectID string
	region    string
}

// NewArtifactRegistryCheck creates an Artifact Registry image verification check.
func NewArtifactRegistryCheck(projectID, region string) *ArtifactRegistryCheck {
	return &ArtifactRegistryCheck{
		projectID: projectID,
		region:    region,
	}
}

// Run executes the Artifact Registry verification.
func (c *ArtifactRegistryCheck) Run(ctx context.Context) Result {
	svc, err := artifactregistry.NewService(ctx)
	if err != nil {
		return Result{
			Category:    "Artifact Registry",
			Name:        fmt.Sprintf("Image Availability (%s)", c.projectID),
			Description: "Verify container images exist in Artifact Registry for rollback capability",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to create Artifact Registry client: %v", err),
			Control:     "CP-10",
		}
	}

	var findings []string
	allPassed := true

	// List repositories
	parent := fmt.Sprintf("projects/%s/locations/%s", c.projectID, c.region)
	repos, err := svc.Projects.Locations.Repositories.List(parent).Context(ctx).Do()
	if err != nil {
		return Result{
			Category:    "Artifact Registry",
			Name:        fmt.Sprintf("Image Availability (%s)", c.projectID),
			Description: "Verify container images exist in Artifact Registry for rollback capability",
			Status:      StatusFail,
			Details:     fmt.Sprintf("Failed to list repositories: %v", err),
			Control:     "CP-10",
		}
	}

	if len(repos.Repositories) == 0 {
		findings = append(findings, "❌ No Artifact Registry repositories found")
		allPassed = false
	} else {
		findings = append(findings, fmt.Sprintf("✅ Found %d repositories", len(repos.Repositories)))

		for _, repo := range repos.Repositories {
			repoName := repo.Name
			shortName := repoName[strings.LastIndex(repoName, "/")+1:]
			findings = append(findings, fmt.Sprintf("  Repository: %s (format: %s)", shortName, repo.Format))

			// List images in each Docker repository
			if repo.Format == "DOCKER" {
				images, imgErr := svc.Projects.Locations.Repositories.DockerImages.List(repoName).PageSize(10).Context(ctx).Do()
				if imgErr != nil {
					findings = append(findings, fmt.Sprintf("  ⚠️ Could not list images: %v", imgErr))
					continue
				}
				if len(images.DockerImages) == 0 {
					findings = append(findings, "  ⚠️ No Docker images found in repository")
				} else {
					findings = append(findings, fmt.Sprintf("  ✅ %d Docker images available", len(images.DockerImages)))
					for _, img := range images.DockerImages {
						// Extract image name from full path
						imgName := img.Name[strings.LastIndex(img.Name, "/")+1:]
						tags := "untagged"
						if len(img.Tags) > 0 {
							tags = strings.Join(img.Tags, ", ")
						}
						findings = append(findings, fmt.Sprintf("    - %s (tags: %s, uploaded: %s)", imgName, tags, img.UploadTime))
					}
				}
			}
		}
	}

	status := StatusPass
	if !allPassed {
		status = StatusFail
	}

	return Result{
		Category:    "Artifact Registry",
		Name:        fmt.Sprintf("Image Availability (%s)", c.projectID),
		Description: "Verify container images exist in Artifact Registry for rollback capability",
		Status:      status,
		Details:     strings.Join(findings, "\n"),
		Control:     "CP-10",
	}
}
