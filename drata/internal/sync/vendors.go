package sync

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/latentarchon/compliance/drata/internal/client"
)

// VendorSyncer registers and manages vendors in Drata.
type VendorSyncer struct {
	client *client.Client
	logger *slog.Logger
	dryRun bool
}

// NewVendorSyncer creates a new vendor syncer.
func NewVendorSyncer(c *client.Client, logger *slog.Logger, dryRun bool) *VendorSyncer {
	return &VendorSyncer{client: c, logger: logger, dryRun: dryRun}
}

// VendorDef defines a vendor to register.
type VendorDef struct {
	Name         string
	Description  string
	Category     string
	RiskLevel    string // CRITICAL, HIGH, MEDIUM, LOW
	WebsiteURL   string
	ContactName  string
	ContactEmail string
}

// ArchonVendors returns the standard set of Latent Archon vendors.
func ArchonVendors() []VendorDef {
	return []VendorDef{
		{
			Name:        "Google Cloud Platform (GCP)",
			Description: "Sole infrastructure provider. Hosts all compute (Cloud Run), storage (Cloud SQL, GCS), AI/ML (Vertex AI, Document AI), identity (Identity Platform), networking (VPC, Cloud Armor, LB), and security services (KMS, Cloud Logging). FedRAMP High authorized, SOC 2 Type II, ISO 27001/27017/27018 certified.",
			Category:    "CLOUD_HOSTING",
			RiskLevel:   "CRITICAL",
			WebsiteURL:  "https://cloud.google.com",
		},
		{
			Name:        "GitHub",
			Description: "Source control and CI/CD platform. Hosts all application repositories with branch protection, PR review requirements, and automated CI/CD pipelines via GitHub Actions. Workload Identity Federation (keyless) for GCP authentication. Secret scanning and Dependabot enabled. SOC 2 certified. No customer data access.",
			Category:    "DEVELOPER_TOOLS",
			RiskLevel:   "HIGH",
			WebsiteURL:  "https://github.com",
		},
	}
}

// SyncVendors registers vendors in Drata, skipping any that already exist.
func (s *VendorSyncer) SyncVendors(ctx context.Context, vendors []VendorDef) error {
	existing, err := s.client.ListVendors(ctx)
	if err != nil {
		return fmt.Errorf("list existing vendors: %w", err)
	}
	existingNames := make(map[string]bool, len(existing))
	for _, v := range existing {
		existingNames[v.Name] = true
	}

	created := 0
	skipped := 0
	for _, vd := range vendors {
		if existingNames[vd.Name] {
			s.logger.Info("vendor already exists, skipping", "name", vd.Name)
			skipped++
			continue
		}

		if s.dryRun {
			s.logger.Info("[DRY RUN] would create vendor", "name", vd.Name, "risk", vd.RiskLevel)
			continue
		}

		v, err := s.client.CreateVendor(ctx, client.CreateVendorRequest{
			Name:         vd.Name,
			Description:  vd.Description,
			Category:     vd.Category,
			RiskLevel:    vd.RiskLevel,
			WebsiteURL:   vd.WebsiteURL,
			ContactName:  vd.ContactName,
			ContactEmail: vd.ContactEmail,
		})
		if err != nil {
			s.logger.Error("failed to create vendor", "name", vd.Name, "error", err)
			continue
		}
		s.logger.Info("created vendor", "name", vd.Name, "id", v.ID)
		created++
	}

	s.logger.Info("vendor sync complete", "created", created, "skipped", skipped, "total", len(vendors))
	return nil
}
