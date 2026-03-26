package sync

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/latentarchon/compliance/drata/internal/client"
)

// RiskSyncer creates and manages risk register entries in Drata.
type RiskSyncer struct {
	client *client.Client
	logger *slog.Logger
	dryRun bool
}

// NewRiskSyncer creates a new risk syncer.
func NewRiskSyncer(c *client.Client, logger *slog.Logger, dryRun bool) *RiskSyncer {
	return &RiskSyncer{client: c, logger: logger, dryRun: dryRun}
}

// RiskDef defines a risk entry for the register.
// Likelihood and Impact are scored 1-5 (1=Very Low, 5=Very High).
type RiskDef struct {
	Name                 string
	Description          string
	Category             string
	InherentLikelihood   int
	InherentImpact       int
	ResidualLikelihood   int
	ResidualImpact       int
	TreatmentPlan        string
}

// ArchonRiskRegister returns the formal risk register for Latent Archon.
// Inherent = before controls, Residual = after controls are applied.
func ArchonRiskRegister() []RiskDef {
	return []RiskDef{
		{
			Name:               "Unauthorized Access to Customer Data",
			Description:        "An attacker gains unauthorized access to customer documents, messages, or workspace data through authentication bypass, privilege escalation, or session hijacking.",
			Category:           "SECURITY",
			InherentLikelihood: 4, InherentImpact: 5,
			ResidualLikelihood: 1, ResidualImpact: 5,
			TreatmentPlan:      "Mitigated by: TOTP MFA on all data endpoints, Firebase Auth pool isolation (admin/chat), 5-layer tenant enforcement (interceptor → RLS → DB roles → vector scoping → audit), per-tenant IP allowlisting via Cloud Armor, 44-attack automated red team suite run monthly.",
		},
		{
			Name:               "Data Exfiltration via Application Vulnerability",
			Description:        "Customer data is extracted through SQL injection, IDOR, path traversal, prompt injection, or API abuse targeting the application layer.",
			Category:           "SECURITY",
			InherentLikelihood: 3, InherentImpact: 5,
			ResidualLikelihood: 1, ResidualImpact: 5,
			TreatmentPlan:      "Mitigated by: PostgreSQL RLS with FORCE (row-level data isolation), parameterized queries via sqlc, Cloud Armor WAF (OWASP Top 10 rules), input validation on all RPC endpoints, workspace-scoped vector search with token restrictions, GoSec + Semgrep SAST in CI.",
		},
		{
			Name:               "Supply Chain Compromise",
			Description:        "A malicious or vulnerable dependency is introduced into the build pipeline, compromising application integrity.",
			Category:           "SECURITY",
			InherentLikelihood: 3, InherentImpact: 4,
			ResidualLikelihood: 1, ResidualImpact: 4,
			TreatmentPlan:      "Mitigated by: Dependabot on all repos (Go, npm, Actions, Terraform), pinned dependency versions, cryptographic integrity (go.sum, pnpm-lock.yaml, .terraform.lock.hcl), CycloneDX/SPDX SBOM generation on every build, Trivy container scanning, Gitleaks secret detection, distroless base images (no shell/package manager).",
		},
		{
			Name:               "Cloud Infrastructure Misconfiguration",
			Description:        "Misconfiguration of GCP resources (IAM, networking, storage) leads to data exposure or unauthorized access.",
			Category:           "OPERATIONAL",
			InherentLikelihood: 3, InherentImpact: 4,
			ResidualLikelihood: 1, ResidualImpact: 4,
			TreatmentPlan:      "Mitigated by: Infrastructure-as-Code (Terragrunt/Terraform) with PR review + plan-as-comment, GCP org policies (sql.restrictPublicIp, iam.disableServiceAccountKeyCreation), VPC private networking (no public IPs), FQDN egress firewall (default deny), least-privilege service accounts (15 specific roles), drift detection on every push to main.",
		},
		{
			Name:               "Denial of Service",
			Description:        "Service availability degraded or disrupted by volumetric DDoS, application-layer attacks, or resource exhaustion.",
			Category:           "OPERATIONAL",
			InherentLikelihood: 3, InherentImpact: 3,
			ResidualLikelihood: 2, ResidualImpact: 2,
			TreatmentPlan:      "Mitigated by: Cloud Armor WAF with rate limiting and adaptive protection, Cloud Run auto-scaling, multi-zone Cloud SQL HA, GCS multi-region replication, Cloud CDN caching, per-tenant IP allowlisting for sensitive orgs.",
		},
		{
			Name:               "Insider Threat",
			Description:        "An authorized employee or contractor misuses access to exfiltrate data, modify configurations, or disrupt service.",
			Category:           "SECURITY",
			InherentLikelihood: 2, InherentImpact: 5,
			ResidualLikelihood: 1, ResidualImpact: 4,
			TreatmentPlan:      "Mitigated by: Least-privilege IAM (separate DB roles per service), comprehensive audit logging (all data operations, IAM changes, admin actions), real-time security email notifications to org admins, Terraform state versioning for infrastructure audit trail, GitHub PR review requirements (no self-merge), Workload Identity Federation (no stored credentials).",
		},
		{
			Name:               "Encryption Key Compromise",
			Description:        "Customer-managed encryption keys (CMEK) are compromised, exposing encrypted data at rest.",
			Category:           "SECURITY",
			InherentLikelihood: 1, InherentImpact: 5,
			ResidualLikelihood: 1, ResidualImpact: 5,
			TreatmentPlan:      "Mitigated by: Cloud KMS with automatic key rotation (365-day schedule), CMEK applied to Cloud SQL and GCS, separate keys per data class, IAM-controlled key access (only service accounts that need encryption), KMS audit logging enabled, FIPS 140-2 validated BoringCrypto in all Go binaries.",
		},
		{
			Name:               "Vendor/Third-Party Breach",
			Description:        "GCP or GitHub suffers a security breach that impacts Latent Archon data or operations.",
			Category:           "THIRD_PARTY",
			InherentLikelihood: 2, InherentImpact: 5,
			ResidualLikelihood: 2, ResidualImpact: 3,
			TreatmentPlan:      "Mitigated by: GCP FedRAMP High authorization (continuous monitoring), single-cloud architecture (no cross-cloud data flows), encryption at rest (AES-256) and in transit (TLS 1.2+), vendor incident response policy with <4hr impact assessment, vendor risk management policy with continuous monitoring of FedRAMP marketplace status.",
		},
		{
			Name:               "Data Loss / Disaster Recovery Failure",
			Description:        "Customer data is permanently lost due to infrastructure failure, accidental deletion, or failed backup restoration.",
			Category:           "OPERATIONAL",
			InherentLikelihood: 2, InherentImpact: 5,
			ResidualLikelihood: 1, ResidualImpact: 3,
			TreatmentPlan:      "Mitigated by: Cloud SQL automated backups with PITR (<5min RPO), GCS object versioning (365-day retention), multi-zone HA for compute and database, Terraform-based full infrastructure rebuild (<1hr RTO), GCS bucket lifecycle policies preventing accidental deletion.",
		},
		{
			Name:               "Regulatory Non-Compliance",
			Description:        "Failure to maintain required compliance posture (NIST 800-53, FedRAMP) resulting in loss of government contracts or legal liability.",
			Category:           "COMPLIANCE",
			InherentLikelihood: 2, InherentImpact: 4,
			ResidualLikelihood: 1, ResidualImpact: 4,
			TreatmentPlan:      "Mitigated by: SSP-Lite mapping ~90 NIST 800-53 Moderate controls, Drata continuous compliance monitoring (this integration), 4 formal security policies (access control, change management, incident response, vendor risk), automated evidence collection (CI/CD artifacts, audit logs, red team reports), annual policy review cycle.",
		},
		{
			Name:               "AI/ML Model Misuse or Prompt Injection",
			Description:        "Adversarial prompts cause the AI system to leak customer data across workspace boundaries, generate harmful content, or bypass access controls.",
			Category:           "SECURITY",
			InherentLikelihood: 3, InherentImpact: 3,
			ResidualLikelihood: 2, ResidualImpact: 2,
			TreatmentPlan:      "Mitigated by: Workspace-scoped vector search with token restrictions (can only retrieve documents from authorized workspace), system prompt hardening, input validation and length limits on all chat messages, image generation limits (4 images, 10MB per response), audit logging of all AI interactions.",
		},
		{
			Name:               "CI/CD Pipeline Compromise",
			Description:        "Attacker compromises the build/deploy pipeline to inject malicious code into production.",
			Category:           "SECURITY",
			InherentLikelihood: 2, InherentImpact: 5,
			ResidualLikelihood: 1, ResidualImpact: 4,
			TreatmentPlan:      "Mitigated by: Workload Identity Federation (zero stored secrets, keyless auth), OIDC providers locked to latentarchon GitHub org, production deployment requires manual GitHub environment gate approval, Terraform plans posted as PR comments (never auto-applied), branch protection on main, Trivy container scanning, Gitleaks secret detection.",
		},
	}
}

// SyncRisks creates risk register entries in Drata, skipping duplicates.
func (s *RiskSyncer) SyncRisks(ctx context.Context, risks []RiskDef) error {
	existing, err := s.client.ListRisks(ctx)
	if err != nil {
		return fmt.Errorf("list existing risks: %w", err)
	}
	existingNames := make(map[string]bool, len(existing))
	for _, r := range existing {
		existingNames[r.Name] = true
	}

	created := 0
	skipped := 0
	for _, rd := range risks {
		if existingNames[rd.Name] {
			s.logger.Info("risk already exists, skipping", "name", rd.Name)
			skipped++
			continue
		}

		if s.dryRun {
			inherentScore := rd.InherentLikelihood * rd.InherentImpact
			residualScore := rd.ResidualLikelihood * rd.ResidualImpact
			s.logger.Info("[DRY RUN] would create risk",
				"name", rd.Name,
				"category", rd.Category,
				"inherent_score", inherentScore,
				"residual_score", residualScore,
			)
			continue
		}

		r, err := s.client.CreateRisk(ctx, client.CreateRiskRequest{
			Name:               rd.Name,
			Description:        rd.Description,
			Category:           rd.Category,
			InherentLikelihood: rd.InherentLikelihood,
			InherentImpact:     rd.InherentImpact,
			ResidualLikelihood: rd.ResidualLikelihood,
			ResidualImpact:     rd.ResidualImpact,
			TreatmentPlan:      rd.TreatmentPlan,
		})
		if err != nil {
			s.logger.Error("failed to create risk", "name", rd.Name, "error", err)
			continue
		}
		s.logger.Info("created risk", "name", rd.Name, "id", r.ID)
		created++
	}

	s.logger.Info("risk sync complete", "created", created, "skipped", skipped, "total", len(risks))
	return nil
}
