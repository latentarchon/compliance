// Package sync implements Drata sync commands for closing compliance gaps.
package sync

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/latentarchon/compliance/drata/internal/client"
)

// EvidenceSyncer uploads compliance documents to Drata's Evidence Library.
type EvidenceSyncer struct {
	client  *client.Client
	logger  *slog.Logger
	ownerID int
	dryRun  bool
}

// NewEvidenceSyncer creates a new evidence syncer.
func NewEvidenceSyncer(c *client.Client, logger *slog.Logger, ownerID int, dryRun bool) *EvidenceSyncer {
	return &EvidenceSyncer{client: c, logger: logger, ownerID: ownerID, dryRun: dryRun}
}

// PolicyDoc describes a compliance document to upload.
type PolicyDoc struct {
	Name        string   // Display name in Drata
	Description string   // Description of the document
	FilePath    string   // Path to the file
	ControlIDs  []string // Drata control IDs to link
}

// ArchonPolicies returns the standard set of Latent Archon compliance documents.
func ArchonPolicies(complianceDir string) []PolicyDoc {
	return []PolicyDoc{
		{
			Name:        "Access Control Policy (POL-AC-001)",
			Description: "Defines account management, authentication requirements (MFA/TOTP), RBAC authorization model, data isolation (RLS), infrastructure access controls, and network-level access controls including per-tenant IP allowlisting.",
			FilePath:    filepath.Join(complianceDir, "policies", "access-control.md"),
			ControlIDs:  []string{"DCF-AC-1", "DCF-AC-2", "DCF-AC-3", "DCF-AC-6", "DCF-AC-7", "DCF-AC-12", "DCF-AC-17"},
		},
		{
			Name:        "Change Management Policy (POL-CM-001)",
			Description: "Establishes change control process (PR-based), baseline configuration management, dependency governance, CI/CD security (WIF keyless auth), container hardening (distroless, FIPS 140-2), emergency change procedures, and rollback procedures.",
			FilePath:    filepath.Join(complianceDir, "policies", "change-management.md"),
			ControlIDs:  []string{"DCF-CM-1", "DCF-CM-2", "DCF-CM-3", "DCF-CM-5", "DCF-CM-6", "DCF-CM-7", "DCF-CM-8"},
		},
		{
			Name:        "Incident Response Policy (POL-IR-001)",
			Description: "Defines incident classification (SEV-1 through SEV-4 with MITRE mapping), response team roles, detection sources (Cloud Armor WAF, audit events, red team), 5-phase response process, forensic preservation, US-CERT/CISA reporting (CAT 1-6 timelines), FedRAMP PMO notification, and customer notification timelines.",
			FilePath:    filepath.Join(complianceDir, "policies", "incident-response.md"),
			ControlIDs:  []string{"DCF-IR-1", "DCF-IR-2", "DCF-IR-4", "DCF-IR-5", "DCF-IR-6", "DCF-IR-8", "DCF-IR-9"},
		},
		{
			Name:        "Vendor Risk Management Policy (POL-VR-001)",
			Description: "Covers vendor classification (4 tiers), GCP as critical vendor (FedRAMP High), pre-engagement assessment, ongoing monitoring, open-source dependency governance (Dependabot, license compliance), subprocessor management, and vendor incident response.",
			FilePath:    filepath.Join(complianceDir, "policies", "vendor-risk.md"),
			ControlIDs:  []string{"DCF-SA-1", "DCF-SA-4", "DCF-SA-9"},
		},
		{
			Name:        "Information Security Policy (POL-IS-001)",
			Description: "Overarching information security program governance. Defines security objectives, governance structure, roles/responsibilities, policy hierarchy, compliance framework (NIST 800-53 Moderate), risk management overview, security architecture principles, exception process, and enforcement.",
			FilePath:    filepath.Join(complianceDir, "policies", "information-security.md"),
			ControlIDs:  []string{"DCF-PL-1", "DCF-PL-2"},
		},
		{
			Name:        "Encryption Policy (POL-EN-001)",
			Description: "Cryptographic standards (AES-256, TLS 1.2+, FIPS 140-2 BoringCrypto), CMEK key management via Cloud KMS with automatic rotation, data-at-rest and in-transit encryption for all services, secrets management (WIF keyless auth, no SA keys), key lifecycle, and prohibited algorithms.",
			FilePath:    filepath.Join(complianceDir, "policies", "encryption.md"),
			ControlIDs:  []string{"DCF-SC-8", "DCF-SC-12", "DCF-SC-13", "DCF-SC-28"},
		},
		{
			Name:        "Data Classification & Retention Policy (POL-DC-001)",
			Description: "4-level classification (CUI/Restricted, Confidential, Internal, Public), complete data inventory with storage/encryption/isolation/retention per type, handling requirements by level, retention schedule, disposal procedures (including cryptographic erasure), and data sovereignty (US-only).",
			FilePath:    filepath.Join(complianceDir, "policies", "data-classification.md"),
			ControlIDs:  []string{"DCF-MP-1", "DCF-MP-6", "DCF-SI-12"},
		},
		{
			Name:        "Business Continuity & Disaster Recovery Policy (POL-BC-001)",
			Description: "Recovery objectives by service tier (RPO <5min / RTO <1hr for Tier 1), backup strategy (Cloud SQL PITR, GCS versioning, IaC rebuild), DR procedures for 5 failure scenarios (DB, Cloud Run, GCS, Vector Search, regional), communication plan, and testing schedule.",
			FilePath:    filepath.Join(complianceDir, "policies", "business-continuity.md"),
			ControlIDs:  []string{"DCF-CP-1", "DCF-CP-2", "DCF-CP-4", "DCF-CP-9", "DCF-CP-10"},
		},
		{
			Name:        "Risk Management Policy (POL-RM-001)",
			Description: "Risk assessment methodology (5×5 likelihood/impact matrix), inherent vs residual scoring, treatment options (mitigate/transfer/accept/avoid), risk appetite statement, 12-entry risk register summary, monitoring cadence, and integration with Drata automated sync.",
			FilePath:    filepath.Join(complianceDir, "policies", "risk-management.md"),
			ControlIDs:  []string{"DCF-RA-1", "DCF-RA-3"},
		},
		{
			Name:        "Acceptable Use Policy (POL-AU-001)",
			Description: "Defines acceptable and prohibited system use, customer data handling rules, credential/secret rules, infrastructure use requirements (IaC-only, no ad hoc gcloud), personal device requirements (encryption, screen lock, updates), incident reporting obligations, and enforcement tiers.",
			FilePath:    filepath.Join(complianceDir, "policies", "acceptable-use.md"),
			ControlIDs:  []string{"DCF-PL-4", "DCF-AC-8"},
		},
		{
			Name:        "Security Awareness & Training Policy (POL-AT-001)",
			Description: "Mandatory training requirements (security awareness, secure development, incident response, phishing), onboarding checklist, role-based training topics, training record tracking via Drata, non-compliance escalation, and effectiveness metrics.",
			FilePath:    filepath.Join(complianceDir, "policies", "security-awareness-training.md"),
			ControlIDs:  []string{"DCF-AT-1", "DCF-AT-2", "DCF-AT-3", "DCF-AT-4"},
		},
		{
			Name:        "Physical Security Policy (POL-PE-001)",
			Description: "Documents GCP FedRAMP High inherited physical controls (PE-2 through PE-18), supplementary controls for remote personnel (device encryption, screen lock, media handling), device loss/theft procedures, and media disposal requirements.",
			FilePath:    filepath.Join(complianceDir, "policies", "physical-security.md"),
			ControlIDs:  []string{"DCF-PE-1", "DCF-PE-2", "DCF-PE-3", "DCF-PE-6"},
		},
		{
			Name:        "Vulnerability Scanning Strategy (DOC-VS-001)",
			Description: "Authenticated scanning strategy for FedRAMP Moderate: Cloud Run serverless inherited OS scanning, full tool inventory (Trivy, GoSec, Semgrep, govulncheck, Gitleaks, red team CLI), scanning schedule (continuous/weekly/monthly/annual), SBOM management (CycloneDX + SPDX), FedRAMP ConMon monthly reporting, and remediation timelines per CVSS severity (Critical/High 30d, Medium 90d, Low 180d).",
			FilePath:    filepath.Join(complianceDir, "policies", "vulnerability-scanning.md"),
			ControlIDs:  []string{"DCF-RA-5", "DCF-SI-2", "DCF-SA-11", "DCF-CM-8"},
		},
		{
			Name:        "System Security Plan (SSP-Lite) — NIST 800-53 Moderate",
			Description: "Comprehensive SSP-Lite mapping ~90 NIST SP 800-53 Rev. 5 Moderate baseline controls across 17 families (AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PS, RA, SA, SC, SI) with implementation details and responsibility model.",
			FilePath:    filepath.Join(complianceDir, "ssp-lite-nist-800-53.md"),
			ControlIDs:  []string{"DCF-PL-2", "DCF-CA-1", "DCF-CA-5"},
		},
		{
			Name:        "Security Architecture Whitepaper",
			Description: "Detailed security architecture covering: multi-pool Firebase Auth with MFA, 5-layer tenant isolation with RLS, encryption (AES-256/TLS 1.2+/CMEK), audit logging, ClamAV malware scanning (fail-closed in production), network security (VPC/Cloud Armor/FQDN egress/DNSSEC), Pub/Sub SIEM export, CI/CD supply chain security (SBOM/SAST/WIF), per-org session timeouts (AC-12/SC-10), and disaster recovery.",
			FilePath:    filepath.Join(complianceDir, "security-whitepaper.md"),
			ControlIDs:  []string{"DCF-SC-1", "DCF-SC-7", "DCF-IA-1", "DCF-AU-1"},
		},
		{
			Name:        "FedRAMP System Security Plan (SSP-LA-001)",
			Description: "Full FedRAMP Rev 5 SSP covering system identification, description, environment, interconnections, applicable laws, information categorization (FIPS 199 Moderate), users and access, architecture diagrams, ports/protocols/services, cryptographic modules, and appendix cross-references.",
			FilePath:    filepath.Join(complianceDir, "fedramp-ssp.md"),
			ControlIDs:  []string{"DCF-PL-2", "DCF-CA-1", "DCF-CA-5", "DCF-PM-1"},
		},
		{
			Name:        "FedRAMP SSP Appendix A — Security Control Implementations",
			Description: "Detailed control implementation narratives for 230+ NIST 800-53 Rev 5 Moderate controls across 20 families (AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR) with responsibility, status, and implementation details.",
			FilePath:    filepath.Join(complianceDir, "fedramp-ssp-appendix-a-controls.md"),
			ControlIDs:  []string{"DCF-PL-2", "DCF-CA-1", "DCF-CA-2", "DCF-CA-5"},
		},
		{
			Name:        "Information System Contingency Plan (ISCP-LA-001)",
			Description: "FedRAMP ISCP covering recovery objectives (RPO/RTO by tier), roles and responsibilities, notification procedures, 5 recovery scenarios (DB failure, Cloud Run failure, GCS failure, Vertex AI failure, regional DR), reconstitution, testing schedule, and backup strategy.",
			FilePath:    filepath.Join(complianceDir, "contingency-plan.md"),
			ControlIDs:  []string{"DCF-CP-1", "DCF-CP-2", "DCF-CP-4", "DCF-CP-9", "DCF-CP-10"},
		},
		{
			Name:        "Configuration Management Plan (CMP-LA-001)",
			Description: "FedRAMP CMP covering configuration items, baseline configuration, change control process (standard/significant/emergency/infrastructure), drift detection, unauthorized change detection, and CM tools.",
			FilePath:    filepath.Join(complianceDir, "configuration-management-plan.md"),
			ControlIDs:  []string{"DCF-CM-1", "DCF-CM-2", "DCF-CM-3", "DCF-CM-6", "DCF-CM-9"},
		},
		{
			Name:        "Continuous Monitoring Plan (CONMON-LA-001)",
			Description: "FedRAMP ConMon plan covering control monitoring frequency, automated monitoring tools, vulnerability management (scanning schedule, remediation SLAs), incident monitoring, monthly/annual reporting deliverables, and evidence collection.",
			FilePath:    filepath.Join(complianceDir, "continuous-monitoring-plan.md"),
			ControlIDs:  []string{"DCF-CA-7", "DCF-RA-5", "DCF-SI-2", "DCF-SI-4"},
		},
		{
			Name:        "Supply Chain Risk Management Plan (SCRMP-LA-001)",
			Description: "FedRAMP SCRMP covering supply chain inventory (vendors, open-source deps, container images), risk assessment for 5 supply chain scenarios, controls (vendor mgmt, dependency pinning, build pipeline security), and monitoring/response procedures.",
			FilePath:    filepath.Join(complianceDir, "supply-chain-risk-management-plan.md"),
			ControlIDs:  []string{"DCF-SR-1", "DCF-SR-2", "DCF-SR-3", "DCF-SA-4", "DCF-SA-9"},
		},
		{
			Name:        "Privacy Impact Assessment (PIA-LA-001)",
			Description: "FedRAMP PIA covering PII inventory (direct and in-document), data flow analysis, 6 privacy risk assessments with mitigations, privacy controls (notice, consent, minimization, purpose limitation, data subject rights), and determination.",
			FilePath:    filepath.Join(complianceDir, "privacy-impact-assessment.md"),
			ControlIDs:  []string{"DCF-PT-1", "DCF-PT-2", "DCF-PT-3", "DCF-PT-5"},
		},
	}
}

// SyncPolicies uploads all compliance documents to Drata Evidence Library.
func (s *EvidenceSyncer) SyncPolicies(ctx context.Context, docs []PolicyDoc) error {
	// First, list existing evidence to avoid duplicates
	existing, err := s.client.ListEvidence(ctx)
	if err != nil {
		return fmt.Errorf("list existing evidence: %w", err)
	}
	existingNames := make(map[string]bool, len(existing))
	for _, e := range existing {
		existingNames[e.Name] = true
	}

	uploaded := 0
	skipped := 0
	for _, doc := range docs {
		if existingNames[doc.Name] {
			s.logger.Info("evidence already exists, skipping", "name", doc.Name)
			skipped++
			continue
		}

		// Verify file exists
		if _, err := os.Stat(doc.FilePath); os.IsNotExist(err) {
			s.logger.Warn("file not found, skipping", "name", doc.Name, "path", doc.FilePath)
			continue
		}

		if s.dryRun {
			s.logger.Info("[DRY RUN] would upload evidence", "name", doc.Name, "file", doc.FilePath, "controls", doc.ControlIDs)
			continue
		}

		item, err := s.client.CreateEvidence(ctx, doc.Name, doc.Description, doc.ControlIDs, doc.FilePath, s.ownerID)
		if err != nil {
			s.logger.Error("failed to upload evidence", "name", doc.Name, "error", err)
			continue
		}
		s.logger.Info("uploaded evidence", "name", doc.Name, "id", item.ID)
		uploaded++
	}

	s.logger.Info("evidence sync complete", "uploaded", uploaded, "skipped", skipped, "total", len(docs))
	return nil
}

// SyncCIArtifact uploads a single CI/CD artifact (SBOM, scan report, etc.) as evidence.
func (s *EvidenceSyncer) SyncCIArtifact(ctx context.Context, name, description, filePath string, controlIDs []string) error {
	if s.dryRun {
		s.logger.Info("[DRY RUN] would upload CI artifact", "name", name, "file", filePath)
		return nil
	}

	// For CI artifacts, we always create a new version (not idempotent — each build is new evidence)
	item, err := s.client.CreateEvidence(ctx, name, description, controlIDs, filePath, s.ownerID)
	if err != nil {
		return fmt.Errorf("upload CI artifact %s: %w", name, err)
	}
	s.logger.Info("uploaded CI artifact", "name", name, "id", item.ID)
	return nil
}

// SyncRedTeamReport uploads a red team execution report.
func (s *EvidenceSyncer) SyncRedTeamReport(ctx context.Context, reportPath string, controlIDs []string) error {
	name := fmt.Sprintf("Red Team Report — %s", strings.TrimSuffix(filepath.Base(reportPath), filepath.Ext(reportPath)))
	description := "Automated red team attack suite execution report (44 attacks across 3 suites: auth bypass, privilege escalation, data exfiltration). MITRE ATT&CK mapped."

	return s.SyncCIArtifact(ctx, name, description, reportPath, controlIDs)
}
