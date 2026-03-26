package sync

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/latentarchon/compliance/drata/internal/client"
)

// AssetSyncer registers infrastructure and application assets in Drata.
type AssetSyncer struct {
	client  *client.Client
	logger  *slog.Logger
	ownerID int
	dryRun  bool
}

// NewAssetSyncer creates a new asset syncer.
func NewAssetSyncer(c *client.Client, logger *slog.Logger, ownerID int, dryRun bool) *AssetSyncer {
	return &AssetSyncer{client: c, logger: logger, ownerID: ownerID, dryRun: dryRun}
}

// AssetDef defines an asset to register.
type AssetDef struct {
	Name        string
	Description string
	AssetType   string // PHYSICAL, VIRTUAL, SOFTWARE, DATA, PERSONNEL, POLICY
}

// ArchonAssets returns the full infrastructure and application asset inventory.
func ArchonAssets() []AssetDef {
	return []AssetDef{
		// --- GCP Infrastructure ---
		{
			Name:        "Cloud Run — archon-chat (Chat API)",
			Description: "User-facing chat API service. Handles streaming conversation, message retrieval, auth. Runs on Cloud Run in latentarchon-chat project. Distroless container, FIPS 140-2 BoringCrypto binary.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Run — archon-admin (Admin API)",
			Description: "Admin API service. Handles org/workspace/document/member CRUD, invites, document ingestion. Runs on Cloud Run in latentarchon-admin project. Distroless container, FIPS 140-2 BoringCrypto binary.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Run — archon-ops (Ops Backend)",
			Description: "Internal operations service. Handles document processing, embedding generation, cron tasks. Runs on Cloud Run in latentarchon-admin project. Not publicly accessible. Distroless container.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Run — chat-spa (Chat Frontend)",
			Description: "Chat SPA served via nginx-unprivileged on Cloud Run in latentarchon-chat project. React/TypeScript/TailwindCSS. Domain: app.latentarchon.com.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Run — admin-spa (Admin Frontend)",
			Description: "Admin SPA served via nginx-unprivileged on Cloud Run in latentarchon-admin project. React/TypeScript/TailwindCSS. Domain: admin.latentarchon.com.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Run — ClamAV (Malware Scanner)",
			Description: "ClamAV antivirus service for document upload scanning. Runs on Cloud Run in latentarchon-admin project. Internal-only, not publicly accessible.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud SQL — PostgreSQL (Primary Database)",
			Description: "PostgreSQL database with Row-Level Security (RLS) enforced via FORCE. Stores organizations, workspaces, documents, messages, audit events. Private IP only, IAM authentication, CMEK encryption, automated backups with PITR (<5min RPO), multi-zone HA.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Storage — Documents Bucket",
			Description: "GCS bucket storing uploaded customer documents. CMEK encryption, object versioning (365-day retention), lifecycle policies. Private access only via service accounts.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Vertex AI — Vector Search Index",
			Description: "Vector search index for RAG document retrieval. gemini-embedding-2-preview model (768 dimensions). PSC-enabled endpoint (no public access). Workspace-scoped token restrictions.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Vertex AI — Gemini (LLM)",
			Description: "Gemini generative AI model for chat responses and image generation. Accessed via aiplatform PredictionClient. Rate limited, image caps (4/response, 10MB total).",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Document AI — OCR Processor",
			Description: "Google Document AI OCR processor for extracting text from uploaded documents (PDF, images). Used in document ingestion pipeline.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud KMS — Encryption Keys",
			Description: "Customer-managed encryption keys (CMEK) for Cloud SQL and GCS. Automatic 365-day rotation. Separate keys per data class.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Armor — WAF Policies",
			Description: "Web Application Firewall policies for both admin and chat load balancers. OWASP Top 10 rules, rate limiting, per-tenant IP allowlisting (dynamic deny rules), adaptive protection.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "VPC — Private Network",
			Description: "Virtual Private Cloud with private subnets, Cloud NAT for outbound, FQDN egress firewall (default deny), Private Service Connect for Vertex AI. No public IPs on any compute resources.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Load Balancers (Admin + Chat)",
			Description: "Global HTTPS load balancers with managed TLS certificates, host-based routing (SPA vs API), Cloud Armor integration. HSTS enforced (2-year max-age).",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Identity Platform — Admin Pool",
			Description: "Firebase Auth / Identity Platform for admin users (latentarchon-admin project). Email magic link + TOTP MFA. Separate from chat pool for blast-radius isolation.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Identity Platform — Chat Pool",
			Description: "Firebase Auth / Identity Platform for chat users (latentarchon-chat project). Email magic link + TOTP MFA. SAML SSO + SCIM provisioning for enterprise tenants.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Tasks — Document Processing Queue",
			Description: "Cloud Tasks queues for async document processing and embedding generation. Rate-limited, retry with backoff.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Cloud Logging + Audit Logs",
			Description: "Centralized logging infrastructure. Cloud Audit Logs for all GCP API calls. Application audit_events table for runtime operations. 365-day retention. SIEM export capability.",
			AssetType:   "VIRTUAL",
		},
		{
			Name:        "Artifact Registry",
			Description: "Docker container registry in both admin and chat GCP projects. Stores built container images. Vulnerability scanning enabled.",
			AssetType:   "VIRTUAL",
		},

		// --- Software ---
		{
			Name:        "Backend Application (Go)",
			Description: "Go backend application (3 server modes: public/admin/ops). Connect-RPC API surface. FIPS 140-2 BoringCrypto. Dependencies: pgx, firebase-admin, aiplatform, connect-rpc, otel.",
			AssetType:   "SOFTWARE",
		},
		{
			Name:        "Admin SPA (React/TypeScript)",
			Description: "Admin frontend application. React 18, TypeScript, TailwindCSS, Vite build, Connect-RPC client. Firebase Auth integration.",
			AssetType:   "SOFTWARE",
		},
		{
			Name:        "Chat SPA (React/TypeScript)",
			Description: "Chat frontend application. React 18, TypeScript, TailwindCSS, Vite build, Connect-RPC client with server streaming. Firebase Auth integration.",
			AssetType:   "SOFTWARE",
		},
		{
			Name:        "Infrastructure as Code (Terragrunt/Terraform)",
			Description: "14+ Terragrunt modules defining all GCP infrastructure. GCS backend with versioning and state locking. Separate staging and production environments.",
			AssetType:   "SOFTWARE",
		},
		{
			Name:        "Red Team Attack Suite (Go CLI)",
			Description: "Automated security testing tool. 44 attacks across 3 suites (auth bypass, privilege escalation, data exfiltration). MITRE ATT&CK mapped. Monthly execution.",
			AssetType:   "SOFTWARE",
		},
		{
			Name:        "CI/CD Pipelines (GitHub Actions)",
			Description: "Automated build, test, and deploy pipelines for all 9 repositories. Workload Identity Federation (keyless). Production gates require manual approval.",
			AssetType:   "SOFTWARE",
		},

		// --- Data ---
		{
			Name:        "Customer Documents",
			Description: "Uploaded customer documents (PDF, DOCX, images). Stored in GCS with CMEK encryption. Processed via Document AI OCR, chunked, and embedded for RAG retrieval.",
			AssetType:   "DATA",
		},
		{
			Name:        "Customer Messages & Conversations",
			Description: "Chat messages and AI-generated responses. Stored in Cloud SQL with RLS enforcement. Workspace-scoped access control.",
			AssetType:   "DATA",
		},
		{
			Name:        "Document Embeddings",
			Description: "Vector embeddings of document chunks. Stored in Vertex AI Vector Search index. Workspace-scoped token restrictions prevent cross-tenant retrieval.",
			AssetType:   "DATA",
		},
		{
			Name:        "Audit Event Logs",
			Description: "Comprehensive audit trail of all system operations. Stored in Cloud SQL audit_events table. Includes user, IP, action, resource, metadata. Preserved indefinitely.",
			AssetType:   "DATA",
		},
	}
}

// SyncAssets registers assets in Drata, skipping duplicates.
func (s *AssetSyncer) SyncAssets(ctx context.Context, assets []AssetDef) error {
	existing, err := s.client.ListAssets(ctx)
	if err != nil {
		return fmt.Errorf("list existing assets: %w", err)
	}
	existingNames := make(map[string]bool, len(existing))
	for _, a := range existing {
		existingNames[a.Name] = true
	}

	created := 0
	skipped := 0
	for _, ad := range assets {
		if existingNames[ad.Name] {
			s.logger.Info("asset already exists, skipping", "name", ad.Name)
			skipped++
			continue
		}

		if s.dryRun {
			s.logger.Info("[DRY RUN] would create asset", "name", ad.Name, "type", ad.AssetType)
			continue
		}

		a, err := s.client.CreateAsset(ctx, client.CreateAssetRequest{
			Name:        ad.Name,
			Description: ad.Description,
			AssetType:   ad.AssetType,
			OwnerID:     s.ownerID,
		})
		if err != nil {
			s.logger.Error("failed to create asset", "name", ad.Name, "error", err)
			continue
		}
		s.logger.Info("created asset", "name", ad.Name, "id", a.ID)
		created++
	}

	s.logger.Info("asset sync complete", "created", created, "skipped", skipped, "total", len(assets))
	return nil
}
