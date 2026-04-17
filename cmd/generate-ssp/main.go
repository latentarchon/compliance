package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type PersonnelRoster struct {
	Organization struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Homepage string `json:"homepage"`
		UUID     string `json:"uuid"`
	} `json:"organization"`
	Personnel []struct {
		Name   string   `json:"name"`
		Title  string   `json:"title"`
		Email  string   `json:"email"`
		UUID   string   `json:"uuid"`
		Roles  []string `json:"roles"`
	} `json:"personnel"`
}

func loadRoster(root string) (*PersonnelRoster, error) {
	data, err := os.ReadFile(filepath.Join(root, "compliance", "personnel.json"))
	if err != nil {
		return nil, fmt.Errorf("personnel.json: %w", err)
	}
	var r PersonnelRoster
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("personnel.json: %w", err)
	}
	return &r, nil
}

func (r *PersonnelRoster) findByRole(role string) *struct {
	Name  string   `json:"name"`
	Title string   `json:"title"`
	Email string   `json:"email"`
	UUID  string   `json:"uuid"`
	Roles []string `json:"roles"`
} {
	for i := range r.Personnel {
		for _, rr := range r.Personnel[i].Roles {
			if rr == role {
				return &r.Personnel[i]
			}
		}
	}
	return nil
}

func main() {
	infraRoot := flag.String("infra-root", "", "path to infra/ directory")
	backendRoot := flag.String("backend-root", "", "path to backend/ directory")
	existingSSP := flag.String("existing-ssp", "", "path to existing ssp.json (preserves metadata/characteristics)")
	outFile := flag.String("out", "", "output file (default: stdout)")
	baseline := flag.String("baseline", "high", "baseline level: moderate, high, il5")
	evidenceDir := flag.String("evidence-dir", "", "output directory for tier-separated evidence files")
	verbose := flag.Bool("v", false, "print infrastructure facts summary")
	flag.Parse()

	root := detectRoot()

	if *infraRoot == "" {
		*infraRoot = filepath.Join(root, "infra")
	}
	if *backendRoot == "" {
		*backendRoot = filepath.Join(root, "backend")
	}
	if *existingSSP == "" {
		*existingSSP = filepath.Join(root, "compliance", "oscal", "ssp.json")
	}

	roster, err := loadRoster(root)
	if err != nil {
		log.Fatalf("roster error: %v", err)
	}

	facts, err := scanInfrastructure(*infraRoot, *backendRoot)
	if err != nil {
		log.Fatalf("scan error: %v", err)
	}

	if *verbose {
		fmt.Fprintln(os.Stderr, formatFactsSummary(facts))
	}

	var doc SSPDocument
	if data, err := os.ReadFile(*existingSSP); err == nil {
		if err := json.Unmarshal(data, &doc); err != nil {
			log.Printf("warning: could not parse existing SSP, generating fresh: %v", err)
			doc = freshSSP(facts, roster)
		} else {
			if len(doc.SystemSecurityPlan.SystemCharacteristics.SystemIDs) > 0 {
				uuidNamespace = doc.SystemSecurityPlan.SystemCharacteristics.SystemIDs[0].ID
			}
			doc.SystemSecurityPlan.Metadata.LastModified = time.Now().UTC().Format(time.RFC3339Nano)
			doc.SystemSecurityPlan.Metadata.Version = bumpPatch(doc.SystemSecurityPlan.Metadata.Version)
		}
	} else {
		doc = freshSSP(facts, roster)
	}

	reqs := buildImplementedRequirements(facts)
	filtered := filterByBaseline(reqs, *baseline)

	doc.SystemSecurityPlan.ControlImplementation = ControlImplementation{
		Description:             fmt.Sprintf("Auto-generated from infrastructure-as-code on %s. Baseline: NIST 800-53 Rev. 5 %s. Controls derived from Terragrunt configs in %s and backend source in %s.", time.Now().UTC().Format("2006-01-02"), *baseline, *infraRoot, *backendRoot),
		ImplementedRequirements: filtered,
	}

	doc.SystemSecurityPlan.ImportProfile.Href = profileHref(*baseline)

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Fatalf("marshal error: %v", err)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, out, 0644); err != nil {
			log.Fatalf("write error: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d controls to %s (%d bytes)\n", len(filtered), *outFile, len(out))
	} else {
		os.Stdout.Write(out)
		fmt.Fprintf(os.Stderr, "\n--- %d controls generated ---\n", len(filtered))
	}

	if *evidenceDir != "" {
		controls := allControls()
		if err := generateEvidence(controls, facts, *baseline, *evidenceDir); err != nil {
			log.Fatalf("evidence generation error: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote evidence files to %s\n", *evidenceDir)
	}
}

func detectRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "compliance")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "infra")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	wd, _ := os.Getwd()
	return wd
}

// uuidNamespace is set once from the SSP's system UUID to ensure generated
// UUIDs are unique per system. Defaults to the Latent Archon system ID.
var uuidNamespace = "LA-DIP-HIGH-2026"

func deterministicUUID(input string) string {
	h := sha256.Sum256([]byte(uuidNamespace + ":" + input))
	hexStr := hex.EncodeToString(h[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexStr[0:8], hexStr[8:12],
		"4"+hexStr[13:16],
		"8"+hexStr[17:20],
		hexStr[20:32])
}

func filterByBaseline(reqs []ImplementedRequirement, level string) []ImplementedRequirement {
	allowed := map[string]bool{"moderate": true}
	if level == "high" || level == "il5" {
		allowed["high"] = true
	}
	if level == "il5" {
		allowed["il5"] = true
	}

	var filtered []ImplementedRequirement
	for _, r := range reqs {
		baseline := "moderate"
		for _, p := range r.Props {
			if p.Name == "baseline" {
				baseline = p.Value
			}
		}
		if allowed[baseline] {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func profileHref(baseline string) string {
	switch baseline {
	case "il5":
		return "https://raw.githubusercontent.com/GSA/fedramp-automation/refs/heads/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.json"
	case "high":
		return "https://raw.githubusercontent.com/GSA/fedramp-automation/refs/heads/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.json"
	default:
		return "https://raw.githubusercontent.com/GSA/fedramp-automation/refs/heads/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json"
	}
}

func bumpPatch(version string) string {
	if version == "" {
		return "1.0.0"
	}
	var major, minor, patch int
	if _, err := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch); err != nil {
		return version
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch+1)
}

func freshSSP(facts *InfraFacts, roster *PersonnelRoster) SSPDocument {
	owner := roster.findByRole("system-owner")
	if owner == nil {
		log.Fatal("personnel.json: no person with system-owner role")
	}

	gcpPartyUUID := "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
	gcpLevAuthUUID := "e7f80910-2132-4435-8657-687989abbbcd"
	gcpComponentUUID := "e5f6a7b8-c9d0-4e1f-8a3b-4c5d6e7f8091"

	return SSPDocument{
		SystemSecurityPlan: SSP{
			UUID: deterministicUUID("ssp-root"),
			Metadata: Metadata{
				Title:        "Latent Archon Document Intelligence Platform — System Security Plan",
				LastModified: time.Now().UTC().Format(time.RFC3339Nano),
				Version:      "1.0.0",
				OscalVersion: "1.1.3",
				Props: []Prop{
					{Name: "marking", Value: "CUI"},
				},
				Roles: []Role{
					{ID: "system-owner", Title: "System Owner"},
					{ID: "information-system-security-officer", Title: "Information System Security Officer"},
					{ID: "authorizing-official", Title: "Authorizing Official"},
				},
				Parties: []Party{
					{
						UUID:           roster.Organization.UUID,
						Type:           "organization",
						Name:           roster.Organization.Name,
						EmailAddresses: []string{roster.Organization.Email},
						Links: []Link{
							{Href: roster.Organization.Homepage, Rel: "homepage"},
						},
					},
					{
						UUID: owner.UUID,
						Type: "person",
						Name: owner.Name,
						Props: []Prop{
							{Name: "job-title", Value: owner.Title},
						},
						EmailAddresses:        []string{owner.Email},
						MemberOfOrganizations: []string{roster.Organization.UUID},
					},
				},
				ResponsibleParties: []ResponsibleParty{
					{RoleID: "system-owner", PartyUUIDs: []string{owner.UUID}},
				},
			},
			ImportProfile: ImportProfile{
				Href: "https://raw.githubusercontent.com/GSA/fedramp-automation/refs/heads/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.json",
			},
			SystemCharacteristics: SystemCharacteristics{
				SystemIDs: []SystemID{
					{IdentifierType: "http://ietf.org/rfc/rfc4122", ID: "LA-DIP-HIGH-2026"},
				},
				SystemName:      "Latent Archon Document Intelligence Platform",
				SystemNameShort: "LA-DIP",
				Description:     "Latent Archon is a multi-tenant document intelligence platform purpose-built for U.S. government agencies handling Controlled Unclassified Information (CUI). The platform provides document management with malware scanning, AI-powered semantic search using Retrieval-Augmented Generation (RAG), interactive conversation over uploaded documents using Google Gemini LLMs, workspace-level data isolation enforced through PostgreSQL Row-Level Security (RLS), and enterprise SSO/SCIM integration.",
				Props: []Prop{
					{Name: "cloud-service-model", Value: "saas"},
					{Name: "cloud-deployment-model", Value: "public-cloud"},
					{Name: "identity-assurance-level", Value: "2"},
					{Name: "authenticator-assurance-level", Value: "2"},
					{Name: "federation-assurance-level", Value: "2"},
				},
				SecuritySensitivity: "high",
				SystemInformation: SystemInformation{
					InformationTypes: []InformationType{
						{
							UUID:        "b9fd4122-978b-4365-bc1f-9a35e081c136",
							Title:       "Customer Documents (CUI)",
							Description: "Customer-uploaded documents including Controlled Unclassified Information per 32 CFR 2002.",
							Categorizations: []Categorization{
								{System: "https://doi.org/10.6028/NIST.SP.800-60v2r1", InformationTypeIDs: []string{"D.14"}},
							},
							ConfidentialityImpact: ImpactLevel{Base: "high"},
							IntegrityImpact:       ImpactLevel{Base: "high"},
							AvailabilityImpact:    ImpactLevel{Base: "moderate"},
						},
					},
				},
				SecurityImpactLevel: SecurityImpactLevel{
					Confidentiality: "high",
					Integrity:       "high",
					Availability:    "moderate",
				},
				Status: Status{
					State:   "under-development",
					Remarks: "System is in pre-authorization status. Infrastructure-as-code validated in staging. Production deployment pending authorization boundary finalization and 3PAO engagement.",
				},
				AuthorizationBoundary: DescriptionBlock{
					Description: fmt.Sprintf("The authorization boundary encompasses all components required to deliver the Latent Archon SaaS offering: application code (Go backend, React SPAs), GCP infrastructure (Cloud Run, Cloud SQL, Cloud Storage, Vertex AI, Cloud Armor, Cloud KMS, Identity Platform), Cloudflare edge services (DNS, Edge WAF, rate limiting, Zero Trust Access), CI/CD pipelines (Cloud Build with container signing), administrative interfaces, and supporting services (ClamAV malware scanning, Document AI OCR). The system uses a three-project architecture for blast-radius isolation: Admin Project (%s), Ops Project (%s), App Project (%s), with KMS in dedicated project (%s).",
						or(facts.AdminProjectID), or(facts.OpsProjectID), or(facts.AppProjectID), or(facts.KMSProjectID)),
				},
				NetworkArchitecture: DescriptionBlock{
					Description: fmt.Sprintf("All inbound traffic flows through Cloudflare Edge WAF (proxied mode — managed rulesets, OWASP, rate limiting, threat score challenges, path probing protection, IP/ASN blocking) → Cloud Armor Origin WAF (OWASP CRS, Cloudflare-only origin restriction) → Regional HTTPS Load Balancer. No services have public IP addresses. Cloud Armor enforces Cloudflare-only origin restriction using auto-updated Cloudflare IP ranges. Cloud Run services use ingress=%s. VPC egress firewall is deny-all by default with FQDN-based allowlist for GCP APIs only. Internal communication uses VPC-native networking with Cloud SQL via VPC peering and Vertex AI via Private Service Connect. Region: %s.",
						or(facts.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"), or(facts.Region, "us-east4")),
				},
				DataFlow: DescriptionBlock{
					Description: fmt.Sprintf("Document upload: Browser → Cloudflare Edge WAF → Cloud Armor → HTTPS LB → Admin API (auth, MFA, RBAC, malware scan) → Cloud Storage (%s, CMEK) → Cloud Tasks → Ops Service (OCR, chunking, embedding) → Vertex AI Vector Search. App query: Browser → Cloudflare Edge WAF → Cloud Armor → HTTPS LB → App API (auth, MFA, workspace check) → Vector Search → Gemini LLM (%s, streaming response) → Client. All data at rest encrypted with AES-256 (CMEK via Cloud KMS). All data in transit encrypted with TLS 1.2+.",
						or(facts.GCSDocumentsBucket), or(facts.GeminiModel, "gemini")),
				},
			},
			SystemImplementation: SystemImplementation{
				LeveragedAuthorizations: []LeveragedAuthorization{
					{
						UUID:  gcpLevAuthUUID,
						Title: "Google Cloud Platform",
						Props: []Prop{{Name: "implementation-point", Value: "external"}},
						Links: []Link{{Href: "#" + gcpComponentUUID, Rel: "uses-service"}},
						PartyUUID:      gcpPartyUUID,
						DateAuthorized: "2018-05-18",
					},
					{
						UUID:           "f8a91b2c-3d4e-4f5a-6b7c-8d9e0f1a2b3c",
						Title:          "Cloudflare (DNS, WAF, Zero Trust Access)",
						Props:          []Prop{{Name: "implementation-point", Value: "external"}},
						PartyUUID:      gcpPartyUUID,
						DateAuthorized: "2024-02-28",
					},
				},
				Users: []User{
					{
						UUID:        "9137a909-0d75-4825-b4a2-757f036a1a0c",
						Title:       "Customer End User",
						Description: "Agency staff using conversation/search functionality via the app SPA.",
						Props: []Prop{
							{Name: "type", Value: "external"},
							{Name: "privilege-level", Value: "non-privileged"},
						},
						RoleIDs: []string{"viewer", "editor"},
						AuthorizedPrivileges: []AuthorizedPriv{{
							Title:              "Conversation and Search",
							Description:        "Access to conversation interface and document search within assigned workspaces.",
							FunctionsPerformed: []string{"document-search", "conversation", "view-documents"},
						}},
					},
					{
						UUID:        "d03ac1e6-e97f-40e7-9fde-e2c9b43f17fe",
						Title:       "Customer Org Admin",
						Description: "Agency administrator managing organization settings, users, and workspaces.",
						Props: []Prop{
							{Name: "type", Value: "external"},
							{Name: "privilege-level", Value: "privileged"},
						},
						RoleIDs: []string{"master_admin", "admin"},
						AuthorizedPrivileges: []AuthorizedPriv{{
							Title:              "Organization Management",
							Description:        "Create/manage workspaces, invite/remove members, upload documents, configure SSO/SCIM, manage IP allowlists.",
							FunctionsPerformed: []string{"user-management", "workspace-management", "document-management", "settings-management"},
						}},
					},
					{
						UUID:        "91c44d8d-ea19-4db3-bbcd-8126859edb3f",
						Title:       "Latent Archon Engineer",
						Description: "Platform developer deploying via CI/CD. No direct production data access.",
						Props: []Prop{
							{Name: "type", Value: "internal"},
							{Name: "privilege-level", Value: "privileged"},
						},
						RoleIDs: []string{"developer"},
						AuthorizedPrivileges: []AuthorizedPriv{{
							Title:              "CI/CD Deployment",
							Description:        "Deploy application containers and infrastructure changes via GitHub Actions with Workload Identity Federation (keyless).",
							FunctionsPerformed: []string{"code-deployment", "infrastructure-management"},
						}},
					},
				},
				Components: []Component{
					{UUID: "d4e5f6a7-b8c9-4d0e-8f2a-3b4c5d6e7f80", Type: "this-system", Title: "Latent Archon Application", Description: "The complete Latent Archon Document Intelligence Platform including Go backend services, React SPAs, and supporting infrastructure.", Status: Status{State: "under-development"}},
					{UUID: gcpComponentUUID, Type: "leveraged-system", Title: "Google Cloud Platform", Description: "FedRAMP High authorized cloud infrastructure providing compute, storage, networking, identity, AI/ML, and security services.", Props: []Prop{{Name: "leveraged-authorization-uuid", Value: gcpLevAuthUUID}}, Status: Status{State: "operational"}},
					{UUID: "f6a7b8c9-d0e1-4f2a-8b4c-5d6e7f809102", Type: "service", Title: "App API (archon-app)", Description: "Cloud Run service handling user-facing API: conversation, search, auth, streaming responses.", Status: Status{State: "under-development"}},
					{UUID: "a7b8c9d0-e1f2-4a3b-8c5d-6e7f80910213", Type: "service", Title: "Admin API (archon-admin)", Description: "Cloud Run service handling admin API: org management, document ingestion, settings, member management.", Status: Status{State: "under-development"}},
					{UUID: "b8c9d0e1-f2a3-4b4c-8d6e-7f8091021324", Type: "service", Title: "Ops Service (archon-ops)", Description: "Cloud Run service handling background processing: document processing, embeddings, cron jobs.", Status: Status{State: "under-development"}},
					{UUID: "c9d0e1f2-a3b4-4c5d-8e7f-809102132435", Type: "service", Title: "Cloud SQL PostgreSQL 15", Description: "Primary relational data store with Row-Level Security (RLS), encrypted at rest with CMEK via Cloud KMS. Private IP only, VPC peering.", Status: Status{State: "under-development"}},
					{UUID: "d0e1f2a3-b4c5-4d6e-8f80-910213243546", Type: "service", Title: "Cloud Storage", Description: "Object storage for customer documents. AES-256-GCM + CMEK, workspace-scoped paths, versioning (all versions preserved indefinitely), 90-day soft-delete recovery.", Status: Status{State: "under-development"}},
					{UUID: "a2b3c4d5-e6f7-4a8b-9c0d-1e2f3a4b5c6d", Type: "service", Title: "Cloudflare Edge WAF", Description: "Edge Web Application Firewall providing first-layer defense: Cloudflare Managed Ruleset, OWASP Core Rule Set, tiered rate limiting, custom firewall rules, Zero Trust Access for admin endpoints. All traffic proxied through Cloudflare before reaching origin.", Status: Status{State: "under-development"}},
					{UUID: "e1f2a3b4-c5d6-4e7f-8091-021324354657", Type: "service", Title: "Cloud Armor Origin WAF", Description: "Origin Web Application Firewall with OWASP CRS v3.3, rate limiting, bot blocking, HTTP method enforcement, per-tenant IP allowlisting, and Cloudflare-only origin restriction.", Status: Status{State: "under-development"}},
					{UUID: "f2a3b4c5-d6e7-4f80-9102-132435465768", Type: "service", Title: "Cloud KMS", Description: "Customer-Managed Encryption Keys (CMEK) for Cloud SQL, GCS, BigQuery, Logging, Vertex AI, Artifact Registry, Cloud Tasks, and app secrets. AES-256 with 90-day automatic rotation, HSM-backed (FIPS 140-2 Level 3).", Status: Status{State: "under-development"}},
					{UUID: "a3b4c5d6-e7f8-4091-8213-243546576879", Type: "service", Title: "Identity Platform", Description: "Firebase Identity Platform providing multi-tenant authentication with TOTP MFA, magic link (passwordless), SAML SSO, and SCIM 2.0.", Status: Status{State: "under-development"}},
					{UUID: "b4c5d6e7-f809-4102-9324-35465768798a", Type: "service", Title: "Vertex AI", Description: "AI/ML services: Vector Search (PSC endpoint, workspace-scoped), Gemini LLM (RAG response generation), embedding API.", Status: Status{State: "under-development"}},
					{UUID: "c5d6e7f8-0910-4213-a435-4657687989ab", Type: "service", Title: "CI/CD Pipeline", Description: "GitHub Actions with Workload Identity Federation (keyless, zero secrets). Includes: build, test, Trivy scan, SBOM generation, deploy to Cloud Run.", Status: Status{State: "operational"}},
					{UUID: "d6e7f809-1021-4324-b546-57687989abbc", Type: "service", Title: "ClamAV Malware Scanner", Description: "Internal-only Cloud Run service providing REST API for document malware scanning. Fail-closed in production.", Status: Status{State: "under-development"}},
				},
			},
			BackMatter: &BackMatter{
				Resources: []Resource{
					{UUID: deterministicUUID("res-baseline"), Title: "FedRAMP Rev5 High Baseline", RLinks: []RLink{{Href: "https://raw.githubusercontent.com/GSA/fedramp-automation/refs/heads/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline-resolved-profile_catalog.json", MediaType: "application/json"}}},
					{UUID: deterministicUUID("res-ac-policy"), Title: "Access Control Policy (POL-AC-001)", Description: "Access control policy document.", RLinks: []RLink{{Href: "./policies/access-control.md", MediaType: "text/markdown"}}},
					{UUID: deterministicUUID("res-ir-policy"), Title: "Incident Response Policy (POL-IR-001)", Description: "Incident response policy and procedures.", RLinks: []RLink{{Href: "./policies/incident-response.md", MediaType: "text/markdown"}}},
					{UUID: deterministicUUID("res-cm-plan"), Title: "Configuration Management Plan", Description: "Configuration management plan document.", RLinks: []RLink{{Href: "./configuration-management-plan.md", MediaType: "text/markdown"}}},
					{UUID: deterministicUUID("res-cp-plan"), Title: "Contingency Plan", Description: "Information system contingency plan (ISCP).", RLinks: []RLink{{Href: "./contingency-plan.md", MediaType: "text/markdown"}}},
					{UUID: deterministicUUID("res-conmon-plan"), Title: "Continuous Monitoring Plan", Description: "Continuous monitoring strategy and procedures.", RLinks: []RLink{{Href: "./continuous-monitoring-plan.md", MediaType: "text/markdown"}}},
					{UUID: deterministicUUID("res-scrm-plan"), Title: "Supply Chain Risk Management Plan", Description: "Supply chain risk management plan (SCRMP).", RLinks: []RLink{{Href: "./supply-chain-risk-management-plan.md", MediaType: "text/markdown"}}},
					{UUID: deterministicUUID("res-pia"), Title: "Privacy Impact Assessment", Description: "Privacy impact assessment (PIA).", RLinks: []RLink{{Href: "./privacy-impact-assessment.md", MediaType: "text/markdown"}}},
				},
			},
		},
	}
}
