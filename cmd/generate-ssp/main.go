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
			doc = freshSSP(facts)
		} else {
			if len(doc.SystemSecurityPlan.SystemCharacteristics.SystemIDs) > 0 {
				uuidNamespace = doc.SystemSecurityPlan.SystemCharacteristics.SystemIDs[0].ID
			}
			doc.SystemSecurityPlan.Metadata.LastModified = time.Now().UTC().Format(time.RFC3339Nano)
			doc.SystemSecurityPlan.Metadata.Version = bumpPatch(doc.SystemSecurityPlan.Metadata.Version)
		}
	} else {
		doc = freshSSP(facts)
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

func freshSSP(facts *InfraFacts) SSPDocument {
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
						UUID: "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
						Type: "organization",
						Name: "Latent Archon, LLC",
						EmailAddresses: []string{"ajhendel@latentarchon.com"},
						Links: []Link{
							{Href: "https://latentarchon.com", Rel: "homepage"},
						},
					},
					{
						UUID: "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f",
						Type: "person",
						Name: "Andrew Hendel",
						Props: []Prop{
							{Name: "job-title", Value: "Chief Executive Officer"},
						},
						EmailAddresses:        []string{"ajhendel@latentarchon.com"},
						MemberOfOrganizations: []string{"b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"},
					},
				},
				ResponsibleParties: []ResponsibleParty{
					{RoleID: "system-owner", PartyUUIDs: []string{"c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f"}},
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
					Description: fmt.Sprintf("All inbound traffic flows through Cloudflare Edge WAF (proxied mode — managed rulesets, OWASP, rate limiting, geo-blocking) → Cloud Armor Origin WAF (OWASP CRS, Cloudflare-only origin restriction) → Regional HTTPS Load Balancer. No services have public IP addresses. Cloud Armor enforces Cloudflare-only origin restriction using auto-updated Cloudflare IP ranges. Cloud Run services use ingress=%s. VPC egress firewall is deny-all by default with FQDN-based allowlist for GCP APIs only. Internal communication uses VPC-native networking with Cloud SQL via VPC peering and Vertex AI via Private Service Connect. Region: %s.",
						or(facts.CloudRunIngress, "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"), or(facts.Region, "us-east4")),
				},
				DataFlow: DescriptionBlock{
					Description: fmt.Sprintf("Document upload: Browser → Cloudflare Edge WAF → Cloud Armor → HTTPS LB → Admin API (auth, MFA, RBAC, malware scan) → Cloud Storage (%s, CMEK) → Cloud Tasks → Ops Service (OCR, chunking, embedding) → Vertex AI Vector Search. App query: Browser → Cloudflare Edge WAF → Cloud Armor → HTTPS LB → App API (auth, MFA, workspace check) → Vector Search → Gemini LLM (%s, streaming response) → Client. All data at rest encrypted with AES-256 (CMEK via Cloud KMS). All data in transit encrypted with TLS 1.2+.",
						or(facts.GCSDocumentsBucket), or(facts.GeminiModel, "gemini")),
				},
			},
		},
	}
}
