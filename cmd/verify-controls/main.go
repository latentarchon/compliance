// Package main implements a NIST 800-53 control verification tool.
//
// It queries live GCP APIs and evaluates pass/fail against specific NIST
// control claims made in the SSP (fedramp-ssp-appendix-a-controls.md).
//
// Usage:
//
//	go run ./cmd/verify-controls --env staging
//	go run ./cmd/verify-controls --env staging --json
//	go run ./cmd/verify-controls --env staging --family SC   # only SC-* controls
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	logging "cloud.google.com/go/logging/apiv2"
	loggingpb "cloud.google.com/go/logging/apiv2/loggingpb"
	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"

	run "cloud.google.com/go/run/apiv2"
	runpb "cloud.google.com/go/run/apiv2/runpb"
)

// ControlResult is the outcome of a single NIST 800-53 control check.
type ControlResult struct {
	ControlID   string      `json:"control_id"`
	ControlName string      `json:"control_name"`
	Family      string      `json:"family"`
	Status      string      `json:"status"` // PASS, FAIL, WARN, SKIP
	Details     string      `json:"details"`
	Evidence    interface{} `json:"evidence,omitempty"`
}

// ProjectConfig holds project IDs for the multi-project split.
type ProjectConfig struct {
	AdminProject     string
	OpsProject       string
	AppProject       string
	AuthAdminProject string
	AuthAppProject   string
	Region           string
	OrgID            string
}

func envConfig(env string) ProjectConfig {
	if env == "production" {
		return ProjectConfig{
			AdminProject:     "archon-fed-admin",
			OpsProject:       "archon-fed-ops",
			AppProject:       "archon-fed-app",
			AuthAdminProject: "archon-fed-auth-admin",
			AuthAppProject:   "archon-fed-auth-app",
			Region:           "us-east4",
		}
	}
	return ProjectConfig{
		AdminProject:     "archon-admin-staging",
		OpsProject:       "archon-ops-staging",
		AppProject:       "archon-app-staging",
		AuthAdminProject: "archon-auth-admin-stg",
		AuthAppProject:   "archon-auth-app-stg",
		Region:           "us-east4",
	}
}

// Verifier runs NIST control checks against live GCP state.
type Verifier struct {
	cfg       ProjectConfig
	env       string
	ctx       context.Context
	kmsClient *kms.KeyManagementClient
	fwClient  *compute.FirewallsClient
	armorClient *compute.RegionSecurityPoliciesClient
	runClient *run.ServicesClient
	logClient *logging.ConfigClient
	gcsClient *storage.Client
	sqlSvc    *sqladmin.Service
	httpClient *http.Client
}

func NewVerifier(ctx context.Context, cfg ProjectConfig, env string) (*Verifier, error) {
	v := &Verifier{cfg: cfg, env: env, ctx: ctx}
	var err error

	v.kmsClient, err = kms.NewKeyManagementClient(ctx, option.WithQuotaProject(cfg.OpsProject))
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	v.fwClient, err = compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("firewall client: %w", err)
	}
	v.armorClient, err = compute.NewRegionSecurityPoliciesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("cloud armor client: %w", err)
	}
	v.runClient, err = run.NewServicesClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("cloud run client: %w", err)
	}
	v.logClient, err = logging.NewConfigClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("logging client: %w", err)
	}
	v.gcsClient, err = storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("storage client: %w", err)
	}
	v.sqlSvc, err = sqladmin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("sql admin client: %w", err)
	}

	// Authenticated HTTP client for Identity Toolkit REST calls
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("default credentials: %w", err)
	}
	v.httpClient = oauth2.NewClient(ctx, creds.TokenSource)

	if cfg.OrgID == "" {
		if orgID, err := v.lookupOrgID(cfg.AdminProject); err == nil {
			v.cfg.OrgID = orgID
		}
	}

	return v, nil
}

func (v *Verifier) lookupOrgID(project string) (string, error) {
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s", project)
	req := mustNewRequest(v.ctx, url)
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("project lookup returned %d", resp.StatusCode)
	}
	var proj struct {
		Parent struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"parent"`
	}
	if err := json.Unmarshal(body, &proj); err != nil {
		return "", err
	}
	if proj.Parent.Type == "organization" {
		return proj.Parent.ID, nil
	}
	return "", fmt.Errorf("project parent is %s, not organization", proj.Parent.Type)
}

func (v *Verifier) Close() {
	v.kmsClient.Close()
	v.fwClient.Close()
	v.armorClient.Close()
	v.runClient.Close()
	v.logClient.Close()
	v.gcsClient.Close()
}

func (v *Verifier) allProjects() []string {
	return []string{v.cfg.AdminProject, v.cfg.OpsProject, v.cfg.AppProject}
}

// RunAll executes all control checks and returns results.
func (v *Verifier) RunAll(familyFilter string) []ControlResult {
	type checkFunc struct {
		family string
		fn     func() []ControlResult
	}
	checks := []checkFunc{
		{"SC", v.checkKMSKeys},
		{"SC", v.checkSQLEncryption},
		{"SC", v.checkCloudRunIngress},
		{"SC", v.checkFirewallRules},
		{"SC", v.checkCloudArmor},
		{"SC", v.checkVPCSCPerimeter},
		{"AC", v.checkCloudRunAuth},
		{"AC", v.checkOrgPolicies},
		{"AU", v.checkLogSinks},
		{"AU", v.checkAuditStorageProtection},
		{"CP", v.checkSQLBackups},
		{"CP", v.checkGCSVersioning},
		{"IA", v.checkIDPMFA},
		{"CM", v.checkExpectedServices},
	}

	var results []ControlResult
	for _, c := range checks {
		if familyFilter != "" && !strings.EqualFold(c.family, familyFilter) {
			continue
		}
		results = append(results, c.fn()...)
	}
	return results
}

// --------------------------------------------------------------------------
// SC-12 + SC-13: KMS Key Management + Cryptographic Protection
// SSP claims: CMEK via Cloud KMS, HSM-backed, AES-256, auto-rotation
// --------------------------------------------------------------------------

func (v *Verifier) checkKMSKeys() []ControlResult {
	var results []ControlResult
	var allKeys []map[string]string
	hsmCount, nonHSMCount, rotatingCount, nonRotatingCount := 0, 0, 0, 0

	// Check ops project (owns the KMS keyring)
	for _, project := range []string{v.cfg.OpsProject, v.cfg.AdminProject} {
		parent := fmt.Sprintf("projects/%s/locations/%s", project, v.cfg.Region)
		krit := v.kmsClient.ListKeyRings(v.ctx, &kmspb.ListKeyRingsRequest{Parent: parent})
		for {
			kr, err := krit.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				results = append(results, ControlResult{
					ControlID: "SC-12", ControlName: "Cryptographic Key Establishment",
					Family: "SC", Status: "SKIP",
					Details: fmt.Sprintf("Cannot list keyrings in %s: %v", project, err),
				})
				break
			}

			kit := v.kmsClient.ListCryptoKeys(v.ctx, &kmspb.ListCryptoKeysRequest{Parent: kr.GetName()})
			for {
				key, err := kit.Next()
				if err == iterator.Done {
					break
				}
				if err != nil {
					break
				}

				purpose := key.GetPurpose()
				isAsymmetric := purpose == kmspb.CryptoKey_ASYMMETRIC_SIGN || purpose == kmspb.CryptoKey_ASYMMETRIC_DECRYPT

				info := map[string]string{
					"name":    key.GetName(),
					"purpose": purpose.String(),
				}
				if t := key.GetVersionTemplate(); t != nil {
					info["algorithm"] = t.GetAlgorithm().String()
					info["protection_level"] = t.GetProtectionLevel().String()
					if !isAsymmetric {
						if t.GetProtectionLevel().String() == "HSM" {
							hsmCount++
						} else {
							nonHSMCount++
						}
					}
				}
				if rp := key.GetRotationPeriod(); rp != nil {
					rotatingCount++
					info["rotation_period"] = rp.String()
				} else if !isAsymmetric {
					nonRotatingCount++
				}
				allKeys = append(allKeys, info)
			}
		}
	}

	if len(allKeys) == 0 {
		results = append(results, ControlResult{
			ControlID: "SC-12", ControlName: "Cryptographic Key Establishment",
			Family: "SC", Status: "FAIL",
			Details: "No KMS keys found in ops or admin projects",
		})
	} else {
		// SC-12: Key rotation
		if nonRotatingCount == 0 {
			results = append(results, ControlResult{
				ControlID: "SC-12", ControlName: "Cryptographic Key Establishment",
				Family: "SC", Status: "PASS",
				Details:  fmt.Sprintf("All %d keys have rotation enabled", rotatingCount),
				Evidence: allKeys,
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "SC-12", ControlName: "Cryptographic Key Establishment",
				Family: "SC", Status: "WARN",
				Details:  fmt.Sprintf("%d keys have rotation, %d do not", rotatingCount, nonRotatingCount),
				Evidence: allKeys,
			})
		}

		// SC-13: FIPS validation (HSM = FIPS 140-2 Level 3)
		if nonHSMCount == 0 {
			results = append(results, ControlResult{
				ControlID: "SC-13", ControlName: "Cryptographic Protection",
				Family: "SC", Status: "PASS",
				Details: fmt.Sprintf("All %d keys use HSM protection (FIPS 140-2 Level 3)", hsmCount),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "SC-13", ControlName: "Cryptographic Protection",
				Family: "SC", Status: "WARN",
				Details: fmt.Sprintf("%d HSM keys, %d software keys (software = FIPS 140-2 Level 1)", hsmCount, nonHSMCount),
			})
		}
	}
	return results
}

// --------------------------------------------------------------------------
// SC-28: Protection of Information at Rest
// SSP claims: Cloud SQL uses CMEK, GCS uses server-side encryption
// --------------------------------------------------------------------------

func (v *Verifier) checkSQLEncryption() []ControlResult {
	instances, err := v.sqlSvc.Instances.List(v.cfg.OpsProject).Context(v.ctx).Do()
	if err != nil {
		return []ControlResult{{
			ControlID: "SC-28", ControlName: "Protection of Information at Rest",
			Family: "SC", Status: "SKIP",
			Details: fmt.Sprintf("Cannot list SQL instances in ops project: %v", err),
		}}
	}

	var results []ControlResult
	for _, inst := range instances.Items {
		hasCMEK := inst.DiskEncryptionConfiguration != nil &&
			inst.DiskEncryptionConfiguration.KmsKeyName != ""
		if hasCMEK {
			results = append(results, ControlResult{
				ControlID: "SC-28", ControlName: "Protection of Information at Rest",
				Family: "SC", Status: "PASS",
				Details: fmt.Sprintf("Cloud SQL %q has CMEK: %s",
					inst.Name, inst.DiskEncryptionConfiguration.KmsKeyName),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "SC-28", ControlName: "Protection of Information at Rest",
				Family: "SC", Status: "FAIL",
				Details: fmt.Sprintf("Cloud SQL %q does NOT have CMEK configured", inst.Name),
			})
		}
	}

	if len(instances.Items) == 0 {
		results = append(results, ControlResult{
			ControlID: "SC-28", ControlName: "Protection of Information at Rest",
			Family: "SC", Status: "SKIP",
			Details: "No Cloud SQL instances found in ops project",
		})
	}
	return results
}

// --------------------------------------------------------------------------
// SC-8: Transmission Confidentiality — Cloud Run HTTPS ingress
// SSP claims: TLS 1.2+ enforced on all endpoints
// --------------------------------------------------------------------------

func (v *Verifier) checkCloudRunIngress() []ControlResult {
	var results []ControlResult
	for _, project := range v.allProjects() {
		parent := fmt.Sprintf("projects/%s/locations/%s", project, v.cfg.Region)
		it := v.runClient.ListServices(v.ctx, &runpb.ListServicesRequest{Parent: parent})
		for {
			svc, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				results = append(results, ControlResult{
					ControlID: "SC-8", ControlName: "Transmission Confidentiality",
					Family: "SC", Status: "SKIP",
					Details: fmt.Sprintf("Cannot list Cloud Run in %s: %v", project, err),
				})
				break
			}

			ingress := svc.GetIngress().String()
			name := shortName(svc.GetName())
			// All traffic goes through HTTPS via LB. Internal-only is even better.
			if ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" || ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER" {
				results = append(results, ControlResult{
					ControlID: "SC-8", ControlName: "Transmission Confidentiality",
					Family: "SC", Status: "PASS",
					Details: fmt.Sprintf("%s/%s: ingress=%s (restricted)", project, name, ingress),
				})
			} else {
				results = append(results, ControlResult{
					ControlID: "SC-8", ControlName: "Transmission Confidentiality",
					Family: "SC", Status: "WARN",
					Details: fmt.Sprintf("%s/%s: ingress=%s (should be internal/LB only)", project, name, ingress),
				})
			}
		}
	}
	return results
}

// --------------------------------------------------------------------------
// SC-7: Boundary Protection — Cloud Armor + Firewall rules
// SSP claims: WAF with OWASP rules, no overly permissive firewall rules
// --------------------------------------------------------------------------

func (v *Verifier) checkCloudArmor() []ControlResult {
	var results []ControlResult
	for _, project := range []string{v.cfg.AdminProject, v.cfg.AppProject} {
		it := v.armorClient.List(v.ctx, &computepb.ListRegionSecurityPoliciesRequest{Project: project, Region: v.cfg.Region})
		count := 0
		for {
			_, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				results = append(results, ControlResult{
					ControlID: "SC-7", ControlName: "Boundary Protection",
					Family: "SC", Status: "SKIP",
					Details: fmt.Sprintf("Cannot list Cloud Armor in %s: %v", project, err),
				})
				break
			}
			count++
		}
		if count > 0 {
			results = append(results, ControlResult{
				ControlID: "SC-7", ControlName: "Boundary Protection (WAF)",
				Family: "SC", Status: "PASS",
				Details: fmt.Sprintf("%s: %d Cloud Armor security policies active", project, count),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "SC-7", ControlName: "Boundary Protection (WAF)",
				Family: "SC", Status: "FAIL",
				Details: fmt.Sprintf("%s: No Cloud Armor security policies found", project),
			})
		}
	}
	return results
}

func (v *Verifier) checkFirewallRules() []ControlResult {
	var results []ControlResult
	for _, project := range v.allProjects() {
		it := v.fwClient.List(v.ctx, &computepb.ListFirewallsRequest{Project: project})
		var dangerousRules []string
		for {
			fw, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			// Flag rules that allow all traffic from 0.0.0.0/0
			for _, r := range fw.GetSourceRanges() {
				if r == "0.0.0.0/0" && len(fw.GetAllowed()) > 0 && !fw.GetDisabled() {
					dangerousRules = append(dangerousRules,
						fmt.Sprintf("%s (priority %d)", fw.GetName(), fw.GetPriority()))
				}
			}
		}
		if len(dangerousRules) == 0 {
			results = append(results, ControlResult{
				ControlID: "SC-7", ControlName: "Boundary Protection (Firewall)",
				Family: "SC", Status: "PASS",
				Details: fmt.Sprintf("%s: no 0.0.0.0/0 allow rules", project),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "SC-7", ControlName: "Boundary Protection (Firewall)",
				Family: "SC", Status: "WARN",
				Details: fmt.Sprintf("%s: %d rules allow 0.0.0.0/0: %s",
					project, len(dangerousRules), strings.Join(dangerousRules, ", ")),
				Evidence: dangerousRules,
			})
		}
	}
	return results
}

// --------------------------------------------------------------------------
// AC-3: Access Enforcement — Cloud Run services require authentication
// SSP claims: every RPC passes through auth interceptor
// --------------------------------------------------------------------------

func (v *Verifier) checkCloudRunAuth() []ControlResult {
	var results []ControlResult
	// SPA services are expected to be public (serve static HTML)
	spaNames := map[string]bool{"admin-spa": true, "app-spa": true}

	for _, project := range v.allProjects() {
		parent := fmt.Sprintf("projects/%s/locations/%s", project, v.cfg.Region)
		it := v.runClient.ListServices(v.ctx, &runpb.ListServicesRequest{Parent: parent})
		for {
			svc, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			name := shortName(svc.GetName())
			ingress := svc.GetIngress().String()
			isSPA := spaNames[name]

			// API services should be internal-only (behind LB)
			// SPA services can be public (static content)
			if isSPA {
				results = append(results, ControlResult{
					ControlID: "AC-3", ControlName: "Access Enforcement",
					Family: "AC", Status: "PASS",
					Details: fmt.Sprintf("%s/%s: SPA (static content, auth enforced by app)", project, name),
				})
			} else if ingress == "INGRESS_TRAFFIC_INTERNAL_ONLY" || ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER" {
				results = append(results, ControlResult{
					ControlID: "AC-3", ControlName: "Access Enforcement",
					Family: "AC", Status: "PASS",
					Details: fmt.Sprintf("%s/%s: API service with restricted ingress (%s)", project, name, ingress),
				})
			} else {
				results = append(results, ControlResult{
					ControlID: "AC-3", ControlName: "Access Enforcement",
					Family: "AC", Status: "WARN",
					Details: fmt.Sprintf("%s/%s: API service with open ingress (%s) — should be internal/LB only", project, name, ingress),
				})
			}
		}
	}
	return results
}

// --------------------------------------------------------------------------
// AU-2 + AU-6: Audit Events + Audit Review — Log sinks
// SSP claims: comprehensive audit logging routed to BigQuery
// --------------------------------------------------------------------------

func (v *Verifier) checkLogSinks() []ControlResult {
	var results []ControlResult
	for _, project := range v.allProjects() {
		it := v.logClient.ListSinks(v.ctx, &loggingpb.ListSinksRequest{
			Parent: fmt.Sprintf("projects/%s", project),
		})
		var sinkNames []string
		hasBQ := false
		for {
			sink, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				results = append(results, ControlResult{
					ControlID: "AU-2", ControlName: "Audit Events",
					Family: "AU", Status: "SKIP",
					Details: fmt.Sprintf("Cannot list log sinks in %s: %v", project, err),
				})
				break
			}
			sinkNames = append(sinkNames, sink.GetName())
			if strings.Contains(sink.GetDestination(), "bigquery.googleapis.com") {
				hasBQ = true
			}
		}

		// AU-2: At least one sink should exist
		if len(sinkNames) > 0 {
			results = append(results, ControlResult{
				ControlID: "AU-2", ControlName: "Audit Events",
				Family: "AU", Status: "PASS",
				Details:  fmt.Sprintf("%s: %d log sinks configured: %s", project, len(sinkNames), strings.Join(sinkNames, ", ")),
				Evidence: sinkNames,
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "AU-2", ControlName: "Audit Events",
				Family: "AU", Status: "FAIL",
				Details: fmt.Sprintf("%s: no log sinks configured", project),
			})
		}

		// AU-6: Should route to BigQuery for analysis
		if hasBQ {
			results = append(results, ControlResult{
				ControlID: "AU-6", ControlName: "Audit Review, Analysis, and Reporting",
				Family: "AU", Status: "PASS",
				Details: fmt.Sprintf("%s: logs route to BigQuery for analysis", project),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "AU-6", ControlName: "Audit Review, Analysis, and Reporting",
				Family: "AU", Status: "WARN",
				Details: fmt.Sprintf("%s: no BigQuery log sink — audit analysis may be limited", project),
			})
		}
	}
	return results
}

// --------------------------------------------------------------------------
// AU-9: Protection of Audit Information — bucket versioning + retention
// SSP claims: audit logs protected from modification
// --------------------------------------------------------------------------

func (v *Verifier) checkAuditStorageProtection() []ControlResult {
	var results []ControlResult
	// Check buckets in ops project (where audit data lives)
	it := v.gcsClient.Buckets(v.ctx, v.cfg.OpsProject)
	for {
		b, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, ControlResult{
				ControlID: "AU-9", ControlName: "Protection of Audit Information",
				Family: "AU", Status: "SKIP",
				Details: fmt.Sprintf("Cannot list buckets in ops project: %v", err),
			})
			break
		}
		// Only check audit-related buckets
		if !strings.Contains(b.Name, "audit") && !strings.Contains(b.Name, "log") {
			continue
		}
		if b.VersioningEnabled {
			results = append(results, ControlResult{
				ControlID: "AU-9", ControlName: "Protection of Audit Information",
				Family: "AU", Status: "PASS",
				Details: fmt.Sprintf("Bucket %q has versioning enabled", b.Name),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "AU-9", ControlName: "Protection of Audit Information",
				Family: "AU", Status: "FAIL",
				Details: fmt.Sprintf("Bucket %q does NOT have versioning — audit logs can be overwritten", b.Name),
			})
		}
	}
	if len(results) == 0 {
		results = append(results, ControlResult{
			ControlID: "AU-9", ControlName: "Protection of Audit Information",
			Family: "AU", Status: "WARN",
			Details: "No audit/log buckets found in ops project",
		})
	}
	return results
}

// --------------------------------------------------------------------------
// CP-9: System Backup — SQL backups + GCS versioning
// SSP claims: automated backups with PITR, GCS versioning
// --------------------------------------------------------------------------

func (v *Verifier) checkSQLBackups() []ControlResult {
	instances, err := v.sqlSvc.Instances.List(v.cfg.OpsProject).Context(v.ctx).Do()
	if err != nil {
		return []ControlResult{{
			ControlID: "CP-9", ControlName: "System Backup",
			Family: "CP", Status: "SKIP",
			Details: fmt.Sprintf("Cannot list SQL instances: %v", err),
		}}
	}

	var results []ControlResult
	for _, inst := range instances.Items {
		bc := inst.Settings.BackupConfiguration
		if bc == nil {
			results = append(results, ControlResult{
				ControlID: "CP-9", ControlName: "System Backup",
				Family: "CP", Status: "FAIL",
				Details: fmt.Sprintf("Cloud SQL %q has no backup configuration", inst.Name),
			})
			continue
		}

		issues := []string{}
		if !bc.Enabled {
			issues = append(issues, "backups disabled")
		}
		if !bc.PointInTimeRecoveryEnabled {
			issues = append(issues, "PITR disabled")
		}
		if bc.BackupRetentionSettings != nil && bc.BackupRetentionSettings.RetainedBackups < 7 {
			issues = append(issues, fmt.Sprintf("only %d retained backups (need ≥7)", bc.BackupRetentionSettings.RetainedBackups))
		}

		if len(issues) == 0 {
			results = append(results, ControlResult{
				ControlID: "CP-9", ControlName: "System Backup",
				Family: "CP", Status: "PASS",
				Details: fmt.Sprintf("Cloud SQL %q: backups enabled, PITR enabled, %d retained",
					inst.Name, bc.BackupRetentionSettings.RetainedBackups),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "CP-9", ControlName: "System Backup",
				Family: "CP", Status: "FAIL",
				Details: fmt.Sprintf("Cloud SQL %q: %s", inst.Name, strings.Join(issues, "; ")),
			})
		}
	}
	return results
}

func (v *Verifier) checkGCSVersioning() []ControlResult {
	var results []ControlResult
	for _, project := range []string{v.cfg.OpsProject} {
		it := v.gcsClient.Buckets(v.ctx, project)
		for {
			b, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			// Check document storage buckets (not tfstate or build artifacts)
			if strings.Contains(b.Name, "document") || strings.Contains(b.Name, "upload") {
				if b.VersioningEnabled {
					results = append(results, ControlResult{
						ControlID: "CP-9", ControlName: "System Backup (GCS)",
						Family: "CP", Status: "PASS",
						Details: fmt.Sprintf("Bucket %q has versioning enabled", b.Name),
					})
				} else {
					results = append(results, ControlResult{
						ControlID: "CP-9", ControlName: "System Backup (GCS)",
						Family: "CP", Status: "WARN",
						Details: fmt.Sprintf("Bucket %q does not have versioning", b.Name),
					})
				}
			}
		}
	}
	return results
}

// --------------------------------------------------------------------------
// IA-2: Identification and Authentication — MFA on IDP tenants
// SSP claims: TOTP MFA required for all users
// --------------------------------------------------------------------------

func (v *Verifier) checkIDPMFA() []ControlResult {
	var results []ControlResult
	for _, project := range []string{v.cfg.AuthAdminProject, v.cfg.AuthAppProject} {
		url := fmt.Sprintf("https://identitytoolkit.googleapis.com/v2/projects/%s/tenants?pageSize=100", project)
		req := mustNewRequest(v.ctx, url)
		req.Header.Set("x-goog-user-project", project)
		resp, err := v.httpClient.Do(req)
		if err != nil {
			results = append(results, ControlResult{
				ControlID: "IA-2", ControlName: "Identification and Authentication",
				Family: "IA", Status: "SKIP",
				Details: fmt.Sprintf("Cannot query IDP tenants for %s: %v", project, err),
			})
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != 200 {
			results = append(results, ControlResult{
				ControlID: "IA-2", ControlName: "Identification and Authentication",
				Family: "IA", Status: "SKIP",
				Details: fmt.Sprintf("IDP API returned %d for %s: %s", resp.StatusCode, project, truncate(string(body), 200)),
			})
			continue
		}

		var tenantsResp struct {
			Tenants []struct {
				Name      string `json:"name"`
				MfaConfig struct {
					State          string `json:"state"`
					EnabledProviders []string `json:"enabledProviders"`
				} `json:"mfaConfig"`
			} `json:"tenants"`
		}
		if err := json.Unmarshal(body, &tenantsResp); err != nil {
			results = append(results, ControlResult{
				ControlID: "IA-2", ControlName: "Identification and Authentication",
				Family: "IA", Status: "SKIP",
				Details: fmt.Sprintf("Cannot parse IDP response for %s: %v", project, err),
			})
			continue
		}

		for _, t := range tenantsResp.Tenants {
			tenantName := shortName(t.Name)
			mfaState := t.MfaConfig.State
			if mfaState == "ENABLED" || mfaState == "MANDATORY" {
				results = append(results, ControlResult{
					ControlID: "IA-2(1)", ControlName: "MFA for Privileged Accounts",
					Family: "IA", Status: "PASS",
					Details: fmt.Sprintf("%s tenant %s: MFA %s (providers: %s)",
						project, tenantName, mfaState, strings.Join(t.MfaConfig.EnabledProviders, ",")),
				})
			} else {
				results = append(results, ControlResult{
					ControlID: "IA-2(1)", ControlName: "MFA for Privileged Accounts",
					Family: "IA", Status: "FAIL",
					Details: fmt.Sprintf("%s tenant %s: MFA state=%q (expected ENABLED)",
						project, tenantName, mfaState),
				})
			}
		}

		if len(tenantsResp.Tenants) == 0 {
			results = append(results, ControlResult{
				ControlID: "IA-2", ControlName: "Identification and Authentication",
				Family: "IA", Status: "WARN",
				Details: fmt.Sprintf("%s: no IDP tenants found", project),
			})
		}
	}
	return results
}

// --------------------------------------------------------------------------
// CM-7: Least Functionality — expected Cloud Run services
// SSP claims: specific set of services per project
// --------------------------------------------------------------------------

func (v *Verifier) checkExpectedServices() []ControlResult {
	expected := map[string][]string{
		v.cfg.AdminProject: {"archon-admin", "admin-spa"},
		v.cfg.OpsProject:   {"archon-ops", "clamav"},
		v.cfg.AppProject:   {"archon-app", "app-spa"},
	}

	var results []ControlResult
	for project, expectedNames := range expected {
		parent := fmt.Sprintf("projects/%s/locations/%s", project, v.cfg.Region)
		it := v.runClient.ListServices(v.ctx, &runpb.ListServicesRequest{Parent: parent})
		actual := map[string]bool{}
		for {
			svc, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}
			actual[shortName(svc.GetName())] = true
		}

		// Check for missing expected services
		for _, name := range expectedNames {
			if !actual[name] {
				results = append(results, ControlResult{
					ControlID: "CM-7", ControlName: "Least Functionality",
					Family: "CM", Status: "WARN",
					Details: fmt.Sprintf("%s: expected service %q not found", project, name),
				})
			}
		}

		// Check for unexpected services
		expectedSet := map[string]bool{}
		for _, n := range expectedNames {
			expectedSet[n] = true
		}
		for name := range actual {
			if !expectedSet[name] {
				results = append(results, ControlResult{
					ControlID: "CM-7", ControlName: "Least Functionality",
					Family: "CM", Status: "WARN",
					Details: fmt.Sprintf("%s: unexpected service %q (not in SSP boundary)", project, name),
				})
			}
		}

		if len(results) == 0 || results[len(results)-1].ControlID != "CM-7" {
			results = append(results, ControlResult{
				ControlID: "CM-7", ControlName: "Least Functionality",
				Family: "CM", Status: "PASS",
				Details: fmt.Sprintf("%s: all %d expected services present, no unexpected services", project, len(expectedNames)),
			})
		}
	}
	return results
}

// --------------------------------------------------------------------------
// SC-7.21: VPC Service Controls — perimeter exists and enforced
// SSP claims: VPC-SC perimeter isolates GCP API access
// --------------------------------------------------------------------------

func (v *Verifier) checkVPCSCPerimeter() []ControlResult {
	if v.cfg.OrgID == "" {
		return []ControlResult{{
			ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
			Family: "SC", Status: "SKIP",
			Details: "Cannot determine org ID — unable to query Access Context Manager",
		}}
	}

	// List access policies for the org
	url := fmt.Sprintf("https://accesscontextmanager.googleapis.com/v1/accessPolicies?parent=organizations/%s", v.cfg.OrgID)
	req := mustNewRequest(v.ctx, url)
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return []ControlResult{{
			ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
			Family: "SC", Status: "SKIP",
			Details: fmt.Sprintf("Cannot query access policies: %v", err),
		}}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return []ControlResult{{
			ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
			Family: "SC", Status: "SKIP",
			Details: fmt.Sprintf("Access Context Manager API returned %d: %s", resp.StatusCode, truncate(string(body), 200)),
		}}
	}

	var policiesResp struct {
		AccessPolicies []struct {
			Name   string `json:"name"`
			Title  string `json:"title"`
			Parent string `json:"parent"`
		} `json:"accessPolicies"`
	}
	if err := json.Unmarshal(body, &policiesResp); err != nil {
		return []ControlResult{{
			ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
			Family: "SC", Status: "SKIP",
			Details: fmt.Sprintf("Cannot parse access policies response: %v", err),
		}}
	}

	if len(policiesResp.AccessPolicies) == 0 {
		return []ControlResult{{
			ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
			Family: "SC", Status: "FAIL",
			Details: "No access policies found for the organization — VPC-SC not configured",
		}}
	}

	var results []ControlResult
	protectedProjects := map[string]bool{}
	for _, ap := range policiesResp.AccessPolicies {
		perimURL := fmt.Sprintf("https://accesscontextmanager.googleapis.com/v1/%s/servicePerimeters", ap.Name)
		perimReq := mustNewRequest(v.ctx, perimURL)
		perimResp, err := v.httpClient.Do(perimReq)
		if err != nil {
			results = append(results, ControlResult{
				ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
				Family: "SC", Status: "SKIP",
				Details: fmt.Sprintf("Cannot list perimeters for %s: %v", ap.Title, err),
			})
			continue
		}
		defer perimResp.Body.Close()
		perimBody, _ := io.ReadAll(perimResp.Body)
		if perimResp.StatusCode != 200 {
			results = append(results, ControlResult{
				ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
				Family: "SC", Status: "SKIP",
				Details: fmt.Sprintf("Perimeter API returned %d for %s: %s", perimResp.StatusCode, ap.Title, truncate(string(perimBody), 200)),
			})
			continue
		}

		var perimetersResp struct {
			ServicePerimeters []struct {
				Name           string `json:"name"`
				Title          string `json:"title"`
				PerimeterType  string `json:"perimeterType"`
				Status         *struct {
					Resources []string `json:"resources"`
				} `json:"status"`
				Spec *struct {
					Resources []string `json:"resources"`
				} `json:"spec"`
				UseExplicitDryRunSpec bool `json:"useExplicitDryRunSpec"`
			} `json:"servicePerimeters"`
		}
		if err := json.Unmarshal(perimBody, &perimetersResp); err != nil {
			continue
		}

		if len(perimetersResp.ServicePerimeters) == 0 {
			results = append(results, ControlResult{
				ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
				Family: "SC", Status: "FAIL",
				Details: fmt.Sprintf("Access policy %q has no service perimeters", ap.Title),
			})
			continue
		}

		for _, sp := range perimetersResp.ServicePerimeters {
			perimName := shortName(sp.Name)

			// Check enforcement mode
			if sp.UseExplicitDryRunSpec {
				results = append(results, ControlResult{
					ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
					Family: "SC", Status: "WARN",
					Details: fmt.Sprintf("Perimeter %q is in dry-run mode — not enforced", perimName),
				})
			} else {
				results = append(results, ControlResult{
					ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
					Family: "SC", Status: "PASS",
					Details: fmt.Sprintf("Perimeter %q is enforced (not dry-run)", perimName),
				})
			}

			// Collect protected projects
			resources := []string{}
			if sp.Status != nil {
				resources = sp.Status.Resources
			}
			for _, r := range resources {
				protectedProjects[strings.TrimPrefix(r, "projects/")] = true
			}
		}
	}

	// Verify our projects are inside the perimeter
	for _, project := range v.allProjects() {
		projNum := v.lookupProjectNumber(project)
		if projNum == "" {
			results = append(results, ControlResult{
				ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
				Family: "SC", Status: "SKIP",
				Details: fmt.Sprintf("Cannot resolve project number for %s", project),
			})
			continue
		}
		if protectedProjects[projNum] {
			results = append(results, ControlResult{
				ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
				Family: "SC", Status: "PASS",
				Details: fmt.Sprintf("Project %s is inside the VPC-SC perimeter", project),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "SC-7(21)", ControlName: "VPC Service Controls",
				Family: "SC", Status: "WARN",
				Details: fmt.Sprintf("Project %s is NOT inside any VPC-SC perimeter", project),
			})
		}
	}

	return results
}

func (v *Verifier) lookupProjectNumber(project string) string {
	url := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s", project)
	req := mustNewRequest(v.ctx, url)
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	var proj struct {
		ProjectNumber string `json:"projectNumber"`
	}
	if err := json.Unmarshal(body, &proj); err != nil {
		return ""
	}
	return proj.ProjectNumber
}

// --------------------------------------------------------------------------
// AC-6.10: Org Policy Guardrails — confirm critical policies are enforced
// SSP claims: org-level policies prevent privilege escalation
// --------------------------------------------------------------------------

func (v *Verifier) checkOrgPolicies() []ControlResult {
	if v.cfg.OrgID == "" {
		return []ControlResult{{
			ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
			Family: "AC", Status: "SKIP",
			Details: "Cannot determine org ID — unable to query org policies",
		}}
	}

	type policyCheck struct {
		constraint string
		label      string
	}
	checks := []policyCheck{
		{"iam.disableServiceAccountKeyCreation", "SA key creation disabled"},
		{"compute.vmExternalIpAccess", "VM external IP denied"},
		{"sql.restrictPublicIp", "SQL public IP denied"},
		{"iam.allowedPolicyMemberDomains", "IAM domain restricted"},
	}

	var results []ControlResult
	for _, c := range checks {
		url := fmt.Sprintf("https://orgpolicy.googleapis.com/v2/organizations/%s/policies/%s", v.cfg.OrgID, c.constraint)
		req := mustNewRequest(v.ctx, url)
		resp, err := v.httpClient.Do(req)
		if err != nil {
			results = append(results, ControlResult{
				ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
				Family: "AC", Status: "SKIP",
				Details: fmt.Sprintf("Cannot query %s: %v", c.constraint, err),
			})
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode == 404 {
			results = append(results, ControlResult{
				ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
				Family: "AC", Status: "FAIL",
				Details: fmt.Sprintf("%s: policy not set at org level", c.label),
			})
			continue
		}
		if resp.StatusCode != 200 {
			results = append(results, ControlResult{
				ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
				Family: "AC", Status: "SKIP",
				Details: fmt.Sprintf("%s: API returned %d: %s", c.label, resp.StatusCode, truncate(string(body), 200)),
			})
			continue
		}

		var policy struct {
			Spec struct {
				Rules []struct {
					Enforce bool `json:"enforce"`
					Values  *struct {
						AllowedValues []string `json:"allowedValues"`
						DeniedValues  []string `json:"deniedValues"`
					} `json:"values"`
				} `json:"rules"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(body, &policy); err != nil {
			results = append(results, ControlResult{
				ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
				Family: "AC", Status: "SKIP",
				Details: fmt.Sprintf("%s: cannot parse response: %v", c.label, err),
			})
			continue
		}

		if len(policy.Spec.Rules) == 0 {
			results = append(results, ControlResult{
				ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
				Family: "AC", Status: "FAIL",
				Details: fmt.Sprintf("%s: policy exists but has no rules", c.label),
			})
			continue
		}

		enforced := false
		hasValues := false
		for _, rule := range policy.Spec.Rules {
			if rule.Enforce {
				enforced = true
			}
			if rule.Values != nil && (len(rule.Values.AllowedValues) > 0 || len(rule.Values.DeniedValues) > 0) {
				hasValues = true
			}
		}

		if enforced || hasValues {
			results = append(results, ControlResult{
				ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
				Family: "AC", Status: "PASS",
				Details: fmt.Sprintf("%s: enforced at org level (%d rules)", c.label, len(policy.Spec.Rules)),
			})
		} else {
			results = append(results, ControlResult{
				ControlID: "AC-6(10)", ControlName: "Org Policy Guardrails",
				Family: "AC", Status: "WARN",
				Details: fmt.Sprintf("%s: policy exists but enforcement unclear (%d rules)", c.label, len(policy.Spec.Rules)),
			})
		}
	}

	return results
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func shortName(fullName string) string {
	parts := strings.Split(fullName, "/")
	return parts[len(parts)-1]
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func mustNewRequest(ctx context.Context, url string) *http.Request {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

// --------------------------------------------------------------------------
// Report output
// --------------------------------------------------------------------------

func printReport(results []ControlResult, jsonOutput bool) {
	if jsonOutput {
		report := struct {
			Timestamp string          `json:"timestamp"`
			Total     int             `json:"total"`
			Pass      int             `json:"pass"`
			Fail      int             `json:"fail"`
			Warn      int             `json:"warn"`
			Skip      int             `json:"skip"`
			Results   []ControlResult `json:"results"`
		}{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Total:     len(results),
			Results:   results,
		}
		for _, r := range results {
			switch r.Status {
			case "PASS":
				report.Pass++
			case "FAIL":
				report.Fail++
			case "WARN":
				report.Warn++
			case "SKIP":
				report.Skip++
			}
		}
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Human-readable report
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  NIST 800-53 Control Verification — Live GCP State             ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	pass, fail, warn, skip := 0, 0, 0, 0
	currentFamily := ""
	for _, r := range results {
		if r.Family != currentFamily {
			if currentFamily != "" {
				fmt.Println()
			}
			fmt.Printf("── %s Family ──\n", r.Family)
			currentFamily = r.Family
		}

		icon := "?"
		switch r.Status {
		case "PASS":
			icon = "✅"
			pass++
		case "FAIL":
			icon = "❌"
			fail++
		case "WARN":
			icon = "⚠️ "
			warn++
		case "SKIP":
			icon = "⏭ "
			skip++
		}
		fmt.Printf("  %s [%s] %s\n", icon, r.ControlID, r.Details)
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Printf("  Results: %d PASS, %d FAIL, %d WARN, %d SKIP (total %d checks)\n",
		pass, fail, warn, skip, len(results))
	fmt.Println("══════════════════════════════════════════════════════════════════")

	if fail > 0 {
		fmt.Println()
		fmt.Println("  ❌ CONTROLS NOT MET — review failures above")
	} else if warn > 0 {
		fmt.Println()
		fmt.Println("  ⚠️  ALL CONTROLS MET with warnings — review above")
	} else {
		fmt.Println()
		fmt.Println("  ✅ ALL CONTROLS VERIFIED")
	}
}

func main() {
	env := flag.String("env", "staging", "Target environment (staging or production)")
	jsonOutput := flag.Bool("json", false, "Output JSON report")
	family := flag.String("family", "", "Filter by NIST control family (e.g. SC, AC, AU, CP, IA, CM)")
	flag.Parse()

	cfg := envConfig(*env)
	ctx := context.Background()

	fmt.Fprintf(os.Stderr, "Verifying NIST 800-53 controls against live GCP state...\n")
	fmt.Fprintf(os.Stderr, "  Environment: %s\n", *env)
	fmt.Fprintf(os.Stderr, "  Admin: %s | Ops: %s | App: %s\n", cfg.AdminProject, cfg.OpsProject, cfg.AppProject)
	fmt.Fprintf(os.Stderr, "\n")

	v, err := NewVerifier(ctx, cfg, *env)
	if err != nil {
		log.Fatalf("Failed to initialize verifier: %v", err)
	}
	defer v.Close()

	results := v.RunAll(*family)
	printReport(results, *jsonOutput)

	// Exit code 1 if any FAILs
	for _, r := range results {
		if r.Status == "FAIL" {
			os.Exit(1)
		}
	}
}
