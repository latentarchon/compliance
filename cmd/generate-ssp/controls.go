package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type ControlDef struct {
	ID             string
	ImplStatus     string
	RoleID         string
	NarrativeFn    func(f *InfraFacts) string
	Baseline       string
	EvidenceTier   string
	ComponentUUIDs []string
	Parameters     []ParamValue
}

type ParamValue struct {
	ParamID string
	Values  []string
}

const (
	thisSystem   = "d4e5f6a7-b8c9-4d0e-8f2a-3b4c5d6e7f80"
	gcpPlatform  = "e5f6a7b8-c9d0-4e1f-8a3b-4c5d6e7f8091"
	appAPI       = "f6a7b8c9-d0e1-4f2a-8b4c-5d6e7f809102"
	adminAPI     = "a7b8c9d0-e1f2-4a3b-8c5d-6e7f80910213"
	opsService   = "b8c9d0e1-f2a3-4b4c-8d6e-7f8091021324"
	cloudSQL     = "c9d0e1f2-a3b4-4c5d-8e7f-809102132435"
	cloudStorage = "d0e1f2a3-b4c5-4d6e-8f80-910213243546"
	edgeWAF      = "a2b3c4d5-e6f7-4a8b-9c0d-1e2f3a4b5c6d"
	cloudArmor   = "e1f2a3b4-c5d6-4e7f-8091-021324354657"
	cloudKMS     = "f2a3b4c5-d6e7-4f80-9102-132435465768"
	idPlatform   = "a3b4c5d6-e7f8-4091-8213-243546576879"
	vertexAI     = "b4c5d6e7-f809-4102-9324-35465768798a"
	ciCD         = "c5d6e7f8-0910-4213-a435-4657687989ab"
	clamAV       = "d6e7f809-1021-4324-b546-57687989abbc"

	// GDC-specific components (IL6)
	gdcPlatform    = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	alloyDBOmni    = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
	gdcObjStorage  = "3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e7f"
	gdcGateway     = "4d5e6f7a-8b9c-4d0e-1f2a-3b4c5d6e7f80"
	gdcAppServer   = "5e6f7a8b-9c0d-4e1f-2a3b-4c5d6e7f8091"
	gdcAdminServer = "6f7a8b9c-0d1e-4f2a-3b4c-5d6e7f809102"
	gdcOpsServer   = "7a8b9c0d-1e2f-4a3b-4c5d-6e7f80910213"
)

var verifiedControlIDs = map[string]bool{
	"ac-2": true, "ac-3": true, "ac-3.8": true, "ac-4": true, "ac-5": true,
	"ac-6.10": true,
	"ac-17": true, "ac-17.1": true,
	"au-4": true, "au-6.1": true, "au-9": true, "au-9.4": true, "au-11": true,
	"cm-6": true, "cm-7.2": true,
	"cp-2": true, "cp-6": true, "cp-9": true,
	"ia-2": true, "ia-2.1": true, "ia-2.2": true, "ia-7": true,
	"mp-2": true, "mp-4": true,
	"sa-10": true, "sa-11": true,
	"sc-5": true, "sc-7": true, "sc-7.4": true, "sc-7.21": true, "sc-8.1": true,
	"sc-12": true, "sc-13": true, "sc-28": true, "sc-28.1": true,
	"si-3": true,
	"ac-4.4": true, "cp-2.3": true, "cp-6.1": true,
	"sc-7.24": true, "sc-28.2": true, "ac-4.21": true, "sc-13.1": true,
}

var manualControlIDs = map[string]bool{
	"at-1": true, "at-2": true, "at-2.2": true, "at-3": true, "at-4": true,
	"pe-3": true,
	"pl-4": true, "pl-4.1": true,
	"pm-2": true,
	"ps-1": true, "ps-2": true, "ps-3": true, "ps-4": true,
	"ps-5": true, "ps-6": true, "ps-7": true, "ps-8": true,
	"pt-1": true, "pt-2": true, "pt-3": true, "pt-4": true,
	"pt-5": true, "pt-6": true, "pt-7": true, "pt-8": true,
}

var inheritedControlIDs = map[string]bool{
	"pe-1": true, "pe-2": true, "pe-3.1": true, "pe-4": true, "pe-5": true,
	"pe-6": true, "pe-6.1": true, "pe-8": true, "pe-9": true, "pe-10": true,
	"pe-11": true, "pe-12": true, "pe-13": true, "pe-13.1": true, "pe-13.2": true,
	"pe-14": true, "pe-15": true, "pe-16": true, "pe-17": true, "pe-18": true,
	"cp-7.2": true, "cp-7.3": true,
	"cp-8.1": true, "cp-8.2": true, "cp-8.3": true, "cp-8.4": true, "cp-8.5": true,
	"ma-3.1": true, "ma-3.2": true, "ma-4.3": true, "ma-5.1": true,
	"mp-6.1": true, "mp-6.2": true, "mp-6.3": true,
	"sc-3": true,
}

func classifyTier(id string) string {
	if verifiedControlIDs[id] {
		return "verified"
	}
	if inheritedControlIDs[id] {
		return "inherited"
	}
	if manualControlIDs[id] {
		return "manual"
	}
	return "templated"
}

func allControls() []ControlDef {
	var all []ControlDef
	all = append(all, verifiedControls()...)
	all = append(all, templatedControls()...)
	all = append(all, manualControls()...)
	all = append(all, inheritedControls()...)
	all = append(all, gapControls()...)
	all = append(all, il5Controls()...)
	all = append(all, il6Controls()...)

	for i := range all {
		all[i].EvidenceTier = classifyTier(all[i].ID)
	}
	return all
}

func or(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "[not configured]"
}

func joinOr(vals []string) string {
	if len(vals) == 0 {
		return "[none]"
	}
	return strings.Join(vals, ", ")
}

func boolStr(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func buildImplementedRequirements(facts *InfraFacts) []ImplementedRequirement {
	controls := allControls()
	reqs := make([]ImplementedRequirement, 0, len(controls))

	for _, c := range controls {
		narrative := c.NarrativeFn(facts)

		implStatus := c.ImplStatus
		if implStatus == "" {
			implStatus = "implemented"
		}

		components := c.ComponentUUIDs
		if len(components) == 0 {
			components = []string{thisSystem}
		}

		byComps := make([]ByComponent, 0, len(components))
		for i, compUUID := range components {
			desc := narrative
			if i > 0 {
				desc = fmt.Sprintf("See %s implementation for full description. This component contributes to the control implementation as described in the primary narrative.", c.ID)
			}
			byComps = append(byComps, ByComponent{
				ComponentUUID: compUUID,
				UUID:          deterministicUUID(fmt.Sprintf("bycomp-%s-%d", c.ID, i)),
				Description:   desc,
				ImplementationStatus: ImplStatus{
					State: implStatus,
				},
			})
		}

		req := ImplementedRequirement{
			UUID:      deterministicUUID("control-" + c.ID),
			ControlID: c.ID,
			Props: []Prop{
				{Name: "implementation-status", Value: implStatus},
				{Name: "evidence-tier", Value: c.EvidenceTier},
			},
			ResponsibleRoles: []RoleRef{
				{RoleID: c.RoleID},
			},
			Statements: []Statement{
				{
					StatementID: c.ID + "_smt",
					UUID:        deterministicUUID("stmt-" + c.ID),
					ByComponents: byComps,
				},
			},
		}

		if c.Baseline != "" {
			req.Props = append(req.Props, Prop{Name: "baseline", Value: c.Baseline})
		}

		if len(c.Parameters) > 0 {
			for _, p := range c.Parameters {
				req.SetParameters = append(req.SetParameters, SetParameter{
					ParamID: p.ParamID,
					Values:  p.Values,
				})
			}
		}

		reqs = append(reqs, req)
	}

	sort.Slice(reqs, func(i, j int) bool {
		return compareControlIDs(reqs[i].ControlID, reqs[j].ControlID) < 0
	})

	return reqs
}

func compareControlIDs(a, b string) int {
	af, an, ae := parseControlID(a)
	bf, bn, be := parseControlID(b)
	if af != bf {
		return strings.Compare(af, bf)
	}
	if an != bn {
		return an - bn
	}
	return ae - be
}

func parseControlID(id string) (family string, num int, enh int) {
	parts := strings.SplitN(id, "-", 2)
	if len(parts) < 2 {
		return id, 0, 0
	}
	family = parts[0]
	rest := parts[1]
	if dot := strings.IndexByte(rest, '.'); dot >= 0 {
		num, _ = strconv.Atoi(rest[:dot])
		enh, _ = strconv.Atoi(rest[dot+1:])
	} else {
		num, _ = strconv.Atoi(rest)
	}
	return
}

func formatFactsSummary(facts *InfraFacts) string {
	var b strings.Builder
	b.WriteString("Infrastructure Facts Summary:\n")
	b.WriteString(fmt.Sprintf("  Region: %s\n", or(facts.Region, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Environment: %s\n", or(facts.Environment, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Deployment: %s\n", or(facts.Deployment, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Admin Project: %s\n", or(facts.AdminProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Ops Project: %s\n", or(facts.OpsProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  App Project: %s\n", or(facts.AppProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  KMS Project: %s\n", or(facts.KMSProjectID, "(not detected)")))
	b.WriteString(fmt.Sprintf("  Cloud SQL: tier=%s, avail=%s, publicIP=%v\n", or(facts.CloudSQLTier), or(facts.CloudSQLAvailability), facts.CloudSQLPublicIP))
	b.WriteString(fmt.Sprintf("  Cloud Run: min=%d, max=%d, ingress=%s\n", facts.CloudRunMinScale, facts.CloudRunMaxScale, or(facts.CloudRunIngress)))
	b.WriteString(fmt.Sprintf("  KMS: rotation=%dd, algorithm=%s\n", facts.KMSRotationDays, or(facts.KMSAlgorithm, "(default)")))
	b.WriteString(fmt.Sprintf("  Cloudflare: WAF=%v, RateLimit=%v, Access=%v, Logpush=%v, FirewallRules=%v\n", facts.CFWAFEnabled, facts.CFRateLimitingEnabled, facts.CFAccessEnabled, facts.CFLogpushEnabled, facts.CFFirewallRulesEnabled))
	b.WriteString(fmt.Sprintf("  Cloudflare WAF: managed=%v, owasp=%v, action=%s\n", facts.CFWAFManagedRuleset, facts.CFWAFOWASPRuleset, or(facts.CFWAFAction, "(not set)")))
	b.WriteString(fmt.Sprintf("  Cloudflare Rate Limiting: login=%v (%d req/%ds)\n", facts.CFLoginRateLimitEnabled, facts.CFLoginRateLimit, facts.CFLoginRatePeriod))
	b.WriteString(fmt.Sprintf("  Cloudflare Firewall: threat_score=%v (threshold=%d), path_protection=%v (%d paths)\n", facts.CFThreatScoreEnabled, facts.CFThreatScoreThreshold, facts.CFPathProtectionEnabled, len(facts.CFBlockedPaths)))
	b.WriteString(fmt.Sprintf("  Cloudflare Access: %d apps, %d service tokens, worker_proxy=%v\n", facts.CFAccessApps, facts.CFAccessServiceTokens, facts.CFWorkerProxyEnabled))
	b.WriteString(fmt.Sprintf("  Cloudflare Zone: ssl=%s, min_tls=%s, tls1.3=%v, always_https=%v, security=%s\n", or(facts.CFSSLMode, "(not set)"), or(facts.CFMinTLS, "(not set)"), facts.CFTLS13, facts.CFAlwaysHTTPS, or(facts.CFSecurityLevel, "(not set)")))
	b.WriteString(fmt.Sprintf("  Cloud Armor: CF restriction=%v\n", facts.CloudArmorCFRestriction))
	b.WriteString(fmt.Sprintf("  Assured Workloads: regime=%s\n", or(facts.AWSComplianceRegime, "(not detected)")))
	b.WriteString(fmt.Sprintf("  ClamAV: %v\n", facts.ClamAVEnabled))
	b.WriteString(fmt.Sprintf("  Audit Logs: retention=%dd, WORM=%v\n", facts.AuditLogRetentionDays, facts.AuditLogWORM))
	b.WriteString(fmt.Sprintf("  Backend: BoringCrypto=%v, RBAC=%v, RLS=%v, Audit=%v, SCIM=%v, DLP=%v\n", facts.BoringCrypto, facts.RBACEnabled, facts.RLSEnabled, facts.AuditLoggingEnabled, facts.SCIMEnabled, facts.DLPEnabled))
	b.WriteString(fmt.Sprintf("  VPC-SC: enabled=%v, enforced=%v, perimeter=%s, %d projects, alerts=%v\n", facts.VPCSCEnabled, facts.VPCSCEnforced, or(facts.VPCSCPerimeterName, "(none)"), facts.VPCSCProtectedProjects, facts.VPCSCViolationAlerts))
	b.WriteString(fmt.Sprintf("  CMEK: SQL=%v, GCS=%v, BigQuery=%v, Logging=%v, Secrets=%v, AR=%v\n", facts.CMEKCloudSQL, facts.CMEKGCS, facts.CMEKBigQuery, facts.CMEKLogging, facts.CMEKSecrets, facts.CMEKArtifactRegistry))
	b.WriteString(fmt.Sprintf("  Cloud Build: %d triggers, binauthz=%v, trivy=%v, govulncheck=%v, SBOM=%v, gosec=%v, semgrep=%v, gitleaks=%v\n", facts.CloudBuildTriggers, facts.CloudBuildBinauthzEnabled, facts.CloudBuildTrivyEnabled, facts.CloudBuildGovulncheck, facts.CloudBuildSBOMEnabled, facts.CloudBuildGosecEnabled, facts.CloudBuildSemgrepEnabled, facts.CloudBuildGitleaksEnabled))
	b.WriteString(fmt.Sprintf("  DLP: template=%v, %d PII types, %d credential types\n", facts.DLPTemplateEnabled, facts.DLPPIIInfoTypes, facts.DLPCredentialTypes))
	b.WriteString(fmt.Sprintf("  RLS: %d tables, %d policies, roles=%v\n", facts.RLSTableCount, facts.RLSPolicyCount, facts.RLSRoles))
	b.WriteString(fmt.Sprintf("  IDP: MFA=%s, %d tenants, app_check=%v, email_link=%v\n", or(facts.IDPMFAState, "(not set)"), facts.IDPTenantCount, facts.IDPAppCheckEnabled, facts.IDPEmailLinkEnabled))
	b.WriteString(fmt.Sprintf("  Cloud Run: %d services scanned\n", len(facts.CloudRunServices)))
	b.WriteString(fmt.Sprintf("  Monitoring: %d alert policies, %d uptime checks, %d audit alert policies, %d log sinks/project\n", facts.MonitoringAlertPolicies, facts.MonitoringUptimeChecks, facts.AuditLogAlertPolicies, facts.AuditLogSinksPerProject))
	b.WriteString(fmt.Sprintf("  Org Policies: %d policies, SA key deny=%v, VM ext IP deny=%v, SQL pub IP deny=%v\n", facts.OrgPolicyCount, facts.OrgPolicySAKeyCreationDeny, facts.OrgPolicyVMExternalIPDeny, facts.OrgPolicySQLPublicIPDeny))
	b.WriteString(fmt.Sprintf("  Org: domain_restricted=%v, shielded_vm=%v, default_sa_deny=%v, access_approval=%v, %d IAM groups\n", facts.OrgPolicyDomainRestricted, facts.OrgPolicyShieldedVM, facts.OrgPolicyDefaultSAGrantDeny, facts.OrgAccessApprovalEnabled, facts.OrgIAMGroupCount))
	b.WriteString(fmt.Sprintf("  VPC: flow_log_sampling=%.0f%%, cloud_shell_disabled=%v\n", facts.FlowLogSampling*100, facts.CloudShellDisabled))
	b.WriteString(fmt.Sprintf("  Artifact Registry: immutable_tags=%v\n", facts.ImmutableTags))
	b.WriteString(fmt.Sprintf("  Email: provider=%s\n", or(facts.EmailProvider, "(not detected)")))

	return b.String()
}
