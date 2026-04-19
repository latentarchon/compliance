package main

import "fmt"

func inheritedControls() []ControlDef {
	return []ControlDef{
		// ── PE family — Physical and Environmental Protection ──────────────
		// Fully inherited from GCP FedRAMP High. Assured Workloads enforces
		// US-only data residency and IL5 compliance regime.

		{ID: "pe-1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Physical and environmental protection policy and procedures are fully inherited from Google Cloud Platform's FedRAMP High authorization. GCP maintains comprehensive physical security policies covering all data center facilities. Assured Workloads regime: %s.",
					or(f.AWSComplianceRegime, "FedRAMP High"))
			}},
		{ID: "pe-2", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Physical access authorizations are fully inherited from GCP. Google maintains authorized personnel lists for all data center facilities with approval from data center management."
			}},
		{ID: "pe-3.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Physical access control — guard all entry points. Inherited from GCP. Google data centers employ 24/7 security guards at all facility entry points with badge-based access control."
			}},
		{ID: "pe-4", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Access control for transmission is fully inherited from GCP. Google controls physical access to information system distribution and transmission lines within data center facilities."
			}},
		{ID: "pe-5", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Access control for output devices is fully inherited from GCP. Google controls physical access to output devices (monitors, printers) in data center facilities."
			}},
		{ID: "pe-6", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Physical access monitoring is fully inherited from GCP. Google monitors physical access to data center facilities using CCTV, badge readers, and intrusion detection systems. Access logs reviewed continuously."
			}},
		{ID: "pe-6.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Intrusion alarms and surveillance equipment monitoring is inherited from GCP. Google maintains 24/7 monitoring of intrusion detection systems and surveillance cameras at all data center facilities."
			}},
		{ID: "pe-8", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Visitor access records are fully inherited from GCP. Google maintains visitor logs for all data center facilities including name, organization, date/time, escort, and purpose of visit."
			}},
		{ID: "pe-9", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Power equipment and cabling protection is fully inherited from GCP. Google protects power equipment and cabling from damage and destruction in all data center facilities."
			}},
		{ID: "pe-10", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Emergency shutoff capability is fully inherited from GCP. Google provides emergency shutoff switches for power in data center facilities."
			}},
		{ID: "pe-11", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Emergency power is fully inherited from GCP. Google provides UPS and diesel generators at all data center facilities with automatic failover to maintain operations during power outages."
			}},
		{ID: "pe-12", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Emergency lighting is fully inherited from GCP. Google provides automatic emergency lighting in all data center facilities."
			}},
		{ID: "pe-13", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Fire protection is fully inherited from GCP. Google employs fire detection and suppression systems in all data center facilities."
			}},
		{ID: "pe-13.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Fire detection — automatic notification. Inherited from GCP. Fire detection systems automatically notify local fire departments and Google security operations."
			}},
		{ID: "pe-13.2", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Fire suppression — automatic activation. Inherited from GCP. Google data centers use automatic fire suppression systems that activate without manual intervention."
			}},
		{ID: "pe-14", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Environmental controls (temperature and humidity) are fully inherited from GCP. Google maintains temperature and humidity controls within acceptable ranges in all data center facilities with continuous monitoring."
			}},
		{ID: "pe-15", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Water damage protection is fully inherited from GCP. Google protects data center facilities from water damage using leak detection sensors and raised flooring."
			}},
		{ID: "pe-16", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Delivery and removal of equipment is fully inherited from GCP. Google authorizes, monitors, and controls delivery and removal of information system components at data center facilities."
			}},
		{ID: "pe-17", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "moderate",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Alternate work site security controls are not applicable — Latent Archon is a SaaS platform with no alternate work sites processing CUI. All data processing occurs within GCP data centers."
			}},
		{ID: "pe-18", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Location of system components — positioning to minimize damage. Inherited from GCP. Google positions data center equipment to minimize potential damage from physical and environmental hazards and to reduce unauthorized access opportunities."
			}},

		// ── CP — Contingency (physical infrastructure) ────────────────────
		{ID: "cp-7.2", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Alternate processing site accessibility is inherited from GCP. Google Cloud regions provide geographically diverse processing sites accessible during disruptions. Terraform IaC enables rapid redeployment to alternate regions."
			}},
		{ID: "cp-7.3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Priority of service at alternate processing site is inherited from GCP. Google Cloud maintains capacity commitments and SLAs that provide priority service provisions."
			}},
		{ID: "cp-8.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Priority of service for telecommunications is inherited from GCP. Google Cloud maintains diverse telecommunications infrastructure with redundant connectivity providers."
			}},
		{ID: "cp-8.2", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Single points of failure in telecommunications are mitigated by GCP. Google Cloud provides multiple independent network paths to all data center facilities."
			}},
		{ID: "cp-8.3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Separation of primary and alternate telecommunications services is inherited from GCP. Google maintains physically separated network paths for primary and backup connectivity."
			}},
		{ID: "cp-8.4", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Provider contingency plan is inherited from GCP. Google maintains telecommunications service provider contingency plans as part of their FedRAMP authorization."
			}},
		{ID: "cp-8.5", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Alternate telecommunication service testing is inherited from GCP. Google tests alternate telecommunications services as part of their contingency plan testing."
			}},

		// ── MA — Maintenance (physical) ───────────────────────────────────
		{ID: "ma-3.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance tools — inspect tools. Inherited from GCP. Google inspects maintenance tools brought into data center facilities for improper or unauthorized modifications."
			}},
		{ID: "ma-3.2", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Maintenance tools — inspect media. Inherited from GCP. Google inspects media containing diagnostic and test programs for malicious code before use in data center facilities."
			}},
		{ID: "ma-4.3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Comparable security for nonlocal maintenance is inherited from GCP. Google provides comparable security for nonlocal maintenance sessions as established for local maintenance."
			}},
		{ID: "ma-5.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Individuals without required access authorizations are escorted during maintenance. Inherited from GCP. Google escorts all non-authorized maintenance personnel within data center facilities."
			}},

		// ── MP — Media Protection (physical) ──────────────────────────────
		{ID: "mp-6.1", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Media sanitization — review, approve, track, document, verify. Inherited from GCP. Google reviews, approves, tracks, documents, and verifies media sanitization and disposal actions for data center equipment."
			}},
		{ID: "mp-6.2", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Equipment testing for media sanitization is inherited from GCP. Google tests sanitization equipment and procedures to verify correct performance."
			}},
		{ID: "mp-6.3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return "Nondestructive techniques for portable storage devices: not applicable — Latent Archon does not use portable storage devices. All data resides within GCP managed storage (Cloud SQL, Cloud Storage, Cloud Logging)."
			}},

		// ── SC — Physical separation ──────────────────────────────────────
		{ID: "sc-3", ImplStatus: "inherited", RoleID: "system-owner", Baseline: "high",
			ComponentUUIDs: []string{gcpPlatform},
			NarrativeFn: func(f *InfraFacts) string {
				return fmt.Sprintf("Security function isolation is provided by GCP's infrastructure. Cloud Run uses gVisor kernel-level sandboxing for workload isolation. VPC Service Controls (%s) isolate API access. Separate GCP projects provide blast-radius isolation between admin (%s), ops (%s), and app (%s) tiers.",
					or(f.VPCSCPerimeterName, "(not configured)"),
					or(f.AdminProjectID), or(f.OpsProjectID), or(f.AppProjectID))
			}},
	}
}
