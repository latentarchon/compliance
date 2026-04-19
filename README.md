# Latent Archon — Compliance

[![OSCAL Validation](https://github.com/latentarchon/compliance/actions/workflows/oscal-validate.yml/badge.svg)](https://github.com/latentarchon/compliance/actions/workflows/oscal-validate.yml)
[![Publish Compliance PDFs](https://github.com/latentarchon/compliance/actions/workflows/publish-pdfs.yml/badge.svg)](https://github.com/latentarchon/compliance/actions/workflows/publish-pdfs.yml)
[![Quarterly ConMon Report](https://github.com/latentarchon/compliance/actions/workflows/quarterly-conmon-report.yml/badge.svg)](https://github.com/latentarchon/compliance/actions/workflows/quarterly-conmon-report.yml)

Security policies, compliance documentation, OSCAL SSP generation, automated compliance tooling, and sales collateral for the Latent Archon Document Intelligence Platform.

| Metric | Value |
|--------|-------|
| **NIST 800-53 Baseline** | High — 355/355 controls implemented |
| **DoD IL5 Overlay** | 42 additional controls (397 total) |
| **FedRAMP Target** | High — full SSP complete, 3PAO engagement Q3 2026 |
| **CJIS** | All 13 policy areas mapped |
| **Red Team** | 99 automated attacks across 6 MITRE ATT&CK-mapped suites |
| **OSCAL SSP** | [Machine-readable SSP](oscal/ssp.json) — generated from IaC via automated scanners |

## OSCAL System Security Plan

The [`oscal/ssp.json`](oscal/ssp.json) file is a machine-readable NIST OSCAL SSP covering the full FedRAMP High baseline plus DoD IL5 overlay controls. It is generated automatically from infrastructure-as-code using Go-based scanners that inspect Terraform configs, GCP org policies, Cloudflare configurations, and CI/CD pipelines.

```bash
npm run generate:oscal    # Regenerate from current IaC state
npm run validate:oscal    # Validate against OSCAL schema
npm run check:drift       # Detect SSP-to-IaC drift
```

## Structure

```
policies/                          # 13 governance policies (NIST 800-53 aligned)
  information-security.md          # POL-IS-001 — Overarching security program
  access-control.md                # POL-AC-001 — AuthN, AuthZ, data isolation
  change-management.md             # POL-CM-001 — Change control, CI/CD security
  incident-response.md             # POL-IR-001 — IR framework, MITRE mapped
  vendor-risk.md                   # POL-VR-001 — Third-party risk management
  encryption.md                    # POL-EN-001 — Cryptographic standards, KMS
  data-classification.md           # POL-DC-001 — Classification, retention, disposal
  business-continuity.md           # POL-BC-001 — BC/DR, backup, recovery
  risk-management.md               # POL-RM-001 — Risk assessment, register, appetite
  acceptable-use.md                # POL-AU-001 — Acceptable/prohibited use
  security-awareness-training.md   # POL-AT-001 — Training requirements
  physical-security.md             # POL-PE-001 — Physical security (CSP inherited)
  vulnerability-scanning.md        # DOC-VS-001 — Scanning strategy, SLA timelines
cloud/                             # Cloud-specific supplements
  gcp.md                           # GCP service mapping and FedRAMP authorization
  aws.md                           # AWS supplement (commented out — GCP-only focus)
  azure.md                         # Azure supplement (commented out — GCP-only focus)
  service-mapping.md               # Cross-cloud equivalence table (commented out — GCP-only focus)
drata/                             # Drata API integration CLI tool (Go)
sales/                             # Sales and procurement collateral
  capability-statement.md
  pipeline-targets.md
security-whitepaper.md             # Customer-facing security architecture whitepaper
fedramp-ssp.md                     # FedRAMP System Security Plan
fedramp-20x-ksi-summaries.md       # FedRAMP 20x Key Security Indicator summaries
fedramp-ssp-appendix-a-controls.md  # Appendix A: High baseline (IL5) + Appendix A-2: High enhancement controls
ssp-lite-nist-800-53.md            # SSP-Lite NIST 800-53 High control mapping
configuration-management-plan.md   # Configuration management plan
continuous-monitoring-plan.md      # Continuous monitoring plan
contingency-plan.md                # Contingency / disaster recovery plan
privacy-impact-assessment.md       # Privacy impact assessment
supply-chain-risk-management-plan.md # Supply chain risk management plan
vulnerability-scanning-strategy.md # Vulnerability scanning strategy (DOC-VS-001)
red-team-mitre-coverage.md         # Red team MITRE ATT&CK coverage matrix (public)
cjis/                              # CJIS Security Policy v5.9.5 compliance
  compliance-mapping.md            # 13 policy area mapping
  management-control-agreement.md  # MCA template for state CSA engagement
  readiness-checklist.md           # Pre-audit checklist
oscal/                             # Machine-readable OSCAL artifacts
  ssp.json                         # NIST OSCAL SSP (High + IL5)
```

## Policy Inventory

| ID | Policy | NIST Controls | Domain |
|----|--------|--------------|--------|
| POL-IS-001 | Information Security | PL-1, PL-2, PM-1, PM-9 | Program governance |
| POL-AC-001 | Access Control | AC-1 through AC-22 | Authentication, authorization, isolation |
| POL-CM-001 | Change Management | CM-1 through CM-8 | Change control, CI/CD, configuration |
| POL-IR-001 | Incident Response | IR-1 through IR-9 | Detection, response, recovery |
| POL-VR-001 | Vendor Risk Management | SA-1 through SA-11 | Third-party, supply chain |
| POL-EN-001 | Encryption | SC-8, SC-12, SC-13, SC-28 | Cryptographic protection |
| POL-DC-001 | Data Classification & Retention | RA-2, MP-1, SI-12, AU-11 | Classification, handling, disposal |
| POL-BC-001 | Business Continuity & DR | CP-1 through CP-10 | Backup, recovery, continuity |
| POL-RM-001 | Risk Management | RA-1, RA-2, RA-3, PM-9 | Risk assessment, treatment |
| POL-AU-001 | Acceptable Use | PL-4, AC-8, AT-2 | System use, prohibited activities |
| POL-AT-001 | Security Awareness & Training | AT-1 through AT-4 | Training, awareness program |
| POL-PE-001 | Physical Security | PE-1 through PE-6, MA-1 | Physical controls (CSP inherited) |

## Audience

| Document | Audience | Purpose |
|----------|----------|---------|
| `policies/*` | Internal / ATO package | Written governance policies for NIST compliance |
| `cloud/*` | Internal / ATO package | Cloud-specific implementation details (GCP active; AWS/Azure commented out) |
| `security-whitepaper.md` | Customers / procurement | Technical security architecture overview |
| `fedramp-ssp.md` | ATO / compliance officers | FedRAMP System Security Plan |
| `fedramp-ssp-appendix-a-controls.md` | ATO / compliance officers / 3PAO | NIST 800-53 control implementations (High baseline, IL5 + enhancement controls in Appendix A-2) |
| `ssp-lite-nist-800-53.md` | ATO / compliance officers | Control-by-control NIST 800-53 mapping |
| `sales/capability-statement.md` | Contracting officers | Company capability one-pager |
| `drata/` | Engineering | Automated Drata compliance sync tool |

## Drata Integration

The `drata/` directory contains a Go CLI tool that syncs compliance data to Drata. See [`drata/README.md`](drata/README.md) for full documentation.

```bash
cd drata && go build -o drata-sync ./cmd/drata-sync/
./drata-sync --owner-id 1 --compliance-dir ../ --dry-run --verbose all
```

**What it syncs**: 13 evidence documents, 2 vendors, 12 risk register entries, 30 assets.  
**Automation**: Weekly GitHub Action + CI/CD evidence push from backend and redteam repos.

## PDF Generation

PDFs are generated from markdown sources and hosted on the marketing site for download.

```bash
npm install
npm run build:pdfs
```

## CI/CD Pipeline

On push to `main`, the `publish-pdfs` workflow:
1. Builds PDFs from all markdown sources
2. Uploads them as a GitHub Actions artifact (90-day retention)

The marketing site (`latentarchon/marketing`) checks out this repo at build time, builds PDFs, and copies them to `public/docs/` before deploying to Firebase Hosting. No PDFs are committed to either repo.

## Technical Maturity Evidence

This repository serves as feasibility evidence for government R&D programs (SBIR/STTR D2P2, OTAs). All work is self-funded — no prior government funding.

| Evidence | Description |
|----------|-------------|
| [OSCAL SSP](oscal/ssp.json) | Machine-readable SSP with 397 controls, generated from IaC |
| [FedRAMP SSP](fedramp-ssp.md) | Full narrative SSP at High baseline with IL5 overlay |
| [Appendix A Controls](fedramp-ssp-appendix-a-controls.md) | 2,600-line control-by-control implementation details |
| [Go Compliance Tooling](cmd/) | SSP generator, OSCAL scanner, access/audit review, POA&M reporting, drift checker |
| [Automated ConMon](cloudbuild-monthly.yaml) | Monthly Cloud Build pipeline: scanning, evidence collection, KSI updates |
| [13 Security Policies](policies/) | NIST-aligned governance policies with annual review cycle |
| [Drata Integration](drata/) | Automated evidence sync to continuous compliance platform |
| [CJIS Mapping](cjis/) | All 13 CJIS policy areas with MCA template |
| [Red Team Program](../redteam/) | 99 automated attacks across 6 MITRE ATT&CK-mapped suites |

## Compliance Automation Pipeline

```
IaC (Terraform/Terragrunt)
  → Go OSCAL Scanner (VPC-SC, CMEK, CI/CD, DLP, RLS, IDP, WAF adapters)
    → oscal/ssp.json (machine-readable)
    → fedramp-ssp.md (human-readable)
    → evidence/ (verified controls, tier summaries)
      → Drata sync (weekly)
      → Cloud Build monthly ConMon
```

## Review Cycle

All policies are reviewed annually. Next review: **March 2027**.
