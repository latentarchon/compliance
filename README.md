# Latent Archon — Compliance

Security policies, compliance documentation, Drata integration tooling, and sales collateral for the Latent Archon Document Intelligence Platform.

## Structure

```
policies/                          # 11 governance policies (NIST 800-53 aligned)
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
fedramp-ssp-appendix-a-controls.md  # Appendix A: Moderate + Appendix A-2: High enhancement controls
ssp-lite-nist-800-53.md            # SSP-Lite NIST 800-53 Moderate control mapping
configuration-management-plan.md   # Configuration management plan
continuous-monitoring-plan.md      # Continuous monitoring plan
contingency-plan.md                # Contingency / disaster recovery plan
privacy-impact-assessment.md       # Privacy impact assessment
supply-chain-risk-management-plan.md # Supply chain risk management plan
vulnerability-scanning-strategy.md # Vulnerability scanning strategy (DOC-VS-001)
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
| `fedramp-ssp-appendix-a-controls.md` | ATO / compliance officers / 3PAO | NIST 800-53 control implementations (Moderate baseline + High enhancement controls in Appendix A-2) |
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

## Review Cycle

All policies are reviewed annually. Next review: **March 2027**.
