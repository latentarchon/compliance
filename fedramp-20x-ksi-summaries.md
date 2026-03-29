# FedRAMP 20x — Key Security Indicator Implementation Summaries

> **Document ID**: KSI-LA-001
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System**: Latent Archon Document Intelligence Platform (LA-DIP)
> **Baseline**: FedRAMP 20x Moderate

Per FedRAMP requirement FRR-KSI-02, this document provides implementation summaries for each KSI theme, including:
1. Goals for implementation and validation (pass/fail criteria)
2. Consolidated information resources to be validated
3. Machine-based validation processes and cycle
4. Non-machine-based validation processes and cycle
5. Current implementation status
6. Clarifications

---

## AFR Order of Criticality

Implementation follows FedRAMP's recommended order:
1. Minimum Assessment Scope (MAS)
2. Authorization Data Sharing (ADS)
3. Using Cryptographic Modules (UCM)
4. Vulnerability Detection and Response (VDR)
5. Significant Change Notifications (SCN)
6. Persistent Validation and Assessment (PVA)
7. Secure Configuration Guide (RSC)
8. Collaborative Continuous Monitoring (CCM)
9. FedRAMP Security Inbox (FSI)
10. Incident Communications Procedures (ICP)

---

## 1. Authorization by FedRAMP

### 1.1 Minimum Assessment Scope (MAS)

**Goal**: Define and document the complete authorization boundary for the LA-DIP system.

**Pass/Fail Criteria**:
- ✅ All GCP projects, services, and data flows are documented in the SSP
- ✅ Authorization boundary diagram includes all components within scope
- ✅ External interconnections are documented with data flow direction and protocol

**Information Resources**:
- `fedramp-ssp.md` §3 (System Environment) — all 15 boundary components
- `fedramp-ssp.md` §4 (System Interconnections) — 6 external systems
- `fedramp-ssp.md` §8 (Architecture and Data Flows) — 4 diagrams
- Terraform/Terragrunt configs (`infra/`) — authoritative IaC for all resources

**Machine-Based Validation** (weekly):
- `terragrunt plan` drift detection (GitHub Actions, `infra/.github/workflows/terragrunt-ci.yml`)
- Compares live GCP state against declared IaC configuration
- Any drift = FAIL (undocumented resources exist outside boundary)

**Non-Machine-Based Validation** (quarterly):
- Manual review of SSP boundary diagram against live GCP Console
- Verify no new projects, services, or interconnections exist undocumented

**Status**: ✅ Implemented — SSP documents all 2 GCP projects, 6 Cloud Run services, and supporting infrastructure.

---

### 1.2 Authorization Data Sharing (ADS)

**Goal**: Share authorization data with all necessary parties per FedRAMP ADS process.

**Pass/Fail Criteria**:
- ✅ OSCAL SSP package is generated and machine-readable
- ✅ Package passes `oscal-cli validate` without errors
- ⬜ Package is submitted to FedRAMP repository (pending sponsor)

**Information Resources**:
- `compliance/oscal/ssp.json` — machine-readable OSCAL SSP
- `compliance/fedramp-ssp.md` + `fedramp-ssp-appendix-a-controls.md` — source documents
- `compliance/.github/workflows/oscal-validate.yml` — CI validation

**Machine-Based Validation** (on every commit):
- OSCAL SSP regenerated from source data
- Validated against FedRAMP Moderate OSCAL profile via `oscal-cli`
- CI blocks merge if validation fails

**Non-Machine-Based Validation** (per submission):
- Manual review of OSCAL package completeness before submission

**Status**: 🔧 In Progress — OSCAL generation tooling being built.

---

### 1.3 Using Cryptographic Modules (UCM)

**Goal**: All cryptographic modules protecting federal customer data are FIPS 140-2 validated.

**Pass/Fail Criteria**:
- ✅ Application crypto: Go BoringCrypto (FIPS 140-2 Level 1, Cert #4407)
- ✅ Data at rest: Cloud KMS CMEK (FIPS 140-2 Level 3) for Cloud SQL, GCS, Vertex AI, Artifact Registry, BigQuery, and Cloud Logging
- ✅ Data in transit: GFE TLS termination (FIPS 140-2 Level 1), TLS 1.2+ enforced
- ✅ No prohibited algorithms (DES, 3DES, RC4, MD5, SHA-1 for signatures, TLS < 1.2)

**Information Resources**:
- `fedramp-ssp.md` §10 (Cryptographic Modules) — 5 modules documented
- `infra/modules/kms/` — Terraform KMS config (AES-256, HSM-backed, 90-day auto-rotation, dual keyrings: regional `us-east1` + multi-region `us` for BigQuery)
- `backend/Dockerfile` — `GOEXPERIMENT=boringcrypto` build flag
- `policies/encryption.md` — POL-EN-001

**Machine-Based Validation** (weekly):
- KSI evidence script queries Cloud KMS key metadata (algorithm, rotation schedule, state)
- Verifies CMEK bindings on Cloud SQL, GCS, Vertex AI, Artifact Registry, BigQuery, and Cloud Logging
- Checks TLS policy on load balancers (minimum version, cipher suites)
- Go binary verification: `go version -m` confirms BoringCrypto linkage

**Non-Machine-Based Validation** (annually):
- Review FIPS certificate validity dates
- Confirm no new cryptographic dependencies added without FIPS validation

**Status**: ✅ Implemented — All five cryptographic modules documented and FIPS-validated.

---

### 1.4 Vulnerability Detection and Response (VDR)

**Goal**: Continuously detect, track, and remediate vulnerabilities across all information resources.

**Pass/Fail Criteria**:
- ✅ Container images scanned on every build (Trivy in CI)
- ✅ Dependencies monitored continuously (Dependabot on all repos)
- ✅ SBOM generated per build (CycloneDX format)
- ✅ Red team exercises run monthly (44 attacks, 3 suites)
- ✅ Scan results uploaded to Drata evidence library

**Information Resources**:
- `backend/.github/workflows/deploy.yaml` — Trivy scan + SBOM generation
- `redteam/` — 44 automated attacks (auth bypass, privilege escalation, data exfiltration)
- `.github/dependabot.yml` — all 9 repos
- `compliance/drata/` — evidence sync CLI
- `policies/vulnerability-scanning.md` — POL-VS-001

**Machine-Based Validation** (continuous):
- Trivy scan: every Docker build (blocks deploy on CRITICAL/HIGH)
- Dependabot: continuous dependency monitoring (auto-PRs)
- Red team: monthly cron (1st of month), all 3 suites in dry-run
- SBOM: generated and uploaded to Drata on every backend deploy

**Non-Machine-Based Validation** (quarterly):
- Review Trivy findings trend report
- Review Dependabot alert aging and remediation timelines
- Red team report executive summary review

**Status**: ✅ Implemented — Full VDR pipeline with automated scanning, red team exercises, and evidence upload.

---

### 1.5 Significant Change Notifications (SCN)

**Goal**: Automatically detect and classify significant changes for FedRAMP reporting.

**Pass/Fail Criteria**:
- ✅ All infrastructure changes go through Terraform/Terragrunt (IaC)
- ✅ All code changes go through GitHub PR with required reviews
- ✅ `terragrunt plan` output posted as PR comment for review
- ⬜ Automated classification of "significant" vs "routine" changes (TODO)

**Information Resources**:
- `infra/.github/workflows/terragrunt-ci.yml` — plan on PR, drift detection on push
- All repo `deploy.yml` workflows — build/test/deploy pipelines
- `policies/change-management.md` — POL-CM-001
- `configuration-management-plan.md`

**Machine-Based Validation** (on every change):
- Terraform plan diff posted to PR comments
- Required reviewers on all PRs to staging/main
- Production deploys require manual GitHub environment approval

**Non-Machine-Based Validation** (monthly):
- Review change log for potential significant changes
- Classify per FedRAMP SCN criteria and notify if required

**Status**: 🔧 Partial — IaC tracking is complete; automated significance classification is TODO.

---

### 1.6 Persistent Validation and Assessment (PVA)

**Goal**: Continuously validate the effectiveness of security controls.

**Pass/Fail Criteria**:
- ✅ Automated contingency plan tests run monthly (CP-4)
- ✅ Red team exercises run monthly (IR-3)
- ✅ IaC drift detection runs weekly
- ✅ Vulnerability scanning runs on every build
- ⬜ KSI evidence collection runs on schedule

**Information Resources**:
- `compliance/contingency-test/` — automated CP-4 test CLI
- `redteam/` — monthly attack exercises
- `infra/.github/workflows/terragrunt-ci.yml` — drift detection
- `compliance/continuous-monitoring-plan.md`

**Machine-Based Validation** (weekly/monthly):
- CP-4 tests: monthly (Cloud SQL backup, GCS versioning, Cloud Run health, KMS keys)
- Red team: monthly (auth bypass, escalation, exfiltration suites)
- Drift detection: weekly (terragrunt plan comparison)
- KSI evidence: weekly (GCP API queries → JSON evidence)

**Non-Machine-Based Validation** (quarterly):
- PVA effectiveness review and trend analysis

**Status**: 🔧 Partial — Individual validation components exist; unified KSI evidence pipeline being built.

---

### 1.7 Secure Configuration Guide (SCG)

**Goal**: Provide secure-by-default configurations and customer guidance.

**Pass/Fail Criteria**:
- ✅ All infrastructure defined in Terraform/Terragrunt (secure defaults)
- ✅ Cloud Armor WAF rules enforce OWASP CRS
- ✅ Egress firewall deny-all-by-default
- ⬜ Customer-facing secure configuration guide document (TODO)

**Information Resources**:
- `infra/modules/` — 14 Terraform modules with secure defaults
- `infra/modules/cloud-armor/` — OWASP CRS, rate limiting, bot blocking
- `backend/docs/TENANT_CONFIGURATION.md` — customer tenant setup guide

**Machine-Based Validation** (weekly):
- Terraform drift detection verifies configs haven't diverged from IaC
- Cloud Armor policy evaluation via GCP API

**Non-Machine-Based Validation** (per release):
- Review new features for security configuration implications

**Status**: 🔧 Partial — IaC secure defaults are complete; customer-facing SCG document is TODO.

---

### 1.8 Collaborative Continuous Monitoring (CCM)

**Goal**: Provide ongoing authorization reports and quarterly reviews.

**Pass/Fail Criteria**:
- ✅ Continuous monitoring plan documented
- ✅ Automated evidence collection and Drata sync
- ⬜ Quarterly review template and cadence (TODO — needs agency sponsor)

**Information Resources**:
- `compliance/continuous-monitoring-plan.md`
- `compliance/drata/` — automated evidence sync (weekly cron)
- Red team reports, CP-4 reports, vulnerability scan results

**Machine-Based Validation** (weekly):
- Drata full sync: Monday 6am UTC (compliance/drata/.github/workflows/drata-sync.yml)
- Evidence library: 13 compliance documents auto-uploaded

**Non-Machine-Based Validation** (quarterly):
- Quarterly review report generation (pending sponsor engagement)

**Status**: 🔧 Partial — monitoring infrastructure exists; quarterly review requires agency sponsor.

---

### 1.9 FedRAMP Security Inbox (FSI)

**Goal**: Operate a secure inbox for FedRAMP and government communications.

**Pass/Fail Criteria**:
- ⬜ Dedicated security inbox operational
- ⬜ Monitored 24/7 with defined SLA

**Information Resources**:
- Planned: `security@latentarchon.com` (Google Workspace)
- `policies/incident-response.md` — communication procedures

**Machine-Based Validation**: N/A — inbox monitoring is human-operated.

**Non-Machine-Based Validation** (persistent):
- Inbox checked daily; critical communications within 1 business day

**Status**: ⬜ TODO — Create and configure `security@latentarchon.com` inbox.

---

### 1.10 Incident Communications Procedures (ICP)

**Goal**: Integrate FedRAMP ICP into incident response procedures.

**Pass/Fail Criteria**:
- ✅ Incident response plan documented (POL-IR-001)
- ✅ Monthly red team exercises test IR procedures
- ⬜ FedRAMP-specific notification timelines integrated (TODO)

**Information Resources**:
- `policies/incident-response.md` — POL-IR-001
- `redteam/` — monthly IR exercises
- `compliance/drata/` — IR evidence upload

**Machine-Based Validation** (monthly):
- Red team exercises generate IR timeline evidence
- Reports uploaded to Drata evidence library

**Non-Machine-Based Validation** (annually):
- Tabletop exercise with FedRAMP notification procedures

**Status**: 🔧 Partial — IR plan and exercises exist; FedRAMP-specific notification timelines need integration.

---

## 2. Change Management

### 2.1 Documenting Changes

**Goal**: All changes are properly documented and configuration baselines updated.

**Pass/Fail Criteria**:
- ✅ All infrastructure changes tracked in Git (Terraform/Terragrunt)
- ✅ All code changes tracked in Git with PR reviews
- ✅ CI/CD enforces build/test/deploy pipeline
- ✅ Production deploys require manual approval gate

**Information Resources**:
- All 9 Git repositories with full commit history
- GitHub Actions workflows (build, test, deploy, plan)
- `policies/change-management.md` — POL-CM-001
- `configuration-management-plan.md`

**Machine-Based Validation** (continuous):
- Git commit log = complete change record
- CI/CD pipeline enforces: lint → test → build → deploy (no manual steps)
- Terraform plan posted to PR for infrastructure changes
- Production environment gate requires GitHub approval

**Non-Machine-Based Validation** (monthly):
- Review merged PRs for completeness of change documentation

**Status**: ✅ Implemented — Full IaC + CI/CD pipeline with required reviews and approval gates.

---

## 3. Cloud Native Architecture

### 3.1 Restricting Network Traffic

**Goal**: All information resources configured to limit inbound and outbound traffic.

**Pass/Fail Criteria**:
- ✅ VPC egress firewall: deny-all by default, FQDN allowlist only
- ✅ Cloud Armor WAF: OWASP CRS, tiered rate limiting (SCIM 30/min, auth 20/min, login 10/min, global 100/min), bot blocking
- ✅ Cloud Armor Adaptive Protection: ML-based L7 DDoS detection enabled on all WAF policies
- ✅ Geographic restriction: OFAC-embargoed countries (CU, IR, KP, SY, RU) blocked at WAF layer
- ✅ No public IPs on any service (Cloud Run, Cloud SQL, Vertex AI all private)
- ✅ Cloud Run ingress restricted via org policy (`run.allowedIngress` = internal + CLB only)
- ✅ Private Service Connect for Vertex AI

**Information Resources**:
- `infra/modules/vpc/` — VPC + egress firewall rules
- `infra/modules/cloud-armor/` — WAF policies
- `infra/modules/load-balancer/` — HTTPS LB with TLS termination
- `fedramp-ssp.md` §8.4 (Network Architecture)

**Machine-Based Validation** (weekly):
- KSI evidence script: query VPC firewall rules, Cloud Armor policies, LB configs
- Verify no public IPs exist on any compute resource
- Verify egress firewall rules match IaC

**Status**: ✅ Implemented.

### 3.2 Minimizing Attack Surface

**Goal**: Minimal attack surface with lateral movement minimized.

**Pass/Fail Criteria**:
- ✅ Serverless-only (Cloud Run) — no VMs to patch
- ✅ Minimal container images (distroless/alpine base)
- ✅ No SSH, no direct database access from internet
- ✅ Two-project isolation (blast radius containment)

**Machine-Based Validation** (weekly):
- Container image scan (Trivy) — no unnecessary packages
- IaC drift detection — no new resources outside boundary

**Status**: ✅ Implemented.

### 3.3 Using Logical Networking

**Goal**: Logical networking enforces traffic flow controls.

**Pass/Fail Criteria**:
- ✅ VPC with private subnets
- ✅ Cloud SQL via VPC peering (private IP only)
- ✅ Vertex AI via Private Service Connect
- ✅ Cross-project access via narrow IAM grants (not network peering)

**Status**: ✅ Implemented.

### 3.4 Optimizing for Availability

**Goal**: Resources optimized for high availability and rapid recovery.

**Pass/Fail Criteria**:
- ✅ Cloud Run: auto-scaling, multi-zone, zero-downtime deploys
- ✅ Cloud SQL: automated backups, PITR enabled
- ✅ GCS: versioning, 90-day soft-delete, WORM retention (2yr locked production), zero auto-delete lifecycle rules
- ✅ Global HTTPS LB: health checks, automatic failover

**Machine-Based Validation** (monthly):
- CP-4 automated tests verify backup/recovery capabilities

**Status**: ✅ Implemented.

---

## 4. Identity and Access Management

### 4.1 Enforcing Phishing-Resistant MFA

**Goal**: MFA enforced on all user authentication.

**Pass/Fail Criteria**:
- ✅ TOTP MFA enforced on all data endpoints (auth interceptor)
- ✅ Step-up MFA for sensitive operations
- ✅ MFA enrollment required before accessing workspace data
- ✅ Backend rejects JWTs without `sign_in_second_factor` claim

**Information Resources**:
- `backend/cmd/server/connect_interceptors.go` — MFA enforcement in auth interceptor
- `infra/modules/identity-platform/` — TOTP MFA enabled on all tenants
- `fedramp-ssp.md` §7.2 (Authentication Requirements)

**Machine-Based Validation** (weekly):
- Query Identity Platform: verify MFA enabled on all tenants
- Application audit logs: no data access without MFA claim

**Status**: ✅ Implemented.

### 4.2 Adopting Passwordless Methods

**Goal**: Secure passwordless authentication when feasible.

**Pass/Fail Criteria**:
- ✅ Magic link (passwordless) as primary auth method
- ✅ SAML SSO federation for enterprise customers
- ✅ No passwords stored by application (delegated to Identity Platform)

**Status**: ✅ Implemented.

### 4.3 Ensuring Least Privilege

**Goal**: Each user/device can only access needed resources.

**Pass/Fail Criteria**:
- ✅ RBAC: 4-tier role model (master_admin, admin, editor, viewer)
- ✅ PostgreSQL RLS: workspace-scoped data isolation
- ✅ GCP IAM: 15 specific roles for terraform-sa (no Owner/Editor)
- ✅ WIF: keyless CI/CD auth (no SA keys — org policy enforced)
- ✅ Database roles: archon_app_ro, archon_admin_rw, archon_ops_rw (enforced via migration; default PUBLIC revoked)
- ✅ Migration-user isolation: Atlas job uses Cloud SQL IAM auth with `SET ROLE archon_migrator` (no static credentials). `postgres` superuser password in Secret Manager as break-glass only, accessible to `gcp-security-admins` group (not mounted on any service or job by default).

**Machine-Based Validation** (weekly):
- Query IAM policy bindings on all projects
- Verify no SA keys exist (org policy audit)
- Verify RLS policies active on all tables
- Verify PUBLIC privileges revoked on all tables (query `information_schema.role_table_grants`)
- Verify DB role grants match expected (archon-app → archon_app_ro, archon-admin → archon_admin_rw, archon-ops → archon_ops_rw)

**Status**: ✅ Implemented.

### 4.4 Securing Non-User Authentication

**Goal**: Appropriately secure auth for non-user accounts and services.

**Pass/Fail Criteria**:
- ✅ WIF for CI/CD (OIDC, no SA keys)
- ✅ Service-to-service: GCP IAM + OIDC tokens
- ✅ Cloud Tasks: OIDC-authenticated task dispatch
- ✅ Org policy `iam.disableServiceAccountKeyCreation` enforced

**Status**: ✅ Implemented.

---

## 5. Incident Response

### 5.1 Incident Documentation and Reporting

**Goal**: Document, report, and analyze security incidents.

**Pass/Fail Criteria**:
- ✅ Incident response plan (POL-IR-001)
- ✅ Monthly red team exercises (44 attacks, 3 suites)
- ✅ MITRE ATT&CK technique mapping on all attacks
- ✅ Reports auto-uploaded to Drata evidence library

**Information Resources**:
- `policies/incident-response.md`
- `redteam/` — 44 attacks across auth bypass, escalation, exfiltration
- `red-infra/` — monitoring dashboard (attack requests, IAM denials, WAF blocks)

**Machine-Based Validation** (monthly):
- Red team CLI runs all suites in dry-run mode
- Generates Markdown report with MITRE mapping and NIST controls matrix
- Report uploaded to Drata

**Status**: ✅ Implemented.

---

## 6. Monitoring, Logging, and Auditing

### 6.1 Operating SIEM Capability

**Goal**: Centralized, tamper-resistant logging of events.

**Pass/Fail Criteria**:
- ✅ Cloud Logging: centralized, immutable, structured JSON
- ✅ Application audit_events table: user actions with IP, user-agent, metadata, session_id, mfa_method
- ✅ Cloud Audit Logs: admin activity + data access (GCP API calls)
- ✅ Log sink to GCS for long-term retention
- ⬜ Formal SIEM tool integration (Cloud Logging serves as SIEM equivalent)

**Information Resources**:
- `infra/modules/audit-logs/` — log sinks, retention policies
- `backend/` — structured JSON logging via Go `slog`
- `fedramp-ssp.md` §8.4 (Cloud Logging → optional SIEM export)

**Machine-Based Validation** (weekly):
- Verify Cloud Logging is enabled on all projects
- Verify log sink configurations match IaC
- Verify audit_events table is being populated
- Verify Cloud SQL database audit flags are active (`cloudsql.enable_pgaudit=on`, `pgaudit.log=ddl,role,write`, `log_statement=ddl`, `log_connections=on`, `log_disconnections=on`, `log_lock_waits=on`, `log_min_duration_statement=1000`)
- Verify break-glass secret access alert policy is active (CRITICAL severity, fires on any `db-postgres-password` Secret Manager access)

**Status**: ✅ Implemented (Cloud Logging as SIEM capability; pgAudit for database-level audit; break-glass secret alerting).

### 6.2 Evaluating Configurations

**Goal**: Persistently evaluate IaC configuration.

**Pass/Fail Criteria**:
- ✅ Terragrunt drift detection runs weekly
- ✅ Plan output captures any configuration changes
- ✅ IaC is the single source of truth for all infrastructure

**Status**: ✅ Implemented.

---

## 7. Service Configuration

### 7.1 Securing Network Traffic

See Cloud Native Architecture §3.1.

### 7.2 Automating Configuration Management

**Goal**: Machine-based resources managed via automation.

**Pass/Fail Criteria**:
- ✅ 100% of infrastructure managed by Terraform/Terragrunt (14 modules)
- ✅ No manual GCP Console changes (gcloud guardrail wrapper enforced)
- ✅ Configuration baselines version-controlled in Git

**Status**: ✅ Implemented.

### 7.3 Automating Secret Management

**Goal**: Automated management and rotation of secrets.

**Pass/Fail Criteria**:
- ✅ Cloud KMS: CMEK with 90-day automatic rotation (HSM-backed, `rotation_period = 7776000s`)
- ✅ Secret Manager: database credentials with 90-day rotation schedule
- ✅ Secret access alerting: Cloud Monitoring fires on any `AccessSecretVersion` call
- ✅ WIF: eliminates SA key secrets entirely
- ✅ No hardcoded secrets (org policy `iam.disableServiceAccountKeyCreation` + `iam.disableServiceAccountKeyUpload` + gitleaks in CI)

**Machine-Based Validation** (weekly):
- Query KMS key rotation schedules (verify 90-day period)
- Verify Secret Manager secret versions, rotation schedules, and access patterns
- Verify secret access alert policies are active
- Verify KMS key lifecycle alert policies are active
- gitleaks scan on every commit

**Status**: ✅ Implemented.

### 7.4 Validating Resource Integrity

**Goal**: Cryptographic methods validate integrity of machine-based resources.

**Pass/Fail Criteria**:
- ✅ Docker image digests (SHA-256) in Artifact Registry
- ✅ Cosign keyless image signing (Sigstore OIDC) — every image cryptographically signed in CI
- ✅ Cosign signature verification required before every Cloud Run deploy
- ✅ Digest-pinned deploys (`image@sha256:...`) — no mutable tag references
- ✅ Artifact Registry immutable tags enabled (prevents tag overwrites)
- ✅ SBOM generated per build (CycloneDX + SPDX)
- ✅ Terraform state uses checksums
- ✅ Atlas migration checksums (atlas.sum)

**Status**: ✅ Implemented.

---

## 8. Supply Chain Risk

### 8.1 Understanding Supply Chain Risks

**Goal**: Understand, monitor, and manage third-party risks.

**Pass/Fail Criteria**:
- ✅ Supply Chain Risk Management Plan documented
- ✅ Vendor risk register (2 vendors: GCP Critical, GitHub High)
- ✅ Risk register (12 entries, inherent/residual scoring)
- ✅ Dependabot on all 9 repos
- ✅ SBOM per build
- ✅ Cosign keyless image signing + verification in CI/CD pipeline
- ✅ Trivy hard fail gate (CRITICAL/HIGH block deploy)
- ✅ Artifact Registry immutable tags + CMEK encryption

**Information Resources**:
- `supply-chain-risk-management-plan.md`
- `compliance/drata/` — vendors, risks, assets commands
- `policies/vendor-risk.md` — POL-VR-001

**Status**: ✅ Implemented.

---

## 9. Recovery Planning

### 9.1 Recovery Capabilities

**Goal**: Define, maintain, and test recovery capabilities.

**Pass/Fail Criteria**:
- ✅ Contingency plan documented
- ✅ Automated CP-4 tests monthly (Cloud SQL backup/PITR, GCS versioning, Cloud Run health, KMS keys, Artifact Registry)
- ✅ RTO/RPO defined per component
- ✅ Test reports uploaded to Drata

**Status**: ✅ Implemented.

---

## Summary Status

| Theme | KSIs | Status |
|-------|------|--------|
| Authorization by FedRAMP | 10 | 🔧 7/10 implemented |
| Change Management | 1 | ✅ Complete |
| Cloud Native Architecture | 8 | ✅ Complete |
| Cybersecurity Education | 2 | 🔧 Partial |
| Identity and Access Management | 7 | ✅ Complete |
| Incident Response | 4 | ✅ Complete |
| Monitoring, Logging, Auditing | 5 | ✅ Complete |
| Policy and Inventory | 3 | ✅ Complete |
| Recovery Planning | 2 | ✅ Complete |
| Service Configuration | 8 | ✅ Complete |
| Supply Chain Risk | 3 | ✅ Complete |

**Remaining TODOs**:
1. OSCAL SSP package generation and CI validation
2. FedRAMP security inbox (`security@latentarchon.com`)
3. Automated SCN significance classification
4. Customer-facing Secure Configuration Guide
5. Cybersecurity education persistent testing evidence
6. FedRAMP-specific ICP notification timelines
7. Agency sponsor engagement for CCM quarterly reviews
