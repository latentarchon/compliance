# FedRAMP 20x — Key Security Indicator Implementation Summaries

> **Document ID**: KSI-LA-001
> **Version**: 1.1 — DRAFT
> **Date**: April 2026
> **System**: Latent Archon Document Intelligence Platform (LA-DIP)
> **Baseline**: FedRAMP 20x Moderate
> **High Readiness**: Appendix A-2 of the SSP documents 85+ FedRAMP High enhancement controls. Technical architecture supports High assessment.

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
- ✅ All cloud environments (GCP projects), services, and data flows are documented in the SSP
<!-- MULTI-CLOUD: Original also listed AWS accounts and Azure subscriptions. -->
- ✅ Authorization boundary diagram includes all components within scope
- ✅ External interconnections are documented with data flow direction and protocol

**Information Resources**:
- `fedramp-ssp.md` §3 (System Environment) — all 15 boundary components
- `fedramp-ssp.md` §4 (System Interconnections) — 6 external systems
- `fedramp-ssp.md` §8 (Architecture and Data Flows) — 4 diagrams
- Terraform/Terragrunt configs (`infra/`) — authoritative IaC for all resources

**Machine-Based Validation** (weekly):
- `terragrunt plan` drift detection (GitHub Actions, `infra/.github/workflows/terragrunt-ci.yml`)
- Compares live cloud state against declared IaC configuration
- Any drift = FAIL (undocumented resources exist outside boundary)

**Non-Machine-Based Validation** (quarterly):
- Manual review of SSP boundary diagram against live cloud console
- Verify no new environments, services, or interconnections exist undocumented

**Status**: ✅ Implemented — SSP documents all cloud environments, container services, and supporting infrastructure per cloud. See [Cloud Environment Supplements](cloud/) for per-cloud details.

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
- Validated against FedRAMP High OSCAL profile via `oscal-cli`
- CI blocks merge if validation fails

**Non-Machine-Based Validation** (per submission):
- Manual review of OSCAL package completeness before submission

**Status**: ✅ Implemented — OSCAL SSP generated (`oscal/ssp.json`, 329KB), CI validates on every push (`oscal-validate.yml`), SSP-IaC drift check included. Only remaining: submission to FedRAMP repository (pending agency sponsor).

---

### 1.3 Using Cryptographic Modules (UCM)

**Goal**: All cryptographic modules protecting federal customer data are FIPS 140-2 validated.

**Pass/Fail Criteria**:
- ✅ Application crypto: Go BoringCrypto (FIPS 140-2 Level 1, Cert #4407)
- ✅ Data at rest: CMEK via cloud KMS (FIPS 140-2 Level 3) for database, object storage, AI services, container registry, and logging
- ✅ Data in transit: Load balancer TLS termination (FIPS 140-2 Level 1), TLS 1.2+ enforced
- ✅ No prohibited algorithms (DES, 3DES, RC4, MD5, SHA-1 for signatures, TLS < 1.2)

**Information Resources**:
- `fedramp-ssp.md` §10 (Cryptographic Modules) — 5 modules documented
- `infra/*/modules/kms/` — Terraform KMS config per cloud (AES-256, HSM-backed, auto-rotation)
- `backend/Dockerfile` — `GOEXPERIMENT=boringcrypto` build flag
- `policies/encryption.md` — POL-EN-001

**Machine-Based Validation** (weekly):
- KSI evidence script queries cloud KMS key metadata (algorithm, rotation schedule, state)
- Verifies CMEK bindings on database, object storage, AI services, container registry, and logging
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
- ✅ Red team exercises run monthly (99 attacks, 6 suites)
- ✅ Scan results uploaded to Drata evidence library

**Information Resources**:
- `backend/.github/workflows/deploy.yaml` — Trivy scan + SBOM generation
- `redteam/` — 99 automated attacks across 6 suites (auth bypass, escalation, exfiltration, leftfield, webapp, manual tools)
- `.github/dependabot.yml` — all 9 repos
- `compliance/drata/` — evidence sync CLI
- `policies/vulnerability-scanning.md` — POL-VS-001

**Machine-Based Validation** (continuous):
- Trivy scan: every Docker build (blocks deploy on CRITICAL/HIGH)
- Dependabot: continuous dependency monitoring (auto-PRs)
- Red team: monthly cron (1st of month), all 6 suites in dry-run
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
- ✅ Automated classification of "significant" vs "routine" changes via `scn-classify` workflows

**Information Resources**:
- `infra/.github/workflows/terragrunt-ci.yml` — plan on PR, drift detection on push
- `{app,admin,backend,infra,redteam,red-infra}/.github/workflows/scn-classify.yml` — PR classification
- `compliance/cmd/classify-scn/` — Go CLI for SCN classification
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

**Status**: ✅ Implemented — IaC tracking + automated SCN classification on all 6 code repos. PR comments classify changes as SIGNIFICANT or ROUTINE with required actions.

---

### 1.6 Persistent Validation and Assessment (PVA)

**Goal**: Continuously validate the effectiveness of security controls.

**Pass/Fail Criteria**:
- ✅ Automated contingency plan tests run monthly (CP-4)
- ✅ Red team exercises run monthly (IR-3)
- ✅ IaC drift detection runs weekly
- ✅ Vulnerability scanning runs on every build
- ✅ KSI evidence collection runs on schedule

**Information Resources**:
- `compliance/contingency-test/` — automated CP-4 test CLI
- `redteam/` — monthly attack exercises
- `infra/.github/workflows/terragrunt-ci.yml` — drift detection
- `compliance/continuous-monitoring-plan.md`

**Machine-Based Validation** (weekly/monthly):
- CP-4 tests: monthly (database backup, storage versioning, container health, KMS keys)
- Red team: monthly (auth bypass, escalation, exfiltration suites)
- Drift detection: weekly (terragrunt plan comparison)
- KSI evidence: weekly (cloud API queries → JSON evidence)

**Non-Machine-Based Validation** (quarterly):
- PVA effectiveness review and trend analysis

**Status**: ✅ Implemented — CP-4, IR-3, drift detection, vulnerability scanning, and KSI evidence collection all running on schedule.

---

### 1.7 Secure Configuration Guide (SCG)

**Goal**: Provide secure-by-default configurations and customer guidance.

**Pass/Fail Criteria**:
- ✅ All infrastructure defined in Terraform/Terragrunt (secure defaults)
- ✅ Cloud Armor WAF rules enforce OWASP CRS
- ✅ Egress firewall deny-all-by-default
- ✅ Customer-facing secure configuration guide document

**Information Resources**:
- `customer-secure-configuration-guide.md` — GUIDE-SCG-001
- `infra/modules/` — 14 Terraform modules with secure defaults
- `infra/modules/cloud-armor/` — OWASP CRS, rate limiting, bot blocking
- `backend/docs/TENANT_CONFIGURATION.md` — customer tenant setup guide

**Machine-Based Validation** (weekly):
- Terraform drift detection verifies configs haven't diverged from IaC
- WAF policy evaluation via cloud API

**Non-Machine-Based Validation** (per release):
- Review new features for security configuration implications

**Status**: ✅ Implemented — IaC secure defaults + customer-facing Secure Configuration Guide (GUIDE-SCG-001).

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
- ✅ Dedicated security inbox operational
- ✅ Monitored 24/7 with defined SLA

**Information Resources**:
- `gcp-security-admins@latentarchon.com` (per-cloud security group)
- `policies/incident-response.md` — communication procedures

**Machine-Based Validation**: N/A — inbox monitoring is human-operated.

**Non-Machine-Based Validation** (persistent):
- Inbox checked daily; critical communications within 1 business day

**Status**: ✅ DONE — Using `gcp-security-admins@latentarchon.com` (per-cloud security group, no shared `security@` inbox — reduces phishing attack surface).

---

### 1.10 Incident Communications Procedures (ICP)

**Goal**: Integrate FedRAMP ICP into incident response procedures.

**Pass/Fail Criteria**:
- ✅ Incident response plan documented (POL-IR-001)
- ✅ Monthly red team exercises test IR procedures
- ✅ FedRAMP-specific notification timelines integrated (POL-IR-001 §8.3, CAT 1-6)

**Information Resources**:
- `policies/incident-response.md` — POL-IR-001
- `redteam/` — monthly IR exercises
- `compliance/drata/` — IR evidence upload

**Machine-Based Validation** (monthly):
- Red team exercises generate IR timeline evidence
- Reports uploaded to Drata evidence library

**Non-Machine-Based Validation** (annually):
- Tabletop exercise with FedRAMP notification procedures

**Status**: ✅ Implemented — IR plan includes FedRAMP ICP (§8.3): US-CERT/CISA reporting (CAT 1-6), FedRAMP PMO notification, Agency ISSO notification, with 1hr/2hr/1wk deadlines per category.

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
- ✅ VPC/VNet egress controls: deny-all by default, explicit allowlists only
- ✅ WAF (Cloud Armor / WAFv2 / Front Door WAF): OWASP CRS, tiered rate limiting, bot blocking
- ✅ Adaptive/intelligent DDoS protection: ML-based L7 detection enabled on all WAF policies
- ✅ Geographic restriction: OFAC-embargoed countries (CU, IR, KP, SY, RU) blocked at WAF layer
- ✅ No public IPs on any service (containers, database, AI services all private)
- ✅ Container ingress restricted to internal + load balancer only
- ✅ Private endpoints for AI services

**Information Resources**:
- `infra/*/modules/vpc/` or `infra/*/modules/vnet/` — Network + egress firewall rules per cloud
- `infra/*/modules/cloud-armor/` or WAF modules — WAF policies per cloud
- `infra/*/modules/load-balancer/` or LB modules — HTTPS LB with TLS termination per cloud
- `fedramp-ssp.md` §8.4 (Network Architecture)

**Machine-Based Validation** (weekly):
- KSI evidence script: query network firewall/security group/NSG rules, WAF policies, LB configs per cloud
- Verify no public IPs exist on any compute resource
- Verify egress controls match IaC

**Status**: ✅ Implemented.

### 3.2 Minimizing Attack Surface

**Goal**: Minimal attack surface with lateral movement minimized.

**Pass/Fail Criteria**:
- ✅ Serverless/managed containers only (Cloud Run / ECS Fargate / Container Apps) — no VMs to patch
- ✅ Minimal container images (distroless/alpine base)
- ✅ No SSH, no direct database access from internet
- ✅ Three-environment isolation (blast radius containment + data-plane compartmentalization)

**Machine-Based Validation** (weekly):
- Container image scan (Trivy) — no unnecessary packages
- IaC drift detection — no new resources outside boundary

**Status**: ✅ Implemented.

### 3.3 Using Logical Networking

**Goal**: Logical networking enforces traffic flow controls.

**Pass/Fail Criteria**:
- ✅ VPC with private subnets
- ✅ Database via private network (private IP only)
- ✅ AI services via private endpoints
- ✅ Cross-environment access via narrow IAM grants (not network peering)

**Status**: ✅ Implemented.

### 3.4 Optimizing for Availability

**Goal**: Resources optimized for high availability and rapid recovery.

**Pass/Fail Criteria**:
- ✅ Container services: auto-scaling, multi-zone, zero-downtime deploys
- ✅ Database: automated backups, PITR enabled
- ✅ Object storage: versioning, soft-delete, WORM retention (production), zero auto-delete lifecycle rules
- ✅ Load balancer: health checks, automatic failover

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
<!-- MULTI-CLOUD: Original also noted AWS/Azure MFA delegated to customer IdP. -->

**Information Resources**:
- `backend/cmd/server/connect_interceptors.go` — MFA enforcement in auth interceptor
- `infra/gcp/modules/identity-platform/` — TOTP MFA enabled on all GCP tenants
- `fedramp-ssp.md` §7.2 (Authentication Requirements)

**Machine-Based Validation** (weekly):
- Query Identity Platform to verify MFA enabled on all tenants
<!-- MULTI-CLOUD: Original also included AWS/Azure SAML-only auth verification. -->
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
- ✅ Cloud IAM: least-privilege roles for terraform/deploy identities (no Owner/Editor/Contributor)
- ✅ WIF/OIDC: keyless CI/CD auth (no static keys — org policy enforced)
- ✅ Database roles: archon_app_ro, archon_admin_rw, archon_ops_rw (enforced via migration; default PUBLIC revoked)
- ✅ Migration-user isolation: Atlas job uses IAM-based DB auth with `SET ROLE archon_migrator` (no static credentials). `postgres` superuser password in secrets management as break-glass only, accessible to security admins (not mounted on any service or job by default).

**Machine-Based Validation** (weekly):
- Query IAM policy bindings on all cloud environments
- Verify no static keys exist (org/account policy audit)
- Verify RLS policies active on all tables
- Verify PUBLIC privileges revoked on all tables (query `information_schema.role_table_grants`)
- Verify DB role grants match expected (archon-app → archon_app_ro, archon-admin → archon_admin_rw, archon-ops → archon_ops_rw)

**Status**: ✅ Implemented.

### 4.4 Securing Non-User Authentication

**Goal**: Appropriately secure auth for non-user accounts and services.

**Pass/Fail Criteria**:
- ✅ WIF/OIDC for CI/CD (no static keys)
- ✅ Service-to-service: cloud IAM + OIDC tokens
- ✅ Task queue: OIDC-authenticated task dispatch
- ✅ Cloud-native policies block static key creation

**Status**: ✅ Implemented.

---

## 5. Incident Response

### 5.1 Incident Documentation and Reporting

**Goal**: Document, report, and analyze security incidents.

**Pass/Fail Criteria**:
- ✅ Incident response plan (POL-IR-001)
- ✅ Monthly red team exercises (99 attacks, 6 suites)
- ✅ MITRE ATT&CK technique mapping on all attacks
- ✅ Reports auto-uploaded to Drata evidence library

**Information Resources**:
- `policies/incident-response.md`
- `redteam/` — 99 attacks across auth bypass, escalation, exfiltration, leftfield, webapp, manual tools
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
- ✅ Cloud-native logging (Cloud Logging): centralized, immutable, structured JSON
<!-- MULTI-CLOUD: Original also listed CloudWatch (AWS) and Azure Monitor. -->
- ✅ Application audit_events table: user actions with IP, user-agent, metadata, session_id, mfa_method
- ✅ Cloud audit logs: admin activity + data access (cloud API calls)
- ✅ Log sink to GCS for long-term retention
- ⬜ Formal SIEM tool integration (Cloud Logging serves as SIEM equivalent)

**Information Resources**:
- `infra/modules/audit-logs/` — log sinks, retention policies
- `backend/` — structured JSON logging via Go `slog`
- `fedramp-ssp.md` §8.4 (Cloud Logging → optional SIEM export)

**Machine-Based Validation** (weekly):
- Verify cloud-native logging is enabled on all environments
- Verify log sink/export configurations match IaC
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
- ✅ 100% of infrastructure managed by Terraform/Terragrunt (per-cloud modules)
- ✅ No manual cloud console changes
- ✅ Configuration baselines version-controlled in Git

**Status**: ✅ Implemented.

### 7.3 Automating Secret Management

**Goal**: Automated management and rotation of secrets.

**Pass/Fail Criteria**:
- ✅ Cloud KMS: CMEK with automatic rotation (HSM-backed)
<!-- MULTI-CLOUD: Original also listed AWS KMS and Key Vault. -->
- ✅ Secrets management: database credentials with rotation schedule
- ✅ Secret access alerting: monitoring fires on any secret access
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
- ✅ Docker image digests (SHA-256) in container registry (Artifact Registry)
<!-- MULTI-CLOUD: Original also listed ECR (AWS) and ACR (Azure). -->
- ✅ Cosign keyless image signing (Sigstore OIDC) — every image cryptographically signed in CI
- ✅ Cosign signature verification required before every container deploy
- ✅ Digest-pinned deploys (`image@sha256:...`) — no mutable tag references
- ✅ Container registry immutable tags enabled (prevents tag overwrites)
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
<!-- MULTI-CLOUD: Original listed 4 vendors including AWS and Azure as Critical. -->
- ✅ Risk register (12 entries, inherent/residual scoring)
- ✅ Dependabot on all 9 repos
- ✅ SBOM per build
- ✅ Cosign keyless image signing + verification in CI/CD pipeline
- ✅ Trivy hard fail gate (CRITICAL/HIGH block deploy)
- ✅ Container registry immutable tags + CMEK encryption

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
- ✅ Automated CP-4 tests monthly (database backup/PITR, storage versioning, container health, KMS keys, container registry)
- ✅ RTO/RPO defined per component
- ✅ Test reports uploaded to Drata

**Status**: ✅ Implemented.

---

## Summary Status

| Theme | KSIs | Status |
|-------|------|--------|
| Authorization by FedRAMP | 10 | ✅ 9/10 implemented (CCM pending agency sponsor) |
| Change Management | 1 | ✅ Complete |
| Cloud Native Architecture | 8 | ✅ Complete |
| Cybersecurity Education | 2 | ✅ Complete (training tracker + persistent testing evidence in EDU-LA-001) |
| Identity and Access Management | 7 | ✅ Complete |
| Incident Response | 4 | ✅ Complete |
| Monitoring, Logging, Auditing | 5 | ✅ Complete |
| Policy and Inventory | 3 | ✅ Complete |
| Recovery Planning | 2 | ✅ Complete |
| Service Configuration | 8 | ✅ Complete |
| Supply Chain Risk | 3 | ✅ Complete |
| High Enhancement Controls | 85+ | ✅ Documented in SSP Appendix A-2 (High-readiness) |

**Remaining TODOs**:
1. ~~OSCAL SSP package generation and CI validation~~ — DONE: `oscal/ssp.json` + `oscal-validate.yml` CI
2. ~~FedRAMP security inbox~~ — DONE: using `gcp-security-admins@latentarchon.com`
3. ~~Automated SCN significance classification~~ — DONE: `scn-classify` workflows on 7 repos, now enforced as required CI checks (blocks merge without `scn-acknowledged` label)
4. ~~Customer-facing Secure Configuration Guide~~ — DONE: `customer-secure-configuration-guide.md`
5. ~~Cybersecurity education persistent testing evidence~~ — DONE: `cybersecurity-education-tracker.md` (EDU-LA-001)
6. ~~FedRAMP-specific ICP notification timelines~~ — DONE: integrated into POL-IR-001
7. ~~ISSO appointment letter~~ — DONE: `isso-appointment-letter.md` (ISSO-APPT-001)
8. ~~Session concurrency limiting (AC-10)~~ — DONE: `user_sessions` table + auth interceptor enforcement, `MAX_CONCURRENT_SESSIONS` config
9. ~~Government repo mirror workflow~~ — DONE: `govt-mirror.yml` scheduled daily + on push to main/staging
10. Agency sponsor engagement for CCM quarterly reviews (requires external engagement)
11. High-delta controls documented in SSP Appendix A-2 (85+ controls); ready for 3PAO assessment at FedRAMP High baseline
