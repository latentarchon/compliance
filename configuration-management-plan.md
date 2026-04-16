# Configuration Management Plan (CMP)

> **Document ID**: CMP-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md, Appendix E)
> **Version**: 1.1 — DRAFT
> **Date**: March 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Plan Owner**: Andrew Hendel, CEO

---

## 1. Introduction

### 1.1 Purpose

This Configuration Management Plan (CMP) establishes the policies, procedures, and tools for managing the configuration of the Latent Archon platform. It ensures that changes are controlled, tracked, tested, and authorized before deployment to production.

### 1.2 Scope

This plan covers all components within the authorization boundary: application code (Go backend, React SPAs), infrastructure-as-code (Terraform/Terragrunt), database schema, container images, cloud resource configurations (GCP), and compliance documentation.
<!-- MULTI-CLOUD: Original also listed AWS and Azure. -->

---

## 2. Configuration Management Roles

| Role | Personnel | Responsibilities |
|------|-----------|------------------|
| **Configuration Manager** | Andrew Hendel (CEO / ISSO) | Oversees CM process, authors changes, approves significant changes |
| **Automation Workforce** | GitHub Actions / Cloud Build | Independent automated testing, scanning, building, and deployment — acts as independent second actor (see SOD-LA-001) |
| **Customer Admin** | Per-customer agency | Manages users and settings within their organization |

> **Note**: Latent Archon is a founder-led, automation-first organization. The traditional Change Advisory Board (CAB) function is performed by the automation workforce’s independent security evaluation of every change — 6 scanners that cannot be bypassed or overridden. As the team scales (POA-15, POA-16), a formal multi-person CAB will be established.

---

## 3. Configuration Items

### 3.1 Configuration Item Inventory

| Category | Items | Repository | Versioning |
|----------|-------|------------|-----------|
| **Application Code** | Go backend (3 services), React SPAs (2) | backend/, admin/, app/ repos | Git SHA + semver tags |
| **Infrastructure** | Terraform modules (14), Terragrunt configs | infra/ repo | Git SHA + Terraform state |
| **Database Schema** | Migrations, canonical schema.sql | backend/shared-go/postgres/ | Sequential migration IDs |
| **Protobuf Definitions** | Service and message definitions | backend/shared-go/proto/ | Git SHA |
| **Container Images** | Distroless Go images | Container Registry (AR / ECR / ACR) | SHA256 digest |
| **Security Policies** | 13 policy documents | compliance/policies/ | Git SHA + version headers |
| **Cloud Resources** | Container services, database, storage, etc. | Terraform state in cloud storage | State version history |
| **Dependencies** | Go modules, NPM packages | go.mod/go.sum, package-lock.json | Lock file hashes |

### 3.2 Baseline Configuration

The production baseline is defined by:
1. **Git main branch**: Authoritative source for all code and IaC
2. **Terraform state**: Authoritative record of deployed cloud resources
3. **PostgreSQL schema**: Current schema as defined by applied migrations
4. **Container registry**: Current production container image digests
5. **go.sum / package-lock.json**: Cryptographic hashes of all dependencies

---

## 4. Change Control Process

### 4.1 Change Categories

| Category | Examples | Approval | Testing Required |
|----------|----------|----------|-----------------|
| **Standard** | Bug fixes, dependency updates, documentation | CI security gates (independent) | CI pipeline (6 scanners) |
| **Significant** | New features, architecture changes, new services | CI security gates + SCN classifier flags as SIGNIFICANT + CEO documents rationale | CI + staging deploy + SCN acknowledgment |
| **Emergency** | Critical vulnerability patches, incident response | CEO authorizes + post-hoc PR within 24 hours | Minimal — deploy then review |
| **Infrastructure** | Terraform changes, cloud resource modifications | CI plan review + SSP-IaC drift checker | Plan review + staging apply first |

### 4.2 Change Request Process

1. **Submit**: Developer creates PR with description, rationale, and testing performed
2. **Automated Review**: CI pipeline runs:
   - `go build ./...` and `go vet ./...`
   - Unit tests (`go test ./...`)
   - GoSec SAST analysis
   - Semgrep pattern matching
   - govulncheck dependency scanning
   - Gitleaks secret detection
   - Trivy container image scan (on Dockerfile changes)
   - SBOM generation
3. **Automated Review**: SCN classifier categorizes change as ROUTINE or SIGNIFICANT. SIGNIFICANT changes require `scn-acknowledged` label before merge.
4. **Merge**: PR merged to protected branch (only after all CI checks pass — CEO cannot bypass)

   > **Automation-first note**: The automation workforce’s 6 independent security scanners serve as the independent review function. As the team grows (POA-16), mandatory human review will be added alongside the automated gates.
5. **Deployment**: CI/CD deploys to staging automatically. Production deployment requires manual promotion.

### 4.3 Infrastructure Change Process

1. **Submit**: Engineer creates PR modifying Terragrunt/Terraform configuration
2. **Plan Review**: `terragrunt plan` output reviewed by CEO for resources being created/modified/destroyed, IAM changes, encryption and network changes. SSP-IaC drift checker validates claims.
3. **Staging Apply**: Changes applied to staging environment first
4. **Validation**: Functional testing in staging
5. **Production Apply**: Changes applied to production after staging validation
6. **State Verification**: Terraform state verified to match expected configuration

### 4.4 Emergency Change Process

1. CEO authorizes emergency change verbally
2. Fix is developed and deployed to production (bypass staging if necessary)
3. Post-deployment PR is created within 24 hours
4. Post-hoc security review within 48 hours
5. CEO documents the emergency change with rationale and security impact assessment

---

## 5. Configuration Monitoring

### 5.1 Drift Detection

| Component | Detection Method | Frequency |
|-----------|-----------------|-----------|
| Infrastructure | `terragrunt plan` (detect drift from state) | Weekly + pre-deploy |
| Dependencies | Dependabot alerts | Continuous |
| Container images | Trivy scan of deployed images | Per-build |
| Database schema | Migration version check | Per-deploy |
| Cloud Armor origin WAF rules | Terraform state comparison | Weekly |
| Cloudflare Edge WAF / rate-limiting / firewall rules | Terraform state comparison (Cloudflare provider) | Weekly |

### 5.2 Unauthorized Change Detection

- **Git branch protection**: Direct pushes to main blocked; all changes require PR
- **Terraform state locking**: Prevents concurrent modifications
- **Audit logging**: All cloud resource changes logged in cloud audit logs
- **Gitleaks**: Detects unauthorized secrets in repository history
- **Cloud monitoring**: Alerts on unexpected resource creation or IAM changes

---

## 6. Tools

| Tool | Purpose |
|------|---------|
| **Git / GitHub** | Version control, PR workflow, branch protection |
| **GitHub Actions** | CI/CD pipeline automation |
| **Terraform 1.5.7** | Infrastructure definition |
| **Terragrunt 0.99.4** | Infrastructure orchestration |
| **GoSec** | Go static security analysis |
| **Semgrep** | Multi-language pattern matching |
| **govulncheck** | Go vulnerability detection |
| **Trivy** | Container image scanning |
| **Gitleaks** | Secret detection |
| **Dependabot** | Dependency update automation |
| **Drata** | Compliance monitoring and evidence collection |
| **sqlc** | Type-safe SQL code generation |
| **Atlas** | Database schema migration versioning and checksums |
| **pgAudit** | PostgreSQL audit logging (DDL, role changes, writes) |
| **IAM Auth Guardrail** | CI job that rejects password-path regressions in atlas-migrate configs |

---

## 7. Plan Maintenance

- **Annual Review**: Full CMP review aligned with SSP annual review
- **Change-Triggered Update**: CMP updated when new tools, repositories, or processes are adopted
- **Training**: All developers trained on CM process during onboarding and when process changes occur

---

_End of Configuration Management Plan_
