# Configuration Management Plan (CMP)

> **Document ID**: CMP-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md, Appendix E)
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Plan Owner**: Andrew Hendel, CEO

---

## 1. Introduction

### 1.1 Purpose

This Configuration Management Plan (CMP) establishes the policies, procedures, and tools for managing the configuration of the Latent Archon platform. It ensures that changes are controlled, tracked, tested, and authorized before deployment to production.

### 1.2 Scope

This plan covers all components within the authorization boundary: application code (Go backend, React SPAs), infrastructure-as-code (Terraform/Terragrunt), database schema, container images, GCP resource configurations, and compliance documentation.

---

## 2. Configuration Management Roles

| Role | Responsibilities |
|------|-----------------|
| **Configuration Manager** | CEO — oversees CM process, approves significant changes |
| **Change Advisory Board (CAB)** | Engineering Lead + Security Lead — reviews and approves changes |
| **Developers** | Submit changes via PRs, write tests, update documentation |
| **CI/CD System** | Automates testing, scanning, building, and deployment |

---

## 3. Configuration Items

### 3.1 Configuration Item Inventory

| Category | Items | Repository | Versioning |
|----------|-------|------------|-----------|
| **Application Code** | Go backend (3 services), React SPAs (2) | backend/, admin/, chat/ repos | Git SHA + semver tags |
| **Infrastructure** | Terraform modules (14), Terragrunt configs | infra/ repo | Git SHA + Terraform state |
| **Database Schema** | Migrations, canonical schema.sql | backend/shared-go/postgres/ | Sequential migration IDs |
| **Protobuf Definitions** | Service and message definitions | backend/shared-go/proto/ | Git SHA |
| **Container Images** | Distroless Go images | Artifact Registry | SHA256 digest |
| **Security Policies** | 13 policy documents | compliance/policies/ | Git SHA + version headers |
| **GCP Resources** | Cloud Run, Cloud SQL, GCS, etc. | Terraform state in GCS | State version history |
| **Dependencies** | Go modules, NPM packages | go.mod/go.sum, package-lock.json | Lock file hashes |

### 3.2 Baseline Configuration

The production baseline is defined by:
1. **Git main branch**: Authoritative source for all code and IaC
2. **Terraform state**: Authoritative record of deployed GCP resources
3. **Cloud SQL schema**: Current schema as defined by applied migrations
4. **Artifact Registry**: Current production container image digests
5. **go.sum / package-lock.json**: Cryptographic hashes of all dependencies

---

## 4. Change Control Process

### 4.1 Change Categories

| Category | Examples | Approval | Testing Required |
|----------|----------|----------|-----------------|
| **Standard** | Bug fixes, dependency updates, documentation | 1 PR reviewer | CI pipeline |
| **Significant** | New features, architecture changes, new services | CAB + Security review | CI + staging deploy |
| **Emergency** | Critical vulnerability patches, incident response | CEO verbal + post-hoc PR | Minimal — deploy then review |
| **Infrastructure** | Terraform changes, GCP resource modifications | CAB + Terragrunt plan review | Plan review + staging apply |

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
3. **Human Review**: At least one CAB member reviews for correctness, security implications, RLS/data isolation impact, and documentation updates
4. **Approval**: Reviewer approves PR. For Significant changes, Security Lead must also approve.
5. **Merge**: PR merged to main branch
6. **Deployment**: CI/CD deploys to staging automatically. Production deployment requires manual promotion.

### 4.3 Infrastructure Change Process

1. **Submit**: Engineer creates PR modifying Terragrunt/Terraform configuration
2. **Plan Review**: `terragrunt plan` output reviewed by CAB for resources being created/modified/destroyed, IAM changes, encryption and network changes
3. **Staging Apply**: Changes applied to staging environment first
4. **Validation**: Functional testing in staging
5. **Production Apply**: Changes applied to production after staging validation
6. **State Verification**: Terraform state verified to match expected configuration

### 4.4 Emergency Change Process

1. CEO authorizes emergency change verbally
2. Fix is developed and deployed to production (bypass staging if necessary)
3. Post-deployment PR is created within 24 hours
4. Post-hoc security review within 48 hours
5. CAB reviews and documents the emergency change

---

## 5. Configuration Monitoring

### 5.1 Drift Detection

| Component | Detection Method | Frequency |
|-----------|-----------------|-----------|
| Infrastructure | `terragrunt plan` (detect drift from state) | Weekly + pre-deploy |
| Dependencies | Dependabot alerts | Continuous |
| Container images | Trivy scan of deployed images | Per-build |
| Database schema | Migration version check | Per-deploy |
| Cloud Armor rules | Terraform state comparison | Weekly |

### 5.2 Unauthorized Change Detection

- **Git branch protection**: Direct pushes to main blocked; all changes require PR
- **Terraform state locking**: Prevents concurrent modifications
- **Audit logging**: All GCP resource changes logged in Cloud Audit Logs
- **Gitleaks**: Detects unauthorized secrets in repository history
- **Cloud Monitoring**: Alerts on unexpected resource creation or IAM changes

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

---

## 7. Plan Maintenance

- **Annual Review**: Full CMP review aligned with SSP annual review
- **Change-Triggered Update**: CMP updated when new tools, repositories, or processes are adopted
- **Training**: All developers trained on CM process during onboarding and when process changes occur

---

_End of Configuration Management Plan_
