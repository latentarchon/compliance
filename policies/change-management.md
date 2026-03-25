# Latent Archon — Change Management Policy

> **Policy ID**: POL-CM-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Engineering Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: CM-1, CM-2, CM-3, CM-4, CM-5, CM-6, CM-7, CM-8, CM-11

---

## 1. Purpose

This policy establishes requirements for managing changes to the Latent Archon platform, including application code, infrastructure configuration, database schema, and operational procedures. It ensures that all changes are authorized, tested, documented, and reversible.

---

## 2. Scope

This policy applies to all changes affecting:

- Application source code (backend, admin SPA, chat SPA)
- Infrastructure as code (Terragrunt/Terraform modules)
- Database schema and migrations
- CI/CD pipeline configuration
- GCP project settings and IAM
- Third-party dependencies
- Operational runbooks and documentation

---

## 3. Change Categories

| Category | Examples | Approval Required | Lead Time |
|----------|---------|-------------------|-----------|
| **Standard** | Bug fixes, dependency updates, documentation | 1 reviewer | Same day |
| **Normal** | New features, API changes, schema migrations | 2 reviewers | 1–3 days |
| **Significant** | Infrastructure changes, security controls, IAM | CTO + Security Lead | 3–5 days |
| **Emergency** | Security patches, incident remediation | CTO (retroactive review within 24 hrs) | Immediate |

---

## 4. Change Control Process

### 4.1 Request

All changes begin as a GitHub Pull Request (PR) against the relevant repository:

| Repository | Content |
|-----------|---------|
| `backend/` | Go backend services |
| `admin/` | Admin SPA (React/TypeScript) |
| `chat/` | Chat SPA (React/TypeScript) |
| `infra/` | Terragrunt modules and environment configs |
| `org/` | GCP organization Terraform |
| `vpc/` | VPC and networking Terraform |
| `red-infra/` | Red team infrastructure Terraform |
| `redteam/` | Red team attack tooling |
| `marketing/` | Marketing site |

### 4.2 Review

- **Code Review**: All PRs require at least one approving review before merge
- **CI Validation**: All PRs must pass automated checks:
  - **Backend**: `go build`, `go vet`, `go test`
  - **Frontend**: `pnpm typecheck`, `pnpm build`
  - **Infrastructure**: `terragrunt fmt`, `terragrunt validate`, `terragrunt plan` (posted as PR comment)
- **Security Review**: Changes to auth, IAM, RBAC, RLS, or encryption require Security Lead review
- **Impact Analysis**: Infrastructure PRs include Terraform plan output showing exact resource changes

### 4.3 Approval

| Change Category | Required Approvals |
|----------------|-------------------|
| Standard | 1 code owner |
| Normal | 2 reviewers (at least 1 code owner) |
| Significant | CTO + Security Lead |
| Emergency | CTO (post-incident review within 24 hrs) |

### 4.4 Deployment

#### Application Deployments

- **Staging**: Automatic on merge to `main` (CI/CD pipeline)
- **Production**: Requires manual approval via GitHub environment gate (`environment: production`)
- **Rollback**: Previous Cloud Run revision remains available; instant rollback via traffic splitting

#### Infrastructure Deployments

- **Terraform plans**: Posted as PR comments for review — **never auto-applied**
- **Apply**: Manual `terragrunt apply` by authorized personnel only
- **Drift detection**: Runs on every push to `main` to detect out-of-band changes

#### Database Migrations

- **Schema changes**: Written as SQL migration files in `shared-go/postgres/migrations/`
- **Atlas**: Migration integrity verified via `atlas.sum` checksum
- **Forward-only**: Migrations are append-only; rollback requires a new forward migration
- **Testing**: Migrations tested in staging before production application

---

## 5. Baseline Configuration

### 5.1 Infrastructure Baseline

All infrastructure is defined in Terragrunt/Terraform and stored in version control:

- **State**: GCS backend with versioning and state locking
- **Modules**: 14+ reusable modules (vpc, cloud-sql, cloud-run, load-balancer, cloud-armor, service-accounts, firebase, gcs, kms, audit-logs, cloud-tasks, vertex-ai, document-ai, artifact-registry)
- **Environments**: Separate staging and production configurations
- **Projects**: Two-project architecture (admin + chat) with per-project configs

### 5.2 Container Baseline

- **Base image**: `gcr.io/distroless/base-debian12` (no shell, no package manager; includes glibc for BoringSSL)
- **Build**: Multi-stage Docker builds with FIPS 140-2 Go binary (`GOEXPERIMENT=boringcrypto`, `CGO_ENABLED=1`)
- **Security**: Debug symbols stripped (`-ldflags="-w -s"`), filesystem paths trimmed (`-trimpath`)
- **SPA**: `nginxinc/nginx-unprivileged:1.27-alpine` for frontend containers

### 5.3 Configuration Management

- All runtime configuration via environment variables (no config files in containers)
- Startup-time validation prevents misconfigured deployments from serving traffic
- Domain cross-validation ensures environment/domain consistency

---

## 6. Dependency Management

### 6.1 Automated Scanning

- **Dependabot**: Configured on all repositories for automated dependency update PRs
- **Frequency**: Weekly scans for all ecosystems (Go modules, npm packages, GitHub Actions, Terraform providers)

### 6.2 Dependency Update Process

- Dependabot PRs are treated as Standard changes (1 reviewer)
- Security-flagged updates (CVEs) are treated as Emergency changes
- Major version bumps are treated as Normal changes (2 reviewers)
- All dependency updates must pass full CI suite before merge

### 6.3 Component Inventory

- **Go**: `go.mod` / `go.sum` (cryptographic integrity verification)
- **JavaScript**: `package.json` / `pnpm-lock.yaml`
- **Terraform**: `.terraform.lock.hcl` (provider checksums)
- **Containers**: Dockerfile pinned base image tags

---

## 7. Least Functionality

### 7.1 Container Hardening

| Measure | Implementation |
|---------|---------------|
| Distroless base | `gcr.io/distroless/base-debian12` — no shell, no package manager; glibc for BoringSSL |
| FIPS 140-2 binary | `CGO_ENABLED=1`, `GOEXPERIMENT=boringcrypto` — BoringSSL (cert #4407) |
| Stripped binary | `-ldflags="-w -s"`, no debug symbols |
| Trimmed paths | `-trimpath`, no local filesystem paths |
| No secrets | All configuration via environment variables |

### 7.2 Browser Security

SPA responses include `Permissions-Policy: camera=(), microphone=(), geolocation=()` disabling unnecessary browser APIs.

### 7.3 Network Restrictions

- All Cloud Run services: private VPC connector, no public IP
- Cloud SQL: private IP only, IAM authentication
- Vertex AI: Private Service Connect (PSC), no public endpoint
- Org policy `sql.restrictPublicIp` blocks public database IPs

---

## 8. CI/CD Security

### 8.1 Keyless Authentication

- All CI/CD uses Workload Identity Federation (WIF) — zero stored secrets
- Org policy `iam.disableServiceAccountKeyCreation` enforces this
- OIDC providers locked to `latentarchon` GitHub organization

### 8.2 Pipeline Security

| Control | Implementation |
|---------|---------------|
| Branch protection | Required on `main`; no force push |
| Required checks | Build, lint, test must pass |
| Signed commits | Encouraged (not yet enforced) |
| Secret scanning | GitHub secret scanning enabled |
| Auto-merge | Disabled for all repositories |

---

## 9. Emergency Changes

Emergency changes (security incidents, critical bugs affecting availability) follow an expedited process:

1. **Immediate**: CTO approves verbally or via Slack
2. **PR created**: Even for emergency changes, a PR is created (may be merged by the author with CTO approval)
3. **Deploy**: Standard deployment pipeline (no manual deploys to production)
4. **Post-incident review**: Within 24 hours, a formal review of the change is conducted
5. **Documentation**: Emergency change documented in incident report

---

## 10. Rollback Procedures

| Component | Rollback Method | Time to Rollback |
|-----------|----------------|-----------------|
| Cloud Run services | Traffic split to previous revision | < 1 minute |
| Database schema | Forward migration (new migration file) | 5–30 minutes |
| Infrastructure | `terragrunt apply` with previous state | 5–15 minutes |
| DNS/TLS | Certificate Manager update | 5–60 minutes |

---

## 11. Audit Trail

All changes are tracked across multiple systems:

| System | What's Tracked |
|--------|---------------|
| GitHub | PR history, reviews, approvals, merges, branch protection events |
| Cloud Build / GitHub Actions | Build logs, deployment logs |
| Terraform | State history (GCS versioned), plan outputs |
| Cloud Audit Logs | GCP API calls, IAM changes, resource modifications |
| Application Audit Events | Runtime changes (user management, document operations) |

---

## 12. Monitoring and Review

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Dependency scan review | Weekly | Engineering |
| Infrastructure drift detection | On every push to main | CI/CD (automated) |
| Terraform state audit | Monthly | Engineering |
| CI/CD pipeline review | Quarterly | Engineering + Security |
| Change management policy review | Annually | Security Lead |

---

## 13. Enforcement

Violations of this policy include:

- Bypassing PR review requirements
- Direct production deployments outside the CI/CD pipeline
- Applying infrastructure changes without plan review
- Failing to document emergency changes within 24 hours

Violations may result in access revocation and disciplinary action.

---

*Next review date: March 2027*
