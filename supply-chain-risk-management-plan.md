# Supply Chain Risk Management Plan (SCRMP)

> **Document ID**: SCRMP-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md, Appendix H)
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Plan Owner**: Andrew Hendel, CEO

---

## 1. Introduction

### 1.1 Purpose

This Supply Chain Risk Management Plan (SCRMP) establishes the framework for identifying, assessing, mitigating, and monitoring supply chain risks associated with the Latent Archon platform. It addresses risks from third-party services, open-source dependencies, development tools, and infrastructure providers.

### 1.2 Scope

This plan covers all external components within or supporting the authorization boundary:
- Cloud infrastructure provider (GCP)
- Source code management and CI/CD (GitHub)
- Open-source software dependencies (Go modules, NPM packages)
- Container base images
- DNS provider (Cloudflare)
- Compliance tooling (Drata)

---

## 2. Supply Chain Inventory

### 2.1 Third-Party Services

| Vendor | Service | Criticality | FedRAMP Status | Review Frequency |
|--------|---------|------------|----------------|-----------------|
| **Google Cloud Platform** | Infrastructure (Cloud Run, SQL, Storage, Vertex AI, KMS, Identity Platform, Armor, Tasks, Logging, Monitoring) | Critical | FedRAMP High | Quarterly |
| **GitHub** | Source control, CI/CD (Actions), Dependabot | High | SOC 2 Type II | Semi-annual |
| **Cloudflare** | DNS, DNSSEC | Medium | FedRAMP Moderate | Annual |
| **Drata** | Compliance automation | Low | SOC 2 Type II | Annual |

### 2.2 Open-Source Dependencies

| Ecosystem | Count (approx.) | Lock File | Integrity Verification |
|-----------|-----------------|-----------|----------------------|
| **Go modules** | ~40 direct, ~120 transitive | go.sum | SHA-256 checksums via Go module mirror |
| **NPM packages (admin)** | ~30 direct, ~800 transitive | package-lock.json | SHA-512 integrity hashes |
| **NPM packages (app)** | ~25 direct, ~700 transitive | package-lock.json | SHA-512 integrity hashes |
| **Terraform providers** | ~5 | .terraform.lock.hcl | SHA-256 checksums |

### 2.3 Container Base Images

| Image | Source | Pinning Method |
|-------|--------|---------------|
| `gcr.io/distroless/static-debian12` | Google Container Registry | Digest (SHA-256) |
| `node:20-alpine` (build stage only) | Docker Hub | Tag + digest |

---

## 3. Risk Assessment

### 3.1 Risk: Compromised GCP Service

- **Likelihood**: Very Low (FedRAMP High authorized, continuous monitoring)
- **Impact**: Critical
- **Mitigations**: GCP FedRAMP High authorization with continuous monitoring; CMEK encryption ensures GCP cannot access data at rest without Latent Archon's keys; multi-project architecture limits blast radius
- **Residual Risk**: Very Low

### 3.2 Risk: Compromised Open-Source Dependency

- **Likelihood**: Medium (supply chain attacks increasing industry-wide)
- **Impact**: High
- **Mitigations**:
  - Dependabot scans daily for known vulnerabilities
  - govulncheck uses Go vulnerability database (updated hourly)
  - Trivy scans container images for CVEs
  - go.sum cryptographic verification prevents tampered modules
  - Minimal dependency principle reduces attack surface
  - SBOM generation provides full transparency
- **Residual Risk**: Low

### 3.3 Risk: Compromised CI/CD Pipeline

- **Likelihood**: Low
- **Impact**: Critical
- **Mitigations**:
  - Workload Identity Federation (no static credentials)
  - Branch protection requires PR review before merge
  - Gitleaks prevents credential exposure in commits
  - GitHub Actions pinned by SHA (not mutable tags)
  - Least-privilege IAM for CI/CD service accounts
- **Residual Risk**: Low

### 3.4 Risk: Compromised Container Base Image

- **Likelihood**: Low
- **Impact**: High
- **Mitigations**:
  - Distroless images (minimal attack surface — no shell, no package manager)
  - Images pinned by digest (immutable reference)
  - Trivy scanning on every build
  - Multi-stage builds (build dependencies not included in runtime image)
- **Residual Risk**: Low

### 3.5 Risk: Dependency License Violation

- **Likelihood**: Low
- **Impact**: Medium
- **Mitigations**:
  - License compliance verified for all direct dependencies
  - Go module licenses visible via pkg.go.dev
  - No copyleft (GPL) dependencies in application code
  - SBOM includes license information
- **Residual Risk**: Very Low

---

## 4. Supply Chain Controls

### 4.1 Vendor Management

Per the Vendor Risk Management Policy (POL-VR-001):

1. **Pre-Engagement**: Security assessment before adopting any new vendor/service
2. **Contractual**: Data processing terms, SLAs, incident notification requirements
3. **Ongoing Monitoring**: Review per tiered schedule (Critical=quarterly, High=semi-annual, Medium/Low=annual)
4. **Offboarding**: Data deletion verification, access revocation, credential rotation

### 4.2 Dependency Management

1. **Pinning**: All dependencies pinned by cryptographic hash (go.sum, package-lock.json, .terraform.lock.hcl)
2. **Automated Updates**: Dependabot creates PRs for dependency updates weekly
3. **CI Validation**: All dependency updates must pass full CI pipeline (build, test, SAST, container scan)
4. **Minimal Dependencies**: Prefer standard library over third-party; single external dependency for drata-sync (golang.org/x/time)
5. **SBOM**: Generated on every build in CycloneDX + SPDX formats

### 4.3 Build Pipeline Security

1. **Workload Identity Federation**: No static service account keys; short-lived tokens via OIDC
2. **Immutable Artifacts**: Container images stored in Artifact Registry with digest verification
3. **Security Gates**: Build fails if any scanner detects Critical/High findings
4. **Audit Trail**: All CI/CD runs logged in GitHub Actions with full output retention

### 4.4 Infrastructure Supply Chain

1. **Terraform Provider Pinning**: Providers locked by version and hash in .terraform.lock.hcl
2. **State Protection**: Terraform state stored in GCS with versioning and encryption
3. **Plan Review**: All infrastructure changes require human review of `terragrunt plan` output
4. **Drift Detection**: Weekly `terragrunt plan` to detect configuration drift

---

## 5. Monitoring and Response

### 5.1 Continuous Monitoring

| Activity | Tool | Frequency |
|----------|------|-----------|
| Dependency vulnerability scanning | Dependabot | Daily |
| Go vulnerability detection | govulncheck | Per-build |
| Container image scanning | Trivy | Per-build |
| Secret detection | Gitleaks | Per-commit |
| Vendor FedRAMP status check | Manual + FedRAMP Marketplace | Quarterly |
| SBOM generation | CI pipeline | Per-build |

### 5.2 Incident Response

If a supply chain compromise is detected:

1. **Contain**: Pin to last known-good version of affected component
2. **Assess**: Determine if compromised version was deployed to production
3. **Remediate**: Update to patched version or remove affected dependency
4. **Investigate**: Review audit logs for exploitation indicators
5. **Report**: Notify affected customers and FedRAMP PMO per incident response timelines
6. **Prevent**: Add detection rules for the specific attack vector

---

## 6. Plan Maintenance

- **Annual Review**: Full SCRMP review aligned with SSP annual review
- **Change-Triggered Update**: Updated when new vendors are adopted or significant dependency changes occur
- **Training**: Development team trained on supply chain security during onboarding

---

_End of Supply Chain Risk Management Plan_
