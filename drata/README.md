# Drata Compliance Sync Tool

Go CLI for syncing Latent Archon compliance data to [Drata](https://drata.com) via their [Public API V2](https://developers.drata.com/openapi/reference/v2/overview/).

## What It Does

| Command | Description |
|---------|-------------|
| `status` | Pull compliance readiness report from Drata (frameworks, controls, personnel, evidence, vendors, risks, monitoring tests) |
| `evidence` | Upload 6 compliance documents (4 policies + SSP + whitepaper) to Evidence Library |
| `vendors` | Register GCP and GitHub as vendors with risk classification |
| `risks` | Create 12-entry formal risk register with inherent/residual scoring and treatment plans |
| `assets` | Register 30 infrastructure, software, and data assets |
| `all` | Run all sync commands + generate status report |
| `ci-artifact` | Upload a single CI/CD artifact (SBOM, scan report, red team report) as evidence |

## Setup

### Prerequisites

1. **Drata account** with API access enabled
2. **API key** — [create one here](https://help.drata.com/en/articles/6695964)
3. **Workspace ID** — found in Drata URL: `app.drata.com/workspaces/{ID}/...`
4. **Owner ID** — your Drata user ID (for evidence ownership)

### Environment Variables

```bash
export DRATA_API_KEY="your-api-key"
export DRATA_WORKSPACE_ID="your-workspace-id"
```

### Build

```bash
cd compliance/drata
go build -o drata-sync ./cmd/drata-sync/
```

## Usage

### Full Sync (recommended for first run)

```bash
# Dry run first to see what would happen
./drata-sync --owner-id 1 --compliance-dir ../  --dry-run --verbose all

# Execute
./drata-sync --owner-id 1 --compliance-dir ../ --verbose all
```

### Individual Commands

```bash
# Check current status
./drata-sync status

# Upload policies and compliance docs
./drata-sync --owner-id 1 --compliance-dir ../ evidence

# Register vendors
./drata-sync vendors

# Create risk register
./drata-sync risks

# Register assets
./drata-sync --owner-id 1 assets
```

### CI/CD Evidence Upload

```bash
# Upload an SBOM from CI pipeline
./drata-sync --owner-id 1 \
  --artifact-name "SBOM — backend v1.2.3" \
  --artifact-desc "CycloneDX SBOM generated during build" \
  --artifact-file ./sbom.json \
  --artifact-controls "CM-8,SA-11" \
  ci-artifact

# Upload red team report
./drata-sync --owner-id 1 \
  --artifact-name "Red Team Report — 2026-03" \
  --artifact-file ./reports/redteam-2026-03.md \
  --artifact-controls "CA-2,CA-8" \
  ci-artifact
```

## GitHub Actions

Two workflows are included:

- **`drata-sync.yml`** — Weekly full sync (Monday 6:00 UTC) + manual trigger
- **`ci-evidence.yml`** — Called by other repos to push CI artifacts

### Required Secrets

| Secret | Description |
|--------|-------------|
| `DRATA_API_KEY` | Drata API key |
| `DRATA_WORKSPACE_ID` | Drata workspace ID |
| `DRATA_OWNER_ID` | Drata user ID for evidence ownership |

## What Gets Synced

### Evidence Library (6 documents)
- Access Control Policy (POL-AC-001)
- Change Management Policy (POL-CM-001)
- Incident Response Policy (POL-IR-001)
- Vendor Risk Management Policy (POL-VR-001)
- System Security Plan (SSP-Lite) — NIST 800-53 Moderate
- Security Architecture Whitepaper

### Vendors (2 entries)
- Google Cloud Platform — Critical (FedRAMP High, SOC 2, ISO 27001)
- GitHub — High (SOC 2, source control + CI/CD)

### Risk Register (12 entries)
Each with inherent/residual likelihood × impact scoring and detailed treatment plans:
- Unauthorized Access to Customer Data
- Data Exfiltration via Application Vulnerability
- Supply Chain Compromise
- Cloud Infrastructure Misconfiguration
- Denial of Service
- Insider Threat
- Encryption Key Compromise
- Vendor/Third-Party Breach
- Data Loss / Disaster Recovery Failure
- Regulatory Non-Compliance
- AI/ML Model Misuse or Prompt Injection
- CI/CD Pipeline Compromise

### Assets (30 entries)
- 20 Virtual (GCP infrastructure: Cloud Run, Cloud SQL, GCS, Vertex AI, etc.)
- 6 Software (backend, frontends, IaC, red team, CI/CD)
- 4 Data (documents, messages, embeddings, audit logs)

## Rate Limiting

The client respects Drata's API rate limit (100 requests/minute) with a token bucket rate limiter. All sync commands are idempotent — they skip items that already exist by name.
