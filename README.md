# Latent Archon — Compliance

Security policies, compliance documentation, and sales collateral for the Latent Archon Document Intelligence Platform.

## Structure

```
policies/              # Internal governance policies (NIST 800-53 aligned)
  access-control.md
  change-management.md
  incident-response.md
  vendor-risk.md
sales/                 # Sales and procurement collateral
  capability-statement.md
  pipeline-targets.md
security-whitepaper.md # Customer-facing security architecture whitepaper
ssp-lite-nist-800-53.md # SSP-Lite NIST 800-53 Moderate control mapping
```

## Audience

| Document | Audience | Purpose |
|----------|----------|---------|
| `policies/*` | Internal / ATO package | Written governance policies for NIST compliance |
| `security-whitepaper.md` | Customers / procurement | Technical security architecture overview |
| `ssp-lite-nist-800-53.md` | ATO / compliance officers | Control-by-control NIST 800-53 mapping |
| `sales/capability-statement.md` | Contracting officers | Company capability one-pager |

## PDF Generation

PDFs are generated from markdown sources and hosted on the marketing site for download.

Install dependencies:

```bash
npm install
npm run build:pdfs
```

## CI/CD Pipeline

On push to `main`, the `publish-pdfs` workflow:
1. Builds PDFs from all markdown sources
2. Uploads them as a GitHub Actions artifact (90-day retention)
3. Sends a `repository_dispatch` to `latentarchon/marketing`, which triggers a rebuild

The marketing site checks out this repo at build time, builds PDFs, and copies them to `public/docs/` before deploying. No PDFs are committed to either repo.

**Required secret**: `MARKETING_DISPATCH_TOKEN` — a fine-grained PAT with `contents: write` on `latentarchon/marketing` (needed for `repository_dispatch`).

## Review Cycle

All policies are reviewed annually. Next review: **March 2027**.
