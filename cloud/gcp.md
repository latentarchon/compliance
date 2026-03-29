# GCP Cloud Environment Supplement

> **Document ID**: CLOUD-GCP-001
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System**: Latent Archon Document Intelligence Platform (LA-DIP)
> **Parent**: [Multi-Cloud Service Mapping](service-mapping.md)

This supplement documents GCP-specific implementation details for the Latent Archon platform. It should be read alongside the core compliance documents (SSP, security whitepaper, policies) and the multi-cloud service mapping.

---

## 1. GCP Authorization & FedRAMP Inheritance

| Field | Value |
|---|---|
| **CSP** | Google Cloud Platform |
| **FedRAMP Authorization** | High P-ATO |
| **Authorization ID** | FR1805181233 |
| **Shared Responsibility** | GCP provides physical security, hypervisor, network fabric, managed service SLAs. Latent Archon is responsible for application logic, RBAC, RLS, data classification, and customer-facing security controls. |

### Inherited Controls

The following NIST 800-53 control families are fully or partially inherited from GCP's FedRAMP High authorization:

| Control Family | Inheritance | Notes |
|---|---|---|
| PE (Physical & Environmental) | Fully inherited | GCP data center physical security |
| SC-8 (Transmission Confidentiality) | Partially inherited | GCP TLS termination at GFE; application enforces HSTS |
| SC-28 (Protection of Information at Rest) | Partially inherited | GCP provides CMEK infrastructure; Latent Archon configures keys |
| AU-6 (Audit Review) | Partially inherited | Cloud Audit Logs provide raw data; Latent Archon defines alerting |
| CP-7 (Alternate Processing Site) | Partially inherited | GCP multi-region capability; Latent Archon configures failover |

---

## 2. GCP Projects

### Two-Project Architecture

| Project | Environment | Project ID | Project Number | Purpose |
|---|---|---|---|---|
| Admin (staging) | Staging | `latentarchon-admin-staging` | 786733428651 | Admin API, ops, DB, storage, vector search, processing |
| App (staging) | Staging | `latentarchon-app-staging` | 462649318418 | User-facing API, SPA, Identity Platform (user pool) |
| Admin (production) | Production | `latentarchon-admin-prod` | _TBD_ | Same as staging admin |
| App (production) | Production | `latentarchon-app-prod` | _TBD_ | Same as staging app |

Production projects are defined in `org/variables.tf` but not yet created via Terraform.

### Cross-Project IAM

| Grant | Source SA | Target Project | Roles | Purpose |
|---|---|---|---|---|
| DB access | `archon-app@latentarchon-app-*` | Admin project | `cloudsql.client`, `cloudsql.instanceUser` | Read-only database access from app API |
| Cloud Armor sync | `archon-admin@latentarchon-admin-*` | App project | `compute.securityAdmin` | IP allowlist sync across projects |

---

## 3. Authorization Boundary Components

### Cloud Run Services (6 total)

| Service | Project | Mode | Purpose | Scaling |
|---|---|---|---|---|
| `archon-app` | App | `SERVER_MODE=public` | User-facing API (conversation, search, auth) | 0–10 instances |
| `app-spa` | App | nginx | React SPA for end users | 0–5 instances |
| `archon-admin` | Admin | `SERVER_MODE=admin` | Admin API (org, workspace, document, member CRUD) | 0–10 instances |
| `archon-ops` | Admin | `SERVER_MODE=ops` | Background processing (embeddings, DLP, cron) | 1–5 instances |
| `admin-spa` | Admin | nginx | React SPA for administrators | 0–5 instances |
| `clamav` | Admin | ClamAV REST | Internal malware scanning service | 1–2 instances |

### Cloud SQL

| Attribute | Value |
|---|---|
| **Engine** | PostgreSQL 15 |
| **Project** | Admin |
| **Region** | `us-east1` |
| **HA** | Regional (automatic failover) |
| **Encryption** | CMEK via Cloud KMS (HSM-backed, 90-day rotation) |
| **Auth** | IAM authentication only (no static passwords in normal operation) |
| **Backups** | Automated daily, 30-day retention, PITR enabled |
| **Audit flags** | pgAudit (DDL + role + write), connection/disconnection logging, slow query (>1s) |
| **RLS** | FORCE enabled on all data tables |

### Cloud Storage (GCS)

| Bucket | Purpose | Versioning | Retention | Encryption |
|---|---|---|---|---|
| Documents | Uploaded document files | Enabled | 365 days | CMEK |
| Generated | AI-generated images | Enabled | 90 days | CMEK |
| Migration logs | Atlas job audit logs | Enabled | 365 days | CMEK |

### Vertex AI

| Resource | Detail |
|---|---|
| **Embedding model** | `gemini-embedding-2-preview` (3072 native dims, MRL-truncated to 768) |
| **Embedding API region** | `us-central1` |
| **Vector Search index** | `us-east1` (PSC endpoint, private networking) |
| **LLM** | Gemini 2.5 Pro (streaming + non-streaming) |
| **LLM region** | `us-east1` |

### Cloud KMS

| Keyring | Location | Keys | Protection |
|---|---|---|---|
| Regional | `us-east1` | Cloud SQL, GCS, Vertex AI, Artifact Registry, Cloud Logging | HSM (L3), 90-day rotation |
| Multi-region | `us` | BigQuery (audit dataset) | HSM (L3), 90-day rotation |
| App secrets | `us-east1` | Microsoft Graph OAuth token encryption | HSM (L3), 90-day rotation |

### Other Services

| Service | Project | Purpose |
|---|---|---|
| **Identity Platform** | Both | Firebase Auth with per-tenant IDP pools, magic link + TOTP MFA |
| **Cloud Armor** | Both | WAF (OWASP CRS 3.3), DDoS protection, bot blocking, IP allowlisting |
| **Global HTTPS LB** | Both | TLS termination (Certificate Manager), host-based routing |
| **Cloud Tasks** | Admin | Async document processing queue |
| **Document AI** | Admin | OCR and document text extraction |
| **Cloud DLP** | Admin | PII and credential detection in uploaded documents |
| **Cloud Monitoring** | Both | Metrics, alerting, dashboards |
| **Cloud Logging** | Both | Centralized logging with CMEK encryption |
| **Cloud Audit Logs** | Both | GCP resource change tracking + data access logging |
| **Artifact Registry** | Both | Docker image storage with vulnerability scanning |
| **Certificate Manager** | Both | Google-managed TLS certificates with DNS authorization |
| **Cloudflare** | External | Authoritative DNS with DNSSEC |

---

## 4. IAM & Service Accounts

### Service Accounts

| SA Name | Project | Purpose | Key Roles |
|---|---|---|---|
| `archon-app@` | App | App API runtime | `cloudsql.client`, `cloudsql.instanceUser` (cross-project) |
| `archon-admin@` | Admin | Admin API runtime | `cloudsql.client`, `cloudsql.instanceUser`, `storage.objectAdmin`, `compute.securityAdmin` (cross-project) |
| `archon-ops@` | Admin | Ops/background processing | `cloudsql.client`, `aiplatform.user`, `documentai.apiUser`, `dlp.user`, `cloudtasks.enqueuer` |
| `github-actions@` | Both | CI/CD deployment | `run.admin`, `artifactregistry.writer` |
| `gh-ci-terraform@` | Admin | Terraform plan in CI | `viewer`, `storage.objectAdmin` (state bucket) |
| `terraform-sa@` | Both | Infrastructure provisioning | `editor`, `iam.securityAdmin`, `aiplatform.admin` |

### Org Policies (enforced org-wide)

| Policy | Effect |
|---|---|
| `iam.disableServiceAccountKeyCreation` | Blocks SA key creation — WIF is the only CI/CD auth method |
| `iam.disableServiceAccountKeyUpload` | Blocks external key import |
| `iam.allowedPolicyMemberDomains` | Restricts IAM bindings to `latentarchon.com` domain |

### Database Roles

| PostgreSQL Role | Maps To | Permissions |
|---|---|---|
| `archon_app_ro` | `archon-app@*` IAM users | SELECT on reference tables; limited INSERT/UPDATE |
| `archon_admin_rw` | `archon-admin@*` IAM users | ALL on all tables |
| `archon_ops_rw` | `archon-ops@*` IAM users | Scoped CRUD for document processing |
| `archon_migrator` | `archon-admin@*` via `SET ROLE` | DDL privileges (table ownership) |

---

## 5. Network Architecture

### VPC Configuration

| Attribute | Admin Project | App Project |
|---|---|---|
| **CIDR** | `10.0.0.0/20` | `10.1.0.0/20` |
| **Subnets** | Serverless VPC connector, private services | Serverless VPC connector |
| **Cloud NAT** | Enabled (egress for ClamAV updates) | Disabled (no outbound needed) |
| **Private Google Access** | Enabled | Enabled |
| **PSC** | Vertex AI Vector Search endpoint | — |

### Egress Firewall (deny-by-default)

Allowed FQDNs:

- `*.googleapis.com` — GCP API access
- `*.gcr.io`, `*.pkg.dev` — Container registry
- `graph.microsoft.com` — Microsoft Graph API (conditional)
- `login.microsoftonline.com` — Microsoft Entra ID (conditional)
- `smtp-relay.gmail.com` — Google Workspace SMTP relay
- Cloudflare DNS endpoints

All other egress is blocked.

---

## 6. FIPS 140-2 Cryptographic Modules

| Layer | Module | FIPS Cert | Level |
|---|---|---|---|
| Application crypto | Go BoringCrypto | #4407 | Level 1 |
| Data at rest (KMS) | Cloud KMS HSM | Multiple (see GCP FedRAMP package) | Level 3 |
| Data in transit (TLS termination) | Google Front End (GFE) | Multiple (see GCP FedRAMP package) | Level 1 |
| Database TLS | Cloud SQL Connector | Uses BoringSSL (GCP-managed) | Level 1 |

---

## 7. Logging & Monitoring

### Log Sinks

| Sink | Destination | Retention | Purpose |
|---|---|---|---|
| Admin audit logs | BigQuery (CMEK) | 365 days | GCP resource changes |
| Data access logs | Cloud Logging (CMEK) | 90 days | API data access events |
| Application logs | Cloud Logging (CMEK) | 30 days | Structured application logs |

### Alert Policies

| Alert | Trigger | Severity |
|---|---|---|
| WAF block spike | >100 blocks in 5 min | WARNING |
| 5xx error rate | >5% over 5 min | CRITICAL |
| Cloud SQL auth failure | Any failed connection | WARNING |
| IAM privilege escalation | `SetIamPolicy` on sensitive resources | CRITICAL |
| KMS key lifecycle | Key disable/destroy/version change | CRITICAL |
| Secret access | Any `AccessSecretVersion` call | WARNING |
| postgres break-glass | Access to `db-postgres-password` secret | CRITICAL |

---

## 8. CI/CD Pipeline

| Stage | Tool | Action |
|---|---|---|
| Source | GitHub (`latentarchon/*`) | Push to `staging` branch triggers deploy |
| Auth | Workload Identity Federation | Keyless OIDC token exchange |
| Build | GitHub Actions | `docker build` with distroless base |
| Scan | Trivy + GoSec + govulncheck + Semgrep | Container + SAST + dependency scanning |
| Sign | Cosign | Keyless image signing via Fulcio |
| Push | Artifact Registry | SHA-256 digest pinned |
| Deploy | `gcloud run deploy` | Rolling update with health checks |
| Infra | Terragrunt | `plan` on PR, drift detection on main |

---

## 9. Disaster Recovery

| Scenario | RPO | RTO | Mechanism |
|---|---|---|---|
| Cloud Run instance failure | 0 | <1 min | Auto-healing, multiple instances |
| Cloud SQL instance failure | 0 | <5 min | Regional HA (automatic failover) |
| Region failure | <1 hr | <4 hr | Cross-region Cloud SQL replica + GCS multi-region |
| Data corruption | Variable | <1 hr | Cloud SQL PITR, GCS versioning |

---

## Cross-Reference

- [Multi-Cloud Service Mapping](service-mapping.md) — canonical equivalence table
- [AWS Cloud Environment Supplement](aws.md)
- [Azure Cloud Environment Supplement](azure.md)
- `infra/gcp/` — Terraform/Terragrunt source of truth
