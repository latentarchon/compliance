# Multi-Cloud Service Mapping

> **Document ID**: CLOUD-MAP-001
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System**: Latent Archon Document Intelligence Platform (LA-DIP)

This document provides the canonical service equivalence mapping across all three supported cloud providers. Each deployment uses functionally equivalent services that meet the same NIST 800-53 Moderate control requirements.

---

## Architecture Pattern

All three clouds follow an identical **three-account/project/subscription** split for blast-radius isolation and data-plane compartmentalization:

| Logical Tier | GCP | AWS | Azure | Purpose |
|---|---|---|---|---|
| **App environment** | GCP Project (`archon-fed-app-*`) | AWS Account (`archon-fed-app`) | Azure Subscription (`archon-fed-app`) | User-facing API + SPA + identity pool (app users) |
| **Ops environment** | GCP Project (`archon-fed-ops-*`) | AWS Account (`archon-fed-ops`) | Azure Subscription (`archon-fed-ops`) | Data tier: database, storage, KMS, AI/ML, task queue, DLP, ClamAV, ops service |
| **Admin environment** | GCP Project (`archon-fed-admin-*`) | AWS Account (`archon-fed-admin`) | Azure Subscription (`archon-fed-admin`) | Admin API + SPA + identity pool (org admins) |

---

## Service Equivalence Table

### Compute & Networking

| Capability | GCP | AWS | Azure |
|---|---|---|---|
| **Container compute** | Cloud Run (serverless) | ECS Fargate (serverless) | Container Apps (serverless) |
| **Virtual network** | VPC + Private Service Connect | VPC + VPC Endpoints | VNet + Private Endpoints |
| **Load balancer** | Global HTTPS Load Balancer | Application Load Balancer (ALB) | Azure Front Door |
| **WAF / DDoS** | Cloud Armor (OWASP CRS) | WAFv2 (OWASP managed rules) | Front Door WAF (OWASP managed rules) |
| **DNS** | Cloudflare (external) | Route 53 | Cloudflare (external) |
| **TLS certificates** | Certificate Manager (DNS auth) | ACM (DNS validation) | Front Door managed certs |
| **Container registry** | Artifact Registry | ECR | Container Registry |
| **NAT / egress** | Cloud NAT | NAT Gateway | NAT Gateway |

### Data & Storage

| Capability | GCP | AWS | Azure |
|---|---|---|---|
| **Relational database** | Cloud SQL PostgreSQL 15 | RDS PostgreSQL | PostgreSQL Flexible Server |
| **Object storage** | Cloud Storage (GCS) | S3 | Blob Storage |
| **Vector search** | Vertex AI Vector Search | OpenSearch Serverless | Azure AI Search |
| **Task / message queue** | Cloud Tasks | SQS (+ DLQ) | Service Bus |

### AI / ML

| Capability | GCP | AWS | Azure |
|---|---|---|---|
| **LLM (text generation)** | Vertex AI — Gemini 2.5 Pro | Bedrock — Claude 3.5 Sonnet | Azure OpenAI — GPT-4o |
| **Embeddings** | Vertex AI — gemini-embedding-2-preview (768 dims) | Bedrock — Titan Embed Text v2 (1024 dims) | Azure OpenAI — text-embedding-3-large (1536 dims) |
| **Document extraction / OCR** | Document AI | Textract | Document Intelligence |
| **PII / DLP detection** | Cloud DLP | Comprehend (PII) | AI Language (PII) |

### Security & Identity

| Capability | GCP | AWS | Azure |
|---|---|---|---|
| **User authentication** | Identity Platform (Firebase Auth) — magic link + TOTP MFA + SAML SSO | SAML IdP providers (SSO only) — no self-service registration | Azure AD (SSO only) — no self-service registration |
| **Key management** | Cloud KMS (HSM-backed, FIPS 140-2 L3) | AWS KMS (HSM-backed, FIPS 140-2 L3) | Key Vault (HSM-backed, FIPS 140-2 L3) |
| **Secrets management** | Secret Manager | Secrets Manager | Key Vault Secrets |
| **Service identity** | IAM Service Accounts + WIF | IAM Roles + OIDC | Managed Identities + Workload Identity |
| **CI/CD auth** | Workload Identity Federation (keyless OIDC) | GitHub Actions OIDC (keyless) | Workload Identity Federation (keyless) |

### Observability

| Capability | GCP | AWS | Azure |
|---|---|---|---|
| **Logging** | Cloud Logging | CloudWatch Logs | Azure Monitor Logs |
| **Metrics / alerting** | Cloud Monitoring | CloudWatch Alarms | Azure Monitor Alerts |
| **Audit trail** | Cloud Audit Logs | CloudTrail | Activity Log |
| **Dashboards** | Cloud Monitoring Dashboards | CloudWatch Dashboards | Azure Monitor Workbooks |

---

## Auth Model Differences

| Aspect | GCP | AWS | Azure |
|---|---|---|---|
| **Self-service registration** | ✅ Magic link (passwordless) | ❌ SSO/SAML only | ❌ SSO/SAML only |
| **MFA** | TOTP (app-enforced) | Delegated to customer IdP | Delegated to customer IdP |
| **Multi-tenant isolation** | Identity Platform tenants (IDP pools) | IAM SAML providers (per-tenant) | Azure AD tenants (per-tenant) |
| **SCIM provisioning** | ✅ Built-in SCIM 2.0 server | ✅ Built-in SCIM 2.0 server | ✅ Built-in SCIM 2.0 server |

---

## FedRAMP Authorization Status

| Provider | Authorization Level | Authorization ID | Notes |
|---|---|---|---|
| **Google Cloud Platform** | FedRAMP High P-ATO | FR1805181233 | All services in boundary are FedRAMP High authorized |
| **Amazon Web Services** | FedRAMP High P-ATO | — | GovCloud available for highest sensitivity |
| **Microsoft Azure** | FedRAMP High P-ATO | — | Azure Government available for highest sensitivity |
| **Cloudflare** | FedRAMP Moderate | — | DNS only (GCP and Azure deployments) |

---

## FIPS 140-2 Cryptographic Module Validation

| Provider | Data at Rest | Data in Transit | Application Crypto |
|---|---|---|---|
| **GCP** | Cloud KMS HSM (L3) | GFE TLS (L1) | Go BoringCrypto (L1, Cert #4407) |
| **AWS** | AWS KMS HSM (L3) | ELB TLS (L1) | Go BoringCrypto (L1, Cert #4407) |
| **Azure** | Key Vault HSM (L3) | Front Door TLS (L1) | Go BoringCrypto (L1, Cert #4407) |

The application binary is identical across all three clouds — compiled with `GOEXPERIMENT=boringcrypto` for FIPS 140-2 validated cryptographic operations. Only the infrastructure layer differs.

---

## Encryption at Rest — Per-Cloud Detail

| Data Store | GCP | AWS | Azure |
|---|---|---|---|
| **Database** | CMEK via Cloud KMS | CMEK via KMS (RDS encryption) | CMEK via Key Vault (TDE) |
| **Object storage** | CMEK via Cloud KMS (GCS) | SSE-KMS (S3) | CMEK via Key Vault (Blob) |
| **Vector index** | CMEK via Cloud KMS (Vertex AI) | Encryption at rest (OpenSearch) | Encryption at rest (AI Search) |
| **Container images** | CMEK via Cloud KMS (Artifact Registry) | Encryption at rest (ECR) | Encryption at rest (ACR) |
| **Audit logs** | CMEK via Cloud KMS (BigQuery + Cloud Logging) | SSE-KMS (CloudWatch + S3) | CMEK via Key Vault (Monitor + Blob) |
| **Secrets** | Secret Manager (auto-encrypted) | Secrets Manager (KMS-backed) | Key Vault (HSM-backed) |
| **Key rotation** | 90-day automatic | 365-day automatic (configurable) | 90-day automatic |

---

## Domain Naming Convention

| Environment | GCP | AWS | Azure |
|---|---|---|---|
| **Production app** | `app.gcp.latentarchon.com` | `app.aws.latentarchon.com` | `app.azure.latentarchon.com` |
| **Production admin** | `admin.gcp.latentarchon.com` | `admin.aws.latentarchon.com` | `admin.azure.latentarchon.com` |
| **Staging app** | `app.gcp.staging.latentarchon.com` | `app.aws.staging.latentarchon.com` | `app.azure.staging.latentarchon.com` |
| **Staging admin** | `admin.gcp.staging.latentarchon.com` | `admin.aws.staging.latentarchon.com` | `admin.azure.staging.latentarchon.com` |
| **API (all)** | `api.app.gcp.{env}.latentarchon.com` | `api.app.aws.{env}.latentarchon.com` | `api.app.azure.{env}.latentarchon.com` |

Wildcard subdomains (`*.app.{cloud}.{env}.latentarchon.com`) enable per-tenant routing across all clouds.

---

## Infrastructure as Code

| Aspect | GCP | AWS | Azure |
|---|---|---|---|
| **IaC root** | `infra/gcp/` | `infra/aws/` | `infra/azure/` |
| **Modules** | 24 Terraform modules | 14 Terraform modules | 14 Terraform modules |
| **State backend** | GCS bucket | S3 + DynamoDB | Azure Blob Storage |
| **Orchestration** | Terragrunt | Terragrunt | Terragrunt |
| **CI/CD** | `terragrunt-ci.yml` (shared workflow) | `terragrunt-ci.yml` (shared workflow) | `terragrunt-ci.yml` (shared workflow) |

---

## Cross-Reference

For cloud-specific implementation details, see:

- [GCP Cloud Environment Supplement](gcp.md)
- [AWS Cloud Environment Supplement](aws.md)
- [Azure Cloud Environment Supplement](azure.md)
