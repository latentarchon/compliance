# Azure Cloud Environment Supplement

> **Document ID**: CLOUD-AZR-001
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System**: Latent Archon Document Intelligence Platform (LA-DIP)
> **Parent**: [Multi-Cloud Service Mapping](service-mapping.md)

This supplement documents Azure-specific implementation details for the Latent Archon platform. It should be read alongside the core compliance documents (SSP, security whitepaper, policies) and the multi-cloud service mapping.

---

## 1. Azure Authorization & FedRAMP Inheritance

| Field | Value |
|---|---|
| **CSP** | Microsoft Azure |
| **FedRAMP Authorization** | High P-ATO (Commercial); FedRAMP High JAB P-ATO (Azure Government) |
| **Shared Responsibility** | Azure provides physical security, hypervisor, network fabric, managed service SLAs. Latent Archon is responsible for application logic, RBAC, RLS, data classification, and customer-facing security controls. |

### Inherited Controls

The following NIST 800-53 control families are fully or partially inherited from Azure's FedRAMP authorization:

| Control Family | Inheritance | Notes |
|---|---|---|
| PE (Physical & Environmental) | Fully inherited | Azure data center physical security |
| SC-8 (Transmission Confidentiality) | Partially inherited | Front Door TLS termination; application enforces HSTS |
| SC-28 (Protection of Information at Rest) | Partially inherited | Azure provides Key Vault infrastructure; Latent Archon configures keys |
| AU-6 (Audit Review) | Partially inherited | Activity Log provides raw data; Latent Archon defines alerting |
| CP-7 (Alternate Processing Site) | Partially inherited | Azure paired regions; Latent Archon configures failover |

---

## 2. Azure Subscriptions

### Two-Subscription Architecture

| Subscription | Environment | Alias | Purpose |
|---|---|---|---|
| App (staging) | Staging | `latentarchon-app` | User-facing API, SPA, AI Search, Azure OpenAI |
| Admin (staging) | Staging | `latentarchon-admin` | Admin API, ops, PostgreSQL, Blob Storage, Service Bus, Document Intelligence |
| App (production) | Production | `latentarchon-app` | Same as staging app |
| Admin (production) | Production | `latentarchon-admin` | Same as staging admin |

Production subscriptions are defined in `infra/azure/environments/production/` but not yet provisioned.

---

## 3. Authorization Boundary Components

### Container Apps (6 total)

| App | Subscription | Mode | Purpose | Scaling |
|---|---|---|---|---|
| `archon-app` | App | `SERVER_MODE=public` | User-facing API (conversation, search, auth) | 0–10 replicas |
| `app-spa` | App | nginx | React SPA for end users | 0–5 replicas |
| `archon-admin` | Admin | `SERVER_MODE=admin` | Admin API (org, workspace, document, member CRUD) | 0–10 replicas |
| `archon-ops` | Admin | `SERVER_MODE=ops` | Background processing (embeddings, DLP, cron) | 1–5 replicas |
| `admin-spa` | Admin | nginx | React SPA for administrators | 0–5 replicas |
| `clamav` | Admin | ClamAV REST | Internal malware scanning service | 1–2 replicas |

### PostgreSQL Flexible Server

| Attribute | Value |
|---|---|
| **Engine** | PostgreSQL 15 |
| **Subscription** | Admin |
| **Region** | `eastus` |
| **HA** | Zone-redundant (automatic failover) |
| **Encryption** | CMEK via Key Vault |
| **Auth** | Azure AD authentication (managed identity) |
| **Backups** | Automated daily, 30-day retention, PITR enabled |
| **Audit** | pgAudit extension (DDL + role + write), connection logging, slow query (>1s) |
| **RLS** | FORCE enabled on all data tables |

### Blob Storage

| Container | Purpose | Versioning | Retention | Encryption |
|---|---|---|---|---|
| `documents` | Uploaded document files | Enabled | 365-day lifecycle | CMEK via Key Vault |
| `generated` | AI-generated images | Enabled | 90-day lifecycle | CMEK via Key Vault |
| `migration-logs` | Atlas job audit logs | Enabled | 365-day lifecycle | CMEK via Key Vault |

### Azure AI Search

| Resource | Detail |
|---|---|
| **Index type** | Vector search |
| **Embedding model** | Azure OpenAI `text-embedding-3-large` — 1536 dimensions |
| **Region** | `eastus` |
| **Encryption** | CMEK via Key Vault |
| **Network** | Private endpoint (VNet-integrated) |

### Azure OpenAI

| Resource | Detail |
|---|---|
| **LLM deployment** | GPT-4o |
| **Embedding deployment** | `text-embedding-3-large` (1536 dimensions) |
| **Region** | `eastus` |
| **Access** | Private endpoint, managed identity auth |

### Key Vault

| Vault | Purpose | SKU | Rotation |
|---|---|---|---|
| Admin vault | Database encryption, storage encryption, application secrets | Premium (HSM-backed) | 90-day automatic |
| App vault | Service-to-service secrets | Premium (HSM-backed) | 90-day automatic |

### Other Services

| Service | Subscription | Purpose |
|---|---|---|
| **Azure AD** | Both | Per-tenant SSO/SAML IdP registration (federated identity) |
| **Front Door + WAF** | Both | Global edge with OWASP managed rules, DDoS protection, rate limiting |
| **Service Bus** | Admin | Async document processing queue (+ dead letter queue) |
| **Document Intelligence** | Admin | Document text extraction (OCR) |
| **AI Language** | Admin | PII detection in uploaded documents |
| **Azure Monitor** | Both | Logs, metrics, alerts, workbooks |
| **Activity Log** | Both | Azure resource change tracking and audit trail |
| **Container Registry** | Both | Docker image storage with vulnerability scanning |
| **Cloudflare** | External | Authoritative DNS with DNSSEC |

---

## 4. IAM & Authentication

### Auth Model: SSO/SAML Only

Azure deployments use **SSO/SAML exclusively** via Azure AD federation. There is no self-service registration, no magic links, and no password-based authentication. Each customer tenant's IdP is federated with Azure AD.

| Aspect | Detail |
|---|---|
| **User auth** | SAML 2.0 via customer IdP (Okta, Entra ID, OneLogin, PingFederate) |
| **MFA** | Delegated to customer IdP (not app-enforced) |
| **SCIM** | Built-in SCIM 2.0 server for automated user lifecycle |
| **JIT provisioning** | Enabled — auto-create user on first federated login |

### Managed Identities (least-privilege)

| Identity | Service | Key Permissions |
|---|---|---|
| `archon-app-identity` | App API | PostgreSQL auth (read-only), AI Search reader, Azure OpenAI user |
| `archon-admin-identity` | Admin API | PostgreSQL auth (read-write), Blob Storage (CRUD), Service Bus sender |
| `archon-ops-identity` | Ops service | PostgreSQL auth (ops scope), Blob Storage (CRUD), Service Bus receiver, Document Intelligence, AI Language, Azure OpenAI |
| `github-actions-identity` | CI/CD | Container Registry push, Container Apps deploy |

### Workload Identity Federation

CI/CD uses Azure AD workload identity federation — no static credentials stored in GitHub.

| Attribute | Value |
|---|---|
| **Issuer** | `https://token.actions.githubusercontent.com` |
| **Subject** | `repo:latentarchon/*:ref:refs/heads/staging` |
| **Audience** | `api://AzureADTokenExchange` |

### Database Roles

Same PostgreSQL role model as GCP/AWS — roles are cloud-agnostic:

| PostgreSQL Role | Maps To | Permissions |
|---|---|---|
| `archon_app_ro` | App managed identity (Azure AD auth) | SELECT on reference tables; limited INSERT/UPDATE |
| `archon_admin_rw` | Admin managed identity (Azure AD auth) | ALL on all tables |
| `archon_ops_rw` | Ops managed identity (Azure AD auth) | Scoped CRUD for document processing |
| `archon_migrator` | Admin identity via `SET ROLE` | DDL privileges (table ownership) |

---

## 5. Network Architecture

### VNet Configuration

| Attribute | Admin Subscription | App Subscription |
|---|---|---|
| **CIDR** | `10.20.0.0/16` | `10.21.0.0/16` |
| **AZs** | 3 (`eastus` zones 1/2/3) | 3 (`eastus` zones 1/2/3) |
| **Subnets** | Container Apps, database (delegated), private endpoints | Container Apps, private endpoints |
| **NAT Gateway** | Enabled | Enabled |
| **Private Endpoints** | PostgreSQL, Blob Storage, Service Bus, Key Vault, Document Intelligence, AI Language | AI Search, Azure OpenAI, Key Vault |
| **NSG Flow Logs** | Enabled → Storage Account | Enabled → Storage Account |

### Network Security Groups

| NSG | Inbound | Outbound |
|---|---|---|
| Container Apps | Front Door service tag (443) | Private endpoints, NAT |
| PostgreSQL (delegated) | Container Apps subnet (5432) | — |

---

## 6. FIPS 140-2 Cryptographic Modules

| Layer | Module | FIPS Cert | Level |
|---|---|---|---|
| Application crypto | Go BoringCrypto | #4407 | Level 1 |
| Data at rest (Key Vault) | Azure Key Vault HSM | Multiple (see Azure FedRAMP package) | Level 3 |
| Data in transit (TLS termination) | Azure Front Door | Multiple (see Azure FedRAMP package) | Level 1 |
| Database TLS | Azure PostgreSQL TLS | Azure-managed certificates | Level 1 |

---

## 7. Logging & Monitoring

### Log Destinations

| Log Type | Destination | Retention | Purpose |
|---|---|---|---|
| Activity Log | Log Analytics Workspace (CMEK) | 365 days | Azure resource change auditing |
| Application logs | Log Analytics Workspace (CMEK) | 30 days | Structured application logs |
| NSG Flow Logs | Storage Account (CMEK) | 90 days | Network traffic analysis |
| Front Door access logs | Log Analytics Workspace (CMEK) | 90 days | HTTP request logging |

### Azure Monitor Alerts

| Alert | Trigger | Severity |
|---|---|---|
| WAF block spike | >100 blocks in 5 min | WARNING |
| 5xx error rate | >5% over 5 min | CRITICAL |
| PostgreSQL auth failure | Any failed connection | WARNING |
| Privileged operation | Role assignment changes on sensitive resources | CRITICAL |
| Key Vault lifecycle | Key disable/purge/rotation failure | CRITICAL |
| Container App failure | Replica restart or crash loop | WARNING |

---

## 8. CI/CD Pipeline

| Stage | Tool | Action |
|---|---|---|
| Source | GitHub (`latentarchon/*`) | Push to `staging` branch triggers deploy |
| Auth | Workload Identity Federation | Keyless Azure AD token exchange |
| Build | GitHub Actions | `docker build` with distroless base |
| Scan | Trivy + GoSec + govulncheck + Semgrep | Container + SAST + dependency scanning |
| Sign | Cosign | Keyless image signing via Fulcio |
| Push | Container Registry | SHA-256 digest pinned |
| Deploy | Container Apps revision update | Rolling update with health checks |
| Infra | Terragrunt | `plan` on PR, drift detection on main |

---

## 9. Disaster Recovery

| Scenario | RPO | RTO | Mechanism |
|---|---|---|---|
| Container App replica failure | 0 | <1 min | Auto-restart, multiple replicas |
| PostgreSQL zone failure | 0 | <5 min | Zone-redundant HA (automatic failover) |
| AZ failure | 0 | <5 min | Zone-redundant Container Apps + PostgreSQL |
| Region failure | <1 hr | <4 hr | Geo-redundant PostgreSQL replica + GRS Blob Storage |
| Data corruption | Variable | <1 hr | PostgreSQL PITR, Blob versioning |

---

## 10. Deployment Prerequisites

Before deploying the Azure environment:

1. **Azure AD tenant** with two subscriptions (app + admin) under a management group
2. **Storage accounts** for Terraform state (one per subscription)
3. **Azure AD app registration** for GitHub Actions workload identity federation
4. **Front Door** custom domain with DNS validation via Cloudflare
5. **Azure OpenAI** access approved (GPT-4o + text-embedding-3-large)
6. **Key Vault** Premium SKU for HSM-backed keys

---

## Cross-Reference

- [Multi-Cloud Service Mapping](service-mapping.md) — canonical equivalence table
- [GCP Cloud Environment Supplement](gcp.md)
- [AWS Cloud Environment Supplement](aws.md)
- `infra/azure/` — Terraform/Terragrunt source of truth
