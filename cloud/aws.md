# AWS Cloud Environment Supplement

> **Document ID**: CLOUD-AWS-001
> **Version**: 1.0 — DRAFT
> **Date**: March 2026
> **System**: Latent Archon Document Intelligence Platform (LA-DIP)
> **Parent**: [Multi-Cloud Service Mapping](service-mapping.md)

This supplement documents AWS-specific implementation details for the Latent Archon platform. It should be read alongside the core compliance documents (SSP, security whitepaper, policies) and the multi-cloud service mapping.

---

## 1. AWS Authorization & FedRAMP Inheritance

| Field | Value |
|---|---|
| **CSP** | Amazon Web Services |
| **FedRAMP Authorization** | High P-ATO (Commercial); FedRAMP High JAB P-ATO (GovCloud) |
| **Shared Responsibility** | AWS provides physical security, hypervisor, network fabric, managed service SLAs. Latent Archon is responsible for application logic, RBAC, RLS, data classification, and customer-facing security controls. |

### Inherited Controls

The following NIST 800-53 control families are fully or partially inherited from AWS's FedRAMP authorization:

| Control Family | Inheritance | Notes |
|---|---|---|
| PE (Physical & Environmental) | Fully inherited | AWS data center physical security |
| SC-8 (Transmission Confidentiality) | Partially inherited | ALB TLS termination; application enforces HSTS |
| SC-28 (Protection of Information at Rest) | Partially inherited | AWS provides KMS infrastructure; Latent Archon configures CMKs |
| AU-6 (Audit Review) | Partially inherited | CloudTrail provides raw data; Latent Archon defines alerting |
| CP-7 (Alternate Processing Site) | Partially inherited | AWS multi-AZ/region capability; Latent Archon configures failover |

---

## 2. AWS Accounts

### Three-Account Architecture

| Account | Environment | Account Alias | Purpose |
|---|---|---|---|
| App (staging) | Staging | `latentarchon-app` | User-facing API, SPA |
| Ops (staging) | Staging | `latentarchon-ops` | Data tier: RDS, S3, KMS, OpenSearch, Bedrock, SQS, Textract, Comprehend, ops service, ClamAV |
| Admin (staging) | Staging | `latentarchon-admin` | Admin API, SPA |
| App (production) | Production | `latentarchon-app` | Same as staging app |
| Ops (production) | Production | `latentarchon-ops` | Same as staging ops |
| Admin (production) | Production | `latentarchon-admin` | Same as staging admin |

Production accounts are defined in `infra/aws/environments/production/` but not yet provisioned.

### Cross-Account IAM

| Grant | Source | Target Account | Roles | Purpose |
|---|---|---|---|---|
| DB access (read-only) | App ECS task role | Ops account | RDS IAM auth + cross-account assume role | Read-only database access from app API |
| DB access (read-write) | Admin ECS task role | Ops account | RDS IAM auth + cross-account assume role | Read-write database access from admin API |

---

## 3. Authorization Boundary Components

### ECS Fargate Services (6 total)

| Service | Account | Mode | Purpose | Scaling |
|---|---|---|---|---|
| `archon-app` | App | `SERVER_MODE=public` | User-facing API (conversation, search, auth) | 1–10 tasks |
| `app-spa` | App | nginx | React SPA for end users | 1–5 tasks |
| `archon-ops` | Ops | `SERVER_MODE=ops` | Background processing (embeddings, DLP, cron) | 1–5 tasks |
| `clamav` | Ops | ClamAV REST | Internal malware scanning service | 1–2 tasks |
| `archon-admin` | Admin | `SERVER_MODE=admin` | Admin API (org, workspace, document, member CRUD) | 1–10 tasks |
| `admin-spa` | Admin | nginx | React SPA for administrators | 1–5 tasks |

### RDS PostgreSQL

| Attribute | Value |
|---|---|
| **Engine** | PostgreSQL 15 |
| **Account** | Ops |
| **Region** | `us-east-1` |
| **HA** | Multi-AZ (automatic failover) |
| **Encryption** | CMEK via AWS KMS |
| **Auth** | IAM authentication (no static passwords in normal operation) |
| **Backups** | Automated daily snapshots, 30-day retention, PITR enabled |
| **Audit** | pgAudit extension (DDL + role + write), connection logging, slow query (>1s) |
| **RLS** | FORCE enabled on all data tables |

### S3 Buckets

| Bucket | Purpose | Versioning | Retention | Encryption |
|---|---|---|---|---|
| Documents | Uploaded document files | Enabled | 365-day lifecycle | SSE-KMS (CMK) |
| Generated | AI-generated images | Enabled | 90-day lifecycle | SSE-KMS (CMK) |
| Migration logs | Atlas job audit logs | Enabled | 365-day lifecycle | SSE-KMS (CMK) |

### OpenSearch Serverless

| Resource | Detail |
|---|---|
| **Collection type** | Vector search |
| **Embedding model** | Amazon Titan Embed Text v2 (via Bedrock) — 1024 dimensions |
| **Region** | `us-east-1` |
| **Encryption** | AWS-managed encryption at rest |
| **Network** | VPC endpoint (private networking) |

### Amazon Bedrock

| Resource | Detail |
|---|---|
| **LLM** | Claude 3.5 Sonnet (Anthropic, via Bedrock) |
| **Embeddings** | Titan Embed Text v2 (1024 dimensions) |
| **Region** | `us-east-1` |
| **Access** | VPC endpoint, IAM-scoped model access |

### AWS KMS

| Key | Purpose | Rotation | Protection |
|---|---|---|---|
| RDS encryption | Database encryption at rest | Annual (automatic) | HSM-backed |
| S3 encryption | Object storage encryption | Annual (automatic) | HSM-backed |
| Application secrets | OAuth token encryption (envelope encryption) | Annual (automatic) | HSM-backed |

### Other Services

| Service | Account | Purpose |
|---|---|---|
| **IAM SAML Providers** | App + Admin | Per-tenant SAML IdP registration (Okta, Entra ID, etc.) |
| **WAFv2** | App + Admin | OWASP managed rules, rate limiting, IP allowlisting |
| **ALB** | App + Admin | TLS termination (ACM certs), host-based routing |
| **SQS** | Ops | Async document processing queue (+ dead letter queue) |
| **Textract** | Ops | Document text extraction (OCR) |
| **Comprehend** | Ops | PII detection in uploaded documents |
| **CloudWatch** | All three | Logs, metrics, alarms, dashboards |
| **CloudTrail** | All three | API call logging and audit trail |
| **ECR** | All three | Docker image storage with vulnerability scanning |
| **Route 53** | App | DNS records + ACM certificate validation |
| **ACM** | App + Admin | TLS certificates for ALB |

---

## 4. IAM & Authentication

### Auth Model: SSO/SAML Only

AWS deployments use **SSO/SAML exclusively**. There is no self-service registration, no magic links, and no password-based authentication. Each customer tenant provides their SAML IdP metadata, which is registered as an `aws_iam_saml_provider`.

| Aspect | Detail |
|---|---|
| **User auth** | SAML 2.0 via customer IdP (Okta, Entra ID, OneLogin, PingFederate) |
| **MFA** | Delegated to customer IdP (not app-enforced) |
| **SCIM** | Built-in SCIM 2.0 server for automated user lifecycle |
| **JIT provisioning** | Enabled — auto-create user on first federated login |

### ECS Task Roles (least-privilege)

| Role | Service | Key Permissions |
|---|---|---|
| `archon-app-task` | App API | RDS IAM auth (read-only, cross-account to ops), OpenSearch access (cross-account to ops), Bedrock invoke (cross-account to ops) |
| `archon-ops-task` | Ops service | RDS IAM auth (ops scope), S3 (CRUD), SQS (receive), Textract, Comprehend, Bedrock, OpenSearch |
| `archon-admin-task` | Admin API | RDS IAM auth (read-write, cross-account to ops), S3 (CRUD, cross-account to ops), SQS (send, cross-account to ops) |
| `github-actions` | CI/CD | ECR push, ECS deploy, task definition update |

### GitHub Actions OIDC

CI/CD uses OIDC federation — no static AWS credentials stored in GitHub.

| Attribute | Value |
|---|---|
| **Provider** | `token.actions.githubusercontent.com` |
| **Audience** | `sts.amazonaws.com` |
| **Condition** | `repo:latentarchon/*:ref:refs/heads/staging` (branch-locked) |

### Database Roles

Same PostgreSQL role model as GCP — roles are cloud-agnostic:

| PostgreSQL Role | Maps To | Permissions |
|---|---|---|
| `archon_app_ro` | App ECS task role (IAM auth) | SELECT on reference tables; limited INSERT/UPDATE |
| `archon_admin_rw` | Admin ECS task role (IAM auth) | ALL on all tables |
| `archon_ops_rw` | Ops ECS task role (IAM auth) | Scoped CRUD for document processing |
| `archon_migrator` | Admin task role via `SET ROLE` | DDL privileges (table ownership) |

---

## 5. Network Architecture

### VPC Configuration

| Attribute | App Account | Ops Account | Admin Account |
|---|---|---|---|
| **CIDR** | `10.11.0.0/16` | `10.12.0.0/16` | `10.10.0.0/16` |
| **AZs** | 3 (`us-east-1a/b/c`) | 3 (`us-east-1a/b/c`) | 3 (`us-east-1a/b/c`) |
| **Subnets** | Public (ALB), private (ECS) | Private (ECS), database (RDS) | Public (ALB), private (ECS) |
| **NAT Gateway** | Enabled (one per AZ) | Enabled (one per AZ for HA) | Enabled (one per AZ) |
| **VPC Endpoints** | ECR, CloudWatch | S3, SQS, KMS, Textract, Comprehend, OpenSearch, Bedrock, ECR, CloudWatch | ECR, CloudWatch |
| **Flow Logs** | Enabled → CloudWatch Logs | Enabled → CloudWatch Logs | Enabled → CloudWatch Logs |

### Security Groups

| Group | Inbound | Outbound |
|---|---|---|
| ALB | 443 (internet) | ECS task SG |
| ECS tasks | ALB SG only | VPC endpoints, NAT, RDS SG |
| RDS | ECS task SG (5432) | — |

---

## 6. FIPS 140-2 Cryptographic Modules

| Layer | Module | FIPS Cert | Level |
|---|---|---|---|
| Application crypto | Go BoringCrypto | #4407 | Level 1 |
| Data at rest (KMS) | AWS CloudHSM | Multiple (see AWS FedRAMP package) | Level 3 |
| Data in transit (TLS termination) | AWS-LC (ALB) | #4631 | Level 1 |
| Database TLS | AWS RDS TLS | AWS-managed certificates | Level 1 |

---

## 7. Logging & Monitoring

### Log Destinations

| Log Type | Destination | Retention | Purpose |
|---|---|---|---|
| CloudTrail | S3 (SSE-KMS) + CloudWatch | 365 days | AWS API call auditing |
| Application logs | CloudWatch Logs | 30 days | Structured application logs |
| VPC Flow Logs | CloudWatch Logs | 90 days | Network traffic analysis |
| ALB access logs | S3 (SSE-KMS) | 90 days | HTTP request logging |

### CloudWatch Alarms

| Alarm | Trigger | Severity |
|---|---|---|
| WAFv2 block spike | >100 blocks in 5 min | WARNING |
| 5xx error rate | >5% over 5 min | CRITICAL |
| RDS auth failure | Any failed connection | WARNING |
| IAM privilege escalation | `PutRolePolicy` / `AttachRolePolicy` on sensitive roles | CRITICAL |
| KMS key lifecycle | Key disable/schedule deletion | CRITICAL |
| ECS task failure | Task exit code ≠ 0 | WARNING |

---

## 8. CI/CD Pipeline

| Stage | Tool | Action |
|---|---|---|
| Source | GitHub (`latentarchon/*`) | Push to `staging` branch triggers deploy |
| Auth | GitHub Actions OIDC | Keyless STS `AssumeRoleWithWebIdentity` |
| Build | GitHub Actions | `docker build` with distroless base |
| Scan | Trivy + GoSec + govulncheck + Semgrep | Container + SAST + dependency scanning |
| Sign | Cosign | Keyless image signing via Fulcio |
| Push | ECR | SHA-256 digest pinned |
| Deploy | ECS rolling update | New task definition revision, health checks |
| Infra | Terragrunt | `plan` on PR, drift detection on main |

---

## 9. Disaster Recovery

| Scenario | RPO | RTO | Mechanism |
|---|---|---|---|
| ECS task failure | 0 | <1 min | ECS service auto-replacement |
| RDS instance failure | 0 | <5 min | Multi-AZ automatic failover |
| AZ failure | 0 | <5 min | Multi-AZ ECS + RDS |
| Region failure | <1 hr | <4 hr | Cross-region RDS read replica + S3 cross-region replication |
| Data corruption | Variable | <1 hr | RDS PITR, S3 versioning |

---

## 10. Deployment Prerequisites

Before deploying the AWS environment:

1. **AWS Organizations** with three accounts (app + ops + admin) in the correct OU
2. **S3 buckets + DynamoDB tables** for Terraform state (one per account)
3. **ACM certificates** for `*.{env}.latentarchon.com` (DNS validated via Route 53)
4. **Route 53 hosted zone** for `latentarchon.com`
5. **Bedrock model access** enabled in AWS Console (Claude 3.5 Sonnet + Titan Embed v2)
6. **GitHub Actions OIDC provider** registered in both accounts

---

## Cross-Reference

- [Multi-Cloud Service Mapping](service-mapping.md) — canonical equivalence table
- [GCP Cloud Environment Supplement](gcp.md)
- [Azure Cloud Environment Supplement](azure.md)
- `infra/aws/` — Terraform/Terragrunt source of truth
