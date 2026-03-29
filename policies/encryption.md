# Latent Archon — Encryption Policy

> **Policy ID**: POL-EN-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Engineering Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: SC-8, SC-12, SC-13, SC-28

---

## 1. Purpose

This policy establishes requirements for cryptographic protection of data at rest, in transit, and in use across the Latent Archon platform. All customer data — including documents, messages, embeddings, and metadata — must be encrypted using approved algorithms and key management practices.

---

## 2. Scope

This policy applies to all data processed, stored, or transmitted by Latent Archon systems, including:

- Customer documents and messages stored in Cloud SQL and GCS
- Vector embeddings in Vertex AI Vector Search
- Data in transit between all system components
- Secrets and credentials
- Backups and archived data
- CI/CD artifacts and container images

---

## 3. Cryptographic Standards

### 3.1 Approved Algorithms

| Use Case | Algorithm | Key Size | Standard |
|----------|-----------|----------|----------|
| Data at rest (storage) | AES-256-GCM | 256-bit | FIPS 197 |
| Data in transit (TLS) | TLS 1.2+ with AEAD ciphers | 256-bit | FIPS 140-2, RFC 8446 |
| Application binary crypto | BoringSSL (BoringCrypto module) | N/A | FIPS 140-2 (cert #4407) |
| Key wrapping (KMS) | AES-256-KW | 256-bit | NIST SP 800-38F |
| Hashing (integrity) | SHA-256 | 256-bit | FIPS 180-4 |
| HMAC (invite tokens) | HMAC-SHA256 | 256-bit | FIPS 198-1 |
| TOTP (MFA) | HMAC-SHA1 (per RFC 6238) | 160-bit | RFC 6238 |

### 3.2 Prohibited Algorithms

The following are explicitly prohibited:

- DES, 3DES, RC4, MD5 (for any purpose)
- RSA keys < 2048 bits
- TLS 1.0, TLS 1.1, SSL 3.0
- Custom or proprietary encryption algorithms
- ECB mode for any block cipher

---

## 4. Data at Rest Encryption

### 4.1 Storage Encryption

| Service | Encryption | Key Type | Rotation |
|---------|-----------|----------|----------|
| **Cloud SQL (PostgreSQL)** | AES-256 | CMEK via Cloud KMS | Automatic, 365-day schedule |
| **Cloud Storage (GCS)** | AES-256 | CMEK via Cloud KMS | Automatic, 365-day schedule |
| **Vertex AI Vector Search** | AES-256 | Google-managed | Google-managed rotation |
| **Artifact Registry** | AES-256 | Google-managed | Google-managed rotation |
| **Cloud Logging** | AES-256 | Google-managed | Google-managed rotation |
| **Terraform State (GCS)** | AES-256 | Google-managed | Google-managed rotation |

### 4.2 Customer-Managed Encryption Keys (CMEK)

- Cloud KMS keys are provisioned via Terraform (`infra/modules/kms/`)
- Separate keys per data class (database vs. object storage)
- Per-tenant CMEK anchor: `organizations.kms_key_name` column stores the KMS key resource name for each tenant, enabling future per-tenant encryption key isolation
- Key access restricted to service accounts that require encryption/decryption
- KMS audit logging enabled for all key operations
- Key destruction requires manual approval with 24-hour scheduled destruction delay

---

## 5. Data in Transit Encryption

### 5.1 External Traffic

| Path | Protocol | Certificate |
|------|----------|-------------|
| Client → Load Balancer | TLS 1.2+ | Google-managed certificate via Certificate Manager |
| All HTTPS endpoints | TLS 1.2+ | HSTS enforced (2-year max-age, includeSubDomains, preload) |

### 5.2 Internal Traffic

| Path | Protocol | Notes |
|------|----------|-------|
| Load Balancer → Cloud Run | HTTPS (TLS) | Google-managed internal TLS |
| Cloud Run → Cloud SQL | TLS via Cloud SQL Proxy | IAM-authenticated, private IP |
| Cloud Run → GCS | HTTPS (TLS) | Google internal encryption |
| Cloud Run → Vertex AI | gRPC + TLS via PSC | Private Service Connect (no public endpoint) |
| Cloud Run → Cloud Tasks | HTTPS (TLS) | Google internal encryption |
| Cloud Run → Document AI | HTTPS (TLS) | Google internal encryption |
| Cloud Run → Identity Platform | HTTPS (TLS) | Google internal encryption |

### 5.3 Certificate Management

- TLS certificates are managed by Google Certificate Manager (auto-provisioned, auto-renewed)
- No manual certificate management required
- Certificate transparency logging enabled by default

---

## 6. Application-Level Cryptography

### 6.1 FIPS 140-2 Compliance

All Go backend binaries are compiled with:

```
CGO_ENABLED=1
GOEXPERIMENT=boringcrypto
```

This links the BoringSSL FIPS 140-2 validated module (Certificate #4407) for all cryptographic operations in the application, including TLS, hashing, and HMAC.

### 6.2 Secrets Management

| Secret Type | Storage | Access |
|-------------|---------|--------|
| Database credentials | Cloud SQL IAM authentication (no passwords) | Per-service-account IAM grants |
| API keys (Firebase, etc.) | GitHub Actions secrets + Cloud Run env vars | WIF-authenticated deployment only |
| HMAC signing keys | Environment variables (injected at deploy) | Per-service, never in source code |
| SCIM bearer tokens | SHA-256 hashed in database | Only hash stored, token shown once on creation |
| TOTP secrets | Encrypted in Identity Platform | Per-user, managed by Identity Platform |

### 6.3 Secret Handling Rules

- **Never** store secrets in source code, container images, or Terraform state
- All secrets injected via environment variables at deployment time
- Service account keys are **prohibited** — org policy `iam.disableServiceAccountKeyCreation` enforces this
- Workload Identity Federation provides keyless authentication from CI/CD to GCP
- Gitleaks runs in CI to detect accidental secret commits

---

## 7. Key Management Lifecycle

| Phase | Process |
|-------|---------|
| **Generation** | Keys generated within Cloud KMS (HSM-backed, FIPS 140-2 Level 3) |
| **Distribution** | No key distribution — KMS performs encryption/decryption server-side |
| **Storage** | Keys never leave KMS; key material is non-exportable |
| **Rotation** | Automatic rotation on 365-day schedule; new key version created, old versions remain for decryption |
| **Revocation** | Key version disabled in KMS; re-encryption with new key required |
| **Destruction** | Scheduled destruction with 24-hour delay; requires manual approval |
| **Audit** | All KMS operations logged in Cloud Audit Logs |

---

## 8. Backup Encryption

- Cloud SQL automated backups inherit CMEK encryption from the database instance
- Point-in-time recovery (PITR) logs are encrypted with the same CMEK key
- GCS object versions are encrypted with the bucket's CMEK key
- Terraform state files in GCS are encrypted at rest (Google-managed keys)

---

## 9. Monitoring and Compliance

| Activity | Frequency | Owner |
|----------|-----------|-------|
| KMS key usage audit | Monthly | Engineering |
| TLS configuration scan | Quarterly | Engineering |
| Certificate expiration monitoring | Continuous (automated) | GCP Certificate Manager |
| Secret scanning (Gitleaks) | On every commit (CI) | Engineering |
| FIPS compliance verification | On each build (BoringCrypto) | CI/CD |
| Encryption policy review | Annual | Security Lead |

---

## 10. Enforcement

- Unencrypted data storage or transmission is a critical policy violation
- Use of prohibited cryptographic algorithms triggers immediate remediation
- Secrets found in source code require emergency rotation and incident response
- GCP org policies enforce encryption requirements at the infrastructure level

---

*Next review date: March 2027*
