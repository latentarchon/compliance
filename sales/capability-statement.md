# Latent Archon — Capability Statement

---

## Company Overview

**Latent Archon, LLC**  
AI-Powered Document Intelligence for Government

**Website**: latentarchon.com  
**Contact**: ajhendel@latentarchon.com  
**DUNS**: *[Pending]*  
**UEI**: *[Pending — SAM.gov registration in progress]*  
**CAGE Code**: *[Assigned upon SAM.gov completion]*

---

## NAICS Codes

| Code | Description |
|------|-------------|
| **518210** | Computing Infrastructure Providers, Data Processing, Web Hosting, and Related Services |
| **511210** | Software Publishers |
| **541511** | Custom Computer Programming Services |
| **541512** | Computer Systems Design Services |
| **541519** | Other Computer Related Services |
| **541715** | Research and Development in the Physical, Engineering, and Life Sciences (AI/ML) |

**Primary NAICS**: 518210  
**PSC Codes**: D302 (IT Systems Development), D306 (IT Systems Analysis), D399 (Other IT Services)

---

## Elevator Pitch

Latent Archon is a multi-tenant document intelligence platform that enables government teams to upload sensitive documents and interact with them through AI-powered conversation — with workspace-level data isolation, CUI-grade security controls, and zero data leakage between organizations. Built entirely on FedRAMP High authorized GCP infrastructure, Latent Archon delivers the capabilities of modern AI to agencies that cannot compromise on security.

---

## Core Capabilities

**AI Document Intelligence**
- Retrieval-Augmented Generation (RAG) conversation over uploaded document collections
- Workspace-scoped vector search with Vertex AI
- Cloud-agnostic text extraction for PDF, DOCX, and office formats (AWS Textract, Azure AI Document Intelligence)
- Gemini-powered streaming responses with source citations
- Inline image generation within conversations via Gemini 2.0 Flash
- Semantic near-duplicate detection (0.97 cosine similarity threshold) and immutable document versioning

**CUI-Grade Security**
- Three-project isolation (separate identity pools for end users and admins, dedicated ops project for data tier)
- PostgreSQL Row-Level Security with fail-closed workspace scoping
- TOTP MFA enforced on all data endpoints with step-up MFA for sensitive operations
- Three least-privilege database roles mapped to GCP IAM service accounts
- ClamAV malware scanning on all uploads with magic-byte validation
- FIPS 140-2 validated cryptography (BoringSSL cert #4407) for all server-side TLS, hashing, and encryption
- Real-time security email notifications to org admins on privilege escalation, failed logins, member changes, and SCIM operations
- Self-service account closure with 90-day data purge and forensic preservation on P1/P2 incidents

**Multi-Tenant Architecture**
- Per-organization Identity Platform tenants with three-layer verification
- SAML 2.0 SSO federation with customer IdPs (Okta, Azure AD, etc.)
- SCIM 2.0 automated user provisioning and deprovisioning
- IdP group-to-role mapping for automated access management

**Data Management & Compliance**
- FOIA-compliant bulk data export with chain-of-custody manifests
- Per-organization usage analytics and cost attribution dashboards
- Per-tenant Cloud Armor IP allowlisting (self-service CIDR configuration synced to WAF)
- Dead letter queue management for failed document processing with admin requeue capability
- Deep readiness probes (`/readyz`) with mode-aware dependency health checks

**Enterprise Operations**
- Infrastructure as Code (Terragrunt/Terraform) with CI/CD via GitHub Actions
- Keyless authentication (Workload Identity Federation — zero stored secrets)
- OpenTelemetry distributed tracing and structured audit logging
- 44-attack internal red team program with MITRE ATT&CK mapping

---

## Differentiators

| Differentiator | Detail |
|---------------|--------|
| **Security-First Architecture** | Built from day one for CUI handling — not a commercial product retrofitted for government |
| **Complete Data Isolation** | PostgreSQL RLS + vector store token restrictions + three-project isolation (auth + data tier) = zero cross-tenant leakage |
| **IL5 Assured Workloads** | GCP IL5 Assured Workloads for data-plane; ~40% of NIST 800-53 High controls inherited |
| **Internal Red Team** | 44 automated attack scenarios across auth bypass, privilege escalation, and data exfiltration |
| **FIPS 140-2 Cryptography** | All server-side TLS, hashing, and encryption use FIPS-validated BoringSSL (NIST cert #4407) via GOEXPERIMENT=boringcrypto |
| **FOIA-Ready Data Export** | Bulk export with chain-of-custody manifests for FOIA compliance and federal record-keeping |
| **Multimodal AI** | Text RAG + inline image generation within conversations via Gemini 2.0 Flash |
| **No Vendor Lock-in** | PostgreSQL (portable), standard containers, Terraform IaC, Connect-RPC (protocol-agnostic) |
| **Rapid Deployment** | Cloud-native serverless architecture — provision a new customer org in minutes, not months |

---

## Technical Stack

| Layer | Technology |
|-------|-----------|
| Compute | Google Cloud Run (serverless containers) |
| Database | Cloud SQL (PostgreSQL 15) with IAM auth |
| Storage | Cloud Storage (AES-256, CMEK available) |
| AI/ML | Vertex AI (Gemini, Vector Search) |
| Identity | Identity Platform (Firebase Auth) with SAML/SCIM |
| Security | Cloud Armor (WAF), Cloud KMS, VPC (private networking) |
| Backend | Go (FIPS 140-2 BoringCrypto, distroless container) |
| Frontend | React + TypeScript (nginx-unprivileged) |
| IaC | Terragrunt / Terraform |
| CI/CD | GitHub Actions with Workload Identity Federation |

---

## Compliance Posture

| Framework | Status |
|-----------|--------|
| **CJIS Security Policy v5.9.5** | All 13 policy areas mapped and implemented; MCA template ready; awaiting first customer engagement for state CSA audit |
| NIST 800-53 High | Full SSP complete; ~40% controls GCP-inherited |
| NIST 800-171 / DFARS 252.204-7012 | Controls mapped and implemented; IL5 Assured Workloads enforced |
| DoD IL5 | GCP IL5 Assured Workloads deployed (staging); production IL5 migration planned |
| FedRAMP High | Infrastructure ready; 3PAO engagement planned Q3 2026 |
| StateRAMP | Planned Q4 2026 (post-FedRAMP) |

---

## Past Performance

*[To be populated as contracts are awarded]*

---

## Socioeconomic Status

*[Update as applicable]*

- [ ] Small Business (SBA size standard for NAICS 518210)
- [ ] 8(a)
- [ ] HUBZone
- [ ] SDVOSB
- [ ] WOSB
- [ ] Economically Disadvantaged WOSB

---

## Contact

**Andrew Hendel**  
Founder & CEO  
ajhendel@latentarchon.com  
latentarchon.com

---

*This capability statement is updated quarterly. Last updated: March 2026.*
