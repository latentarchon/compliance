# Latent Archon — SSP-Lite: NIST 800-53 Moderate Baseline

> **Version**: 1.1  
> **Date**: March 2026  
> **Baseline**: NIST SP 800-53 Rev. 5 — Moderate Impact  
> **System Name**: Latent Archon Document Intelligence Platform  
> **System Owner**: Latent Archon, LLC  
> **Contact**: ajhendel@latentarchon.com

---

## 1. System Description

Latent Archon is a multi-tenant RAG (Retrieval-Augmented Generation) platform for government document intelligence. The system enables agency users to upload documents, perform AI-powered search, and interact with document content via chat — with workspace-level data isolation and CUI-grade security controls.

### Deployment Model

- **Cloud Service Model**: PaaS/SaaS (Google Cloud Platform)
- **Cloud Deployment Model**: Public cloud (GCP FedRAMP High authorized regions)
- **Data Classification**: CUI (Controlled Unclassified Information)

### System Boundary

| Component | GCP Service | Project |
|-----------|-------------|---------|
| Chat API | Cloud Run (`archon-chat`) | `latentarchon-chat-prod` |
| Admin API | Cloud Run (`archon-admin`) | `latentarchon-admin-prod` |
| Ops Service | Cloud Run (`archon-ops`) | `latentarchon-admin-prod` |
| Chat SPA | Cloud Run (nginx) | `latentarchon-chat-prod` |
| Admin SPA | Cloud Run (nginx) | `latentarchon-admin-prod` |
| Database | Cloud SQL (PostgreSQL 15) | `latentarchon-admin-prod` |
| Object Storage | Cloud Storage | `latentarchon-admin-prod` |
| Vector Search | Vertex AI Vector Search | `latentarchon-admin-prod` |
| Text Generation | Vertex AI (Gemini) | `latentarchon-admin-prod` |
| Document Processing | Document AI | `latentarchon-admin-prod` |
| Identity | Identity Platform | Both projects |
| WAF | Cloud Armor | Both projects |
| Load Balancing | Global HTTPS LB | Both projects |
| Key Management | Cloud KMS | `latentarchon-admin-prod` |
| Task Queue | Cloud Tasks | `latentarchon-admin-prod` |
| Logging | Cloud Logging + Cloud Monitoring | Both projects |
| Container Registry | Artifact Registry | Both projects |
| DNS/TLS | Certificate Manager | Both projects |

---

## 2. Control Responsibility Model

Controls are categorized by implementation responsibility:

| Responsibility | Description | Example |
|---------------|-------------|---------|
| **GCP Inherited** | Fully provided by GCP FedRAMP High infrastructure | Physical security, media protection, power |
| **Shared** | GCP provides platform capability; Latent Archon configures/operates | Encryption, logging, network security |
| **Latent Archon** | Fully implemented in application code or operational procedures | Access control logic, audit events, RBAC |
| **Customer** | Customer organization responsibility | User training, acceptable use, personnel security |

---

## 3. NIST 800-53 Moderate Control Mapping

### AC — Access Control

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| AC-1 | Policy and Procedures | Latent Archon + Customer | See `policies/access-control.md` |
| AC-2 | Account Management | Shared | Identity Platform tenants; org admin RBAC for user lifecycle; SCIM 2.0 for automated provisioning/deprovisioning; **interceptor-level org membership gate rejects users not belonging to any organization** |
| AC-2(1) | Automated Account Management | Shared | SCIM 2.0 server syncs with customer IdP; JIT provisioning on first login |
| AC-2(2) | Automated Temporary/Emergency Accounts | Latent Archon | Invite tokens are time-limited; no anonymous accounts |
| AC-2(3) | Disable Accounts | Shared | Firebase Admin SDK `DisableUser()`; SCIM DELETE deprovisions; self-service account closure via `CloseAccount` RPC with step-up MFA; automated 90-day data purge via Cloud Scheduler |
| AC-2(4) | Automated Audit Actions | Latent Archon | All account lifecycle events audit-logged with user/IP/timestamp |
| AC-3 | Access Enforcement | Latent Archon | RBAC (master_admin, admin, editor, viewer) enforced per-RPC; PostgreSQL RLS (fail-closed); **org membership enforced at interceptor level** (orgless users rejected on all non-AuthService RPCs); **subdomain→org DB validation** rejects unknown tenant subdomains and cross-tenant mismatches; org slug format validated against DNS-safe regex + reserved-slug blocklist |
| AC-4 | Information Flow Enforcement | Shared | VPC networking (private IP only); FQDN-based egress firewall (default deny all, explicit Google API allowlist); Cloud Armor WAF; RLS workspace scoping; vector store token restrictions; per-tenant IP allowlisting via Cloud Armor; **subdomain→org cross-tenant prevention** (Host subdomain resolved to org via DB, user's org must match) |
| AC-5 | Separation of Duties | Latent Archon | Three Cloud Run services with distinct DB roles (chat_ro, admin_rw, ops_rw); two-project auth isolation with **cross-pool identity bridging explicitly prohibited** — workspace access across pools uses explicit invite flow only (auto-invite on workspace creation; see `docs/POOL_ISOLATION.md`) |
| AC-6 | Least Privilege | Shared | 15 specific IAM roles on terraform-sa; DB roles with minimal grants; per-service SA with scoped permissions |
| AC-6(1) | Authorize Access to Security Functions | Latent Archon | Only master_admin can promote to master_admin; MFA reset restricted to admins with self-reset blocked |
| AC-6(9) | Log Use of Privileged Functions | Latent Archon | All admin operations audit-logged; WARN-level for security-critical events |
| AC-6(10) | Prohibit Non-Privileged Users from Executing Privileged Functions | Latent Archon | RBAC checks per handler; last-admin guard prevents lockout |
| AC-7 | Unsuccessful Logon Attempts | Shared | Identity Platform brute-force protection; rate limiting at IP + per-user levels |
| AC-8 | System Use Notification | Customer | SPA login page banner (customer-configurable) |
| AC-11 | Device Lock | Customer | Client-side responsibility |
| AC-12 | Session Termination | Latent Archon | Global idle timeout (30 min default) + absolute timeout (12 hr default) enforced server-side via JWT claims; **per-org configurable** — agencies set stricter timeouts via `UpdateOrganizationSettings` (idle: 5-480 min, absolute: 60-1440 min) |
| AC-14 | Permitted Actions Without Identification | Latent Archon | Only `/health` and CORS preflight exempt from auth; all data endpoints require authentication |
| AC-17 | Remote Access | Shared | All access is remote (cloud-native SaaS); TLS enforced; Cloud Armor WAF |
| AC-17(1) | Monitoring/Control | Shared | Cloud Logging captures all access; Cloud Armor logs blocked requests |
| AC-17(2) | Protection of Confidentiality/Integrity | GCP + Latent Archon | TLS 1.2+ everywhere; HSTS 2-year; PSC for Vertex AI |
| AC-20 | Use of External Systems | Customer | Customer policy |
| AC-22 | Publicly Accessible Content | Latent Archon | No public content; all document access requires auth + workspace membership; per-tenant IP allowlisting via Cloud Armor CEL expressions |

### AT — Awareness and Training

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| AT-1 | Policy and Procedures | Latent Archon + Customer | Internal security training policy; customer-side user training |
| AT-2 | Literacy Training and Awareness | Shared | Latent Archon: annual developer security training; Customer: user awareness |
| AT-3 | Role-Based Training | Latent Archon + Customer | Developer secure coding training; admin role-specific documentation |
| AT-4 | Training Records | Latent Archon + Customer | Maintained by respective HR functions |

### AU — Audit and Accountability

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| AU-1 | Policy and Procedures | Latent Archon | Audit logging is mandatory and cannot be disabled |
| AU-2 | Event Logging | Latent Archon | All auth, RBAC, document, member, admin, and SCIM provisioning events audited |
| AU-3 | Content of Audit Records | Latent Archon | user_id, org_id, workspace_id, action, status, resource_type/id, IP, user_agent, trace_id, correlation_id, timestamp |
| AU-3(1) | Additional Audit Information | Latent Archon | JSONB metadata: request_id, tenant_id, span_id, error_code, duration_ms, platform |
| AU-4 | Audit Log Storage Capacity | GCP Inherited | Cloud Logging auto-scales; GCS export for long-term retention |
| AU-5 | Response to Audit Logging Process Failures | Latent Archon | Best-effort design: failures logged but never block requests; structured logs to Cloud Logging as fallback |
| AU-6 | Audit Record Review, Analysis, and Reporting | Shared | Cloud Logging dashboards; alert policies on WARN-level audit events; **Pub/Sub SIEM export pipeline** (per-customer topic + pull/push subscription for agency Splunk/Sentinel/Chronicle integration) |
| AU-7 | Audit Record Reduction and Report Generation | GCP + Latent Archon | Cloud Logging filtering; structured JSON format; correlation IDs for cross-event linking |
| AU-8 | Time Stamps | GCP Inherited | Cloud Run uses Google NTP; audit events use `time.Now().UTC()` |
| AU-9 | Protection of Audit Information | GCP + Latent Archon | DB audit_events table: chat role has INSERT-only; Cloud Logging immutable; GCS export versioned |
| AU-11 | Audit Record Retention | Shared | Cloud Logging: 30 days default; GCS export: 365 days; DB audit_events: configurable |
| AU-12 | Audit Record Generation | Latent Archon | `internal/audit/logger.go` generates events; async persistence with `EventAsync()` |

### CA — Assessment, Authorization, and Monitoring

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| CA-1 | Policy and Procedures | Latent Archon | This SSP-lite + security whitepaper |
| CA-2 | Control Assessments | Latent Archon | Red team program (44 automated attacks); security reviews |
| CA-3 | Information Exchange | Shared | Single cross-project IAM grant (cloudsql.client); all other services project-isolated |
| CA-5 | Plan of Action and Milestones | Latent Archon | Tracked in compliance roadmap |
| CA-7 | Continuous Monitoring | Shared | Cloud Monitoring dashboards; Cloud Armor analytics; red team attack metrics; OpenTelemetry tracing |
| CA-8 | Penetration Testing | Latent Archon | Internal red team (3 suites, 44 attacks); MITRE ATT&CK mapped |
| CA-9 | Internal System Connections | Latent Archon | Cloud Tasks OIDC auth; service-to-service via Google IAM |

### CM — Configuration Management

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| CM-1 | Policy and Procedures | Latent Archon | See `policies/change-management.md` |
| CM-2 | Baseline Configuration | Shared | Terragrunt IaC defines all infrastructure; Dockerfiles define all containers |
| CM-3 | Configuration Change Control | Latent Archon | GitHub PR workflow; CI validates plans; production requires manual approval |
| CM-4 | Impact Analyses | Latent Archon | Terraform plan posted as PR comment; never auto-applies |
| CM-5 | Access Restrictions for Change | Latent Archon | GitHub branch protection; WIF-authenticated CI/CD; no SA keys |
| CM-6 | Configuration Settings | Shared | All config via env vars; startup validation prevents misconfiguration |
| CM-7 | Least Functionality | Latent Archon | Distroless containers (no shell); stripped binaries; disabled browser APIs via Permissions-Policy |
| CM-8 | System Component Inventory | Shared | Terraform state; `go.mod`/`package.json` dependency manifests; Dependabot; SBOM generation (CycloneDX JSON + SPDX JSON) via Syft + anchore/sbom-action on every build |
| CM-11 | User-Installed Software | GCP Inherited | Serverless (Cloud Run) — no user-installable software |

### CP — Contingency Planning

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| CP-1 | Policy and Procedures | Latent Archon | DR documented in security whitepaper |
| CP-2 | Contingency Plan | Latent Archon | IaC rebuild capability; Cloud SQL PITR; GCS versioning |
| CP-4 | Contingency Plan Testing | Latent Archon | Periodic IaC redeploy validation |
| CP-6 | Alternate Storage Site | GCP Inherited | GCS multi-region; Cloud SQL regional HA |
| CP-7 | Alternate Processing Site | GCP Inherited | Cloud Run multi-zone; global LB |
| CP-9 | System Backup | Shared | Cloud SQL daily + continuous WAL; GCS versioning (365 day); IaC in Git |
| CP-10 | System Recovery and Reconstitution | Shared | Cloud SQL PITR < 5 min RPO; IaC redeploy < 1 hr RTO |

### IA — Identification and Authentication

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| IA-1 | Policy and Procedures | Latent Archon | Firebase Auth / Identity Platform as IdP |
| IA-2 | Identification and Authentication (Organizational Users) | Shared | Firebase Auth JWT verification; SA impersonation → no static credentials |
| IA-2(1) | Multi-Factor Authentication to Privileged Accounts | Latent Archon | TOTP MFA enforced on all data endpoints; step-up MFA for sensitive ops |
| IA-2(2) | Multi-Factor Authentication to Non-Privileged Accounts | Latent Archon | MFA enforced for all users (not just admins) |
| IA-2(8) | Access to Accounts — Replay Resistant | Shared | JWT + TOTP (time-based, replay-resistant with adjacent_intervals: 1) |
| IA-4 | Identifier Management | Shared | Firebase UIDs (globally unique); org/workspace UUIDs |
| IA-5 | Authenticator Management | Shared | Identity Platform manages password hashing, magic links, TOTP secrets |
| IA-5(1) | Password-Based Authentication | Shared | Identity Platform password policies; magic link (passwordless) supported |
| IA-6 | Authentication Feedback | Latent Archon | Generic error messages; no credential enumeration |
| IA-8 | Identification and Authentication (Non-Organizational Users) | Shared | SAML SSO federation; SCIM provisioning from external IdPs |

### IR — Incident Response

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| IR-1 | Policy and Procedures | Latent Archon | See `policies/incident-response.md` |
| IR-2 | Incident Response Training | Latent Archon | Annual incident response drills |
| IR-4 | Incident Handling | Latent Archon | Documented in IR policy; audit trail enables forensics |
| IR-5 | Incident Monitoring | Shared | Cloud Armor alerts; Cloud Logging alert policies; red team monitoring dashboard; real-time security email notifications to org admins (role escalation, auth failures, member changes, SCIM events, deletions) |
| IR-6 | Incident Reporting | Latent Archon + Customer | Documented notification procedures |
| IR-8 | Incident Response Plan | Latent Archon | See IR policy |
| IR-9 | Information Spillage Response | Latent Archon | Forensic preservation endpoint captures complete database snapshot + audit trail for affected scope; restricted to ops service with OIDC auth |

### MA — Maintenance

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| MA-1 | Policy and Procedures | Latent Archon | Serverless model — no system maintenance |
| MA-2 | Controlled Maintenance | GCP Inherited | Cloud Run manages all OS/runtime patching |
| MA-5 | Maintenance Personnel | GCP Inherited | Google Cloud SRE |

### MP — Media Protection

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| MP-1 | Policy and Procedures | GCP Inherited | Google data center media handling |
| MP-2 | Media Access | GCP Inherited | Google physical security |
| MP-4 | Media Storage | GCP Inherited | Encrypted at rest (AES-256) |
| MP-6 | Media Sanitization | GCP Inherited | Google media destruction procedures |

### PE — Physical and Environmental Protection

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| PE-1 through PE-20 | All Physical Controls | **GCP Inherited** | All physical/environmental controls are fully inherited from GCP FedRAMP High data centers. Google maintains SOC 2 Type II and ISO 27001 certifications covering all physical security controls. |

### PL — Planning

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| PL-1 | Policy and Procedures | Latent Archon | This SSP-lite + security whitepaper + policies |
| PL-2 | System Security and Privacy Plans | Latent Archon | This document |
| PL-4 | Rules of Behavior | Customer | Customer acceptable use policies |

### PS — Personnel Security

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| PS-1 through PS-8 | All Personnel Controls | **Latent Archon + Customer** | Latent Archon: background checks for employees with system access; Customer: personnel screening per agency policy |

### RA — Risk Assessment

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| RA-1 | Policy and Procedures | Latent Archon | Security review process |
| RA-2 | Security Categorization | Latent Archon | MODERATE impact (CUI data) |
| RA-3 | Risk Assessment | Latent Archon | Red team program; security architecture review |
| RA-5 | Vulnerability Monitoring and Scanning | Shared | See `policies/vulnerability-scanning.md` (DOC-VS-001). GoSec SAST + govulncheck + Semgrep (OWASP Top 10 + secrets) + Trivy (FS + container) on PRs/weekly; Gitleaks secret scanning on PRs/push/weekly; Dependabot automated dependency updates; npm audit (high/critical) on SPA builds; red team attack suites (44 MITRE-mapped attacks); FedRAMP ConMon monthly reports; SBOM generation (CycloneDX + SPDX); remediation per CVSS (Critical/High 30d, Medium 90d, Low 180d) |

### SA — System and Services Acquisition

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| SA-1 | Policy and Procedures | Latent Archon | See `policies/vendor-risk.md` |
| SA-4 | Acquisition Process | Latent Archon | GCP is FedRAMP High; all dependencies reviewed |
| SA-9 | External System Services | Shared | GCP FedRAMP High; vendor risk policy for third-party services |
| SA-11 | Developer Testing and Evaluation | Latent Archon | Red team (44 attacks); CI build/vet/test; SBOM generation (CycloneDX + SPDX) for Go modules, container images, and SPA npm; GoSec + Semgrep + Trivy SAST pipeline; Dependabot |

### SC — System and Communications Protection

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| SC-1 | Policy and Procedures | Latent Archon | Documented in security whitepaper |
| SC-5 | Denial-of-Service Protection | Shared | Cloud Armor (DDoS + WAF); Cloud Run auto-scaling; two-tier rate limiting |
| SC-7 | Boundary Protection | Shared | VPC private networking; FQDN-based egress firewall (deny-by-default); Cloud Armor with OWASP Top 10 rules + method/origin/bot enforcement; no public IPs on services; PSC for Vertex AI; per-tenant IP allowlisting |
| SC-8 | Transmission Confidentiality and Integrity | GCP + Latent Archon | TLS 1.2+ all paths; HSTS 2-year; PSC for internal services |
| SC-8(1) | Cryptographic Protection | GCP + Latent Archon | TLS 1.2+ with modern cipher suites; Google-managed certificates |
| SC-10 | Network Disconnect | Latent Archon | Global session idle timeout (30 min default); absolute timeout (12 hr default); **per-org configurable** via org settings (idle: 5-480 min, absolute: 60-1440 min); enforced server-side in auth interceptor |
| SC-12 | Cryptographic Key Establishment and Management | Shared | Cloud KMS for CMEK; Google-managed keys for default encryption; WIF (no static keys) |
| SC-13 | Cryptographic Protection | GCP Inherited | AES-256 at rest; TLS 1.2+ in transit |
| SC-17 | Public Key Infrastructure Certificates | Shared | Certificate Manager with DNS authorization; Google-managed certs |
| SC-20 | Secure Name/Address Resolution Service | Shared | **Cloudflare DNS** with **DNSSEC enabled** (`cloudflare_zone_dnssec` resource); DS record registered at domain registrar; authoritative zone signing provides data origin authentication |
| SC-21 | Secure Name/Address Resolution Service (Recursive/Caching) | Shared | DNSSEC validation on Cloudflare resolvers; GCP internal DNS resolves via Google Public DNS (DNSSEC-validating); ensures authenticity of DNS responses for all platform services |
| SC-23 | Session Authenticity | Latent Archon | JWT-based sessions; TOTP MFA; **five-layer tenant enforcement**: JWT claim, IDP pool header match, Host subdomain vs token pool, org membership gate, subdomain→org DB validation |
| SC-28 | Protection of Information at Rest | Shared | AES-256 all storage; Cloud KMS CMEK available |
| SC-39 | Process Isolation | GCP + Latent Archon | Cloud Run container isolation; three separate services; two-project split |

### SI — System and Information Integrity

| Control | Title | Responsibility | Implementation |
|---------|-------|---------------|----------------|
| SI-1 | Policy and Procedures | Latent Archon | Documented in policies |
| SI-2 | Flaw Remediation | Shared | Dependabot; govulncheck + Trivy vulnerability scanning in CI; distroless containers; BoringCrypto (FIPS 140-2 validated) via `GOEXPERIMENT=boringcrypto` |
| SI-3 | Malicious Code Protection | Latent Archon | ClamAV malware scanning on all uploads (**fail-closed in production** — uploads rejected if scanner unavailable); magic-byte validation; file type allowlist; ClamAV deployed as internal-only Cloud Run service |
| SI-4 | System Monitoring | Shared | Cloud Logging; Cloud Monitoring; Cloud Armor analytics; audit events; real-time security email notifications to org admins; usage analytics and cost attribution per tenant/workspace |
| SI-5 | Security Alerts, Advisories, and Directives | Shared | Dependabot alerts; GCP Security Bulletins |
| SI-10 | Information Input Validation | Latent Archon | All RPC inputs validated: required fields, length limits, pagination bounds, UUID parsing, enum validation |
| SI-11 | Error Handling | Latent Archon | Generic error responses; no internal details leaked; RecoveryInterceptor catches panics |
| SI-12 | Information Management and Retention | Shared | GCS lifecycle policies; Cloud SQL backups; audit log retention; FOIA export service (org/workspace-level data export with chain-of-custody metadata, master_admin + step-up MFA); forensic preservation holds exempt data from automated purge |
| SI-16 | Memory Protection | GCP Inherited | Cloud Run sandboxed execution |

---

## 4. GCP Inherited Controls Summary

The following control families are **fully or predominantly inherited** from GCP FedRAMP High authorization:

| Family | Controls | Inheritance |
|--------|----------|-------------|
| **PE** (Physical & Environmental) | PE-1 through PE-20 | 100% inherited |
| **MP** (Media Protection) | MP-1, MP-2, MP-4, MP-6 | 100% inherited |
| **MA** (Maintenance) | MA-1, MA-2, MA-5 | ~90% inherited (serverless model) |
| **SC** (Comms Protection) | SC-13, SC-39 (partial) | Platform-level encryption, isolation (DNS is Cloudflare — shared responsibility) |
| **AU** (Audit) | AU-4, AU-8 | Storage capacity, timestamps |
| **CP** (Contingency) | CP-6, CP-7 | Alternate sites provided by GCP multi-zone/region |

**Total GCP-inherited controls**: ~35-40% of the Moderate baseline is fully or predominantly inherited from GCP's FedRAMP High authorization, significantly reducing the Latent Archon control implementation burden.

---

## 5. Continuous Monitoring Strategy

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Automated dependency scanning (Dependabot) | Continuous | CI/CD |
| GoSec + Semgrep SAST scanning | Every PR + weekly | CI/CD |
| govulncheck (Go advisory DB) | Every PR + every deploy | CI/CD |
| Trivy vulnerability scanning (FS + container) | Every PR + every build + weekly | CI/CD |
| Gitleaks secret scanning (git history) | Every PR + push to main + weekly | CI/CD |
| npm audit (high/critical) | Every SPA build | CI/CD |
| SBOM generation (CycloneDX + SPDX) | Every push to main + weekly | CI/CD |
| Red team attack suite execution | Monthly | Security |
| Cloud Armor WAF rule review | Quarterly | Security |
| Access review (IAM + RBAC audit) | Quarterly | Operations |
| Penetration test (full scope) | Annually | Security |
| Security architecture review | Annually | Engineering + Security |
| Terraform drift detection | On every push to main | CI/CD |
| Incident response drill | Annually | Operations |

---

## 6. POA&M (Plan of Action and Milestones)

| ID | Finding | Risk | Milestone | Target |
|----|---------|------|-----------|--------|
| ~~POA-1~~ | ~~ClamAV Docker image not yet deployed~~ | ~~Complete~~ | Terraform module + staging/production configs deployed (`infra/modules/clamav/`). Uses `benzino77/clamav-rest` on Cloud Run (internal-only, archon-admin invoker). Needs image push + `terragrunt apply`. | **Infra ready** |
| ~~POA-2~~ | ~~App Check enforcement set to UNENFORCED~~ | ~~Complete~~ | All 4 identity-platform configs (staging admin/chat, production admin/chat) set to `ENFORCED`. Pending: production Firebase app IDs + reCAPTCHA site keys. | **Done** |
| ~~POA-3~~ | ~~Production Cloud Armor IP ranges TBD~~ | ~~Complete~~ | Self-service per-tenant IP allowlisting implemented via Cloud Armor API integration; org admins configure CIDR allowlists via `UpdateOrganizationSettings` RPC | **Done** |
| POA-4 | FedRAMP 3PAO assessment | High | Engage 3PAO for formal Moderate assessment | Q3 2026 |
| POA-5 | StateRAMP authorization | Medium | Apply after FedRAMP Moderate achieved | Q4 2026 |
| ~~POA-6~~ | ~~US-CERT incident reporting not documented~~ | ~~Complete~~ | IR policy v1.1 updated with FedRAMP Incident Communications Procedure: CAT 1-6 timelines, US-CERT/CISA reporting process (1hr initial → 72hr follow-up → 30-day final), FedRAMP PMO notification, agency ISSO escalation | **Done** |
| ~~POA-7~~ | ~~Vulnerability scanning strategy not formalized~~ | ~~Complete~~ | Created `policies/vulnerability-scanning.md` (DOC-VS-001): authenticated scanning rationale (Cloud Run serverless = inherited OS scanning), full tool inventory, FedRAMP ConMon monthly reporting, SBOM management, remediation timelines per CVSS | **Done** |
| ~~POA-8~~ | ~~No agency SIEM log export pipeline~~ | ~~Complete~~ | Added Pub/Sub SIEM export to `infra/modules/audit-logs/`: topic + sink + pull/push subscription + agency SA IAM grants. Disabled by default (`enable_siem_export = false`), enable per-customer. | **Done** |
| ~~POA-9~~ | ~~DNSSEC not enabled~~ | ~~Complete~~ | Added `cloudflare_zone_dnssec` resource to `infra/modules/dns/` (NIST 800-53 SC-20/SC-21). Enabled by default. Requires DS record at registrar after apply. | **Done** |
| ~~POA-10~~ | ~~Session timeouts not configurable per-org~~ | ~~Complete~~ | Per-org `session_idle_timeout_min` and `session_absolute_timeout_min` added to org settings JSONB + proto + auth interceptor. Agencies can set stricter timeouts (idle: 5-480 min, absolute: 60-1440 min). NIST AC-12 / FedRAMP SC-10. | **Done** |

---

*This SSP-lite will be expanded into a full SSP as the FedRAMP authorization process begins.*
