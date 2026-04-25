# Templated Controls

Generated: 2026-04-25

Total: 315 controls


## AC Family

### AC-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a formal Access Control Policy (POL-AC-001, `policies/access-control.md`) that defines account management procedures, authentication requirements, authorization model, data isolation controls, and network-level access controls. The policy is reviewed annually by the Security Lead, approved by the CEO, and disseminated to all personnel via the compliance document repository. Changes follow the Change Management Policy (POL-CM-001) requiring PR-based review and approval.

---

### AC-2.1

**Status:** implemented | **Baseline:** moderate

Latent Archon provides a SCIM 2.0 server (`internal/sso/scim_handler.go`) conforming to RFC 7643/7644. The SCIM server supports automated user provisioning (create), deprovisioning (delete), attribute updates (replace/patch), and group management. Customer IdPs connect via SCIM bearer token authentication with SHA-256 hashed tokens. JIT provisioning auto-creates accounts on first federated login.

---

### AC-2.2

**Status:** implemented | **Baseline:** moderate

The system does not support anonymous or temporary accounts. All invite tokens are time-limited and single-use. Emergency access to GCP infrastructure uses IAM Conditions with time-limited grants (maximum 4 hours) and requires CEO/CTO approval documented in the incident response log.

---

### AC-2.3

**Status:** implemented | **Baseline:** moderate

Inactive accounts are detected via an automated access-review tool (cmd/access-review) that runs weekly via Cloud Build. The tool queries Identity Platform tenants across all projects, enumerates users, and flags accounts with no successful authentication in 90+ days. In dry-run mode (default), it generates a report for administrative review. With --disable, it calls the Identity Platform accounts:update API to disable flagged accounts. Disabled accounts are automatically removed after 90 additional days via the account purge service. Reports are archived to GCS and accessible via the 3PAO assessment portal.

---

### AC-2.4

**Status:** implemented | **Baseline:** moderate

Automated audit logging captures all account lifecycle events: creation (invite, SCIM, JIT), modification (role change, attribute update), enabling, disabling (admin action, inactivity, SCIM DELETE), and removal (admin action, self-service close). Logs include actor, target, action, timestamp, IP, user agent, and correlation ID. Logs stored in Cloud Logging with CMEK encryption.

---

### AC-2.5

**Status:** implemented | **Baseline:** moderate

Inactive sessions are automatically terminated after 15 minutes of inactivity. The session timeout is enforced server-side via the auth interceptor. Users must re-authenticate (including MFA) to resume. Logout is available via the `SignOut` RPC which invalidates the Firebase refresh token.

---

### AC-6

**Status:** implemented | **Baseline:** moderate

The system employs the principle of least privilege: (1) Application RBAC restricts each role to minimum necessary functions; (2) GCP IAM uses custom roles scoped to specific APIs per service account; (3) Cloud Build SA has least-privilege IAM per project; (4) Cloud Run services run as dedicated service accounts with only required API permissions; (5) Users are assigned the `viewer` role by default and must be explicitly elevated.

---

### AC-6.1

**Status:** implemented | **Baseline:** moderate

Privileged access to security functions is restricted: (1) `master_admin` role required for SSO/SCIM configuration, IP allowlist management, and security settings; (2) GCP IAM Conditions restrict production access to break-glass scenarios with time-limited grants (max 4 hours); (3) Terraform/Terragrunt changes require PR approval before apply; (4) Cloud Build deployment SA permissions are scoped per project.

---

### AC-6.2

**Status:** implemented | **Baseline:** moderate

Non-privileged accounts are used for all non-security functions. Engineers use personal accounts for development and non-privileged access. Privileged operations (infrastructure changes, production access) require separate authorization via PR approval (IaC changes) or break-glass process (emergency access). No engineer has standing privileged access to production.

---

### AC-6.5

**Status:** implemented | **Baseline:** moderate

Privileged accounts are restricted to authorized personnel: (1) GCP organization-level roles limited to CEO/CTO; (2) Project Owner roles not assigned — Terraform SA uses custom roles; (3) `master_admin` application role assigned only to designated tenant administrators; (4) SCIM token management restricted to `master_admin` role.

---

### AC-6.9

**Status:** implemented | **Baseline:** moderate

All privileged function executions are logged: (1) Application audit log captures all admin mutations (role changes, member management, SSO config, IP allowlist changes) with actor, action, timestamp, IP, and correlation ID; (2) GCP Cloud Audit Logs capture all Admin Activity and Data Access events; (3) Cloudflare audit logs capture all configuration changes.

---

### AC-7

**Status:** implemented | **Baseline:** moderate

The system enforces a limit of 5 consecutive failed login attempts within a 15-minute window. After exceeding the threshold, the account is temporarily locked for 30 minutes. Firebase Identity Platform enforces this at the authentication layer. Additionally, Cloudflare rate limiting applies tiered limits to login endpoints (10 requests/10s per IP) to prevent credential stuffing. All failed authentication attempts are logged with IP, user agent, and timestamp.

---

### AC-8

**Status:** implemented | **Baseline:** moderate

The system displays a system use notification banner before granting access. The login page includes a DoD/Federal notice and consent banner informing users that: (1) they are accessing a U.S. Government information system, (2) usage may be monitored and recorded, (3) unauthorized use is prohibited and subject to criminal and civil penalties. Users must acknowledge the banner before proceeding to authentication.

---

### AC-10

**Status:** implemented | **Baseline:** moderate

The system limits concurrent sessions to 3 per user. When a fourth session is initiated, the new session is rejected with an error instructing the user to sign out from another device. Session tracking uses a server-side user_sessions table with last-seen timestamps; the auth interceptor counts active sessions (seen within the idle timeout window) and enforces the limit per request.

---

### AC-11

**Status:** implemented | **Baseline:** moderate

The system initiates a session lock after 15 minutes of inactivity. The session lock obscures all information on the display with a re-authentication prompt. Users must provide full credentials (including MFA) to re-establish the session. The timeout is enforced both client-side (React idle detection) and server-side (JWT expiration + refresh token validation).

---

### AC-12

**Status:** implemented | **Baseline:** moderate

Sessions are automatically terminated after 15 minutes of inactivity (server-side enforcement) and after a maximum session duration of 12 hours regardless of activity. Users can manually terminate sessions via the `SignOut` RPC which invalidates the Firebase refresh token. Session termination is logged.

---

### AC-14

**Status:** implemented | **Baseline:** moderate

The only actions permitted without identification and authentication are: (1) viewing the marketing site (latentarchon.com); (2) viewing the login/consent banner page. All API endpoints require authentication. The health check endpoint (`/healthz`) returns only HTTP 200 with no sensitive data.

---

### AC-17.2

**Status:** implemented | **Baseline:** moderate

All remote access sessions are encrypted using TLS 1.2+ (FIPS 140-2 validated via BoringSSL). Cloudflare enforces minimum TLS 1.2. Cloud Run services only accept HTTPS. Internal service-to-service communication within the VPC uses mTLS via Cloud Run's built-in service mesh.

---

### AC-20

**Status:** implemented | **Baseline:** moderate

External information systems connecting to Latent Archon are limited to: (1) Customer IdPs via SAML 2.0 SSO and SCIM 2.0 — connections require explicit configuration by tenant admin; (2) Customer browsers via HTTPS. No direct system-to-system API access is provided to external systems without explicit authorization. All external connections traverse the full WAF stack.

---

### AC-21

**Status:** implemented | **Baseline:** moderate

Information sharing decisions are enforced by workspace-level data isolation. PostgreSQL RLS ensures users can only access documents in workspaces they are members of. Cross-workspace data sharing is not supported by design. Document access requires both workspace membership and appropriate RBAC role (editor or above for upload, viewer or above for read).

---

### AC-22

**Status:** implemented | **Baseline:** moderate

The system does not make any information publicly accessible. All content is behind authentication. The marketing site (latentarchon.com) contains only public marketing material, no system data. Content designated as publicly accessible is limited to API documentation and status page.

---


## AU Family

### AU-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains an Audit and Accountability Policy (POL-AU-001) defining audit event generation, review, analysis, and retention requirements. The policy is reviewed annually and updated as needed.

---

### AU-2

**Status:** implemented | **Baseline:** moderate

The system generates audit records for: (a) authentication events (login success/failure, MFA, SSO, logout); (b) authorization decisions (RBAC checks, RLS enforcement); (c) account lifecycle (create, modify, disable, delete, role change); (d) data access (document upload, download, search, conversation); (e) admin actions (tenant settings, SSO config, IP allowlist, SCIM); (f) system events (deployment, configuration change, error); (g) security events (WAF blocks, rate limit triggers, threat score challenges).

---

### AU-3

**Status:** implemented | **Baseline:** moderate

Audit records contain: (1) event type and subtype; (2) timestamp (UTC, millisecond precision); (3) source (component, service, API); (4) outcome (success/failure); (5) user identity (user ID, email); (6) source IP address; (7) user agent; (8) correlation ID for request tracing; (9) affected resource (document ID, workspace ID, org ID); (10) action details (before/after for mutations).

---

### AU-3.1

**Status:** implemented | **Baseline:** moderate

Additional audit detail is generated for privileged actions including: full request/response metadata for admin mutations, before/after state for configuration changes, IAM policy diffs for GCP changes, and file hashes for document operations.

---

### AU-5

**Status:** implemented | **Baseline:** moderate

The system alerts designated personnel in the event of audit processing failures. Cloud Monitoring alerting policies are configured for: (1) log ingestion failures; (2) audit log export failures; (3) log sink errors; (4) storage capacity thresholds. Alerts are sent via email and PagerDuty.

---

### AU-5.1

**Status:** implemented | **Baseline:** moderate

Additional warning is provided when allocated audit log storage volume reaches 80% of capacity. Cloud Monitoring alerting policies monitor GCS bucket size and Cloud Logging ingestion rates.

---

### AU-6

**Status:** implemented | **Baseline:** moderate

Audit records are reviewed weekly via an automated audit-review tool (cmd/audit-review) that queries BigQuery audit_logs datasets across all projects. The tool checks for: (1) failed authentication spikes (>10/hour); (2) IAM policy changes (SetIamPolicy events); (3) privilege escalation attempts (CreateRole, CreateServiceAccountKey); (4) bulk data deletion events; (5) off-hours administrative access by non-service-accounts; (6) application-layer auth failures. Reports are generated weekly via Cloud Build scheduler and archived to GCS. Cloud Monitoring alert policies provide real-time anomaly detection in parallel.

---

### AU-7

**Status:** implemented | **Baseline:** moderate

Audit reduction and report generation capability is provided by: (1) Cloud Logging advanced queries with filtering by severity, resource, user, time range, and custom fields; (2) Log Analytics for SQL-based log querying; (3) Cloudflare analytics dashboard; (4) Custom compliance reporting scripts in the compliance repository.

---

### AU-8

**Status:** implemented | **Baseline:** moderate

Timestamps in audit records use UTC with millisecond precision, synchronized to Google's internal time service (TrueTime) which provides globally consistent, GPS/atomic-clock-backed timestamps. Cloud Run containers inherit GCP's NTP configuration. Application timestamps use `time.Now().UTC()` in Go.

---

### AU-12

**Status:** implemented | **Baseline:** moderate

Audit record generation is provided at: (1) Application layer via `internal/audit/logger.go` for all business logic events; (2) GCP Cloud Audit Logs for all infrastructure API calls; (3) Cloudflare audit logs for edge configuration changes; (4) Cloud Build logs for CI/CD pipeline execution; (5) VPC flow logs on all subnets with 100% sampling rate for complete network traffic metadata. Audit generation is enabled by default and cannot be disabled by non-privileged users.

---


## CA Family

### CA-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Security Assessment and Authorization Policy (POL-CA-001) defining assessment procedures, authorization requirements, and continuous monitoring activities. The policy is reviewed annually.

---

### CA-2

**Status:** implemented | **Baseline:** moderate

Security assessments are conducted annually and include: (1) automated NIST control verification (`cmd/verify-controls`); (2) IaC-to-SSP drift detection (`cmd/check-ssp-iac-drift`); (3) vulnerability scanning (Trivy, GoSec, Semgrep, govulncheck); (4) penetration testing; (5) 3PAO assessment for FedRAMP authorization.

---

### CA-2.1

**Status:** implemented | **Baseline:** moderate

Independent assessors (3PAO) conduct annual security assessments. Automated assessment tools run continuously: daily security scans via Cloud Build, weekly KSI evidence collection, monthly contingency/incident response exercises.

---

### CA-3

**Status:** implemented | **Baseline:** moderate

System interconnections are authorized, documented, and managed via Terragrunt: (1) Cross-project IAM — app SA receives cloudsql.client, storage.objectViewer, and aiplatform.user on the ops project; admin SA receives cloudtasks.enqueuer, storage.objectAdmin, and cloudsql.client on the ops project; Cloud Build SAs receive firebase.viewer and identityplatform.viewer on auth projects for deployment validation; (2) Cross-project Pub/Sub — Cloud Scheduler publishes cron events to ops project via push subscriptions; (3) Customer IdP connections via SAML/SCIM require explicit admin configuration; (4) Cloudflare-to-origin connections secured via Cloud Armor Cloudflare-only restriction; (5) GitHub-to-GCP connections via Workload Identity Federation.

---

### CA-5

**Status:** implemented | **Baseline:** moderate

Plan of Action and Milestones (POA&M) is maintained in the SSP (Appendix I) and tracked via automated tooling. An automated POA&M report generator (cmd/poam-report) runs daily via Cloud Build, parsing SARIF scan results from GoSec, Semgrep, Trivy, govulncheck, and Gitleaks. Findings are deduplicated by fingerprint (tool + rule + location), tracked with severity-based remediation deadlines (CRITICAL: 15 days, HIGH: 30 days, MEDIUM: 90 days, LOW: 180 days), and automatically closed when resolved. Reports are archived to GCS and accessible via the 3PAO assessment portal.

---

### CA-6

**Status:** implemented | **Baseline:** moderate

The system is pursuing FedRAMP authorization via the 20x process. The authorizing official (AO) is identified in the SSP metadata. Authorization decisions are based on: SSP, security assessment report, POA&M, and continuous monitoring evidence.

---

### CA-7

**Status:** implemented | **Baseline:** moderate

Continuous monitoring includes: (1) daily automated security scans (GoSec, Semgrep, Trivy, govulncheck) via Cloud Build; (2) weekly KSI evidence collection; (3) monthly CP-4/IR-3/AT-2 exercises; (4) real-time Cloud Monitoring alerts for security events; (5) automated SSP-IaC drift detection; (6) weekly audit log review; (7) automated OSCAL SSP generation from IaC.

---

### CA-8

**Status:** implemented | **Baseline:** moderate

Penetration testing is conducted annually by qualified assessors and includes: (1) external network penetration testing; (2) web application testing (OWASP methodology); (3) API security testing; (4) social engineering testing. An internal red team capability (`redteam/`) provides continuous adversarial testing.

---

### CA-9

**Status:** implemented | **Baseline:** moderate

Internal system connections are documented and authorized: (1) Cloud Tasks to Cloud Run ops service via OIDC-authenticated dispatch (admin SA holds iam.serviceAccounts.actAs on ops SA for token generation); (2) Cloud Run to Cloud SQL via VPC peering (private IP only, IAM-authenticated); (3) Cloud Run to Vertex AI via Private Service Connect; (4) Cloud Run to GCS via GCP internal networking; (5) Cloud Run to Cloud KMS via GCP internal networking. All connections defined in Terragrunt IaC.

---


## CM Family

### CM-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Configuration Management Policy (POL-CM-001) defining baseline configuration, change control procedures, and configuration monitoring requirements. All infrastructure is managed as code via Terragrunt.

---

### CM-2

**Status:** implemented | **Baseline:** moderate

Baseline configurations are established and documented in Terragrunt IaC (`infra/`) with full Git version history. The current baseline includes: (1) GCP project configurations; (2) Network architecture (VPC, firewall rules, Cloud Armor); (3) Compute configurations (Cloud Run); (4) Data tier (Cloud SQL, GCS, Vertex AI); (5) Security services (KMS, Identity Platform, ClamAV); (6) Edge services (Cloudflare WAF, DNS, Access).

---

### CM-2.1

**Status:** implemented | **Baseline:** moderate

Baseline configurations are reviewed and updated: (1) with every Terragrunt apply (Git-tracked change history); (2) when system components are installed or upgraded (module version updates); (3) as part of annual security assessment. Terragrunt plan/apply workflow ensures all changes are reviewed before deployment.

---

### CM-3

**Status:** implemented | **Baseline:** moderate

Configuration changes are controlled through: (1) Git-based PR workflow requiring review and approval; (2) Terragrunt plan output reviewed before apply; (3) FedRAMP SCN classification on all PRs (GitHub Actions); (4) CI/CD pipeline validation (lint, test, security scan) before merge; (5) Cloud Build deployment with digest-pinned container images.

---

### CM-3.2

**Status:** implemented | **Baseline:** moderate

Changes are tested before implementation: (1) Terragrunt plan shows exact diff before apply; (2) PR CI runs format check, validation, and plan; (3) Backend PR CI runs tests, vet, vuln check, and migration validation; (4) Frontend PR CI runs typecheck and audit; (5) Staging deployment precedes production.

---

### CM-4

**Status:** implemented | **Baseline:** moderate

Security impact analysis is conducted for all changes via: (1) FedRAMP SCN (Significant Change Notification) classifier on PRs that automatically labels changes by impact level; (2) Terragrunt plan review for infrastructure changes; (3) Security-focused code review for application changes.

---

### CM-5

**Status:** implemented | **Baseline:** moderate

Access restrictions for configuration changes: (1) Git repository requires PR approval before merge; (2) Terragrunt apply restricted to authorized CI/CD pipelines and designated engineers; (3) GCP IAM restricts infrastructure API access; (4) Cloudflare API access restricted to authorized accounts; (5) No direct cloud CLI mutations — all changes via IaC.

---

### CM-7

**Status:** implemented | **Baseline:** moderate

The system restricts functionality to essential capabilities: (1) Cloud Run containers run minimal Go binaries with no shell access; (2) Only required GCP APIs are enabled (managed via Terragrunt `apis/terragrunt.hcl`); (3) Assured Workloads restricts allowed GCP services to IL5-approved set; (4) VPC egress firewall blocks all outbound except FQDN-allowlisted GCP APIs.

---

### CM-7.1

**Status:** implemented | **Baseline:** moderate

Periodic review of unnecessary functions is performed: (1) Terragrunt `apis/terragrunt.hcl` lists all enabled APIs — reviewed quarterly; (2) IAM policy auditing identifies unused permissions; (3) Cloud Run service configurations reviewed for unnecessary environment variables or mount paths.

---

### CM-8

**Status:** implemented | **Baseline:** moderate

System component inventory is maintained via: (1) Terragrunt IaC as the authoritative inventory of all infrastructure components; (2) Cloud Run service revisions tracked in Artifact Registry; (3) SBOM (Software Bill of Materials) generated daily via Cloud Build (CycloneDX + SPDX formats); (4) Go module dependencies tracked in go.mod/go.sum; (5) Frontend dependencies tracked in package-lock.json.

---

### CM-8.1

**Status:** implemented | **Baseline:** moderate

Component inventory is updated: (1) automatically on every deployment (new container image → new SBOM); (2) daily via scheduled SBOM generation; (3) on every `go mod tidy` or `npm install` that changes dependency files.

---

### CM-9

**Status:** implemented | **Baseline:** moderate

Configuration management plan defines: (1) IaC tool chain (Terraform + Terragrunt); (2) branching strategy (staging → production promotion); (3) PR review requirements; (4) CI/CD pipeline stages; (5) rollback procedures (redeploy previous Cloud Run revision). Plan documented in CLAUDE.md and infra/CLAUDE.md.

---

### CM-10

**Status:** implemented | **Baseline:** moderate

Software usage restrictions: (1) All dependencies are open-source with compatible licenses (checked via `go-licenses`); (2) No proprietary software installed on infrastructure; (3) GCP services are commercially licensed through the Google Cloud agreement; (4) Cloudflare services are commercially licensed.

---

### CM-11

**Status:** implemented | **Baseline:** moderate

User-installed software is not applicable — the system is a SaaS platform. Users interact via web browser only and cannot install software on the system. Cloud Run containers are immutable — runtime modifications are not possible.

---


## CP Family

### CP-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Contingency Planning Policy (POL-CP-001) and Information System Contingency Plan (ISCP) defining recovery strategies, roles, and procedures. The policy and plan are reviewed annually and after significant system changes.

---

### CP-3

**Status:** implemented | **Baseline:** moderate

Contingency plan training is provided: (1) within 30 days of role assignment; (2) annually thereafter; (3) via monthly automated exercises (CP-4 via Cloud Build cron). Training covers: backup restoration, Cloud Run rollback, incident communication, and Terragrunt disaster recovery.

---

### CP-4

**Status:** implemented | **Baseline:** moderate

Contingency plan testing is conducted monthly via automated Cloud Build exercises (`cloudbuild-monthly.yaml`). Tests include: (1) Cloud SQL backup restoration; (2) Cloud Run service redeploy from Artifact Registry; (3) GCS object recovery from versions; (4) Terragrunt plan validation for disaster recovery. Results archived to GCS and accessible via the 3PAO assessment portal.

---

### CP-7

**Status:** implemented | **Baseline:** moderate

Alternate processing is available via: (1) Cloud Run auto-scales across zones within the region; (2) Terragrunt configs can deploy to alternate US regions for disaster recovery; (3) Cloudflare provides edge caching and DDoS protection independent of origin region. Regional failover procedure documented in ISCP.

---

### CP-8

**Status:** implemented | **Baseline:** moderate

Telecommunications services for the system are provided by: (1) Google Cloud's global network (redundant fiber, peering); (2) Cloudflare's edge network (300+ cities, anycast routing); (3) Multiple ISP paths to GCP regions. No single telecommunications provider failure affects system availability.

---

### CP-10

**Status:** implemented | **Baseline:** moderate

Recovery procedures documented for five failure scenarios: (1) Database failure → Cloud SQL PITR; (2) Cloud Run failure → redeploy from Artifact Registry; (3) GCS failure → restore from versioned objects; (4) Vector Search failure → rebuild from source documents; (5) Regional failure → redeploy to alternate US region via Terragrunt. Target RTOs: Tier 1 < 1 hour, Tier 2 < 4 hours.

---


## IA Family

### IA-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains an Identification and Authentication Policy (POL-IA-001) defining authenticator requirements, identity proofing, and credential management procedures. The policy is reviewed annually.

---

### IA-2.8

**Status:** implemented | **Baseline:** moderate

Replay-resistant authentication is implemented via: (1) TOTP codes are time-based (30-second window) with server-side used-code tracking to prevent replay; (2) Firebase Auth JWTs include `iat` (issued-at) and `exp` (expiry) claims; (3) SAML assertions include `NotOnOrAfter` conditions. All authentication tokens are transmitted over TLS.

---

### IA-2.12

**Status:** implemented | **Baseline:** moderate

PIV/CAC authentication is accepted via SAML federation. Customer agencies configure their IdP to perform certificate-based authentication (PIV/CAC) and federate to Latent Archon via SAML 2.0. The system accepts the IdP's authentication assertion without requiring direct certificate validation.

---

### IA-3

**Status:** implemented | **Baseline:** moderate

Device identification and authentication: (1) Cloudflare Zero Trust Access enforces device posture checks for admin access; (2) Service-to-service authentication within GCP uses Workload Identity (automatic mTLS); (3) CI/CD uses Workload Identity Federation with GitHub OIDC tokens — no long-lived credentials.

---

### IA-4

**Status:** implemented | **Baseline:** moderate

Identifier management: (1) User identifiers are globally unique Firebase UIDs (128-bit); (2) Organization IDs and workspace IDs are UUIDs generated server-side; (3) GCP service account identifiers follow naming convention `{service}@{project}.iam.gserviceaccount.com`; (4) Identifiers are never reused — deleted users' UIDs are retired.

---

### IA-5

**Status:** implemented | **Baseline:** moderate

Authenticator management: (1) Passwords hashed with scrypt (Firebase default, FIPS-compatible); (2) TOTP secrets encrypted at rest in Identity Platform; (3) SCIM bearer tokens hashed with SHA-256 before storage; (4) GCP service account keys not used — Workload Identity Federation provides keyless auth; (5) API tokens are never logged or exposed in responses.

---

### IA-5.1

**Status:** implemented | **Baseline:** moderate

Password-based authentication enforces: (1) minimum 12 characters; (2) at least one uppercase, one lowercase, one digit, one special character; (3) password history (last 12 passwords); (4) maximum age 90 days; (5) minimum age 1 day; (6) passwords checked against breached password database (Have I Been Pwned k-anonymity API). Firebase Identity Platform enforces these policies.

---

### IA-5.2

**Status:** implemented | **Baseline:** moderate

PKI-based authentication is supported via SAML federation (customer IdP performs certificate validation for PIV/CAC). TLS certificates for the system are managed by: (1) Cloudflare for edge certificates (automatic renewal, CT logging); (2) Google-managed SSL certificates for Cloud Run/Load Balancer.

---

### IA-5.6

**Status:** implemented | **Baseline:** moderate

Authenticators are protected commensurate with the security category of the information: (1) TOTP secrets stored in Identity Platform with CMEK encryption; (2) SCIM tokens hashed (SHA-256) — plaintext never stored; (3) Firebase refresh tokens are opaque and revocable; (4) Session tokens transmitted only over TLS.

---

### IA-6

**Status:** implemented | **Baseline:** moderate

Authentication feedback is obscured: (1) Login errors return generic 'Invalid credentials' without specifying whether email or password was incorrect; (2) Password fields are masked in the UI; (3) TOTP codes are masked after entry; (4) Failed login attempts are logged server-side but error details are not returned to the client.

---

### IA-8

**Status:** implemented | **Baseline:** moderate

Non-organizational users (agency end users) are identified and authenticated through: (1) Firebase Identity Platform with mandatory MFA; (2) SAML SSO federation with customer IdP; (3) SCIM 2.0 automated provisioning from customer IdP. All non-org users must belong to a customer organization.

---

### IA-8.1

**Status:** implemented | **Baseline:** moderate

PIV credentials from other agencies are accepted via SAML federation. Customer agencies perform PIV/CAC authentication at their IdP and federate to Latent Archon via SAML 2.0 assertions.

---

### IA-8.2

**Status:** implemented | **Baseline:** moderate

FICAM-approved third-party credentials are accepted via SAML 2.0 federation. The system supports any FICAM-approved credential provider that implements SAML 2.0.

---

### IA-11

**Status:** implemented | **Baseline:** moderate

Re-authentication is required for: (1) session timeout (15 minutes inactivity); (2) privilege escalation (step-up MFA for sensitive operations like account closure, SSO configuration changes); (3) maximum session duration (12 hours); (4) accessing admin endpoints protected by Cloudflare Zero Trust Access.

---


## IR Family

### IR-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains an Incident Response Policy (POL-IR-001) and Incident Response Plan defining incident categories, severity levels, response procedures, escalation paths, and reporting requirements. The policy is reviewed annually.

---

### IR-2

**Status:** implemented | **Baseline:** moderate

Incident response training is provided: (1) within 30 days of role assignment; (2) annually thereafter; (3) via monthly automated exercises (IR-3 via Cloud Build cron). Training covers: incident detection, classification, containment, eradication, recovery, and post-incident activities.

---

### IR-3

**Status:** implemented | **Baseline:** moderate

Incident response exercises are conducted monthly via automated Cloud Build exercises (`cloudbuild-monthly.yaml`). Exercises include tabletop scenarios and simulated incident handling. Exercise results are documented and archived to GCS.

---

### IR-4

**Status:** implemented | **Baseline:** moderate

Incident handling includes: (1) preparation — monitoring dashboards, runbooks, communication templates; (2) detection — automated alerts via Cloud Monitoring, Cloudflare security events, audit log analysis; (3) analysis — log correlation, impact assessment; (4) containment — WAF rule updates, service isolation via Cloud Armor, account disabling; (5) eradication — root cause analysis, vulnerability remediation; (6) recovery — service restoration, verification; (7) post-incident — lessons learned, control updates.

---

### IR-5

**Status:** implemented | **Baseline:** moderate

Incidents are tracked from detection through resolution. Each incident is assigned a unique ID, severity level, and tracked with: timeline, responders, actions taken, evidence collected, resolution, and lessons learned. Incident records maintained in the incident log with minimum 3-year retention.

---

### IR-6

**Status:** implemented | **Baseline:** moderate

Incident reporting follows: (1) internal escalation within 1 hour of detection; (2) US-CERT notification within 1 hour for significant incidents per FedRAMP requirements; (3) customer notification within 24 hours; (4) FedRAMP PMO notification within 72 hours; (5) monthly incident summary in continuous monitoring deliverables.

---

### IR-7

**Status:** implemented | **Baseline:** moderate

Incident response assistance is provided via: (1) documented runbooks for common incident types; (2) automated incident detection and alerting; (3) log analysis tools (Cloud Logging queries, Cloudflare analytics); (4) communication channels (PagerDuty, email, Slack).

---

### IR-8

**Status:** implemented | **Baseline:** moderate

The Incident Response Plan is reviewed annually and updated after: (1) significant incidents; (2) exercise findings; (3) organizational changes; (4) system architecture changes. The plan is distributed to all incident response personnel and available in the compliance repository.

---


## MA Family

### MA-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a System Maintenance Policy (POL-MA-001) defining maintenance procedures for cloud-based systems. Physical maintenance is inherited from GCP. Logical maintenance is performed via CI/CD pipeline and Terragrunt IaC.

---

### MA-2

**Status:** implemented | **Baseline:** moderate

Controlled maintenance activities include: (1) dependency updates via PR-reviewed `go mod` and `npm` changes; (2) infrastructure updates via Terragrunt plan/apply; (3) security patching via automated vulnerability scans triggering PRs; (4) database maintenance via Cloud SQL automated maintenance windows (Sunday 04:00 UTC). All maintenance is logged and trackable via Git history.

---

### MA-3

**Status:** implemented | **Baseline:** moderate

Maintenance tools are controlled: (1) all maintenance performed via approved tools (Terragrunt, GitHub, Cloud Console read-only); (2) no direct SSH or console access to compute instances (Cloud Run is serverless); (3) database maintenance via Cloud SQL Admin API only; (4) maintenance tool access controlled via IAM.

---

### MA-4

**Status:** implemented | **Baseline:** moderate

All maintenance is performed remotely — there is no physical access to infrastructure (cloud-native). Remote maintenance sessions are: (1) authenticated via GCP IAM; (2) encrypted via TLS/SSH; (3) logged via Cloud Audit Logs; (4) time-limited for break-glass access (max 4 hours).

---

### MA-5

**Status:** implemented | **Baseline:** moderate

Maintenance personnel are authorized before access: (1) engineers require PR approval for IaC changes; (2) break-glass production access requires CEO/CTO approval with documented justification; (3) GCP support cases require explicit consent before Google personnel access any resources. Non-escorted maintenance is not applicable (no physical access).

---

### MA-6

**Status:** implemented | **Baseline:** moderate

Timely maintenance is ensured by: (1) automated vulnerability scanning (daily) surfaces required patches; (2) dependency update PRs created within 7 days of CVE publication; (3) critical patches applied within 24 hours; (4) Cloud SQL maintenance windows ensure database patches applied automatically.

---


## MP Family

### MP-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Media Protection Policy (POL-MP-001). Physical media controls are inherited from GCP's FedRAMP High authorization. Digital media (data at rest) is protected via CMEK encryption.

---

### MP-3

**Status:** implemented | **Baseline:** moderate

CUI marking: (1) all data at rest is treated as CUI per the SSP security categorization; (2) GCS bucket names include environment identifier for classification; (3) OSCAL SSP metadata includes `marking: CUI`; (4) system use notification banner indicates CUI handling requirements.

---

### MP-5

**Status:** implemented | **Baseline:** moderate

Media transport is controlled: (1) all data in transit encrypted with TLS 1.2+; (2) no physical media transport — all data movement is network-based; (3) data exports (if any) require admin authorization and are encrypted; (4) GCP handles physical media transport/disposal under their FedRAMP authorization.

---

### MP-6

**Status:** implemented | **Baseline:** moderate

Media sanitization is inherited from GCP's FedRAMP High authorization for physical media. Digital sanitization: (1) account closure triggers 90-day automated data purge; (2) document deletion removes from GCS and purges embeddings; (3) Cloud SQL row-level deletion with vacuum for space reclamation; (4) KMS key destruction after data retention period; (5) Per-tenant crypto-shredding: destroying a tenant's Cloud KMS key versions renders all envelope-encrypted data (document chunks, chat messages, GCS objects, OAuth tokens) permanently irrecoverable without requiring individual record deletion.

---

### MP-7

**Status:** implemented | **Baseline:** moderate

Media use restrictions: (1) no removable media can be connected to system components (serverless architecture); (2) data download restricted by RBAC role; (3) DLP scanning prevents sensitive data exfiltration; (4) no USB, CD/DVD, or other removable media interfaces exist on Cloud Run containers.

---


## PL Family

### PL-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Security Planning Policy (POL-PL-001) and this System Security Plan (SSP). The SSP is auto-generated from infrastructure-as-code configurations and reviewed annually.

---

### PL-2

**Status:** implemented | **Baseline:** moderate

This System Security Plan (SSP) is maintained in OSCAL format (`compliance/oscal/ssp.json`), auto-generated from Terragrunt IaC configurations by `cmd/generate-ssp`. The SSP describes: (1) authorization boundary; (2) system architecture; (3) security controls; (4) responsible roles. The SSP is consistent with the system architecture because it is derived from the same IaC source of truth.

---

### PL-10

**Status:** implemented | **Baseline:** moderate

Baseline security configuration is established via Terragrunt IaC — all security-relevant settings are codified and version-controlled. Changes require PR review, CI validation, and plan approval before apply.

---

### PL-11

**Status:** implemented | **Baseline:** moderate

Privacy plan integration: the system protects PII in accordance with NIST SP 800-122 and handles CUI per 32 CFR 2002. Privacy controls are implemented through: (1) data minimization (collect only necessary PII); (2) purpose limitation; (3) encryption at rest and in transit; (4) access controls (RBAC + RLS); (5) data retention and disposal policies.

---


## PM Family

### PM-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains an Information Security Program Plan documenting: (1) security program structure; (2) roles and responsibilities; (3) management commitment; (4) coordination among organizational entities; (5) compliance requirements. The plan is reviewed annually.

---

### PM-3

**Status:** implemented | **Baseline:** moderate

Security and privacy resources are allocated through: (1) dedicated compliance infrastructure (compliance repo, automated tools); (2) engineering time for security controls; (3) third-party security assessment budget; (4) security tooling budget (scanning tools, compliance automation).

---

### PM-4

**Status:** implemented | **Baseline:** moderate

POA&M is maintained in the SSP (Appendix I) and updated continuously as vulnerabilities are discovered, assessed, and remediated. POA&M items include milestones and completion dates. The 3PAO assessment portal provides real-time POA&M visibility.

---

### PM-5

**Status:** implemented | **Baseline:** moderate

System inventory: Latent Archon maintains a single system boundary documented in this SSP. The system inventory is maintained in Terragrunt IaC (infrastructure components) and SBOM generation (software components).

---

### PM-6

**Status:** implemented | **Baseline:** moderate

Risk management is measured through: (1) security scan results trending; (2) POA&M age and closure rates; (3) incident frequency and severity trending; (4) control assessment pass rates (via `cmd/verify-controls`); (5) time-to-remediate metrics.

---

### PM-7

**Status:** implemented | **Baseline:** moderate

Enterprise architecture is aligned with security requirements: (1) three-project GCP isolation; (2) defense-in-depth WAF (edge + origin); (3) zero-trust networking (deny-all egress, private IPs only); (4) CMEK encryption; (5) IaC for all infrastructure. Security is a foundational architectural principle, not an afterthought.

---

### PM-8

**Status:** implemented | **Baseline:** moderate

Critical infrastructure plan: the system supports federal agency document intelligence capabilities. Business continuity is maintained through: (1) multi-zone Cloud Run deployment; (2) automated backups and recovery; (3) Terragrunt-based disaster recovery to alternate regions.

---

### PM-9

**Status:** implemented | **Baseline:** moderate

Risk management strategy: (1) risk assessment conducted annually and on significant changes; (2) risks tracked in risk register; (3) risk acceptance documented by AO; (4) continuous monitoring for emerging risks.

---

### PM-10

**Status:** implemented | **Baseline:** moderate

Security authorization process follows FedRAMP 20x methodology: (1) automated evidence collection; (2) machine-readable SSP (OSCAL); (3) automated control verification; (4) continuous monitoring deliverables; (5) annual reassessment.

---

### PM-11

**Status:** implemented | **Baseline:** moderate

Risk management process is defined and includes: risk identification (threat modeling, vulnerability scanning), risk analysis (likelihood × impact), risk response (mitigate, accept, transfer), and risk monitoring (continuous).

---

### PM-14

**Status:** implemented | **Baseline:** moderate

Insider threat testing is conducted through: (1) monthly red team exercises (`redteam/`); (2) RBAC permission boundary testing; (3) RLS data isolation verification; (4) audit log completeness testing.

---

### PM-15

**Status:** implemented | **Baseline:** moderate

Security contacts and groups are established: (1) security@latentarchon.com for vulnerability reports; (2) PagerDuty for on-call escalation; (3) incident response team distribution list; (4) FedRAMP PMO contact for authorization matters.

---

### PM-16

**Status:** implemented | **Baseline:** moderate

Threat awareness program includes: (1) subscription to US-CERT advisories; (2) monitoring NIST NVD for relevant CVEs; (3) automated govulncheck for Go vulnerability detection; (4) Trivy container scanning for OS-level vulnerabilities; (5) threat intelligence from Cloudflare threat analytics.

---


## RA Family

### RA-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Risk Assessment Policy (POL-RA-001) defining risk assessment methodology, frequency, and reporting requirements. Risk assessments are conducted annually and on significant system changes.

---

### RA-2

**Status:** implemented | **Baseline:** moderate

Security categorization follows FIPS 199 and NIST SP 800-60: the system is categorized as Moderate impact for confidentiality, integrity, and availability. Information types include CUI documents, conversation data, user PII, and audit logs. Categorization documented in this SSP.

---

### RA-3

**Status:** implemented | **Baseline:** moderate

Risk assessments identify threats, vulnerabilities, and likelihood/impact of exploitation. Risk assessment results are documented in the risk register and inform security control selection and POA&M prioritization.

---

### RA-3.1

**Status:** implemented | **Baseline:** moderate

Supply chain risk assessment is conducted for all critical dependencies: (1) GCP services (covered by GCP's FedRAMP High authorization); (2) Go module dependencies (vulnerability scanning, license checking); (3) npm dependencies (audit, license checking); (4) container base images (Trivy scanning).

---

### RA-5

**Status:** implemented | **Baseline:** moderate

Vulnerability scanning is automated and continuous: (1) daily GoSec + Semgrep + Trivy + govulncheck via Cloud Build scheduled job; (2) daily SBOM generation (CycloneDX + SPDX); (3) PR-time scanning (test, vet, vuln, gitleaks) via Cloud Build; (4) npm audit on frontend PRs; (5) container image scanning via Trivy.

---

### RA-5.2

**Status:** implemented | **Baseline:** moderate

Vulnerability scanning tools are updated: (1) Trivy database updates automatically on each scan; (2) govulncheck uses the Go vulnerability database (updated continuously); (3) Semgrep rules updated with each release; (4) GoSec rules updated with each release.

---

### RA-5.5

**Status:** implemented | **Baseline:** moderate

Privileged access for vulnerability scanning: (1) Cloud Build SA has read access to source code and container images; (2) security scanning runs in isolated Cloud Build workers; (3) scan results are not exposed to non-privileged users.

---

### RA-7

**Status:** implemented | **Baseline:** moderate

Risk response: identified risks are responded to by: (1) mitigate — implement additional controls; (2) accept — document risk acceptance with AO approval; (3) transfer — leverage GCP's FedRAMP authorization for inherited controls; (4) avoid — eliminate the risk source.

---

### RA-9

**Status:** implemented | **Baseline:** moderate

Criticality analysis: system components are classified by criticality: (1) Tier 1 (critical) — authentication, database, encryption; (2) Tier 2 (important) — document processing, search, AI services; (3) Tier 3 (supporting) — monitoring, logging, admin UI. Recovery priorities follow tier classification.

---


## SA Family

### SA-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a System and Services Acquisition Policy (POL-SA-001) defining secure development practices, acquisition requirements, and third-party service evaluation criteria.

---

### SA-2

**Status:** implemented | **Baseline:** moderate

Security resources are allocated: (1) dedicated compliance tooling and automation; (2) engineering time for security controls; (3) budget for third-party assessments; (4) security scanning infrastructure (Cloud Build scheduled jobs).

---

### SA-3

**Status:** implemented | **Baseline:** moderate

System development lifecycle: (1) planning — requirements include security controls; (2) development — secure coding standards (OWASP, Go security best practices); (3) testing — automated security scanning, peer review; (4) deployment — CI/CD with container signing; (5) operations — continuous monitoring; (6) disposal — data purge procedures.

---

### SA-4

**Status:** implemented | **Baseline:** moderate

Acquisition requirements include security specifications: (1) GCP services selected from FedRAMP High authorized services; (2) Cloudflare selected based on FedRAMP Moderate authorization; (3) open-source dependencies evaluated for security posture, maintenance status, and license compatibility.

---

### SA-4.1

**Status:** implemented | **Baseline:** moderate

Functional security properties are documented: (1) OSCAL SSP describes security functions of all components; (2) component security capabilities are verified via `cmd/verify-controls`; (3) design documentation includes security architecture diagrams.

---

### SA-4.2

**Status:** implemented | **Baseline:** moderate

Design and implementation information: (1) infrastructure defined in Terragrunt (full source available); (2) application source code in Go (auditable); (3) security-relevant design decisions documented in ADRs and CLAUDE.md files.

---

### SA-4.9

**Status:** implemented | **Baseline:** moderate

Functions, ports, protocols, and services in use are documented in the SSP network architecture and data flow sections. Only HTTPS (443) is exposed externally. All internal communication uses GCP private networking.

---

### SA-5

**Status:** implemented | **Baseline:** moderate

System documentation includes: (1) architecture documentation (SSP, ADRs); (2) API documentation; (3) operational runbooks; (4) security configuration guides (Terragrunt modules); (5) user guides for admin and app interfaces.

---

### SA-8

**Status:** implemented | **Baseline:** moderate

Security engineering principles: (1) defense in depth (dual WAF, RBAC + RLS, CMEK + TLS); (2) least privilege (per-service IAM, RBAC roles); (3) fail secure (ClamAV fail-closed, auth interceptor deny-by-default); (4) separation of duties (three-project architecture); (5) zero trust (private IPs, CF Access, mTLS).

---

### SA-9

**Status:** implemented | **Baseline:** moderate

External system services: (1) GCP — FedRAMP High authorized, IL5 available; (2) Cloudflare — FedRAMP Moderate authorized; (3) GitHub — used for source control and CI/CD, no CUI stored; All external services evaluated for security posture before adoption.

---

### SA-11.1

**Status:** implemented | **Baseline:** moderate

Static code analysis: (1) GoSec for Go-specific security issues; (2) Semgrep for general security patterns; (3) govulncheck for known Go vulnerabilities; (4) gitleaks for secret detection. All tools run automatically in CI/CD pipeline.

---


## SC Family

### SC-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a System and Communications Protection Policy (POL-SC-001) defining encryption requirements, boundary protection, and communication security standards.

---

### SC-2

**Status:** implemented | **Baseline:** moderate

Application partitioning separates user functionality from management functionality: (1) separate Cloud Run services for app API, admin API, and ops service; (2) separate GCP projects for app and admin workloads; (3) separate Cloudflare Access policies for admin endpoints; (4) RBAC enforces functional separation within the application.

---

### SC-4

**Status:** implemented | **Baseline:** moderate

Information in shared resources is protected: (1) PostgreSQL RLS ensures workspace-level data isolation in the shared database; (2) GCS object paths are workspace-scoped (workspace UUID prefix); (3) Vertex AI Vector Search uses workspace-scoped metadata filtering; (4) Cloud Run containers are stateless — no shared memory between requests.

---

### SC-7.3

**Status:** implemented | **Baseline:** moderate

Access points are limited to: (1) HTTPS (port 443) via Cloudflare for end-user access; (2) Cloudflare Zero Trust Access for admin endpoints. No SSH, RDP, or direct console access. All access traverses the full WAF stack.

---

### SC-7.5

**Status:** implemented | **Baseline:** moderate

Default deny: (1) VPC egress firewall denies all outbound by default, with FQDN allowlist for required GCP APIs only; (2) Cloud Armor denies all non-Cloudflare traffic; (3) Cloud Run ingress restricted to internal + load balancer; (4) RBAC denies access by default — explicit grants required.

---

### SC-7.7

**Status:** implemented | **Baseline:** moderate

Split tunneling prevention: not directly applicable to a SaaS system. However, all system access is forced through the WAF stack (Cloudflare → Cloud Armor → LB → Cloud Run). There is no way to bypass the boundary protection to reach origin services directly.

---

### SC-7.8

**Status:** implemented | **Baseline:** moderate

Traffic is routed to authenticated proxy: all inbound traffic is proxied through Cloudflare (authenticated via Cloud Armor Cloudflare-only IP restriction). Internal traffic between GCP services uses GCP's internal networking with service identity verification.

---

### SC-8

**Status:** implemented | **Baseline:** moderate

Transmission confidentiality and integrity: all data in transit is encrypted with TLS 1.2+ (minimum enforced by Cloudflare and GCP). HSTS headers enforce HTTPS. Internal GCP service-to-service communication uses mTLS via Cloud Run's built-in service mesh. Transactional email uses Gmail API with domain-wide delegation over Google's internal API transport rather than external SMTP relay.

---

### SC-10

**Status:** implemented | **Baseline:** moderate

Network connections are terminated after: (1) 15 minutes of inactivity (application session timeout); (2) 12 hours maximum session duration; (3) Cloudflare connection timeouts for idle TCP connections; (4) Cloud Run request timeouts (300 seconds for streaming, 60 seconds for standard).

---

### SC-12.1

**Status:** implemented | **Baseline:** moderate

Key availability is maintained through: (1) Cloud KMS provides 99.999% SLA; (2) keys are replicated within the region; (3) key versions are preserved for decryption of historical data; (4) key destruction requires explicit action with a 24-hour scheduled destruction delay.

---

### SC-15

**Status:** implemented | **Baseline:** moderate

Collaborative computing devices: not applicable. The system is a web-based SaaS application. No collaborative computing devices (video conferencing, audio) are part of the system. User sessions are independent.

---

### SC-17

**Status:** implemented | **Baseline:** moderate

PKI certificates: (1) Cloudflare manages edge TLS certificates (automatic renewal via DigiCert/Let's Encrypt); (2) GCP manages origin certificates (Google Trust Services CA); (3) Certificate transparency logging is enabled. No manual certificate management required.

---

### SC-18

**Status:** implemented | **Baseline:** moderate

Mobile code: the system uses JavaScript (React SPA) served from controlled origins only. Content Security Policy (CSP) headers restrict script sources. No ActiveX, Java applets, or Flash. Third-party scripts are limited to reCAPTCHA (Google) with SRI integrity verification.

---

### SC-20

**Status:** implemented | **Baseline:** moderate

Secure name/address resolution: DNS is managed via Cloudflare with DNSSEC enabled. All DNS queries for system domains are authenticated. Cloudflare provides DNS-layer DDoS protection.

---

### SC-21

**Status:** implemented | **Baseline:** moderate

DNS resolution validation: the system performs DNSSEC validation for outbound DNS queries via GCP's internal DNS resolver which validates DNSSEC-signed responses.

---

### SC-22

**Status:** implemented | **Baseline:** moderate

Architecture for public DNS: Cloudflare provides authoritative DNS for all system domains with fault-tolerance (anycast, multiple name servers), DNSSEC, and DDoS protection.

---

### SC-23

**Status:** implemented | **Baseline:** moderate

Session authenticity: (1) Firebase Auth JWTs are signed with RS256; (2) JWT signature verified on every request; (3) CSRF protection via SameSite cookie attribute and custom headers; (4) Session tokens bound to user identity and not transferable.

---

### SC-39

**Status:** implemented | **Baseline:** moderate

Process isolation: (1) Cloud Run containers provide OS-level process isolation (gVisor sandbox); (2) each request executes in an isolated context; (3) no shared mutable state between requests; (4) PostgreSQL RLS provides data-level isolation within the database.

---


## SI Family

### SI-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a System and Information Integrity Policy (POL-SI-001) defining vulnerability management, malware protection, monitoring, and patching requirements.

---

### SI-2

**Status:** implemented | **Baseline:** moderate

Flaw remediation: (1) critical vulnerabilities patched within 24 hours; (2) high within 7 days; (3) medium within 30 days; (4) low within 90 days. Vulnerability scanning runs daily via Cloud Build. Patch status tracked in POA&M.

---

### SI-2.2

**Status:** implemented | **Baseline:** moderate

Automated flaw remediation status monitoring: (1) daily vulnerability scans (GoSec, Semgrep, Trivy, govulncheck) report results to Cloud Build; (2) scan results archived to GCS evidence bucket; (3) Cloud Monitoring alerts on new critical/high findings.

---

### SI-3.1

**Status:** implemented | **Baseline:** moderate

Centralized malware management: ClamAV definitions are updated daily via freshclam. The ClamAV service is deployed as a Cloud Run service accessible only within the VPC. Scan results are logged to Cloud Logging for centralized analysis.

---

### SI-4

**Status:** implemented | **Baseline:** moderate

System monitoring: (1) Cloud Monitoring provides infrastructure metrics and alerting; (2) Cloud Logging provides centralized log aggregation; (3) Cloudflare analytics provides edge-layer visibility; (4) Application audit logging provides business-logic event tracking; (5) Automated SSP-IaC drift detection.

---

### SI-4.1

**Status:** implemented | **Baseline:** moderate

System-wide intrusion detection: (1) Cloudflare WAF detects and blocks web application attacks; (2) Cloud Armor detects and blocks L7 attacks; (3) Cloud Monitoring log-based metrics detect anomalous patterns; (4) Application audit logs detect unauthorized access attempts.

---

### SI-4.2

**Status:** implemented | **Baseline:** moderate

Automated monitoring tools: (1) Cloud Monitoring alerting policies for SLO violations; (2) Cloudflare Security Events for WAF triggers; (3) log-based metrics for authentication failures, rate limiting, error rates; (4) uptime checks for service availability.

---

### SI-4.4

**Status:** implemented | **Baseline:** moderate

Inbound and outbound traffic monitoring: (1) Cloudflare provides full visibility into inbound HTTP traffic (requests, responses, WAF actions, threat scores); (2) VPC flow logs capture network-level traffic metadata (100% sampling); (3) Cloud Armor logs capture origin-layer WAF decisions; (4) VPC egress firewall logs capture outbound connection attempts.

---

### SI-4.5

**Status:** implemented | **Baseline:** moderate

Automated alerts for security-relevant events: (1) authentication failure spikes → email + PagerDuty; (2) WAF block rate increase → Cloud Monitoring alert; (3) error rate SLO violation → PagerDuty; (4) unauthorized API access attempts → audit log alert; (5) configuration drift detected → CI alert.

---

### SI-5

**Status:** implemented | **Baseline:** moderate

Security alerts and advisories: (1) US-CERT advisories monitored; (2) Go vulnerability database (govulncheck) checked daily; (3) NVD CVE feed monitored for dependencies; (4) Cloudflare security advisories; (5) GCP security bulletins. Relevant advisories trigger vulnerability assessment and patching within defined SLAs.

---

### SI-6

**Status:** implemented | **Baseline:** moderate

Security function verification: (1) `cmd/verify-controls` validates NIST controls against live GCP state; (2) `cmd/check-ssp-iac-drift` verifies SSP accuracy against IaC; (3) `cmd/generate-ssp` regenerates SSP from IaC to prevent drift; (4) CI/CD pipeline validates security configurations on every change.

---

### SI-7

**Status:** implemented | **Baseline:** moderate

Software and information integrity: (1) container images built in Cloud Build with deterministic builds; (2) container image digests (SHA-256) used for deployment (not mutable tags); (3) Artifact Registry immutable tags prevent tag overwrite after publication; (4) Git commit signing for source code integrity; (5) SBOM generation tracks all components. Binary Authorization attestation is not currently enabled — the IL5 gcp.restrictServiceUsage org policy blocks containeranalysis.googleapis.com. Compensating controls: digest-pinned deploys, Trivy scan gating, Cosign-signed digests, immutable AR tags.

---

### SI-7.1

**Status:** implemented | **Baseline:** moderate

Integrity checking: (1) container image digests verified at deployment; (2) Go module checksums verified via go.sum; (3) npm integrity verified via package-lock.json; (4) Terraform provider checksums verified; (5) ClamAV definition checksums verified on update.

---

### SI-8

**Status:** implemented | **Baseline:** moderate

Spam protection: (1) reCAPTCHA Enterprise on registration and login endpoints; (2) Cloudflare Bot Management; (3) rate limiting on all API endpoints; (4) email sending restricted to transactional notifications only (no bulk email).

---

### SI-10

**Status:** implemented | **Baseline:** moderate

Information input validation: (1) Connect-RPC/Protobuf enforces type-safe API contracts; (2) Server-side validation for all user inputs; (3) SQL injection prevented by parameterized queries (no string interpolation); (4) XSS prevented by React's automatic escaping and CSP headers; (5) File upload validation (MIME type, size limits, malware scan, SVG short-circuit to block XML-based attack vectors); (6) Vector post-condition validation ensures embedding pipeline integrity.

---

### SI-11

**Status:** implemented | **Baseline:** moderate

Error handling: (1) generic error messages returned to users (no stack traces, no internal details); (2) detailed error information logged server-side only; (3) Connect-RPC error codes used for API responses; (4) unhandled panics caught by recovery middleware and logged.

---

### SI-12

**Status:** implemented | **Baseline:** moderate

Information handling and retention: (1) CUI handled in accordance with 32 CFR 2002; (2) data retained per customer agreement and applicable regulations; (3) automated 90-day purge for closed accounts; (4) audit logs retained minimum 1 year; (5) CMEK encryption for all data at rest.

---

### SI-16

**Status:** implemented | **Baseline:** moderate

Memory protection: (1) Cloud Run uses gVisor sandbox providing memory isolation between containers; (2) Go's memory safety (garbage collection, bounds checking, no buffer overflows); (3) no use of unsafe packages in application code; (4) Cloud SQL uses GCP's managed memory protection.

---


## SR Family

### SR-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Supply Chain Risk Management Policy (POL-SR-001) defining requirements for evaluating, selecting, and monitoring third-party components and services.

---

### SR-2

**Status:** implemented | **Baseline:** moderate

Supply chain controls: (1) GCP and Cloudflare selected from FedRAMP-authorized providers; (2) Go dependencies evaluated for maintenance, security posture, and license; (3) container base images from Google's distroless catalog; (4) no direct vendor access to production systems.

---

### SR-3

**Status:** implemented | **Baseline:** moderate

Supply chain protection: (1) daily SBOM generation captures all software components; (2) vulnerability scanning of all dependencies; (3) license compliance checking; (4) pinned dependency versions (go.sum, package-lock.json); (5) container image digests used instead of mutable tags.

---

### SR-5

**Status:** implemented | **Baseline:** moderate

Authenticity verification: (1) Go module checksums verified via go.sum and Go checksum database; (2) container base image provenance from Google's artifact registry; (3) Terraform provider checksums verified; (4) npm package integrity verified via package-lock.json.

---

### SR-6

**Status:** implemented | **Baseline:** moderate

Supplier assessments: (1) GCP assessed via FedRAMP High authorization package; (2) Cloudflare assessed via FedRAMP Moderate authorization; (3) open-source dependencies assessed via automated vulnerability scanning and SBOM analysis.

---

### SR-8

**Status:** implemented | **Baseline:** moderate

Notification agreements: (1) GCP security bulletins provide vulnerability notifications; (2) Go team publishes security advisories for the Go ecosystem; (3) GitHub Dependabot provides automated vulnerability notifications for dependencies.

---

### SR-10

**Status:** implemented | **Baseline:** moderate

Inspection of systems: (1) container images inspected by Trivy before deployment; (2) source code inspected by SAST tools (GoSec, Semgrep); (3) infrastructure configurations inspected by Terragrunt plan; (4) no closed-source components in the application stack.

---

### SR-11

**Status:** implemented | **Baseline:** moderate

Component authenticity: (1) SBOM generated daily (CycloneDX + SPDX) capturing all component versions and sources; (2) Go module checksums verified against Go checksum database; (3) container image digests immutably reference specific builds.

---

### SR-12

**Status:** implemented | **Baseline:** moderate

Component disposal: (1) deprecated dependencies removed via `go mod tidy` and PR review; (2) unused GCP services disabled via Terragrunt `apis/terragrunt.hcl`; (3) old container image versions cleaned up via Artifact Registry lifecycle policies.

---


## AC Family

### AC-2.11

**Status:** implemented | **Baseline:** high

Usage conditions are enforced: (1) sessions limited to authorized time windows when configured by tenant admin; (2) IP allowlisting restricts access to approved networks; (3) Cloudflare Access policies enforce device posture requirements for admin endpoints.

---

### AC-2.12

**Status:** implemented | **Baseline:** high

Account monitoring for atypical usage: (1) auth interceptor logs all access with behavioral attributes (IP, user agent, time, action); (2) anomalous login patterns (new IP, new device, unusual time) trigger additional logging; (3) Cloud Monitoring log-based metrics detect access pattern anomalies.

---

### AC-2.13

**Status:** implemented | **Baseline:** high

Accounts posing significant risk are disabled within 1 hour: (1) accounts with confirmed credential compromise disabled via Firebase Admin SDK; (2) accounts exhibiting malicious behavior blocked at the application layer; (3) automated detection triggers account lockout pending investigation.

---

### AC-3.3

**Status:** implemented | **Baseline:** high

Mandatory access control: (1) PostgreSQL RLS policies enforce workspace-level data isolation (mandatory — cannot be bypassed by application code); (2) GCP org policies enforce security constraints (public IP restriction, location restriction, service restriction); (3) Assured Workloads enforces compliance regime constraints.

---


## AU Family

### AU-6.3

**Status:** implemented | **Baseline:** high

Audit analysis is correlated across: (1) application audit logs; (2) GCP Cloud Audit Logs; (3) Cloudflare security events; (4) WAF logs; (5) VPC flow logs. Correlation is performed using request correlation IDs and timestamps.

---

### AU-10

**Status:** implemented | **Baseline:** high

Non-repudiation: (1) all actions are attributed to authenticated user identity (Firebase UID); (2) audit records include cryptographic binding (CMEK-encrypted, tamper-evident); (3) GCP Cloud Audit Logs provide Google-attested audit trail; (4) Git commits signed for code change attribution.

---


## CM Family

### CM-3.4

**Status:** implemented | **Baseline:** high

Automated security impact analysis via FedRAMP SCN (Significant Change Notification) classifier integrated into CI/CD. The classifier automatically analyzes PRs and labels them by impact level (routine, significant, critical) based on files changed, security control implications, and architecture impact.

---

### CM-5.1

**Status:** implemented | **Baseline:** high

Automated access enforcement for change control: (1) GitHub branch protection requires PR approval; (2) CI/CD pipeline must pass before merge; (3) Terragrunt plan output reviewed and approved before apply; (4) Cloud Build deployment uses signed container images.

---


## CP Family

### CP-2.1

**Status:** implemented | **Baseline:** high

Contingency plan is coordinated with: (1) GCP support for infrastructure-level incidents; (2) Cloudflare support for edge-layer incidents; (3) customer agencies for service disruptions; (4) FedRAMP PMO for authorization-impacting incidents.

---

### CP-7.1

**Status:** implemented | **Baseline:** high

Alternate processing site provides equivalent security: Terragrunt IaC ensures identical security configuration in any deployment region. Assured Workloads constraints apply across all US regions.

---


## IA Family

### IA-5.7

**Status:** implemented | **Baseline:** high

Unencrypted static authenticators are not embedded in applications: (1) no hardcoded credentials in source code (enforced by gitleaks scanning); (2) Workload Identity Federation provides keyless auth (no service account keys); (3) application secrets stored in GCP Secret Manager.

---


## IR Family

### IR-4.1

**Status:** implemented | **Baseline:** high

Automated incident handling: (1) Cloud Monitoring alerts trigger PagerDuty pages; (2) Cloudflare auto-mitigates DDoS attacks; (3) rate limiting automatically blocks abuse; (4) automated account lockout on failed auth threshold. Manual investigation required for complex incidents.

---


## SC Family

### SC-7.18

**Status:** implemented | **Baseline:** high

Fail secure: if boundary protection mechanisms fail, the system defaults to deny: (1) Cloud Armor defaults to deny-all if rules cannot be evaluated; (2) VPC egress firewall defaults to deny-all; (3) Cloud Run rejects requests if auth middleware fails; (4) ClamAV operates fail-closed (upload rejected if scan unavailable).

---


## SI Family

### SI-4.12

**Status:** implemented | **Baseline:** high

Automated organization-generated alerts: security events from Cloud Monitoring, Cloudflare, and application audit logs generate automated alerts to security personnel via email and PagerDuty.

---


## PE Family

### PE-1

**Status:** inherited | **Baseline:** moderate

Physical and environmental protection policy and procedures are fully inherited from Google Cloud Platform's FedRAMP High authorization. GCP maintains comprehensive physical security policies covering all data center facilities. Assured Workloads regime: IL5.

---

### PE-2

**Status:** inherited | **Baseline:** moderate

Physical access authorizations are fully inherited from GCP. Google maintains authorized personnel lists for all data center facilities with approval from data center management.

---

### PE-3.1

**Status:** inherited | **Baseline:** high

Physical access control — guard all entry points. Inherited from GCP. Google data centers employ 24/7 security guards at all facility entry points with badge-based access control.

---

### PE-4

**Status:** inherited | **Baseline:** moderate

Access control for transmission is fully inherited from GCP. Google controls physical access to information system distribution and transmission lines within data center facilities.

---

### PE-5

**Status:** inherited | **Baseline:** moderate

Access control for output devices is fully inherited from GCP. Google controls physical access to output devices (monitors, printers) in data center facilities.

---

### PE-6

**Status:** inherited | **Baseline:** moderate

Physical access monitoring is fully inherited from GCP. Google monitors physical access to data center facilities using CCTV, badge readers, and intrusion detection systems. Access logs reviewed continuously.

---

### PE-6.1

**Status:** inherited | **Baseline:** high

Intrusion alarms and surveillance equipment monitoring is inherited from GCP. Google maintains 24/7 monitoring of intrusion detection systems and surveillance cameras at all data center facilities.

---

### PE-8

**Status:** inherited | **Baseline:** moderate

Visitor access records are fully inherited from GCP. Google maintains visitor logs for all data center facilities including name, organization, date/time, escort, and purpose of visit.

---

### PE-9

**Status:** inherited | **Baseline:** moderate

Power equipment and cabling protection is fully inherited from GCP. Google protects power equipment and cabling from damage and destruction in all data center facilities.

---

### PE-10

**Status:** inherited | **Baseline:** moderate

Emergency shutoff capability is fully inherited from GCP. Google provides emergency shutoff switches for power in data center facilities.

---

### PE-11

**Status:** inherited | **Baseline:** moderate

Emergency power is fully inherited from GCP. Google provides UPS and diesel generators at all data center facilities with automatic failover to maintain operations during power outages.

---

### PE-12

**Status:** inherited | **Baseline:** moderate

Emergency lighting is fully inherited from GCP. Google provides automatic emergency lighting in all data center facilities.

---

### PE-13

**Status:** inherited | **Baseline:** moderate

Fire protection is fully inherited from GCP. Google employs fire detection and suppression systems in all data center facilities.

---

### PE-13.1

**Status:** inherited | **Baseline:** high

Fire detection — automatic notification. Inherited from GCP. Fire detection systems automatically notify local fire departments and Google security operations.

---

### PE-13.2

**Status:** inherited | **Baseline:** high

Fire suppression — automatic activation. Inherited from GCP. Google data centers use automatic fire suppression systems that activate without manual intervention.

---

### PE-14

**Status:** inherited | **Baseline:** moderate

Environmental controls (temperature and humidity) are fully inherited from GCP. Google maintains temperature and humidity controls within acceptable ranges in all data center facilities with continuous monitoring.

---

### PE-15

**Status:** inherited | **Baseline:** moderate

Water damage protection is fully inherited from GCP. Google protects data center facilities from water damage using leak detection sensors and raised flooring.

---

### PE-16

**Status:** inherited | **Baseline:** moderate

Delivery and removal of equipment is fully inherited from GCP. Google authorizes, monitors, and controls delivery and removal of information system components at data center facilities.

---

### PE-17

**Status:** inherited | **Baseline:** moderate

Alternate work site security controls are not applicable — Latent Archon is a SaaS platform with no alternate work sites processing CUI. All data processing occurs within GCP data centers.

---

### PE-18

**Status:** inherited | **Baseline:** high

Location of system components — positioning to minimize damage. Inherited from GCP. Google positions data center equipment to minimize potential damage from physical and environmental hazards and to reduce unauthorized access opportunities.

---


## CP Family

### CP-7.2

**Status:** inherited | **Baseline:** high

Alternate processing site accessibility is inherited from GCP. Google Cloud regions provide geographically diverse processing sites accessible during disruptions. Terraform IaC enables rapid redeployment to alternate regions.

---

### CP-7.3

**Status:** inherited | **Baseline:** high

Priority of service at alternate processing site is inherited from GCP. Google Cloud maintains capacity commitments and SLAs that provide priority service provisions.

---

### CP-8.1

**Status:** inherited | **Baseline:** high

Priority of service for telecommunications is inherited from GCP. Google Cloud maintains diverse telecommunications infrastructure with redundant connectivity providers.

---

### CP-8.2

**Status:** inherited | **Baseline:** high

Single points of failure in telecommunications are mitigated by GCP. Google Cloud provides multiple independent network paths to all data center facilities.

---

### CP-8.3

**Status:** inherited | **Baseline:** high

Separation of primary and alternate telecommunications services is inherited from GCP. Google maintains physically separated network paths for primary and backup connectivity.

---

### CP-8.4

**Status:** inherited | **Baseline:** high

Provider contingency plan is inherited from GCP. Google maintains telecommunications service provider contingency plans as part of their FedRAMP authorization.

---

### CP-8.5

**Status:** inherited | **Baseline:** high

Alternate telecommunication service testing is inherited from GCP. Google tests alternate telecommunications services as part of their contingency plan testing.

---


## MA Family

### MA-3.1

**Status:** inherited | **Baseline:** high

Maintenance tools — inspect tools. Inherited from GCP. Google inspects maintenance tools brought into data center facilities for improper or unauthorized modifications.

---

### MA-3.2

**Status:** inherited | **Baseline:** high

Maintenance tools — inspect media. Inherited from GCP. Google inspects media containing diagnostic and test programs for malicious code before use in data center facilities.

---

### MA-4.3

**Status:** inherited | **Baseline:** high

Comparable security for nonlocal maintenance is inherited from GCP. Google provides comparable security for nonlocal maintenance sessions as established for local maintenance.

---

### MA-5.1

**Status:** inherited | **Baseline:** high

Individuals without required access authorizations are escorted during maintenance. Inherited from GCP. Google escorts all non-authorized maintenance personnel within data center facilities.

---


## MP Family

### MP-6.1

**Status:** inherited | **Baseline:** high

Media sanitization — review, approve, track, document, verify. Inherited from GCP. Google reviews, approves, tracks, documents, and verifies media sanitization and disposal actions for data center equipment.

---

### MP-6.2

**Status:** inherited | **Baseline:** high

Equipment testing for media sanitization is inherited from GCP. Google tests sanitization equipment and procedures to verify correct performance.

---

### MP-6.3

**Status:** inherited | **Baseline:** high

Nondestructive techniques for portable storage devices: not applicable — Latent Archon does not use portable storage devices. All data resides within GCP managed storage (Cloud SQL, Cloud Storage, Cloud Logging).

---


## SC Family

### SC-3

**Status:** inherited | **Baseline:** high

Security function isolation is provided by GCP's infrastructure. Cloud Run uses gVisor kernel-level sandboxing for workload isolation. VPC Service Controls (archon_staging) isolate API access. Separate GCP projects provide blast-radius isolation between admin (archon-admin-staging), ops (archon-ops-staging), and app (archon-app-staging) tiers.

---


## AC Family

### AC-6.3

**Status:** implemented | **Baseline:** high

Network access to privileged commands is restricted: (1) GCP IAM restricts administrative API access to authorized service accounts and break-glass personnel; (2) Cloudflare Access enforces identity-based access to admin endpoints; (3) no SSH/RDP access to production — Cloud Run is serverless; (4) database access restricted to VPC-peered service accounts only.

---

### AC-6.7

**Status:** implemented | **Baseline:** high

Review of user privileges: (1) quarterly access reviews via automated access-review tool; (2) GCP IAM Recommender identifies excess permissions; (3) application RBAC roles reviewed by org master_admin; (4) SCIM-managed accounts automatically reflect IdP group changes.

---

### AC-11.1

**Status:** implemented | **Baseline:** high

Session lock — pattern-hiding displays: the SPA renders a full-screen re-authentication overlay when a session times out, hiding all previously displayed CUI content. The session state is cleared client-side; resumption requires full re-authentication including MFA.

---

### AC-18

**Status:** implemented | **Baseline:** moderate

Wireless access: not applicable — Latent Archon is a SaaS platform hosted entirely on GCP Cloud Run (serverless). There are no organization-controlled wireless access points. End-user wireless connectivity is the responsibility of the customer agency. GCP data center wireless controls are inherited.

---

### AC-19

**Status:** implemented | **Baseline:** moderate

Access control for mobile devices: (1) Cloudflare Access device posture checks enforce OS version, disk encryption, and screen lock for admin access; (2) application enforces session timeouts and re-authentication on all devices; (3) no organization-issued mobile devices — access is via standard web browser with MFA required.

---

### AC-20.1

**Status:** implemented | **Baseline:** high

Limits on authorized use of external systems: (1) the system does not permit connections from external information systems to process, store, or transmit CUI; (2) external system access is limited to API integrations authenticated via SCIM tokens or SAML/OIDC federation; (3) all external integrations documented and reviewed quarterly.

---


## AU Family

### AU-6.5

**Status:** implemented | **Baseline:** high

Integrated analysis of audit records: audit logs from application (15 alert policies), GCP Cloud Audit Logs, and Cloudflare security events are aggregated in Cloud Logging (8 log sinks/project). Cross-source correlation uses request IDs and timestamps for unified analysis.

---

### AU-6.6

**Status:** implemented | **Baseline:** high

Correlation with physical monitoring: not applicable for SaaS — physical monitoring is inherited from GCP. Application-level correlation integrates: (1) authentication events with IP geolocation; (2) Cloudflare threat scores with access patterns; (3) rate limiting triggers with user accounts.

---

### AU-9.2

**Status:** implemented | **Baseline:** high

Audit logs stored in separate system: audit logs are exported to a dedicated logging project via 8 log sinks per project. Log buckets use CMEK encryption and are in a separate GCP project from the application workloads, with independent IAM policies preventing application service accounts from modifying audit records.

---

### AU-9.3

**Status:** implemented | **Baseline:** high

Cryptographic protection of audit information: (1) audit logs encrypted at rest with CMEK via Cloud KMS; (2) audit logs encrypted in transit with TLS 1.2+; (3) WORM (Write Once Read Many) retention prevents deletion or modification of audit records.

---

### AU-12.1

**Status:** implemented | **Baseline:** high

System-wide audit trail compiled from individual records: Cloud Logging aggregates audit records from all Cloud Run services, Cloud SQL, Cloud Storage, Identity Platform, and application audit logs into a unified, time-ordered trail queryable via Cloud Logging API and BigQuery.

---

### AU-12.3

**Status:** implemented | **Baseline:** high

Changes to logging configuration require privileged access and are logged: (1) Cloud Logging sink configuration managed exclusively via Terragrunt; (2) changes require PR approval; (3) GCP Admin Activity audit logs capture all logging configuration changes; (4) org policies prevent service accounts from modifying org-level sinks.

---

### AU-16

**Status:** implemented | **Baseline:** high

Cross-organizational audit logging: (1) Cloudflare provides edge-layer audit events (WAF, rate limiting, Access) via Logpush; (2) GCP Cloud Audit Logs provide infrastructure events; (3) application audit logs provide business-logic events. All three sources are aggregated in Cloud Logging for cross-organizational audit trail.

---


## CA Family

### CA-7.1

**Status:** implemented | **Baseline:** high

Independent assessor for continuous monitoring: automated monitoring tools (Cloud Monitoring, Cloudflare analytics, OSCAL SSP-IaC drift detection) provide independent assessment data. 3PAO engagement planned for initial authorization assessment.

---


## CM Family

### CM-3.1

**Status:** implemented | **Baseline:** high

Automated change control: (1) GitHub PR-based workflow with required approvals; (2) CI/CD pipeline automatically runs tests, security scans, and Terragrunt plan; (3) 2 Cloud Build triggers enforce automated build/deploy pipeline; (4) FedRAMP SCN classifier labels PRs by security impact.

---

### CM-3.3

**Status:** implemented | **Baseline:** high

Security representative for change control: FedRAMP SCN classifier automatically flags security-impacting changes. Critical/significant changes require explicit security review documented in PR comments.

---

### CM-3.6

**Status:** implemented | **Baseline:** high

Cryptographic integrity verification: (1) Go module checksums verified via go.sum; (2) container image digests ensure immutable references; (3) Cosign-signed container image digests verify provenance; (4) Terraform provider checksums verified by HashiCorp's registry.

---

### CM-3.7

**Status:** implemented | **Baseline:** high

Changes reviewed and approved before implementation: (1) Terragrunt plan output must be reviewed before apply; (2) GitHub branch protection enforces PR approvals; (3) CI pipeline must pass before merge is allowed; (4) no direct pushes to staging or main branches.

---

### CM-3.8

**Status:** implemented | **Baseline:** high

Prevent or restrict unverified changes: (1) branch protection prevents direct commits; (2) all changes must pass CI pipeline; (3) Terragrunt apply requires prior plan approval; (4) org policies prevent console-based infrastructure changes for restricted resources.

---

### CM-7.5

**Status:** implemented | **Baseline:** high

Authorized software allowlisting: (1) 25 org policies restrict which GCP services can be used; (2) Cloud Run only executes container images from authorized Artifact Registry repositories; (3) Binary Authorization (binauthz=false) enforces attestation-based image allowlisting; (4) Go module proxy and checksum database verify authorized packages.

---

### CM-12

**Status:** implemented | **Baseline:** high

Information location: CUI is stored exclusively within: (1) Cloud SQL PostgreSQL (structured data, CMEK-encrypted); (2) Cloud Storage (documents, CMEK-encrypted); (3) Vertex AI Vector Search (embeddings, no raw CUI). All storage within US regions enforced by Assured Workloads location constraints.

---

### CM-14

**Status:** implemented | **Baseline:** high

Signed components: (1) container images signed via Cosign with digest pinning; (2) Go binaries built with verified module checksums; (3) Terraform providers verified via HashiCorp GPG signatures; (4) SBOMs generated for component provenance.

---


## CP Family

### CP-2.5

**Status:** implemented | **Baseline:** high

Contingency plan continues essential missions: Terragrunt IaC enables full environment rebuild in an alternate GCP region within hours. Assured Workloads constraints apply to all US regions. Cloud SQL automated backups and Cloud Storage multi-region replication ensure data availability.

---

### CP-2.8

**Status:** implemented | **Baseline:** high

Identify critical assets: critical assets documented in SSP authorization boundary: Cloud SQL (CUI data), Cloud Storage (CUI documents), Cloud KMS (encryption keys), Identity Platform (authentication). Recovery priority: (1) auth, (2) database, (3) storage, (4) application services.

---

### CP-4.1

**Status:** implemented | **Baseline:** high

Contingency plan testing coordination: monthly automated CP-4 exercises run via Cloud Build cron. Tests coordinate recovery of Cloud SQL, Cloud Storage, and Cloud Run services. Results archived to GCS evidence bucket.

---

### CP-4.2

**Status:** implemented | **Baseline:** high

Alternate processing site testing: Terragrunt IaC supports deployment to any US GCP region. Contingency plan testing includes validation that IaC applies cleanly to alternate regions with Assured Workloads compliance constraints.

---

### CP-6.2

**Status:** implemented | **Baseline:** high

Recovery time and consistency objectives for alternate storage: Cloud SQL automated backups provide RPO < 24 hours. Cloud Storage objects replicated with versioning. Backup encryption uses same CMEK keys (Cloud KMS in archon-kms-staging). RTO target: 4 hours for full service restoration.

---

### CP-6.3

**Status:** implemented | **Baseline:** high

Accessibility of alternate storage site: Cloud SQL backups and Cloud Storage objects accessible from any authorized GCP region via IAM. No physical access required. Assured Workloads ensures alternate storage remains within US boundaries.

---

### CP-9.1

**Status:** implemented | **Baseline:** high

Testing backups: monthly CP-4 exercises include backup restoration verification: (1) Cloud SQL backup restored to test instance; (2) Cloud Storage objects verified for integrity; (3) results documented and archived to GCS.

---

### CP-9.5

**Status:** implemented | **Baseline:** high

Transfer to alternate storage: Cloud SQL automated backups stored in GCP-managed backup infrastructure. Cloud Storage objects can be replicated to alternate regions via gsutil. All backups encrypted with CMEK from archon-kms-staging.

---

### CP-9.8

**Status:** implemented | **Baseline:** high

Cryptographic protection of backup information: all backups encrypted at rest with AES-256 via CMEK (Cloud KMS). Backup transmission encrypted with TLS 1.2+. KMS keys for backup encryption stored in dedicated project with independent IAM.

---

### CP-10.2

**Status:** implemented | **Baseline:** high

Transaction recovery: Cloud SQL supports point-in-time recovery (PITR) using write-ahead logs. Application uses database transactions with rollback on failure. No partial transaction commits reach persistent state.

---

### CP-10.4

**Status:** implemented | **Baseline:** high

Restore within time period: RTO target is 4 hours. Terragrunt IaC enables infrastructure rebuild. Cloud SQL PITR enables database recovery to any point within the backup window. Cloud Storage versioning enables document recovery. Monthly CP-4 exercises validate recovery time.

---


## IA Family

### IA-2.5

**Status:** implemented | **Baseline:** high

Group authentication — individual identification first: all authentication is individual (no shared accounts). Firebase Identity Platform issues per-user JWTs with unique UID. TOTP MFA bound to individual user accounts. MFA state: ENABLED across 4 tenants.

---

### IA-2.6

**Status:** implemented | **Baseline:** high

Multi-factor authentication for network access to privileged accounts: (1) all admin API access requires MFA (magic link + TOTP); (2) GCP console access requires Google MFA; (3) Cloudflare Access enforces MFA for admin dashboard; (4) GitHub requires 2FA for repository access.

---

### IA-8.4

**Status:** implemented | **Baseline:** high

Use of defined profiles for identity verification: customer agencies use SAML/OIDC federation with their authoritative IdP (Okta, Azure AD, ADFS, PingFederate). Identity assertions conform to SAML 2.0 and OpenID Connect profiles. Latent Archon does not issue credentials — relies on customer IdP assertions.

---

### IA-9

**Status:** implemented | **Baseline:** high

Service identification and authentication: (1) Cloud Run services authenticate to each other via GCP service account identity tokens; (2) SCIM clients authenticate via SHA-256 hashed bearer tokens; (3) Cloudflare Workers authenticate to origin via CF Access JWT; (4) Cloud Build authenticates via Workload Identity Federation (keyless).

---

### IA-10

**Status:** implemented | **Baseline:** high

Adaptive authentication: the system adjusts authentication requirements based on context: (1) new device/IP triggers additional logging and security notification; (2) admin operations require step-up MFA re-verification; (3) account closure requires explicit MFA confirmation; (4) Cloudflare Access enforces device posture checks for admin endpoints.

---

### IA-12

**Status:** implemented | **Baseline:** moderate

Identity proofing: for federated users, identity proofing is delegated to the customer agency's IdP which performs initial identity verification. For direct users, identity is established through organizational email verification (magic link to verified domain email) and admin-approved invitations.

---

### IA-12.2

**Status:** implemented | **Baseline:** moderate

Identity evidence validation: identity evidence is validated through: (1) SAML/OIDC assertions from trusted customer IdPs with verified metadata; (2) email domain verification via magic link; (3) SCIM provisioning from authoritative HR/IdP systems with pre-established trust.

---

### IA-12.3

**Status:** implemented | **Baseline:** moderate

Identity evidence verification: for federated authentication, the customer IdP serves as the authoritative identity source. SAML assertions and OIDC tokens are cryptographically verified against the IdP's published certificates/JWKS. For direct accounts, email link verification serves as identity evidence.

---

### IA-12.4

**Status:** implemented | **Baseline:** moderate

In-person identity proofing: not applicable — Latent Archon is a SaaS platform. In-person identity proofing is performed by the customer agency as part of their personnel security process before users are provisioned via SCIM or admin invite.

---

### IA-12.5

**Status:** implemented | **Baseline:** moderate

Address confirmation: identity address confirmation is delegated to the customer agency's personnel security process. The system confirms organizational email addresses via magic link verification to the registered email domain.

---


## IR Family

### IR-4.11

**Status:** implemented | **Baseline:** high

Integrated incident response team: the same engineering team handles development, operations, and security incident response. Incident handling procedures include coordination with GCP support (infrastructure), Cloudflare support (edge-layer), and customer agency POCs (data breach).

---

### IR-6.1

**Status:** implemented | **Baseline:** high

Automated incident reporting: (1) Cloud Monitoring alerts automatically page on-call via PagerDuty; (2) Cloudflare security events trigger notifications; (3) application security events (auth failures, rate limit triggers) generate automated alerts; (4) FedRAMP incident reporting to CISA within required timeframes.

---

### IR-6.2

**Status:** implemented | **Baseline:** high

Vulnerabilities related to incidents: security vulnerabilities discovered during incident investigation are documented, tracked, and remediated. Post-incident reviews identify root causes and drive security improvements documented in incident response reports.

---


## PL Family

### PL-8

**Status:** implemented | **Baseline:** moderate

Security and privacy architecture: the system follows a zero-trust architecture with defense-in-depth: (1) edge WAF (Cloudflare) → origin WAF (Cloud Armor) → application auth → RBAC → RLS; (2) CMEK encryption at rest; (3) TLS 1.2+ in transit; (4) VPC Service Controls for API isolation; (5) separate GCP projects for blast-radius containment.

---


## PM Family

### PM-12

**Status:** implemented | **Baseline:** moderate

Insider threat program: (1) principle of least privilege limits blast radius of insider actions; (2) comprehensive audit logging tracks all privileged operations; (3) no standing production access — break-glass only; (4) code changes require PR review; (5) infrastructure changes require Terragrunt plan review.

---

### PM-13

**Status:** implemented | **Baseline:** moderate

Security and privacy workforce: engineering team maintains security skills through: (1) annual security awareness training; (2) secure coding training (OWASP Top 10); (3) hands-on incident response exercises (monthly automated CP-4/IR-3/AT-2); (4) FedRAMP-specific training for compliance personnel.

---

### PM-17

**Status:** implemented | **Baseline:** moderate

Protecting CUI on external systems: CUI is not permitted on external systems. All CUI processing occurs within the FedRAMP-authorized boundary (GCP + Cloudflare). External system access is limited to authenticated API integrations that do not transfer CUI outside the boundary.

---

### PM-18

**Status:** implemented | **Baseline:** moderate

Privacy program plan: Latent Archon maintains a privacy program including: (1) Privacy Policy published and reviewed annually; (2) Privacy Impact Assessment (PIA) for CUI handling; (3) data minimization practices; (4) DLP scanning for PII detection; (5) automated data retention and purge policies.

---

### PM-20

**Status:** implemented | **Baseline:** moderate

Dissemination of privacy program information: privacy program information disseminated through: (1) published Privacy Policy; (2) system use notification banner; (3) personnel onboarding materials; (4) privacy training integrated into security awareness training.

---

### PM-21

**Status:** implemented | **Baseline:** moderate

Accounting of disclosures: the system maintains records of CUI disclosures through: (1) comprehensive audit logging of all data access; (2) RLS-enforced workspace isolation prevents unauthorized cross-tenant disclosure; (3) API access logs track all data retrieval with user identity and timestamp.

---

### PM-22

**Status:** implemented | **Baseline:** moderate

Personally identifiable information quality: (1) SCIM 2.0 synchronization ensures user attributes reflect authoritative IdP data; (2) email verification via magic link validates contact information; (3) users can update their own profile attributes; (4) stale accounts flagged after 90 days of inactivity.

---

### PM-23

**Status:** implemented | **Baseline:** moderate

Data governance body: the CEO serves as data governance authority responsible for PII handling decisions, privacy policy approval, and data retention decisions. Security Lead serves as operational privacy officer.

---

### PM-24

**Status:** implemented | **Baseline:** moderate

Data integrity board: data integrity is maintained through: (1) PostgreSQL ACID transactions; (2) Cloud SQL automated consistency checks; (3) application-level validation on all inputs; (4) CMEK encryption prevents tampering; (5) audit log integrity protected by WORM retention.

---

### PM-25

**Status:** implemented | **Baseline:** moderate

Minimization of PII: the system collects minimum necessary PII: email address (authentication), display name (UI), IP address (security logging). No SSN, date of birth, or demographic data collected. Customer documents (CUI) are the customer's data — the platform processes but does not extract PII from documents except for DLP scanning.

---

### PM-26

**Status:** implemented | **Baseline:** moderate

Complaint management: privacy complaints are handled through: (1) support email published in Privacy Policy; (2) complaints logged and tracked; (3) response within 30 days; (4) escalation path to CEO for unresolved complaints.

---

### PM-27

**Status:** implemented | **Baseline:** moderate

Privacy reporting: privacy metrics reported quarterly including: (1) number of privacy incidents; (2) PII breach notifications issued; (3) privacy complaints received and resolved; (4) DLP scan results summary; (5) data retention compliance status.

---

### PM-28

**Status:** implemented | **Baseline:** moderate

Risk framing: risk management approach aligned with NIST RMF. Risk assessment considers: (1) CUI confidentiality (high impact); (2) system availability for mission-critical operations; (3) supply chain risks (mitigated by FedRAMP-authorized providers). 25 org policies enforce risk boundaries.

---

### PM-30

**Status:** implemented | **Baseline:** moderate

Supply chain risk management plan: documented in SCRMP (supply-chain-risk-management-plan.md). Key elements: (1) use only FedRAMP-authorized IaaS; (2) open-source dependency scanning; (3) SBOM generation for supply chain transparency; (4) container image provenance verification.

---

### PM-31

**Status:** implemented | **Baseline:** moderate

Continuous monitoring strategy: documented in ConMon plan. Automated monitoring includes: (1) daily vulnerability scans; (2) OSCAL SSP-IaC drift detection; (3) Cloud Monitoring infrastructure alerts; (4) Cloudflare security event monitoring; (5) monthly compliance exercises. Results reported to AO monthly.

---

### PM-32

**Status:** implemented | **Baseline:** moderate

Purposing: all system components are dedicated to their authorized purpose. GCP projects scoped to specific functions (admin, ops, app, KMS). No shared-purpose infrastructure. Assured Workloads enforces compliance regime on all resources within the boundary.

---


## PS Family

### PS-9

**Status:** implemented | **Baseline:** high

Position descriptions: all positions with system access have documented security responsibilities: (1) engineers responsible for secure coding, PR review, incident response; (2) CEO/CTO responsible for authorization decisions, risk acceptance; (3) Security Lead responsible for control implementation and assessment.

---


## PT Family

### PT-5.2

**Status:** implemented | **Baseline:** high

Privacy Act statements: system use notification banner includes privacy notice informing users of: (1) authority for data collection; (2) purpose of collection; (3) routine uses; (4) consequences of not providing information. Published in Privacy Policy and displayed at login.

---


## RA Family

### RA-5.4

**Status:** implemented | **Baseline:** high

Discoverable information: (1) Cloudflare proxying hides origin IP addresses; (2) Cloud Run services have no public IP; (3) server headers stripped by Cloud Run; (4) error messages return generic responses (no stack traces); (5) security scanning tools (GoSec=true, Semgrep=true) identify information leakage in source code.

---

### RA-10

**Status:** implemented | **Baseline:** high

Threat hunting: (1) Cloud Logging aggregates all security events for proactive analysis; (2) audit log alert policies detect anomalous patterns; (3) Cloudflare threat intelligence provides real-time threat data; (4) monthly security review includes threat hunting across audit logs and WAF events.

---


## SA Family

### SA-15

**Status:** implemented | **Baseline:** high

Development process, standards, and tools: (1) Go backend built with BoringCrypto=true (FIPS 140-2 validated); (2) security scanning integrated into CI/CD (GoSec=true, Semgrep=true, Trivy=true, govulncheck=true, Gitleaks=true); (3) SBOM generation=true for provenance; (4) PR-based development workflow with required reviews.

---

### SA-16

**Status:** implemented | **Baseline:** high

Developer-provided training resources: (1) Go official documentation and security guidelines; (2) OWASP Top 10 reference in secure coding training; (3) internal CLAUDE.md files document security requirements and patterns; (4) PR review process provides ongoing peer training.

---

### SA-17

**Status:** implemented | **Baseline:** high

Developer security and privacy architecture and design: (1) zero-trust architecture documented in SSP; (2) defense-in-depth with multiple WAF layers; (3) multi-tenant isolation via RLS and per-tenant auth pools; (4) CMEK encryption for all data stores; (5) VPC Service Controls for API isolation.

---

### SA-20

**Status:** implemented | **Baseline:** high

Customized development of critical components: all application code is custom-developed by Latent Archon. No COTS components process CUI. Open-source dependencies (Go modules, npm packages) are scanned for vulnerabilities and license compliance before inclusion.

---

### SA-21

**Status:** implemented | **Baseline:** high

Developer screening: all developers undergo background screening per PS-3 requirements before receiving repository or infrastructure access. Access to production systems requires additional authorization. SBOM=true provides transparency into developer-selected components.

---

### SA-22

**Status:** implemented | **Baseline:** high

Unsupported system components: (1) Go version tracked and updated regularly; (2) container base images use Google's distroless (minimal, maintained); (3) npm dependencies audited for end-of-life status; (4) GCP services used are all Generally Available and fully supported; (5) govulncheck identifies components with known vulnerabilities.

---


## SC Family

### SC-7.29

**Status:** implemented | **Baseline:** high

Separate subnets for connecting to different security domains: (1) three-project GCP architecture separates admin, ops, and app tiers; (2) VPC peering with restricted routes limits cross-project connectivity; (3) Private Service Connect endpoints for Vertex AI eliminate public network traversal.

---

### SC-16

**Status:** implemented | **Baseline:** high

Transmission of security and privacy attributes: (1) Firebase JWTs carry user identity, tenant, MFA status, and custom claims; (2) Cloudflare Access JWTs carry identity and device posture; (3) GCP service account tokens carry IAM identity and scopes; (4) all security attributes transmitted via cryptographically signed tokens.

---

### SC-24

**Status:** implemented | **Baseline:** high

Fail in known state: (1) Cloud Run services restart automatically on failure in a known-good state from the immutable container image; (2) Cloud SQL maintains ACID consistency through crash recovery; (3) auth middleware fails closed (rejects requests on error); (4) ClamAV fails closed (rejects uploads on scan failure).

---

### SC-25

**Status:** implemented | **Baseline:** high

Thin nodes: Cloud Run containers are stateless thin nodes — all persistent state in Cloud SQL and Cloud Storage. Containers rebuilt from scratch on each deployment. No local persistent storage. Container images use distroless base (minimal OS surface).

---

### SC-38

**Status:** implemented | **Baseline:** high

Operations security: (1) infrastructure-as-code prevents configuration knowledge from being a single point of failure; (2) Terragrunt modules are version-controlled and auditable; (3) no undocumented production changes — all changes via PR; (4) security configurations are deterministic and reproducible.

---


## SI Family

### SI-4.10

**Status:** implemented | **Baseline:** high

Visibility of encrypted communications: (1) TLS terminated at Cloudflare edge and GCP load balancer — application sees decrypted traffic for inspection; (2) Cloud Armor WAF inspects decrypted HTTP traffic; (3) application-level audit logging captures business-logic events from decrypted request content.

---

### SI-4.22

**Status:** implemented | **Baseline:** high

Unauthorized network services: (1) Cloud Run only exposes configured ports (8080 for HTTP); (2) VPC firewall deny-all default prevents unauthorized network services; (3) org policies restrict which GCP services can be enabled; (4) Cloud Run ingress restricted to internal + load balancer only.

---


## SR Family

### SR-2.1

**Status:** implemented | **Baseline:** high

Establish SCRM team: supply chain risk management responsibilities assigned to the engineering team. CEO provides oversight. Security Lead evaluates new dependencies and infrastructure providers for supply chain risk.

---

### SR-11.1

**Status:** implemented | **Baseline:** high

Component authenticity — public registry verification: (1) Go modules verified against Go checksum database (sum.golang.org); (2) npm packages verified via package-lock.json integrity hashes; (3) container base images from Google's Artifact Registry; (4) SBOM generation=true captures component provenance.

---

### SR-11.2

**Status:** implemented | **Baseline:** high

Component authenticity — component disposal: deprecated or vulnerable components are removed through: (1) `go mod tidy` removes unused modules; (2) npm audit identifies deprecated packages; (3) Trivy=true flags vulnerable container layers; (4) Artifact Registry lifecycle policies remove old image versions.

---


## AC Family

### AC-2.7

**Status:** implemented | **Baseline:** high

Privileged role-based access scheme: (1) four application roles (master_admin, admin, editor, viewer) with per-RPC enforcement; (2) three database roles (archon_admin_rw) enforce least-privilege at the PostgreSQL layer; (3) GCP IAM custom roles scoped per service account; (4) no shared or group privileged accounts.

---

### AC-6.8

**Status:** implemented | **Baseline:** high

Privilege levels for code execution: (1) Cloud Run containers execute as non-root with read-only filesystem; (2) gVisor sandbox restricts syscall surface; (3) application code runs under a dedicated service account per service with least-privilege IAM; (4) no privileged containers or host-level access.

---


## AU Family

### AU-5.2

**Status:** implemented | **Baseline:** high

Real-time alerts for audit event failures: 15 monitoring alert policies and 10 audit alert policies configured in Cloud Monitoring. Alerts fire within minutes of detection and page on-call via PagerDuty. Log sink failures generate GCP-level alerts.

---


## IA Family

### IA-5.13

**Status:** implemented | **Baseline:** high

Expiration of cached authenticators: (1) Firebase ID tokens expire after 1 hour; (2) Firebase refresh tokens can be revoked server-side via Admin SDK; (3) JWKS cache expires after 5 minutes, forcing re-fetch from Cloudflare; (4) session cookies have explicit expiration; (5) SCIM bearer tokens do not expire but can be rotated on demand.

---


## SC Family

### SC-7.10

**Status:** implemented | **Baseline:** high

Prevent exfiltration: (1) VPC Service Controls perimeter "archon_staging" prevents unauthorized API-level data extraction from 4 projects; (2) DLP inspect template detects 9 PII types in document content; (3) VPC egress firewall blocks all non-allowlisted outbound; (4) Cloud Storage has no public access; (5) audit logging tracks all data access.

---

### SC-12.6

**Status:** inherited | **Baseline:** high

Physical control of cryptographic keys: inherited from GCP. Cloud KMS HSMs are physically secured within Google data centers. FIPS 140-2 Level 3 certification requires physical tamper evidence and tamper response mechanisms. Key material never leaves the HSM boundary in plaintext.

---


## SI Family

### SI-4.14

**Status:** inherited | **Baseline:** high

Wireless intrusion detection: inherited from GCP. Google monitors wireless access within data center facilities. Not applicable at the SaaS layer — Latent Archon has no organization-controlled wireless infrastructure.

---

### SI-7.15

**Status:** implemented | **Baseline:** high

Code authentication: (1) Binary Authorization=false verifies cryptographic attestations before deploying container images to Cloud Run; (2) Go modules authenticated via checksum database (sum.golang.org); (3) npm packages authenticated via package-lock.json integrity hashes; (4) Gitleaks=true prevents credential leakage in code.

---

