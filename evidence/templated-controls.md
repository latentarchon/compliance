# Templated Controls

Generated: 2026-04-17

Total: 196 controls


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

Inactive accounts are detected via an automated access-review tool (cmd/access-review) that runs weekly via Cloud Build. The tool queries Identity Platform tenants across all projects, enumerates users, and flags accounts with no successful authentication in 90+ days. In dry-run mode (default), it generates a report for administrative review. With --disable, it calls the Identity Platform accounts:update API to disable flagged accounts. Disabled accounts are automatically removed after 90 additional days via the account purge service. Reports are uploaded to Drata as evidence.

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

Privileged accounts are restricted to authorized personnel: (1) GCP organization-level roles limited to CEO/CTO; (2) Project Owner roles not assigned — Terraform SA uses custom roles; (3) `master_admin` application role assigned only to designated org administrators; (4) SCIM token management restricted to `master_admin` role.

---

### AC-6.9

**Status:** implemented | **Baseline:** moderate

All privileged function executions are logged: (1) Application audit log captures all admin mutations (role changes, member management, SSO config, IP allowlist changes) with actor, action, timestamp, IP, and correlation ID; (2) GCP Cloud Audit Logs capture all Admin Activity and Data Access events; (3) Cloudflare audit logs capture all configuration changes.

---

### AC-6.10

**Status:** implemented | **Baseline:** moderate

Non-privileged users cannot execute privileged functions. The Connect-RPC interceptor chain enforces RBAC checks before every RPC handler. Attempts to invoke admin-only RPCs with insufficient role are rejected with `PermissionDenied` and logged. GCP IAM prevents non-authorized identities from accessing infrastructure APIs.

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

External information systems connecting to Latent Archon are limited to: (1) Customer IdPs via SAML 2.0 SSO and SCIM 2.0 — connections require explicit configuration by org admin; (2) Customer browsers via HTTPS. No direct system-to-system API access is provided to external systems without explicit authorization. All external connections traverse the full WAF stack.

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

The system generates audit records for: (a) authentication events (login success/failure, MFA, SSO, logout); (b) authorization decisions (RBAC checks, RLS enforcement); (c) account lifecycle (create, modify, disable, delete, role change); (d) data access (document upload, download, search, conversation); (e) admin actions (org settings, SSO config, IP allowlist, SCIM); (f) system events (deployment, configuration change, error); (g) security events (WAF blocks, rate limit triggers, threat score challenges).

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

Audit records are reviewed weekly via an automated audit-review tool (cmd/audit-review) that queries BigQuery audit_logs datasets across all projects. The tool checks for: (1) failed authentication spikes (>10/hour); (2) IAM policy changes (SetIamPolicy events); (3) privilege escalation attempts (CreateRole, CreateServiceAccountKey); (4) bulk data deletion events; (5) off-hours administrative access by non-service-accounts; (6) application-layer auth failures. Reports are generated weekly via Cloud Build scheduler and uploaded to Drata. Cloud Monitoring alert policies provide real-time anomaly detection in parallel.

---

### AU-6.1

**Status:** implemented | **Baseline:** moderate

Automated analysis of audit records is performed using: (1) Cloud Logging log-based metrics for authentication failures, authorization denials, and WAF blocks; (2) Cloudflare Security Analytics for edge-layer threat detection; (3) Custom Cloud Monitoring dashboards correlating application and infrastructure events.

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

Audit record generation is provided at: (1) Application layer via `internal/audit/logger.go` for all business logic events; (2) GCP Cloud Audit Logs for all infrastructure API calls; (3) Cloudflare audit logs for edge configuration changes; (4) Cloud Build logs for CI/CD pipeline execution. Audit generation is enabled by default and cannot be disabled by non-privileged users.

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

System interconnections are authorized and documented: (1) Customer IdP connections via SAML/SCIM require explicit admin configuration; (2) GCP service interconnections managed via Terragrunt IAM modules; (3) Cloudflare-to-origin connections secured via Cloud Armor Cloudflare-only restriction; (4) GitHub-to-GCP connections via Workload Identity Federation.

---

### CA-5

**Status:** implemented | **Baseline:** moderate

Plan of Action and Milestones (POA&M) is maintained and tracked via Drata. An automated POA&M report generator (cmd/poam-report) runs daily via Cloud Build, parsing SARIF scan results from GoSec, Semgrep, Trivy, govulncheck, and Gitleaks. Findings are deduplicated by fingerprint (tool + rule + location), tracked with severity-based remediation deadlines (CRITICAL: 15 days, HIGH: 30 days, MEDIUM: 90 days, LOW: 180 days), and automatically closed when resolved. Reports are uploaded to Drata as evidence artifacts.

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

Internal system connections are documented and authorized: (1) Cloud Run to Cloud SQL via VPC peering (private IP only); (2) Cloud Run to Vertex AI via Private Service Connect; (3) Cloud Run to GCS via GCP internal networking; (4) Cloud Run to Cloud KMS via GCP internal networking; (5) Cloud Run to Cloud Tasks via GCP internal networking. All connections defined in Terragrunt IaC.

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

Configuration changes are controlled through: (1) Git-based PR workflow requiring review and approval; (2) Terragrunt plan output reviewed before apply; (3) FedRAMP SCN classification on all PRs (GitHub Actions); (4) CI/CD pipeline validation (lint, test, security scan) before merge; (5) Cloud Build deployment with container signing (Binary Authorization on ops project).

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

Contingency plan testing is conducted monthly via automated Cloud Build exercises (`cloudbuild-monthly.yaml`). Tests include: (1) Cloud SQL backup restoration; (2) Cloud Run service redeploy from Artifact Registry; (3) GCS object recovery from versions; (4) Terragrunt plan validation for disaster recovery. Results uploaded to Drata.

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

### IA-2.1

**Status:** implemented | **Baseline:** moderate

Multi-factor authentication (MFA) is required for all privileged and non-privileged network access. TOTP-based MFA (RFC 6238) is enforced at the application layer via the auth interceptor. Users who have not enrolled in MFA are blocked from accessing any functionality. MFA enrollment is mandatory during first login.

---

### IA-2.2

**Status:** implemented | **Baseline:** moderate

MFA is required for all non-privileged network access. The same TOTP MFA requirement applies to all user roles (viewer through master_admin). No exemptions are granted.

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

Incident response exercises are conducted monthly via automated Cloud Build exercises (`cloudbuild-monthly.yaml`). Exercises include tabletop scenarios and simulated incident handling. Exercise results are documented and uploaded to Drata.

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

Media sanitization is inherited from GCP's FedRAMP High authorization for physical media. Digital sanitization: (1) account closure triggers 90-day automated data purge; (2) document deletion removes from GCS and purges embeddings; (3) Cloud SQL row-level deletion with vacuum for space reclamation; (4) KMS key destruction after data retention period.

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

Security and privacy resources are allocated through: (1) dedicated compliance infrastructure (compliance repo, automated tools); (2) engineering time for security controls; (3) third-party security assessment budget; (4) security tooling budget (Drata, scanning tools).

---

### PM-4

**Status:** implemented | **Baseline:** moderate

POA&M is maintained in Drata and updated continuously as vulnerabilities are discovered, assessed, and remediated. POA&M items include milestones and completion dates.

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

External system services: (1) GCP — FedRAMP High authorized, IL5 available; (2) Cloudflare — FedRAMP Moderate authorized; (3) GitHub — used for source control and CI/CD, no CUI stored; (4) Drata — used for compliance tracking, no CUI stored. All external services evaluated for security posture before adoption.

---

### SA-10

**Status:** implemented | **Baseline:** moderate

Configuration management in development: (1) all code in Git with full history; (2) PR-based workflow with required reviews; (3) branch protection rules; (4) CI/CD pipeline validates all changes; (5) infrastructure changes require Terragrunt plan review.

---

### SA-11

**Status:** implemented | **Baseline:** moderate

Developer security testing: (1) SAST via GoSec and Semgrep (daily + PR-time); (2) dependency scanning via govulncheck and npm audit; (3) container scanning via Trivy; (4) secret scanning via gitleaks; (5) unit and integration testing; (6) manual security review for sensitive changes.

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

Transmission confidentiality and integrity: all data in transit is encrypted with TLS 1.2+ (minimum enforced by Cloudflare and GCP). HSTS headers enforce HTTPS. Internal GCP service-to-service communication uses mTLS via Cloud Run's built-in service mesh.

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

Flaw remediation: (1) critical vulnerabilities patched within 24 hours; (2) high within 7 days; (3) medium within 30 days; (4) low within 90 days. Vulnerability scanning runs daily via Cloud Build. Patch status tracked in POA&M via Drata.

---

### SI-2.2

**Status:** implemented | **Baseline:** moderate

Automated flaw remediation status monitoring: (1) daily vulnerability scans (GoSec, Semgrep, Trivy, govulncheck) report results to Cloud Build; (2) scan results uploaded to Drata as evidence; (3) Cloud Monitoring alerts on new critical/high findings.

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

Inbound and outbound traffic monitoring: (1) Cloudflare provides full visibility into inbound HTTP traffic (requests, responses, WAF actions, threat scores); (2) VPC flow logs capture network-level traffic metadata; (3) Cloud Armor logs capture origin-layer WAF decisions; (4) VPC egress firewall logs capture outbound connection attempts.

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

Software and information integrity: (1) container images built in Cloud Build with deterministic builds; (2) container image digests (SHA-256) used for deployment (not mutable tags); (3) Binary Authorization attests images on ops project; (4) Git commit signing for source code integrity; (5) SBOM generation tracks all components.

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

Information input validation: (1) Connect-RPC/Protobuf enforces type-safe API contracts; (2) Server-side validation for all user inputs; (3) SQL injection prevented by parameterized queries (no string interpolation); (4) XSS prevented by React's automatic escaping and CSP headers; (5) File upload validation (MIME type, size limits, malware scan).

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

Usage conditions are enforced: (1) sessions limited to authorized time windows when configured by org admin; (2) IP allowlisting restricts access to approved networks; (3) Cloudflare Access policies enforce device posture requirements for admin endpoints.

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

### SC-7.21

**Status:** implemented | **Baseline:** high

Isolation of system components: (1) three-project GCP architecture provides blast-radius isolation; (2) separate service accounts per Cloud Run service; (3) VPC peering with restricted routes; (4) KMS keys in dedicated project with separate IAM.

---


## SI Family

### SI-4.12

**Status:** implemented | **Baseline:** high

Automated organization-generated alerts: security events from Cloud Monitoring, Cloudflare, and application audit logs generate automated alerts to security personnel via email and PagerDuty.

---

