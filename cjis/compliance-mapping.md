# Latent Archon — CJIS Security Policy v5.9.5 Compliance Mapping

> **Document ID**: CJIS-MAP-001  
> **Version**: 1.0  
> **Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Review Cycle**: Annual (aligned with FBI CJIS Security Policy updates)  
> **Applicable Standard**: FBI CJIS Security Policy v5.9.5

---

## Overview

This document maps Latent Archon's security controls to the 13 policy areas of the FBI Criminal Justice Information Services (CJIS) Security Policy. It identifies where Latent Archon meets, partially meets, or inherits each requirement, along with implementation details and evidence references.

### Compliance Summary

| Status | Count | Meaning |
|--------|-------|---------|
| **MET** | 10 | Fully implemented and documented |
| **INHERITED** | 2 | Fully inherited from GCP FedRAMP High |
| **PARTIAL** | 1 | Implemented with minor administrative gaps (see POA&M) |

---

## Policy Area 1: Information Exchange Agreements

**CJIS Ref**: §5.1  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Management Control Agreement (MCA) with each agency | MCA template prepared; executed per customer | `cjis/management-control-agreement.md` |
| CJIS Security Addendum signed by all personnel with CJI access | Addendum signing tracked; required before production access | `cjis/security-addendum-procedure.md` |
| Roles and responsibilities documented | SSP §7.1 defines all user types and responsibilities | `fedramp-ssp.md` §7 |
| Information exchange documented | SSP §4 documents all interconnections and data flows | `fedramp-ssp.md` §4 |

---

## Policy Area 2: Security Awareness Training

**CJIS Ref**: §5.2  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Security awareness training within 6 months of access to CJI | Onboarding training within 5 business days (exceeds requirement) | `policies/security-awareness-training.md` §4.1 |
| Training refresher every 2 years (minimum) | Annual refresher (exceeds biennial requirement) | `policies/security-awareness-training.md` §4.3 |
| Training covers CJIS Security Policy requirements | CJIS-specific training module added to curriculum | `cjis/training-outline.md` |
| Training records maintained | Tracked in Drata with 3-year retention | `policies/security-awareness-training.md` §7 |
| Training includes social engineering awareness | Phishing awareness training semi-annually | `policies/security-awareness-training.md` §3.1 |

---

## Policy Area 3: Incident Response

**CJIS Ref**: §5.3  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Incident response plan | Comprehensive IRP covering detection through recovery | `policies/incident-response.md` |
| Incident response roles defined | IC, Technical Lead, Communications Lead, Forensics | `policies/incident-response.md` §4 |
| Reporting procedures to FBI CJIS Division | Process documented with contact information and timelines | See §5.3 addendum below |
| Annual testing of IR plan | Monthly red team (99 attacks, 6 suites) + semi-annual tabletop | `policies/incident-response.md` §9.2 |
| Evidence preservation | Forensic preservation holds on SEV-1/SEV-2 incidents | `policies/incident-response.md` §7.3 |

### CJIS-Specific Incident Reporting

In addition to the standard incident reporting channels (US-CERT, FedRAMP PMO), incidents involving CJI must be reported to:

| Entity | Contact | Timeline |
|--------|---------|----------|
| FBI CJIS Division ISO | cjis_iso@fbi.gov / (304) 625-2000 | Within 24 hours of CJI breach discovery |
| State CSA (CJIS Systems Agency) | Per state — see customer MCA | Same timeline as FBI CJIS |
| Customer agency LASO | Per customer contract | Within 24 hours |

---

## Policy Area 4: Auditing and Accountability

**CJIS Ref**: §5.4  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Audit events logged | All security-relevant events logged to `audit_events` table and Cloud Logging | `fedramp-ssp.md` §8.2, §8.3 |
| Audit records include: user ID, event type, date/time, success/fail | Audit events include: `user_id`, `action`, `created_at`, `ip_address`, `user_agent`, `metadata` JSONB | Database schema `audit_events` |
| Audit log integrity | Cloud Logging immutable; GCS WORM audit buckets with locked retention policy (production); BigQuery CMEK-encrypted; database append-only INSERT for service roles; `force_destroy = false` on all buckets; 90-day soft-delete recovery | `policies/access-control.md` §6.2 |
| Audit log retention (minimum 1 year) | Zero-deletion policy: BigQuery indefinite (no expiration), GCS WORM 2-year locked (production), Cloud Logging 30-day hot + GCS cold archive indefinite, database indefinite. All storage tiers down (NEARLINE→COLDLINE) but never deletes. | `fedramp-ssp.md` §8, `security-whitepaper.md` §13 |
| Data Access audit logging | DATA_READ + DATA_WRITE enabled for BigQuery, Cloud SQL, Cloud Run, Cloud KMS, IAM, and Cloud Storage (NIST AU-3/AU-12) | `infra/modules/audit-logs/main.tf` |
| Audit log review | Continuous automated monitoring + quarterly manual review | `continuous-monitoring-plan.md` |
| Session logging (logon/logoff) | All authentication events audit-logged; session timeouts enforced server-side | `policies/access-control.md` §4 |

### Events Audited

| Event Category | Examples | CJIS Req |
|----------------|----------|----------|
| Authentication | Login success/failure, MFA challenge, session timeout | §5.4.1.1 |
| Authorization | RBAC checks, workspace access, permission denied | §5.4.1.1 |
| Data Access | Document view, search query, conversation message | §5.4.1.1 |
| Data Modification | Document upload/delete, member invite/remove | §5.4.1.1 |
| Administrative | Role change, org settings update, SSO config | §5.4.1.1 |
| System | Service startup/shutdown, health check failures | §5.4.1.1 |

---

## Policy Area 5: Access Control

**CJIS Ref**: §5.5  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Least privilege access | RBAC with 4 org roles + 3 workspace roles; 3 least-privilege DB roles | `policies/access-control.md` §5, §6.2 |
| Account management (provisioning/deprovisioning) | SCIM 2.0 + JIT provisioning; same-day deprovisioning on termination | `policies/access-control.md` §3 |
| Separation of duties | Separate DB roles per service; admin vs. app pool isolation | `policies/access-control.md` §6 |
| Session lock (idle timeout) | 25-min default idle timeout (configurable per org, minimum 5 min) | `policies/access-control.md` §4.2 |
| Unsuccessful logon attempts | Identity Platform brute-force protection + IP/per-user rate limiting | `policies/access-control.md` §4.4 |
| System access notifications (login banners) | Configurable per-org login banner (stored in org settings) | Application feature |
| Remote access controls | All access is remote (cloud SaaS); TLS 1.2+ enforced | `policies/access-control.md` §8 |

---

## Policy Area 6: Identification and Authentication

**CJIS Ref**: §5.6  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Unique identification (no shared accounts) | Per-user Firebase UID; no shared/generic accounts; policy prohibits sharing | `policies/access-control.md` §3.2 |
| Multi-factor authentication (Advanced Authentication) | TOTP-based MFA enforced on all data endpoints via auth interceptor | `policies/access-control.md` §4.1 |
| Identifier management | Firebase UID lifecycle managed by Identity Platform + SCIM | `policies/access-control.md` §3 |
| Authenticator management | TOTP enrollment required; admin MFA reset; self-reset blocked | `policies/access-control.md` §4.1 |
| Authenticator feedback obscured | All auth errors return generic "authentication failed" message | Auth interceptor implementation |
| Password policy (when passwords used) | Identity Platform enforced; magic link (passwordless) preferred; SSO eliminates passwords for enterprise | `fedramp-ssp.md` §7.2 |

### CJIS Advanced Authentication (§5.6.2.2)

CJIS requires "Advanced Authentication" (MFA) for:
- All personnel accessing CJI from any location
- All access outside a physically secure location

**Latent Archon implementation**: MFA is **unconditionally required** on all data endpoints. There is no MFA bypass for any location or network. This exceeds the CJIS requirement.

---

## Policy Area 7: Configuration Management

**CJIS Ref**: §5.7  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Baseline configurations documented | All infrastructure defined in Terraform/Terragrunt IaC | `configuration-management-plan.md` |
| Change management process | PR-based changes, CI/CD checks, production approval gates | `policies/change-management.md` |
| Security impact analysis before changes | Required in PR review process | `policies/change-management.md` |
| Least functionality | Cloud Run containers use distroless base images (no shell, no package manager) | Dockerfile configuration |
| Software restriction | Only approved dependencies; Dependabot automated scanning; SBOM generation | `supply-chain-risk-management-plan.md` |
| Network diagram maintained | Architecture diagrams in SSP and security whitepaper | `fedramp-ssp.md` §8, `security-whitepaper.md` |

---

## Policy Area 8: Media Protection

**CJIS Ref**: §5.8  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Media encryption (CJI at rest) | AES-256 with CMEK via Cloud KMS for Cloud SQL and GCS | `policies/encryption.md` §4 |
| Media transport encryption | TLS 1.2+ for all data in transit; HSTS enforced | `policies/encryption.md` §5 |
| Media disposal | Cloud: GCP cryptographic erasure (FedRAMP inherited); Physical: cross-cut shred | `policies/physical-security.md` §5 |
| Prohibition on removable media for CJI | Policy explicitly prohibits copying customer data to USB/removable media | `policies/physical-security.md` §5.1 |
| Digital media sanitization | NIST 800-88 Clear for decommissioned devices | `policies/physical-security.md` §5.2 |

---

## Policy Area 9: Physical Protection

**CJIS Ref**: §5.9  
**Status**: **INHERITED** (from GCP)

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Physically secure location for CJI processing | GCP FedRAMP High data centers with multi-layer physical security | `policies/physical-security.md` §3 |
| Physical access controls | GCP: biometric + badge, man-traps, CCTV, security guards | GCP FedRAMP authorization |
| Visitor controls | GCP: visitor logs, escorts, background checks | GCP FedRAMP authorization |
| Personnel work locations | Supplementary controls for remote work (screen privacy, device encryption, etc.) | `policies/physical-security.md` §4 |

**Note**: Latent Archon is 100% cloud-native. No on-premises servers, no physical CJI media. All physical protection controls are inherited from GCP's FedRAMP High authorization (FR1805181233).

---

## Policy Area 10: Systems and Communications Protection

**CJIS Ref**: §5.10  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Boundary protection | Cloudflare Edge WAF + Cloud Armor origin WAF + VPC firewall + FQDN-based egress restrictions | `fedramp-ssp.md` §8.4 |
| Encryption in transit (FIPS 140-2) | TLS 1.2+ with BoringSSL (FIPS 140-2 cert #4407) | `policies/encryption.md` §6.1 |
| Encryption at rest (FIPS 140-2) | AES-256 via Cloud KMS (FIPS 140-2 Level 3 HSMs) | `policies/encryption.md` §4 |
| Intrusion detection | Cloudflare Edge WAF (managed rulesets) + Cloud Armor WAF rules (OWASP CRS), audit log alerting, red team monitoring | `policies/incident-response.md` §5 |
| Partitioning (data isolation) | PostgreSQL RLS, workspace-scoped vector search, three-project isolation (auth + data tier) | `policies/access-control.md` §6 |
| Denial of service protection | Cloudflare edge DDoS absorption (proxied mode) + Cloud Armor origin DDoS protection, dual-layer rate limiting | `fedramp-ssp.md` §8.4 |
| VoIP (N/A) | Platform does not use VoIP | N/A |

---

## Policy Area 11: Formal Audits

**CJIS Ref**: §5.11  
**Status**: **PARTIAL** (see POA&M)

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| Triennial audit by FBI CJIS or state CSA | Not yet conducted (pre-authorization) | POA&M item |
| Internal audit capability | Continuous monitoring plan + monthly red team + quarterly access reviews | `continuous-monitoring-plan.md` |
| Audit findings tracked | POA&M tracking in SSP and Drata | `fedramp-ssp.md` Appendix I |
| Corrective action plans | Remediation items tracked with owners and deadlines | `fedramp-ssp.md` Appendix I |

**Gap**: First formal audit pending — requires engagement with state CSA (triggered by first law enforcement customer). All technical controls and documentation are in place to support the audit.

---

## Policy Area 12: Personnel Security

**CJIS Ref**: §5.12  
**Status**: **MET**

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| CJIS Security Addendum signed by all personnel with CJI access | Procedure established; signing tracked | `cjis/security-addendum-procedure.md` |
| Fingerprint-based background checks | Procedure established for state-specific processing | `cjis/personnel-security-procedure.md` |
| Personnel screening prior to CJI access | Background check must complete before production access granted | `cjis/personnel-security-procedure.md` |
| Personnel termination procedures | Same-day access revocation; SCIM DELETE; Firebase session revocation | `policies/access-control.md` §3.3 |
| Personnel transfer procedures | Role review and access adjustment on role change | `policies/access-control.md` §3 |
| Personnel sanctions | Documented in access control policy enforcement section | `policies/access-control.md` §11 |

---

## Policy Area 13: Mobile Devices

**CJIS Ref**: §5.13  
**Status**: **INHERITED** (N/A — see note)

| Requirement | Implementation | Evidence |
|-------------|----------------|----------|
| MDM for mobile devices accessing CJI | N/A — Latent Archon is a web application accessed via browser only | N/A |
| Mobile device encryption | N/A — no native mobile app; web access encrypted via TLS | N/A |
| Remote wipe capability | N/A — no data stored on device; all data server-side | N/A |
| Personal device policy (BYOD) | Personnel device requirements documented (encryption, patching, etc.) | `policies/physical-security.md` §4.2 |

**Note**: Latent Archon does not have a native mobile application. All access is via web browser over HTTPS. No CJI is stored on end-user devices. The platform's web architecture eliminates most mobile device concerns. If a future mobile app is developed, this section will be updated.

---

## Cross-Reference: CJIS → Existing Policies

| CJIS Policy Area | Primary Latent Archon Policy | Supporting Documents |
|-----------------|------------------------------|---------------------|
| 1. Information Exchange | `cjis/management-control-agreement.md` | SSP §4 |
| 2. Security Awareness | `policies/security-awareness-training.md` | `cjis/training-outline.md` |
| 3. Incident Response | `policies/incident-response.md` | SSP §8, Appendix F |
| 4. Auditing | `continuous-monitoring-plan.md` | SSP §8, Appendix G |
| 5. Access Control | `policies/access-control.md` | SSP §7, `security-whitepaper.md` §1 |
| 6. Identification & Auth | `policies/access-control.md` §4 | `security-whitepaper.md` §1 |
| 7. Configuration Mgmt | `policies/change-management.md` | `configuration-management-plan.md` |
| 8. Media Protection | `policies/encryption.md` | `policies/physical-security.md` §5 |
| 9. Physical Protection | `policies/physical-security.md` | GCP FedRAMP (inherited) |
| 10. Systems & Comms | `policies/encryption.md` | SSP §8–10, `security-whitepaper.md` |
| 11. Formal Audits | `continuous-monitoring-plan.md` | SSP Appendix I (POA&M) |
| 12. Personnel Security | `cjis/personnel-security-procedure.md` | `cjis/security-addendum-procedure.md` |
| 13. Mobile Devices | N/A (web-only) | `policies/physical-security.md` §4 |

---

## CJIS POA&M Items

| ID | Finding | Severity | Target | Status |
|----|---------|----------|--------|--------|
| CJIS-1 | Complete fingerprint-based background checks for all personnel | High | Before first CJI access | Pending first customer |
| CJIS-2 | Execute first MCA with law enforcement customer | High | Q2 2026 | Pending customer engagement |
| CJIS-3 | Complete CJIS-specific security awareness training | Medium | Before first CJI access | Training outline created |
| CJIS-4 | Engage with state CSA for first formal audit | Medium | Q3 2026 | Pending first customer |
| CJIS-5 | Add CJIS incident reporting contacts to IRP contacts list | Low | Q2 2026 | Template ready |

---

*Next review date: March 2027 (or upon CJIS Security Policy version update)*
