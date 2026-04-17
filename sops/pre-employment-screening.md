# Pre-Employment Screening Standard Operating Procedure

> **Document ID**: SOP-HR-001
> **Parent Documents**: POL-IS-001 §2.1, SSP-LA-001 PS-3
> **Version**: 1.0
> **Date**: April 2026
> **Owner**: CEO / ISSO
> **NIST 800-53 Controls**: PS-2, PS-3, PS-6, PS-7

---

## 1. Purpose

This SOP defines the step-by-step process for screening, verifying, and onboarding personnel who will have access to Latent Archon information systems, source code, cloud infrastructure, or customer data. It implements the requirements of POL-IS-001 §2.1 (US Person Requirement) and NIST 800-53 PS-3 (Personnel Screening).

---

## 2. Applicability

This procedure applies to:

- All prospective employees
- All prospective contractors and subcontractors
- Third-party assessors (3PAOs) with system access
- Any individual who will access Latent Archon systems, repositories, or cloud projects

---

## 3. Pre-Offer Phase

### 3.1 Position Risk Designation (PS-2)

Before posting a position, classify it by risk level:

| Risk Level | Criteria | Screening Tier |
|-----------|----------|---------------|
| **High** | Production infrastructure access, ISSO duties, break-glass access, or direct customer data access | Tier 3 (comprehensive) |
| **Moderate** | Code commit access, staging environment access, CI/CD pipeline access | Tier 2 (standard) |
| **Low** | No system access (administrative, marketing, non-technical) | Tier 1 (basic) |

Document the risk designation in the job posting internal notes.

---

## 4. Post-Offer / Pre-Access Phase

All steps below must be completed **before** granting any system access.

### 4.1 US Person Verification (Required — No Exceptions)

| Step | Action | Evidence | Timeline |
|------|--------|----------|----------|
| 1 | Request government-issued photo identification | Copy retained in HR file | Day 1 of offer acceptance |
| 2 | Verify US person status per 22 CFR § 120.62: US citizen, lawful permanent resident, or protected individual (8 U.S.C. § 1324b(a)(3)) | I-9 Employment Eligibility Verification form | Within 3 business days of start |
| 3 | Record verification in personnel file | Signed US Person Attestation form (see §4.1.1) | Day 1 |
| 4 | For contractors: verify US person attestation clause in contract | Executed Contractor Security Addendum (CSA-TPL-001) | Before contract execution |

#### 4.1.1 US Person Attestation Statement

The following statement must be signed by all personnel:

> I attest that I am a United States person as defined by 22 CFR § 120.62 (a citizen of the United States, a lawful permanent resident as defined by 8 U.S.C. § 1101(a)(20), or a protected individual as defined by 8 U.S.C. § 1324b(a)(3)). I understand that this status is a mandatory requirement for access to Latent Archon information systems, which process Controlled Unclassified Information (CUI) within DoD IL5 Assured Workloads.
>
> Signature: ________________________  Date: ____________
> Printed Name: ________________________

### 4.2 Background Screening (PS-3)

Initiate background check appropriate to position risk designation:

| Tier | Components | Vendor | Timeline |
|------|-----------|--------|----------|
| **Tier 1 (Basic)** | Identity verification, SSN trace | _[TBD — select vendor]_ | 3-5 business days |
| **Tier 2 (Standard)** | Tier 1 + criminal history (7-year, all jurisdictions), sex offender registry | _[TBD]_ | 5-7 business days |
| **Tier 3 (Comprehensive)** | Tier 2 + employment verification (5 years), education verification, professional reference checks (2 minimum) | _[TBD]_ | 7-14 business days |

**Adjudication**: The CEO / ISSO reviews background check results and makes a suitability determination. Adverse findings do not automatically disqualify — the nature, severity, and recency of the finding are considered against the position's risk level.

**Re-screening**: Background checks are re-conducted every 5 years or upon position change to a higher risk designation.

### 4.3 Access Agreements (PS-6)

Before granting system access, the individual must sign:

| Agreement | Document | Tracking |
|-----------|----------|----------|
| Acceptable Use Policy | POL-AU-001 | Signature + date in HR file |
| Non-Disclosure Agreement | NDA (company template) | Executed copy in HR file |
| Rules of Behavior | rules-of-behavior.md | Electronic acceptance tracked in `rob_acceptances` DB table |
| Contractor Security Addendum | CSA-TPL-001 (contractors only) | Executed copy in HR/vendor file |

---

## 5. Access Provisioning

After all screening and agreements are complete:

### 5.1 Provisioning Checklist

| Step | Action | Owner | Verification |
|------|--------|-------|-------------|
| 1 | Add to Google Workspace (latentarchon.com domain) | CEO | User appears in admin console |
| 2 | Add to GitHub organization with appropriate team | CEO | `gh api /orgs/latentarchon/members` shows user |
| 3 | Grant GCP IAM roles via Terragrunt (IaC only — never console) | CEO (author IaC) → CI/CD (apply) | `terragrunt plan` shows expected bindings |
| 4 | Configure MFA on all accounts | New hire | Verify MFA enabled in Google Workspace admin |
| 5 | Add to Drata personnel tracking | CEO | Drata shows personnel as compliant |
| 6 | Schedule security awareness training (AT-2) | CEO | Training tracker updated |
| 7 | Update `compliance/personnel.json` roster | CEO | OSCAL generators reflect new personnel |
| 8 | Update separation-of-duties-matrix.md if roles change | CEO | SOD-LA-001 reflects current state |

### 5.2 First-Day Orientation Checklist

| Topic | Duration | Materials |
|-------|----------|-----------|
| Security architecture overview | 30 min | security-whitepaper.md |
| Acceptable use and data handling | 15 min | POL-AU-001, POL-DC-001 |
| Incident response procedures | 15 min | POL-IR-001 |
| CUI handling requirements | 15 min | NIST 800-171 overview |
| Development security practices (if engineering) | 30 min | OWASP Top 10, secure Go patterns |
| Rules of Behavior acceptance | 5 min | In-app ROB acceptance flow |

---

## 6. Contractor-Specific Requirements (PS-7)

In addition to all steps above, contractors require:

| Requirement | Details |
|------------|---------|
| **Executed CSA** | Contractor Security Addendum (CSA-TPL-001) with US person attestation |
| **Scope limitation** | Access limited to specific projects/repos needed for contract scope |
| **Time-bound access** | IAM Conditions with expiration date matching contract end |
| **Sponsor** | Internal sponsor (CEO) responsible for contractor's access and actions |
| **Access review** | Monthly review of contractor access during contract period |
| **Offboarding** | Same-day access revocation upon contract completion (PS-4 procedures) |

---

## 7. Disqualifying Conditions

Access will not be granted if any of the following are true:

- Individual is not a US person (no exceptions — POL-IS-001 §2.1)
- Background check reveals disqualifying adverse findings as determined by CEO/ISSO
- Individual refuses to sign required access agreements
- Individual refuses MFA enrollment

---

## 8. Record Retention

| Record | Retention Period | Storage |
|--------|-----------------|---------|
| US person verification (I-9, attestation) | Duration of employment + 3 years | HR file (encrypted) |
| Background check results | Duration of employment + 1 year | HR file (encrypted) |
| Access agreements (signed) | Duration of employment + 1 year | HR file (encrypted) |
| Provisioning/deprovisioning records | 7 years | Audit logs (WORM) |

---

## 9. Procedure Revision History

| Version | Date | Change |
|---------|------|--------|
| 1.0 | April 2026 | Initial SOP |

---

_End of Pre-Employment Screening SOP — SOP-HR-001_
