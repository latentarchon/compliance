# Latent Archon — CJIS Security Addendum Procedure

> **Document ID**: CJIS-SA-001  
> **Version**: 1.0  
> **Date**: March 2026  
> **Owner**: Chief Executive / Security Lead  
> **Review Cycle**: Annual

---

## 1. Purpose

The FBI CJIS Security Policy (§5.1.1.5, §5.12) requires that every individual with unescorted logical or physical access to Criminal Justice Information (CJI) must execute a CJIS Security Addendum. This document establishes Latent Archon's procedure for managing Security Addendum execution, tracking, and renewal.

---

## 2. What Is the CJIS Security Addendum?

The CJIS Security Addendum is an **FBI-published standard form** that binds individuals to:

- Comply with the CJIS Security Policy
- Protect the confidentiality of CJI
- Report security incidents
- Accept sanctions for violations
- Acknowledge that violations may result in criminal penalties under applicable federal and state law

The form is **not** something Latent Archon creates — it is the **standard FBI form** provided by the state CSA (CJIS Systems Agency) or obtained from the FBI CJIS Division.

**Form reference**: FBI CJIS Security Policy, Appendix H — "CJIS Security Addendum"

---

## 3. Who Must Sign

### 3.1 Required Signers

| Person | Trigger | Timeline |
|--------|---------|----------|
| **CEO / Founder** | First law enforcement customer engagement | Before MCA execution |
| **All engineers with production access** | Hire or role change to production access | Before CJI access is provisioned |
| **Any contractor with CJI access** | Contract execution | Before CJI access is provisioned |
| **Any operations personnel** | Role assignment | Before CJI access is provisioned |

### 3.2 Who Does NOT Need to Sign

- Personnel with **no access** to CJI or production systems containing CJI
- Marketing, sales, or business personnel without system access
- Customer end users (they are governed by their own agency's CJIS policies)

### 3.3 Determining CJI Access

A person has "access to CJI" if they can:
- View, query, or export customer documents in production
- Access Cloud SQL production database (even read-only)
- Access GCS buckets containing customer documents
- Access Cloud Logging exports that may contain CJI metadata
- Deploy code to production services that process CJI
- Access break-glass emergency credentials

**Note**: CI/CD automation (GitHub Actions) operates under Workload Identity Federation with no human-equivalent access. Automated systems do not sign the addendum.

---

## 4. Procedure

### 4.1 Obtaining the Form

1. **State-specific form**: Each state CSA may have a state-specific version of the Security Addendum. When engaging with a new state, request the addendum form from the state CSA or the customer agency's LASO (Local Agency Security Officer).

2. **Standard FBI form**: If the state CSA does not provide a state-specific form, use the standard FBI CJIS Security Addendum from Appendix H of the CJIS Security Policy.

3. **Digital copies**: Store blank addendum forms in `compliance/cjis/forms/` organized by state.

### 4.2 Execution Process

| Step | Action | Responsible |
|------|--------|-------------|
| 1 | Identify individual requiring CJI access | Hiring manager / CEO |
| 2 | Provide CJIS Security Addendum form to individual | Security Lead |
| 3 | Individual reads and signs the addendum | Individual |
| 4 | Witness signature (Security Lead or CEO) | Security Lead / CEO |
| 5 | Scan and store signed addendum | Security Lead |
| 6 | Record in CJIS Personnel Tracker | Security Lead |
| 7 | Provision production/CJI access | Engineering Lead |

### 4.3 Access Blocking

**CJI access MUST NOT be provisioned until the signed addendum is on file.** This is enforced by:

- Production access provisioning (GCP IAM, database roles) requires Security Lead sign-off
- Security Lead verifies addendum and background check status before approving
- This check is documented in the provisioning ticket/PR

---

## 5. Storage and Retention

| Item | Location | Retention |
|------|----------|-----------|
| Signed addendum (scan/PDF) | `compliance/cjis/signed-addenda/` (encrypted) or Drata evidence library | Duration of employment + 3 years |
| Personnel tracker | `compliance/cjis/personnel-tracker.md` | Active maintenance |
| State-specific blank forms | `compliance/cjis/forms/` | Current version maintained |

### 5.1 Security of Signed Addenda

Signed addenda contain PII (name, signature, date). They must be:
- Stored encrypted (GCS with CMEK, or encrypted local storage)
- Access restricted to CEO and Security Lead only
- Not committed to public/shared repositories in unencrypted form
- Available for audit by state CSA upon request

---

## 6. Renewal and Re-execution

| Event | Action Required |
|-------|----------------|
| **CJIS Security Policy version update** | Re-execute addendum if state CSA requires |
| **State CSA form update** | Re-execute with updated form |
| **Every 3 years** (best practice) | Re-execute to confirm ongoing acknowledgment |
| **Role change** | Review — re-execute if access scope changes |
| **Return from extended leave** | Review — re-execute if policy changed during absence |

---

## 7. Personnel Tracker

Maintain the following information for each individual with CJI access:

| Field | Description |
|-------|-------------|
| Full legal name | As it appears on addendum |
| Role / title | Current position |
| Addendum signed date | Date of most recent execution |
| Addendum version | FBI form version or state-specific version |
| Background check status | Pending / Cleared / Expired |
| Background check date | Date fingerprint results received |
| State(s) cleared | Which state CSA(s) have cleared this individual |
| CJI access provisioned date | When production access was granted |
| Training completion date | Most recent CJIS-specific training |
| Notes | Any exceptions, renewals, etc. |

### Template: `compliance/cjis/personnel-tracker.md`

```markdown
| Name | Role | Addendum Signed | Addendum Version | BG Check Status | BG Check Date | State(s) | Access Provisioned | Training Date | Notes |
|------|------|-----------------|------------------|-----------------|---------------|----------|-------------------|---------------|-------|
| Andrew Hendel | CEO | _[TBD]_ | _[TBD]_ | Pending | — | — | — | — | First signer |
```

---

## 8. Audit Readiness

During a state CSA audit, the auditor may request:

1. List of all personnel with CJI access
2. Signed addenda for each person on the list
3. Background check completion records
4. Training completion records
5. Evidence that access was not provisioned before addendum signing

The personnel tracker (Section 7) plus the signed addenda archive provides all of this.

---

## 9. Termination / Offboarding

When an individual with a signed CJIS Security Addendum leaves the organization:

1. **Revoke all CJI access immediately** (same-day, per access control policy §3.3)
2. **Update personnel tracker** — mark as "Separated" with date
3. **Do NOT destroy the signed addendum** — retain per Section 5 retention schedule
4. **Notify customer agencies** if required by MCA terms
5. **Collect any physical materials** (though cloud-only model minimizes this)

---

*Next review date: March 2027*
