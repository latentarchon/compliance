# Latent Archon — CJIS Personnel Security Procedure

> **Document ID**: CJIS-PS-001  
> **Version**: 1.0  
> **Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Review Cycle**: Annual  
> **CJIS Ref**: §5.12 — Personnel Security

---

> **Organizational context**: Latent Archon is a founder-led, automation-first security organization. CJIS procedures will be activated when a law enforcement customer requiring CJI access is onboarded. References to "Security Lead" describe the target-state role (POA-15); until that hire, the CEO / ISSO fulfills all duties. See SOD-LA-001.

## 1. Purpose

The CJIS Security Policy requires that all personnel with unescorted logical or physical access to Criminal Justice Information (CJI) undergo fingerprint-based background checks and meet personnel security requirements. This document establishes Latent Archon's procedure for personnel screening, background checks, and ongoing personnel security management.

---

## 2. Applicability

### 2.1 Covered Personnel

Any individual who has, or will have, access to:

- Production database (Cloud SQL) containing CJI
- Production object storage (GCS) containing customer documents classified as CJI
- Production Cloud Logging exports that may contain CJI metadata
- Production Cloud Run services that process CJI
- Break-glass emergency credentials for production systems
- CI/CD deployment pipelines that push to production (since code runs in CJI-processing context)

### 2.2 Excluded

- Automated systems (GitHub Actions via WIF — no human access)
- Customer end users (governed by their own agency's CJIS policies)
- Personnel with access only to staging/development environments (no CJI present)
- Sales, marketing, or business personnel without system access

---

## 3. Fingerprint-Based Background Check Process

### 3.1 Overview

CJIS requires a **state and national fingerprint-based record check** processed through the state's CJIS Systems Agency (CSA). This is NOT the same as a commercial background check (e.g., Checkr, Sterling) — it must go through the FBI/state criminal history record system.

### 3.2 Process by State

Each state has a slightly different process. The general flow:

| Step | Action | Responsible | Timeline |
|------|--------|-------------|----------|
| 1 | Customer agency introduces Contractor to state CSA | Customer LASO | Week 1 |
| 2 | CSA provides fingerprint submission instructions and authorized channeler list | State CSA | Week 1-2 |
| 3 | Individual gets fingerprinted at authorized channeler (e.g., IdentoGO, local PD) | Individual | Week 2-3 |
| 4 | Fingerprint card or electronic submission sent to state CSA | Channeler/Individual | Week 2-3 |
| 5 | State CSA processes state + FBI criminal history check | State CSA | Week 3-6 |
| 6 | Results returned to customer agency or CSA | State CSA | Week 4-6 |
| 7 | Agency/CSA notifies Contractor of clearance status | Customer LASO / CSA | Week 4-6 |

### 3.3 State-Specific Notes

#### New York
- **CSA**: NY Division of Criminal Justice Services (DCJS)
- **Process**: Electronic fingerprinting via IdentoGO (MorphoTrust/IDEMIA)
- **Scheduling**: identogo.com — search for "CJIS" or agency-specific service code
- **Cost**: ~$80-100 per person (state + FBI check)
- **Timeline**: 2-4 weeks typical
- **Contact**: DCJS Security Officer — (518) 457-6101

#### New Jersey
- **CSA**: NJ State Police, CJIS Unit
- **Process**: Electronic fingerprinting via IdentoGO
- **Cost**: ~$60-75 per person
- **Timeline**: 2-4 weeks typical
- **Contact**: NJ State Police CJIS — (609) 882-2000 ext. 2890

#### California
- **CSA**: CA Department of Justice (DOJ), Bureau of Criminal Information and Analysis
- **Process**: Live Scan fingerprinting at DOJ-approved locations
- **Cost**: ~$50-70 per person (DOJ + FBI)
- **Timeline**: 2-6 weeks (CA can be slower)
- **Contact**: CA DOJ CJIS — (916) 210-3380

#### Connecticut
- **CSA**: CT Department of Emergency Services and Public Protection (DESPP)
- **Process**: Electronic fingerprinting via IdentoGO
- **Cost**: ~$75-90 per person
- **Timeline**: 2-3 weeks typical
- **Contact**: DESPP CSO — (860) 685-8000

#### Texas
- **CSA**: TX Department of Public Safety (DPS), Crime Records Service
- **Process**: Electronic fingerprinting via IdentoGO
- **Cost**: ~$40-50 per person
- **Timeline**: 1-3 weeks (TX is generally fast)
- **Contact**: TX DPS CJIS — (512) 424-2000

#### Florida
- **CSA**: FL Department of Law Enforcement (FDLE)
- **Process**: Electronic fingerprinting via IdentoGO
- **Cost**: ~$50-60 per person
- **Timeline**: 2-4 weeks typical
- **Contact**: FDLE CJIS — (850) 410-7000

### 3.4 Multi-State Clearance

If Latent Archon serves law enforcement customers in multiple states, personnel may need background checks through each state's CSA. Some states accept other states' checks as a courtesy; others require their own independent check.

**Best practice**: Get the background check through the first customer's state CSA, then ask subsequent state CSAs if they accept out-of-state results or require a new check.

---

## 4. Screening Requirements

### 4.1 Before CJI Access

The following must be completed BEFORE production/CJI access is provisioned:

- [ ] CJIS Security Addendum signed (see `security-addendum-procedure.md`)
- [ ] Fingerprint-based background check submitted (results pending is acceptable IF escorted/supervised access per §5.12.1.2(1))
- [ ] Fingerprint-based background check cleared (for unescorted access)
- [ ] CJIS security awareness training completed (see `training-outline.md`)
- [ ] Personnel tracker updated

### 4.2 Disqualifying Findings

Per CJIS Security Policy §5.12.1.2:

- Any felony conviction
- Misdemeanor involving dishonesty (perjury, fraud, etc.) within the last 10 years
- Outstanding warrants
- Adjudicated as mentally incompetent

If a background check returns a disqualifying finding:
1. Individual is NOT granted CJI access
2. CEO makes final determination in consultation with customer agency
3. Decision is documented and filed

### 4.3 Pending Background Check

If a background check is submitted but results are pending:

- **Option A** (preferred): Delay CJI access until results received
- **Option B** (if operationally necessary): Grant supervised access only, with direct oversight by a cleared individual. Document the supervision arrangement.

---

## 5. Ongoing Personnel Security

### 5.1 Re-screening

| Trigger | Action |
|---------|--------|
| Every 5 years | Re-submit fingerprint-based background check (best practice) |
| State CSA requirement | Re-screen per state schedule (varies) |
| Arrest or legal issue | Self-reporting required; immediate review |
| Customer request | Re-screen upon agency request |

### 5.2 Self-Reporting

All personnel with CJI access must immediately report:

- Arrest or criminal charge (regardless of disposition)
- Restraining orders
- Changes in legal name
- Loss or theft of credentials or devices with system access

Failure to self-report is a policy violation per `policies/access-control.md` §11.

### 5.3 Termination / Separation

When a covered individual separates from Latent Archon:

| Step | Action | Timeline | Responsible |
|------|--------|----------|-------------|
| 1 | Disable all GCP IAM access | Same day | Engineering Lead |
| 2 | Revoke all Firebase/Identity Platform sessions | Same day | Engineering Lead |
| 3 | Revoke GitHub access | Same day | CEO |
| 4 | Update personnel tracker (mark "Separated") | Same day | Security Lead |
| 5 | Notify customer agencies per MCA requirements | Within 24 hours | CEO |
| 6 | Archive (do NOT destroy) signed addendum and background check records | Same day | Security Lead |

---

## 6. Records Management

### 6.1 What to Retain

| Record | Retention | Storage |
|--------|-----------|---------|
| Signed CJIS Security Addendum | Employment + 3 years | Encrypted storage / GCS evidence bucket |
| Background check clearance confirmation | Employment + 3 years | Encrypted storage / GCS evidence bucket |
| Fingerprint receipt/confirmation | Employment + 3 years | Encrypted storage |
| Personnel tracker | Active maintenance; archived versions indefinitely | `compliance/cjis/personnel-tracker.md` |
| Training completion records | Employment + 3 years | Compliance repository |
| Separation/termination records | 3 years post-separation | Encrypted storage |

### 6.2 What NOT to Retain

- Fingerprint images (retained only by FBI/state — Contractor does not store)
- Criminal history record details (Contractor receives cleared/not cleared only)
- Social Security numbers (not needed; fingerprint submission uses ORI, not SSN)

---

## 7. Personnel Tracker

See `security-addendum-procedure.md` §7 for the tracker format.

The tracker is the **single source of truth** for audit readiness. It must be updated:
- When a new person is onboarded
- When a background check status changes
- When training is completed
- When a person separates
- Before any audit

---

## 8. Costs

| Item | Approximate Cost | Paid By |
|------|-----------------|---------|
| Fingerprint-based background check | $40-100 per person per state | Latent Archon |
| IdentoGO appointment | Included in above | Latent Archon |
| CJIS Security Addendum | Free (FBI form) | N/A |
| CJIS security awareness training | Internal (no external cost) | Latent Archon |

**Budget estimate for a team of 5, one state**: ~$250-500 total.

---

*Next review date: March 2027*
