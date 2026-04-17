# Contractor Security Addendum

> **Template ID**: CSA-TPL-001
> **Version**: 1.0
> **Date**: April 2026
> **Parent Documents**: POL-IS-001 §2.1, SOP-HR-001, SSP-LA-001 PS-7
> **NIST 800-53 Controls**: PS-7, PS-3, PS-6, AT-2

---

This Contractor Security Addendum ("Addendum") is entered into as an addendum to the agreement ("Agreement") between Latent Archon, LLC ("Company") and the contractor identified below ("Contractor").

## Contractor Information

| Field | Value |
|-------|-------|
| **Contractor Name** | ________________________ |
| **Company/Organization** | ________________________ |
| **Contract Start Date** | ________________________ |
| **Contract End Date** | ________________________ |
| **Scope of Work** | ________________________ |
| **Systems/Repos Accessed** | ________________________ |
| **Internal Sponsor** | ________________________ |
| **Position Risk Designation** | High / Moderate / Low |

---

## 1. US Person Attestation (Required — No Exceptions)

### 1.1 Attestation

The Contractor attests and certifies the following:

> I, the undersigned, attest that I am a **United States person** as defined by 22 CFR § 120.62, specifically: a citizen of the United States, a lawful permanent resident as defined by 8 U.S.C. § 1101(a)(20), or a protected individual as defined by 8 U.S.C. § 1324b(a)(3).
>
> I understand that:
>
> 1. This attestation is a mandatory prerequisite for access to Latent Archon information systems.
> 2. Latent Archon systems process Controlled Unclassified Information (CUI) within DoD Impact Level 5 (IL5) Assured Workloads.
> 3. US person status is required by DFARS 252.204-7012, the DoD Cloud Computing Security Requirements Guide (CC SRG), and GCP Assured Workloads personnel controls.
> 4. A false attestation constitutes a material breach of this Agreement and may result in immediate termination and legal action.
> 5. If my US person status changes during the contract period, I must notify the Company within 24 hours.

### 1.2 If Contractor is an Organization

If the Contractor is an organization (not an individual), the Contractor certifies that **all personnel** who will access Latent Archon systems under this Agreement are US persons. The Contractor must:

- Maintain a list of all personnel with system access and provide it to Company upon request
- Verify US person status of each individual before granting system access
- Notify Company within 24 hours if any non-US-person is inadvertently granted access
- Remove any non-US-person's access immediately upon discovery

---

## 2. Background Screening

### 2.1 Screening Requirements

The Contractor agrees to undergo (or ensure all accessing personnel undergo) background screening appropriate to the position risk designation, including:

- **All positions**: Identity verification and criminal history check (7-year, all jurisdictions)
- **High Risk positions**: Employment verification (5 years), education verification, and professional reference checks

### 2.2 Screening Responsibility

- [ ] **Option A**: Company will conduct background screening at Company's expense
- [ ] **Option B**: Contractor will provide evidence of equivalent background screening conducted within the past 12 months

---

## 3. Security Obligations

The Contractor agrees to the following security obligations:

### 3.1 Access Controls

- Access is limited to the specific systems, repositories, and cloud projects identified in the Contractor Information table above
- All access requires multi-factor authentication (MFA) enrollment
- Access credentials must not be shared with any other individual
- The Contractor must report any suspected credential compromise within 1 hour

### 3.2 Data Handling

- Contractor must not store Company or customer data on personal devices unless encrypted with full-disk encryption (FileVault or BitLocker)
- Contractor must not transmit Company or customer data to personal email accounts or unauthorized cloud storage
- Contractor must not copy, export, or exfiltrate customer data outside the authorization boundary
- All CUI must be handled in accordance with NIST SP 800-171 and 32 CFR 2002

### 3.3 Incident Reporting

- The Contractor must report any suspected security incident to the Company's security contact within 1 hour of discovery
- Security incidents include: unauthorized access, data exposure, malware, phishing attempts, lost/stolen devices, and suspicious activity

### 3.4 Acceptable Use

- The Contractor has read and agrees to comply with the Company's Acceptable Use Policy (POL-AU-001)
- The Contractor has read and agrees to comply with the Company's Rules of Behavior

---

## 4. Non-Disclosure

The Contractor agrees to the following confidentiality obligations:

- All information regarding Company systems, architecture, security controls, customer data, and business operations is confidential
- Confidential information must not be disclosed to any third party without written authorization
- These obligations survive the termination of this Agreement for a period of 3 years

---

## 5. Security Training

The Contractor agrees to complete the following security training before accessing Company systems:

| Training Module | Requirement |
|----------------|-------------|
| Security Awareness Fundamentals (SAT-001) | Within 5 business days of access provisioning |
| CUI Handling & Data Protection (SAT-006) | Within 5 business days of access provisioning |
| Incident Response Procedures (SAT-004) | Within 5 business days of access provisioning |
| Role-specific training (if applicable) | Within 10 business days of access provisioning |

Annual re-training is required for contracts exceeding 12 months.

---

## 6. Access Termination

Upon contract completion, termination, or expiration:

- All system access will be revoked within 4 hours (same-day for involuntary termination)
- The Contractor must return or certify destruction of all Company data, credentials, and materials
- The Contractor must confirm deletion of any locally stored Company data
- Post-termination confidentiality obligations remain in effect per §4

---

## 7. Compliance Verification

The Company reserves the right to:

- Audit the Contractor's compliance with this Addendum at any time
- Review access logs and audit trails for the Contractor's system activity
- Require additional security measures based on evolving threat landscape or regulatory requirements
- Terminate access immediately if any provision of this Addendum is violated

---

## 8. Signatures

### Contractor

| Field | Value |
|-------|-------|
| **Signature** | ________________________ |
| **Printed Name** | ________________________ |
| **Title** | ________________________ |
| **Date** | ________________________ |

### Latent Archon, LLC

| Field | Value |
|-------|-------|
| **Signature** | ________________________ |
| **Printed Name** | ________________________ |
| **Title** | CEO / ISSO |
| **Date** | ________________________ |

---

_End of Contractor Security Addendum — CSA-TPL-001_
