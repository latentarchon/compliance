# Latent Archon — CJIS Security Awareness Training Outline

> **Document ID**: CJIS-TR-001  
> **Version**: 1.0  
> **Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Delivery**: Self-paced module + acknowledgment  
> **Duration**: ~45 minutes  
> **Frequency**: Within 6 months of CJI access (CJIS minimum); annually thereafter (Latent Archon standard)  
> **CJIS Ref**: §5.2 — Security Awareness Training

---

## 1. Purpose

This training module satisfies the CJIS Security Policy §5.2 requirement that all personnel with access to Criminal Justice Information (CJI) receive security awareness training. It supplements Latent Archon's general security awareness training (POL-AT-001) with CJIS-specific content.

---

## 2. Audience

All Latent Archon personnel who have signed the CJIS Security Addendum and have (or will have) logical access to systems containing CJI.

---

## 3. Training Modules

### Module 1: What Is CJIS? (10 min)

- **FBI CJIS Division** — mission, role, scope
- **Criminal Justice Information (CJI)** — definition, examples
  - Criminal History Record Information (CHRI)
  - National Crime Information Center (NCIC) data
  - Identity History Summary (rap sheet)
  - Biometric data (fingerprints, mugshots)
  - Case files, arrest reports, investigative records
- **What CJI looks like in Latent Archon** — customer-uploaded documents that may contain CJI
- **Why it matters** — unauthorized disclosure can compromise investigations, endanger lives, and violate federal law
- **Criminal penalties** — unauthorized access or disclosure of CJI is a federal offense under 28 CFR Part 20 and applicable state laws

### Module 2: CJIS Security Policy Overview (10 min)

- **13 Policy Areas** — brief overview of each
- **CJIS Security Addendum** — what you signed and what it means
- **Management Control Agreement** — how Latent Archon's obligations connect to customer agencies
- **State CSA role** — who audits us and why
- **Your personal responsibility** — the addendum is a personal commitment, not just a company one
- **Sanctions** — policy violations can result in access revocation, termination, and criminal referral

### Module 3: Handling CJI in Latent Archon (10 min)

- **What you CAN do**:
  - Access production systems for authorized operational purposes
  - Deploy code through approved CI/CD pipelines
  - Respond to incidents per the incident response plan
  - View audit logs for security monitoring purposes
- **What you CANNOT do**:
  - Copy CJI to personal devices, USB drives, or personal cloud storage
  - Share CJI with anyone not authorized under the MCA
  - Access CJI outside of your job function (curiosity browsing)
  - Take screenshots of CJI
  - Discuss CJI content in unsecured channels (public Slack, personal email)
  - Disable or bypass security controls (MFA, session timeouts, RLS)
- **Data classification reminder** — all customer documents in law enforcement workspaces should be treated as CJI unless explicitly classified otherwise
- **Minimum necessary principle** — access only the data you need for your specific task

### Module 4: Incident Reporting for CJI (5 min)

- **What to report**:
  - Suspected unauthorized access to CJI
  - Lost or stolen devices with system access
  - Social engineering attempts targeting CJI
  - Any anomaly in audit logs related to CJI workspaces
  - Accidental exposure of CJI (wrong recipient, screen share, etc.)
- **How to report**:
  - Immediate verbal notification to Security Lead or CEO
  - Written incident report within 4 hours
  - Do NOT attempt to investigate on your own — preserve evidence
- **CJIS-specific reporting** — incidents involving CJI must be reported to the customer agency and state CSA within 24 hours (handled by Incident Commander)
- **No retaliation** — reporting suspected incidents is required and protected

### Module 5: Advanced Authentication & Physical Security (5 min)

- **MFA is non-negotiable** — CJIS requires advanced authentication for all CJI access
- **Session timeouts** — do not attempt to keep sessions alive; re-authenticate when prompted
- **Screen security** — lock screen when stepping away; use privacy screen in shared spaces
- **Clean desk** — no CJI on printed materials; if printed, cross-cut shred immediately
- **Secure environment** — ensure conversations about CJI cannot be overheard
- **Device security** — full-disk encryption, OS patches, firewall enabled

### Module 6: Background Checks & Ongoing Obligations (5 min)

- **Fingerprint-based background check** — why it's required, what happens with the results
- **Self-reporting obligation** — you MUST report arrests, charges, or legal issues immediately
- **Re-screening** — may be required periodically or upon state CSA request
- **Travel** — notify Security Lead if traveling internationally (CJIS access may be restricted)
- **Separation** — CJI access is revoked immediately upon separation; addendum obligations continue

---

## 4. Assessment

After completing the training modules, personnel must:

1. **Pass a short quiz** (10 questions, 80% passing score):
   - What is CJI? (definition)
   - Who must sign the CJIS Security Addendum?
   - What is the incident reporting timeline for CJI breaches?
   - Can you copy CJI to a USB drive? (No)
   - What is advanced authentication? (MFA)
   - What should you do if you suspect unauthorized CJI access?
   - What triggers a self-reporting obligation?
   - Where is Latent Archon CJI stored? (GCP us-east4)
   - Who is the state CSA? (State-specific criminal justice services agency)
   - What are the consequences of CJIS policy violations?

2. **Sign acknowledgment** confirming:
   - Completion of all 6 modules
   - Understanding of CJIS Security Policy obligations
   - Understanding of personal responsibilities under the Security Addendum
   - Commitment to report incidents per the reporting procedure

---

## 5. Training Records

| Record | System | Retention |
|--------|--------|-----------|
| Module completion | GCS evidence bucket | Employment + 3 years |
| Quiz score | GCS evidence bucket | Employment + 3 years |
| Signed acknowledgment | Compliance repository | Employment + 3 years |
| Trainer/facilitator (if live session) | Internal records | Employment + 3 years |

Records are available for audit by state CSA upon request.

---

## 6. Remediation

| Condition | Action |
|-----------|--------|
| Quiz score < 80% | Retake training and quiz within 5 business days |
| Training not completed within 30 days of due date | Reminder notification |
| Training not completed within 60 days | CJI access suspended until training completed |
| Repeated non-completion | Escalation to CEO; documented in personnel file |

---

## 7. Annual Refresher

Annual refresher training covers:

- Updates to CJIS Security Policy since last training (version changes)
- Recap of handling rules (Module 3)
- Recent incidents or near-misses (sanitized)
- Red team findings relevant to CJI protection
- Quiz (same format, updated questions)
- Re-acknowledgment

---

*Next review date: March 2027 (or upon CJIS Security Policy version update)*
