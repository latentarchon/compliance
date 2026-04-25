# Manual Controls

Generated: 2026-04-25

Total: 25 controls


## AT Family

### AT-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Security Awareness and Training Policy (POL-AT-001) requiring annual security awareness training for all personnel and role-based training for privileged users. The policy is reviewed annually and updated as needed. Training completion is tracked via Drata.

---

### AT-2

**Status:** implemented | **Baseline:** moderate

Security awareness training is provided to all personnel within 30 days of onboarding and annually thereafter. Training covers: phishing, social engineering, insider threats, CUI handling, incident reporting, password security, and secure development practices. Monthly CP-4/IR-3/AT-2 exercises are conducted via automated Cloud Build cron.

---

### AT-2.2

**Status:** implemented | **Baseline:** moderate

Insider threat awareness is included in security awareness training. Personnel are trained to recognize indicators of insider threats including: unauthorized data exfiltration, unusual access patterns, policy violations, and social engineering targeting internal personnel.

---

### AT-3

**Status:** implemented | **Baseline:** moderate

Role-based security training is provided to personnel with assigned security roles: (1) Developers receive secure coding training (OWASP Top 10, NIST guidelines); (2) Operations personnel receive incident response and contingency plan training; (3) Security personnel receive NIST 800-53 control assessment training. Training occurs within 30 days of role assignment and annually.

---

### AT-4

**Status:** implemented | **Baseline:** moderate

Security training records are maintained in Drata. Records include: trainee name, training date, training type, completion status, and expiration date. Records are retained for the duration of employment plus 3 years.

---


## PE Family

### PE-3

**Status:** inherited | **Baseline:** high

Physical access control is fully inherited from Google Cloud Platform's FedRAMP High authorization. GCP data centers implement multi-layer physical security including badge access, biometric verification, security guards, video surveillance, and mantrap entry systems.

---


## PL Family

### PL-4

**Status:** implemented | **Baseline:** moderate

Rules of behavior are established for all personnel: (1) acceptable use of system resources; (2) CUI handling requirements; (3) security incident reporting obligations; (4) consequences of non-compliance. All personnel acknowledge rules of behavior before being granted system access.

---

### PL-4.1

**Status:** implemented | **Baseline:** moderate

Rules of behavior include social media and networking restrictions: personnel are prohibited from posting CUI, system architecture details, security configurations, or vulnerability information on social media or public forums.

---


## PM Family

### PM-2

**Status:** implemented | **Baseline:** moderate

The CEO serves as the Senior Information Security Officer (SISO) responsible for: (1) security program oversight; (2) risk management decisions; (3) authorization decisions; (4) resource allocation for security activities.

---


## PS Family

### PS-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Personnel Security Policy (POL-PS-001) defining screening requirements, access agreements, and termination procedures. The policy is reviewed annually.

---

### PS-2

**Status:** implemented | **Baseline:** moderate

Position risk designations are assigned based on the level of system access: (1) engineers with infrastructure access — high risk; (2) support personnel with limited access — moderate risk; (3) all positions are reviewed annually for appropriate risk designation.

---

### PS-3

**Status:** implemented | **Baseline:** moderate

Personnel screening includes background investigations appropriate to position risk level. Screening is completed before granting system access. Rescreening occurs every 5 years for high-risk positions.

---

### PS-4

**Status:** implemented | **Baseline:** moderate

Personnel termination procedures: (1) system access disabled within 4 hours of termination notification; (2) GCP IAM permissions revoked; (3) GitHub organization access removed; (4) Cloudflare access revoked; (5) exit interview conducted covering security obligations; (6) all company equipment collected.

---

### PS-5

**Status:** implemented | **Baseline:** moderate

Personnel transfer procedures: (1) access reviewed within 24 hours of transfer; (2) IAM permissions adjusted to new role requirements; (3) unnecessary access revoked; (4) transfer documented in personnel records.

---

### PS-6

**Status:** implemented | **Baseline:** moderate

Access agreements are signed by all personnel before system access is granted. Agreements cover: (1) acceptable use; (2) CUI handling obligations; (3) security incident reporting; (4) non-disclosure; (5) consequences of non-compliance. Agreements are reviewed and re-signed annually.

---

### PS-7

**Status:** implemented | **Baseline:** moderate

Third-party personnel security requirements: (1) all contractors subject to same screening requirements as employees; (2) third-party access limited to minimum necessary; (3) third-party access monitored and audited; (4) third-party access agreements required.

---

### PS-8

**Status:** implemented | **Baseline:** moderate

Personnel sanctions for non-compliance include: (1) verbal warning; (2) written warning; (3) access suspension; (4) termination. Sanctions are applied based on severity and frequency of the violation. All sanctions are documented.

---


## PT Family

### PT-1

**Status:** implemented | **Baseline:** moderate

Latent Archon maintains a Privacy Policy that governs the collection, use, retention, and disclosure of PII. The policy is published on the company website and reviewed annually.

---

### PT-2

**Status:** implemented | **Baseline:** moderate

Authority to collect PII is established through: (1) customer service agreements; (2) terms of service; (3) privacy policy; (4) applicable federal regulations (32 CFR 2002 for CUI). Collection is limited to what is necessary for system functionality.

---

### PT-3

**Status:** implemented | **Baseline:** moderate

Purpose specification: PII is collected and processed solely for: (1) user authentication and account management; (2) audit logging; (3) customer support. PII is not used for marketing, profiling, or purposes beyond the stated scope.

---

### PT-4

**Status:** implemented | **Baseline:** moderate

Consent for PII processing is obtained through: (1) terms of service acceptance; (2) system use notification banner acknowledgment; (3) privacy policy acceptance. Users are informed of data processing purposes before providing PII.

---

### PT-5

**Status:** implemented | **Baseline:** moderate

Privacy notice: users are provided with clear, accessible information about: (1) what PII is collected; (2) why it is collected; (3) how it is used; (4) with whom it may be shared; (5) how long it is retained; (6) how to exercise privacy rights.

---

### PT-6

**Status:** implemented | **Baseline:** moderate

System of records: PII is maintained in: (1) Firebase Identity Platform (auth data); (2) Cloud SQL (user profiles, org memberships); (3) audit logs (user actions). Each store has defined retention periods and access controls.

---

### PT-7

**Status:** implemented | **Baseline:** moderate

Data minimization: the system collects only the minimum PII necessary: (1) email address (authentication); (2) display name (UI); (3) IP address (security logging). No SSN, date of birth, or other unnecessary PII is collected.

---

### PT-8

**Status:** implemented | **Baseline:** moderate

Accuracy of PII: (1) users can update their display name and email via account settings; (2) SCIM synchronization keeps user attributes current with the authoritative IdP; (3) stale accounts are disabled after 90 days of inactivity.

---

