# CJIS Management Control Agreement (MCA)

## Between Latent Archon, LLC and [AGENCY NAME]

---

> **Document ID**: MCA-[AGENCY-ABBREV]-001  
> **Version**: 1.0  
> **Effective Date**: [DATE]  
> **Expiration Date**: [DATE + 3 years, or per agency requirement]

---

## 1. Parties

**Contractor (Cloud Service Provider)**:  
Latent Archon, LLC  
Andrew Hendel, Chief Executive Officer  
ajhendel@latentarchon.com  
New York, NY

**Agency (Criminal Justice Agency)**:  
[Agency Name]  
[Agency Contact Name], [Title]  
[Agency Contact Email]  
[Agency Address]

---

## 2. Purpose

This Management Control Agreement establishes the terms, conditions, and security responsibilities under which Latent Archon, LLC ("Contractor") will provide cloud-based document intelligence services to [Agency Name] ("Agency") involving access to, processing of, and storage of Criminal Justice Information (CJI) as defined by the FBI CJIS Security Policy.

This agreement is required under CJIS Security Policy §5.1.1.5 and supplements any existing contract or service agreement between the parties.

---

## 3. Scope of Services

Latent Archon will provide the following services that involve CJI:

- Secure document upload, storage, and lifecycle management
- AI-powered search (Retrieval-Augmented Generation) over uploaded documents
- Interactive conversation interface with source citations over document collections
- Multi-tenant workspace isolation with organization-scoped access controls
- Enterprise SSO federation (SAML 2.0) and automated user provisioning (SCIM 2.0)
- Administrative dashboard for user management, document management, and audit review

---

## 4. Contractor Security Responsibilities

Latent Archon agrees to the following security responsibilities in compliance with the CJIS Security Policy v5.9.5:

### 4.1 Personnel Security

- All Contractor personnel with logical access to CJI will execute the CJIS Security Addendum prior to being granted access
- All Contractor personnel with access to CJI will undergo state and national fingerprint-based background checks through the appropriate state CSA
- Background checks will be completed before CJI access is provisioned
- Contractor will maintain a current list of all personnel with CJI access and provide it to Agency upon request
- Contractor will notify Agency within 24 hours of any personnel change (termination, role change) affecting CJI access

### 4.2 Security Awareness Training

- All Contractor personnel with CJI access will complete CJIS security awareness training within 6 months of initial access and biennially thereafter (Contractor exceeds this with annual training)
- Training will cover CJIS Security Policy requirements, CJI handling procedures, and incident reporting
- Training records will be maintained and available for audit

### 4.3 Access Controls

- CJI access is restricted to authorized personnel on a need-to-know basis
- Multi-factor authentication (TOTP) is enforced on all data endpoints
- Session timeouts are enforced (25-minute idle, 12-hour absolute; agency may configure stricter)
- Role-based access control limits each user to minimum necessary privileges
- All access events are audit-logged

### 4.4 Data Protection

- CJI is encrypted at rest using AES-256 with Customer-Managed Encryption Keys (CMEK) via Google Cloud KMS (FIPS 140-2 Level 3)
- CJI is encrypted in transit using TLS 1.2+ with FIPS 140-2 validated cryptography (BoringSSL, NIST cert #4407)
- CJI is logically isolated at the workspace level via PostgreSQL Row-Level Security (fail-closed)
- CJI is not stored on removable media or end-user devices
- All document uploads are scanned for malware (ClamAV, fail-closed in production)

### 4.5 Infrastructure

- All infrastructure is hosted on Google Cloud Platform (GCP), FedRAMP High authorized (FR1805181233)
- All services operate within a Virtual Private Cloud (VPC) with no public IP addresses
- Web Application Firewall (Cloud Armor) with OWASP Core Rule Set protects all endpoints
- FQDN-based egress firewall blocks all outbound traffic except approved GCP API endpoints
- Infrastructure is defined and managed as code (Terraform/Terragrunt) with no manual console changes

### 4.6 Incident Response

- Contractor will report any security incident involving CJI to Agency within 24 hours of discovery
- Contractor will report to the FBI CJIS Division ISO and the applicable state CSA per CJIS Security Policy §5.3
- Contractor maintains a documented incident response plan with defined roles, procedures, and escalation paths
- Contractor conducts monthly automated security testing (44 attack scenarios) and semi-annual tabletop exercises
- Evidence preservation procedures are in place for forensic investigation

### 4.7 Auditing

- Contractor will maintain audit logs of all CJI access for a minimum of one year
- Audit logs include: user identity, date/time, event type, success/failure, IP address, and action details
- Contractor will cooperate with Agency, state CSA, and FBI CJIS Division audits
- Contractor will provide audit log exports to Agency upon request within 5 business days

### 4.8 Configuration Management

- All system changes follow a documented change management process
- Changes to production systems require peer review, automated testing, and approval
- Baseline configurations are maintained in version-controlled infrastructure-as-code
- Vulnerability scanning (Dependabot, Trivy) is automated in CI/CD pipeline

### 4.9 Media and Data Disposal

- Upon contract termination, all Agency CJI will be permanently deleted within 30 days
- Deletion is verified and a certificate of destruction provided to Agency
- Cloud storage uses cryptographic erasure (key destruction) per NIST 800-88
- Database records are hard-deleted (not soft-deleted) with verification

---

## 5. Agency Responsibilities

Agency agrees to:

- Designate a Local Agency Security Officer (LASO) as the security point of contact
- Provide Contractor with the applicable state-specific CJIS Security Addendum form
- Coordinate fingerprint-based background checks for Contractor personnel through the state CSA
- Notify Contractor of any changes to Agency security requirements
- Manage end-user access within the platform (inviting/removing users, assigning roles)
- Ensure Agency end users comply with Agency's own CJIS policies and training requirements
- Notify Contractor within 24 hours of any Agency personnel termination requiring access revocation

---

## 6. State CSA Coordination

| Item | Responsible Party |
|------|------------------|
| Initial CSA engagement | Agency (introduces Contractor to CSA) |
| Background check submission | Contractor (submits; Agency/CSA processes) |
| Audit scheduling | State CSA |
| Audit cooperation | Both parties |
| Corrective action plans | Contractor (for Contractor findings); Agency (for Agency findings) |

---

## 7. Subcontractors

Contractor does not currently use subcontractors for CJI processing. If subcontractors are engaged in the future:

- Agency will be notified in writing 30 days prior
- Subcontractor personnel must meet all requirements of this agreement
- Subcontractor must execute a separate MCA or be covered under this agreement

---

## 8. Data Location

All CJI processed under this agreement is stored and processed within:

- **Region**: Google Cloud Platform `us-east4` (Moncks Corner, South Carolina)
- **Country**: United States (CONUS)
- **Backup region**: GCP-managed within CONUS

CJI will not be stored or processed outside the continental United States.

---

## 9. Right to Audit

Agency and/or the applicable state CSA and/or the FBI CJIS Division reserve the right to:

- Audit Contractor's compliance with this agreement and the CJIS Security Policy
- Request and receive audit logs, personnel lists, and security documentation
- Conduct on-site or remote security assessments with reasonable notice (30 days)

Contractor will cooperate fully with all audit requests and provide requested documentation within 5 business days.

---

## 10. Breach Notification

In the event of a confirmed or suspected breach involving CJI:

| Notification | Timeline | Method |
|-------------|----------|--------|
| Agency LASO | Within 24 hours | Phone + email |
| State CSA | Within 24 hours | Per state procedure |
| FBI CJIS Division ISO | Within 24 hours | cjis_iso@fbi.gov / (304) 625-2000 |
| Affected individuals (if PII involved) | Per applicable state breach notification law | Written notice |

---

## 11. Term and Termination

- This agreement is effective for **3 years** from the effective date, unless terminated earlier
- Either party may terminate with **60 days** written notice
- Upon termination, Contractor will complete data destruction per §4.9 within 30 days
- Sections 4.6 (Incident Response), 4.7 (Auditing), 4.9 (Data Disposal), and 9 (Right to Audit) survive termination

---

## 12. Signatures

**Latent Archon, LLC**

Signature: ___________________________  
Name: Andrew Hendel  
Title: Chief Executive Officer  
Date: _______________

**[Agency Name]**

Signature: ___________________________  
Name: [Agency Contact Name]  
Title: [Agency Contact Title]  
Date: _______________

**[Agency Name] — LASO**

Signature: ___________________________  
Name: [LASO Name]  
Title: Local Agency Security Officer  
Date: _______________

---

*This Management Control Agreement satisfies the requirements of FBI CJIS Security Policy §5.1.1.5.*
