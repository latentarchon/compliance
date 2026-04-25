# Rules of Behavior

> **Document ID**: ROB-LA-001
> **Version**: 1.0
> **Effective Date**: April 2026
> **Owner**: Andrew Hendel, CEO / ISSO
> **Review Cycle**: Annual
> **NIST 800-53 Controls**: PL-4, PL-4(1), PS-6, AT-2

---

## 1. Purpose

These Rules of Behavior establish the security responsibilities and acceptable use standards for all individuals who access the Latent Archon Document Intelligence Platform. Acknowledgment of these rules is required before system access is granted, as required by FedRAMP and NIST SP 800-53 control PL-4.

---

## 2. Applicability

These rules apply to:
- All Latent Archon employees, contractors, and temporary personnel
- Third-party administrators with platform access
- Customer agency administrators (customer-specific rules in Section 7)

---

## 3. General Rules

### 3.1 Authentication and Access

- I will use only my assigned account credentials to access the system.
- I will enroll in and maintain multi-factor authentication (TOTP) as required.
- I will not share my credentials, MFA device, or session tokens with anyone.
- I will not attempt to access accounts, data, or workspaces that I am not authorized to use.
- I will lock or log out of my session when leaving my workstation unattended.
- I will report any suspected credential compromise to the CEO / ISSO immediately.

### 3.2 Data Handling

- I will handle all customer data as Controlled Unclassified Information (CUI) unless a higher classification is specified.
- I will not copy, download, or transfer customer data to personal devices or unauthorized systems.
- I will not store customer data in unapproved locations (personal email, cloud storage, USB drives).
- I will not share customer data with unauthorized individuals, including other customers.
- I will report any suspected data breach or unauthorized disclosure immediately.

### 3.3 System Use

- I will use the system only for authorized business purposes.
- I will not attempt to circumvent security controls, access controls, or audit mechanisms.
- I will not install unauthorized software or modify system configurations without approval.
- I will not introduce malware, test tools, or attack code into production or staging environments without explicit authorization from the CEO / ISSO.
- I will comply with all applicable federal, state, and local laws while using the system.

### 3.4 Infrastructure and Code

- I will follow the change management process for all code and infrastructure changes.
- I will not make out-of-band changes to cloud resources via console; all changes go through Terraform/Terragrunt.
- I will not commit secrets, credentials, API keys, or PII to source code repositories.
- I will review and address security scanner findings within the documented SLA timelines.
- I will not disable, bypass, or weaken security scanning in CI/CD pipelines.

### 3.5 Incident Reporting

- I will immediately report any suspected security incident, data breach, or policy violation to the CEO / ISSO.
- I will preserve evidence and not attempt to investigate or remediate on my own without coordination.
- I will cooperate fully with incident response and forensic investigation activities.
- I will not disclose incident details outside the authorized incident response team.

---

## 4. Social Media and External Site Restrictions (PL-4(1))

- I will not post system architecture details, security configurations, or internal procedures on social media or public forums.
- I will not discuss customer identities, agency relationships, or FedRAMP authorization status on personal social media without explicit approval.
- I will not use personal social media accounts for system administration or customer communication.
- I will obtain approval from the CEO before publishing any technical content related to the platform.

---

## 5. Remote Access Rules

- I will access the system only from approved devices with current security patches.
- I will use encrypted connections (TLS 1.2+) for all remote access.
- I will not access the system from public or shared computers.
- I will ensure my home network uses WPA2/WPA3 encryption.
- I will report any loss or theft of a device used to access the system within 1 hour.

---

## 6. Consequences of Non-Compliance

Violation of these rules may result in:
- Immediate suspension of system access
- Disciplinary action up to and including termination
- Referral to law enforcement for criminal violations
- Notification to affected customer agencies and FedRAMP PMO

---

## 7. Customer Agency Administrator Rules

Customer agency administrators with access to the Admin portal agree to:
- Manage user accounts within their organization only
- Enforce their agency's security policies for end users
- Report security incidents affecting their users to Latent Archon within 1 hour
- Not attempt to access other organizations' data or admin panels
- Comply with the session timeout and MFA requirements configured for their organization

---

## 8. Acknowledgment

By signing below, I acknowledge that I have read, understand, and agree to comply with these Rules of Behavior. I understand that violation may result in loss of access and disciplinary action.

| Field | Value |
|-------|-------|
| **Printed Name** | _________________________________ |
| **Signature** | _________________________________ |
| **Date** | _________________________________ |
| **Title/Role** | _________________________________ |
| **Organization** | _________________________________ |

---

## 9. Annual Re-Acknowledgment

These rules must be re-acknowledged annually. The CEO / ISSO maintains a log of all acknowledgments (via the compliance repository).

| Name | Role | Initial Acknowledgment | Last Re-Acknowledgment |
|------|------|----------------------|----------------------|
| Andrew Hendel | CEO / ISSO | April 2026 | — |

---

_End of Rules of Behavior — ROB-LA-001_
