# Latent Archon — Acceptable Use Policy

> **Policy ID**: POL-AU-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: PL-4, AC-8, AT-2

---

> **Organizational context**: Latent Archon is a founder-led, automation-first security organization. The CEO/ISSO directs all policy. As the team scales, all personnel will acknowledge this policy via Drata. See SOD-LA-001.

## 1. Purpose

This policy defines acceptable and prohibited uses of Latent Archon information systems, data, and resources by all personnel. It establishes expectations for responsible use and protects the organization, its customers, and its employees from security risks arising from misuse.

---

## 2. Scope

This policy applies to all employees, contractors, and temporary personnel who access:

- Latent Archon production and staging environments
- Source code repositories (GitHub)
- Cloud console and infrastructure (GCP)
<!-- MULTI-CLOUD: Original also listed AWS and Azure. -->
- Customer data in any form
- Internal communication systems
- Company-provided or company-connected devices

---

## 3. Acceptable Use

### 3.1 General Principles

- Use Latent Archon systems **only** for authorized business purposes
- Protect customer data as if it were your own confidential information
- Report security concerns or suspicious activity immediately
- Follow the principle of least privilege — access only what you need
- Keep all credentials, MFA devices, and access tokens secure and private

### 3.2 Authorized Activities

| Activity | Requirements |
|----------|-------------|
| Accessing production systems | MFA required, audit logged, business justification |
| Code development and review | Via approved tools (GitHub, approved IDE), signed commits preferred |
| Infrastructure management | Via Terragrunt/Terraform only (no ad hoc cloud CLI mutations) |
| Customer data access | Only for troubleshooting with customer consent, logged, minimized |
| Security testing | Only via approved red team tools on staging, with notification |
| Open-source contributions | Must not include proprietary code or customer data |

---

## 4. Prohibited Activities

### 4.1 Strictly Prohibited

The following are **strictly prohibited** and may result in immediate termination:

- Accessing customer data without business justification
- Sharing credentials, MFA tokens, or API keys with others
- Circumventing security controls (disabling MFA, bypassing auth, modifying audit logs)
- Exfiltrating customer data, source code, or proprietary information
- Installing unauthorized software on production infrastructure
- Using production systems for personal projects
- Connecting production databases to personal devices or non-approved tools
- Running unauthorized security tests against production systems
- Sharing customer data with unauthorized parties or AI services outside the platform

### 4.2 Prohibited Without Prior Approval

The following require explicit written approval from CTO or CEO:

- Granting new IAM roles at the cloud organization/account level
- Creating service account keys (also blocked by org/account policy)
- Modifying cloud org/account policies
- Adding new third-party services that process customer data
- Making emergency changes to production (per Change Management Policy)
- Accessing another employee's account or workspace

---

## 5. Data Handling

### 5.1 Customer Data Rules

- **Never** copy customer data to personal devices, email, or unapproved storage
- **Never** use customer data for testing (use synthetic data)
- **Never** share customer data in screenshots, demos, or support tickets without redaction
- **Never** use customer data to train AI models or for any purpose beyond the customer's service
- Customer data access must be logged via the application's audit system
- Access to customer data requires both authentication (MFA) and authorization (RBAC)

### 5.2 Credential and Secret Rules

- Use Workload Identity Federation / OIDC for cloud authentication (no service account keys)
- Store all secrets in GitHub Actions secrets or container environment variables
- **Never** commit secrets, API keys, or tokens to source code repositories
- Use unique passwords for all Latent Archon accounts
- Report lost or compromised credentials immediately

---

## 6. Infrastructure Use

### 6.1 Production Environment

- All production changes **must** go through the CI/CD pipeline (PR → review → merge → deploy)
- Direct cloud CLI mutations to production are **prohibited** (enforced by CLI guardrail wrappers)
- Terraform is the only authorized method for infrastructure changes
- Production deployment requires manual approval via GitHub environment gate
- Emergency changes follow the Emergency Change procedure in POL-CM-001

### 6.2 Staging Environment

- Staging may be used for development, testing, and security testing
- Red team testing is permitted on staging only (with team notification)
- Staging must not contain real customer data

### 6.3 Source Code

- All code changes via pull request with at least one reviewer
- Branch protection enforced on `main` (no force push, no self-merge)
- Code review includes security review for sensitive changes
- Open-source dependencies must be from approved sources with compatible licenses

---

## 7. Communication and Reporting

### 7.1 Security Incident Reporting

All personnel **must** report suspected security incidents immediately, including:

- Unauthorized access attempts or suspicious activity
- Lost or stolen devices with access to Latent Archon systems
- Phishing attempts targeting Latent Archon personnel
- Suspected data breaches or data exposure
- Vulnerabilities discovered in Latent Archon systems

Report to: CEO / ISSO via direct message (per Incident Response Policy)

### 7.2 Whistleblower Protection

Personnel who report security concerns in good faith are protected from retaliation, regardless of the outcome of the investigation.

---

## 8. Personal Device Use

### 8.1 Requirements for Personal Devices Accessing Company Systems

- Full-disk encryption enabled
- Screen lock with biometric or strong password (< 5 min timeout)
- Operating system and browser kept up to date
- Company GitHub account protected with MFA
- No jailbroken or rooted devices

### 8.2 Device Loss or Theft

- Report immediately to CEO / ISSO
- Remote session revocation initiated for all active sessions
- GitHub personal access tokens revoked
- Cloud access reviewed and revoked if needed

---

## 9. Monitoring and Enforcement

### 9.1 Monitoring

Latent Archon systems are monitored for policy compliance. Monitoring includes:

- Cloud audit logs for all cloud API calls
- Application audit events for data access
- GitHub audit logs for repository access and changes
- WAF logs for network-level activity

### 9.2 Enforcement

| Violation Severity | Example | Consequence |
|-------------------|---------|-------------|
| **Minor** | Accessing staging without MFA, missing code review | Verbal warning, coaching |
| **Moderate** | Unauthorized access to customer data, sharing credentials | Written warning, mandatory retraining |
| **Severe** | Data exfiltration, circumventing security controls | Immediate access revocation, termination, potential legal action |

### 9.3 Policy Acknowledgment

All personnel must:

- Read and acknowledge this policy within 5 business days of onboarding
- Re-acknowledge annually upon policy renewal
- Acknowledgment tracked via Drata personnel compliance checks

---

*Next review date: March 2027*
