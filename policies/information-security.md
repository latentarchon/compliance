# Latent Archon — Information Security Policy

> **Policy ID**: POL-IS-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: PL-1, PL-2, PM-1, PM-2, PM-9, PM-10, PM-11

---

> **Organizational context**: Latent Archon is a founder-led, automation-first security organization. The CEO/ISSO directs all security functions while an integrated automation workforce independently executes scanning, deployment, monitoring, and evidence collection. As the team scales, role-specific duties will transfer to dedicated personnel (POA-15, POA-16). See SOD-LA-001 for the automation-first security architecture.

## 1. Purpose

This policy establishes the overarching information security program for Latent Archon, defining security objectives, governance structure, roles and responsibilities, and the framework for all subordinate security policies. As a provider of CUI-grade document intelligence services to U.S. government agencies, Latent Archon is committed to protecting the confidentiality, integrity, and availability of all information assets.

---

## 2. Scope

This policy applies to:

- All Latent Archon employees, contractors, and temporary personnel
- All information systems, data, and infrastructure operated by Latent Archon
- All third-party services processing Latent Archon or customer data
- All development, staging, and production environments

### 2.1 Personnel Eligibility — US Person Requirement

All personnel with logical or physical access to Latent Archon information systems, source code repositories, CI/CD pipelines, cloud infrastructure, or customer data **must be United States persons** as defined by 22 CFR § 120.62 (U.S. citizens, lawful permanent residents, or protected individuals under 8 U.S.C. § 1324b(a)(3)).

This requirement applies to:

- All employees regardless of role or access level
- All contractors, subcontractors, and temporary personnel
- All third-party assessors (3PAOs) and auditors with system access

**Rationale**: The system operates within GCP IL5 Assured Workloads processing CUI and DoD mission data. DFARS 252.204-7012, the DoD Cloud Computing SRG (IL5), and GCP Assured Workloads personnel controls require US person access restrictions for all personnel handling controlled information or administering systems that process it.

**Verification**: US person status is verified during pre-employment screening (PS-3) through government-issued identification. Verification records are retained in HR files. Contractor agreements must include a US person attestation clause. Status is re-verified upon contract renewal or position change.

**Exceptions**: None. This requirement has no exception process. Foreign nationals may not be granted access to Latent Archon systems under any circumstances, including temporary or read-only access.

---

## 3. Security Objectives

| Objective | Description |
|-----------|-------------|
| **Confidentiality** | Protect customer data (documents, messages, workspace content) from unauthorized disclosure through encryption, access control, and tenant isolation |
| **Integrity** | Ensure data is not modified without authorization through audit logging, input validation, and cryptographic integrity checks |
| **Availability** | Maintain service availability through multi-zone HA, automated backups, disaster recovery procedures, and incident response capabilities |

---

## 4. Governance Structure

### 4.1 Roles and Responsibilities

| Role | Security Responsibilities |
|------|--------------------------|
| **CEO / ISSO** | Security program leadership: policy, technical decisions, architecture, incident response, compliance monitoring, risk acceptance | Andrew Hendel |
| **CI/CD System** | Independent automated security scanning, deployment gating, drift detection — acts as second actor | GitHub Actions / Cloud Build |
| **Customer Admin** | Security awareness within their org; incident reporting; acceptable use adherence | Per-customer agency |

### 4.2 Policy Hierarchy

| Level | Document | Purpose |
|-------|----------|---------|
| **1 — Program** | Information Security Policy (this document) | Overarching security program governance |
| **2 — System** | FedRAMP System Security Plan (SSP-LA-001) | NIST 800-53 High baseline (IL5) control mapping + implementation narratives |
| **3 — Technical** | Security Architecture Whitepaper | Detailed technical security implementation |
| **4 — Operational** | Subordinate Policies | Domain-specific requirements (see Section 5) |

---

## 5. Subordinate Policies

The following policies implement specific domains of the information security program:

| Policy | ID | Domain |
|--------|-----|--------|
| Access Control Policy | POL-AC-001 | Authentication, authorization, data isolation, network access |
| Change Management Policy | POL-CM-001 | Change control, configuration management, CI/CD security |
| Incident Response Policy | POL-IR-001 | Incident detection, response, recovery, notification |
| Vendor Risk Management Policy | POL-VR-001 | Third-party risk, supply chain security, subprocessors |
| Encryption Policy | POL-EN-001 | Data encryption, key management, cryptographic standards |
| Data Classification & Retention Policy | POL-DC-001 | Data classification, handling, retention, disposal |
| Business Continuity & Disaster Recovery Policy | POL-BC-001 | Continuity planning, backup, recovery procedures |
| Risk Management Policy | POL-RM-001 | Risk assessment, treatment, monitoring |
| Acceptable Use Policy | POL-AU-001 | Acceptable system use, prohibited activities |
| Security Awareness & Training Policy | POL-AT-001 | Training requirements, awareness program |
| Physical Security Policy | POL-PE-001 | Physical access, environmental controls |

---

## 6. Compliance Framework

### 6.1 Primary Framework

Latent Archon's security program is based on **NIST SP 800-53 Rev. 5 High** baseline with DoD IL5 requirements, selected because:

- Aligns with FedRAMP High and DoD IL5 requirements for government SaaS handling CUI and DoD mission data
- Provides comprehensive coverage across 17 control families
- Satisfies DFARS 252.204-7012 and CUI protection requirements (NIST SP 800-171)
- Maps cleanly to SOC 2 Trust Services Criteria
- Enforced at the infrastructure layer by GCP IL5 Assured Workloads

### 6.2 Continuous Compliance

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Drata automated compliance monitoring | Continuous | Automated (CEO verifies) |
| Red team attack suite execution | Monthly | Automated (CEO reviews) |
| Policy review and update | Annual | CEO / ISSO |
| Access review | Quarterly | CEO / ISSO + automated drift checker |
| Vulnerability scanning (Dependabot + Trivy) | Continuous (automated) | Automated |
| Risk assessment review | Annual | CEO / ISSO |
| Penetration testing | Annual (external) | 3PAO (POA-1) |

---

## 7. Risk Management

Latent Archon maintains a formal risk register (managed in Drata) with:

- **12 identified risks** across Security, Operational, Third-Party, and Compliance categories
- **Quantitative scoring**: Inherent (likelihood × impact) → Controls → Residual (likelihood × impact)
- **Treatment plans** documented for each risk with specific control references
- **Annual review** with re-scoring based on threat landscape changes

---

## 8. Incident Management

Security incidents are managed under the Incident Response Policy (POL-IR-001) with:

- 4 severity levels (SEV-1 through SEV-4) with MITRE ATT&CK mapping
- Defined response team with primary and backup personnel
- Automated detection via dual-layer WAF (Cloudflare Edge + Cloud Armor), audit event alerting, and red team monitoring dashboard
- Customer notification timelines (24 hours for confirmed breaches)
- Post-incident review with lessons learned and POA&M tracking

---

## 9. Security Architecture Principles

| Principle | Implementation |
|-----------|---------------|
| **Defense in Depth** | 5-layer org isolation (interceptor → RLS → DB roles → vector scoping → audit) |
| **Least Privilege** | Separate DB roles per service, per-service IAM, no shared credentials |
| **Zero Trust** | All requests authenticated and authorized; no implicit trust based on network position; Cloudflare Zero Trust Access for admin endpoints (identity gate at edge) |
| **Encryption Everywhere** | AES-256 at rest, TLS 1.2+ in transit, CMEK via cloud KMS (HSM-backed), FIPS 140-2 BoringCrypto |
| **Immutable Infrastructure** | Distroless containers, IaC-managed, no SSH access to production |
| **Separation of Duties** | Admin/app auth pool isolation, PR review requirements, production deploy gates |
| **Audit Everything** | Comprehensive audit_events table + cloud audit logs + object storage versioning |

---

## 10. Exceptions

Exceptions to any security policy require:

- Written justification including business need and risk assessment
- Compensating controls identified
- CEO or CTO approval (depending on risk tier)
- Maximum 90-day exception period (renewable with re-approval)
- Documentation in Drata with tracking and review

---

## 11. Enforcement

- All personnel are required to read and acknowledge this policy and all applicable subordinate policies
- Policy violations are investigated and may result in disciplinary action up to and including termination
- Security incidents resulting from policy violations are documented and tracked
- Repeated violations or willful disregard for security policies may result in immediate access revocation

---

## 12. Policy Maintenance

| Activity | Frequency | Trigger |
|----------|-----------|---------|
| Scheduled review | Annual | Calendar |
| Regulatory change review | On occurrence | New regulation or framework update |
| Incident-driven review | On occurrence | Post-incident findings |
| Architecture change review | On occurrence | Significant infrastructure or application changes |

---

*Next review date: March 2027*
