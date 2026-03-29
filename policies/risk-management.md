# Latent Archon — Risk Management Policy

> **Policy ID**: POL-RM-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Security Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: RA-1, RA-2, RA-3, PM-9, PM-28

---

## 1. Purpose

This policy establishes a systematic approach to identifying, assessing, treating, and monitoring information security risks to the Latent Archon platform. Risk management decisions drive security investments, control selection, and resource allocation.

---

## 2. Scope

This policy covers risks to:

- Customer data confidentiality, integrity, and availability
- Platform infrastructure and services
- Third-party and supply chain dependencies
- Regulatory and compliance obligations
- Business operations and reputation

---

## 3. Risk Management Framework

### 3.1 Process Overview

```
Identify → Assess → Treat → Monitor → Review
    ↑                                      |
    └──────────────────────────────────────┘
```

### 3.2 Risk Identification

Sources of risk identification:

| Source | Frequency | Examples |
|--------|-----------|---------|
| Threat intelligence | Continuous | CVE advisories, CSP security bulletins, CISA alerts |
| Vulnerability scanning | Continuous (CI) | Dependabot, Trivy, GoSec, govulncheck, Semgrep |
| Red team testing | Monthly | 44-attack automated suite (auth bypass, escalation, exfiltration) |
| Architecture reviews | On change | New service, new data flow, new vendor |
| Incident post-mortems | On occurrence | Lessons learned from security incidents |
| Compliance audits | Annual | Drata monitoring, framework gap analysis |
| Personnel input | Ongoing | Bug reports, security suggestions |

---

## 4. Risk Assessment Methodology

### 4.1 Scoring Matrix

Risks are scored on two dimensions: **Likelihood** (probability of occurrence) and **Impact** (severity if realized). Each is scored 1-5:

**Likelihood Scale**:

| Score | Label | Definition |
|-------|-------|-----------|
| 1 | Very Low | Unlikely to occur (< 5% annual probability) |
| 2 | Low | Could occur but not expected (5-20%) |
| 3 | Medium | Reasonably possible (20-50%) |
| 4 | High | More likely than not (50-80%) |
| 5 | Very High | Expected to occur (> 80%) |

**Impact Scale**:

| Score | Label | Definition |
|-------|-------|-----------|
| 1 | Negligible | No measurable effect on operations or data |
| 2 | Minor | Limited operational disruption, no data breach, self-contained |
| 3 | Moderate | Significant operational disruption or limited data exposure |
| 4 | Major | Extended service outage or confirmed data breach affecting customers |
| 5 | Critical | Catastrophic data breach, regulatory action, existential business impact |

### 4.2 Risk Score Calculation

```
Risk Score = Likelihood × Impact
```

| Risk Score | Rating | Response Required |
|------------|--------|-------------------|
| 1-4 | **Low** | Accept or monitor; document rationale |
| 5-9 | **Medium** | Treat within 90 days; assign owner |
| 10-15 | **High** | Treat within 30 days; CEO notification |
| 16-25 | **Critical** | Immediate treatment; CEO decision required |

### 4.3 Inherent vs. Residual Risk

- **Inherent risk**: Risk score before any controls are applied
- **Residual risk**: Risk score after controls and mitigations are in place
- Both scores are tracked in the risk register
- Residual risk that exceeds acceptable threshold requires additional treatment or formal acceptance

---

## 5. Risk Treatment

### 5.1 Treatment Options

| Option | Description | When Used |
|--------|------------|-----------|
| **Mitigate** | Implement controls to reduce likelihood or impact | Most common; default for Medium+ risks |
| **Transfer** | Shift risk to a third party (insurance, contractual) | When cost-effective and risk is insurable |
| **Accept** | Acknowledge risk without additional treatment | When residual risk is within appetite and treatment cost exceeds benefit |
| **Avoid** | Eliminate the activity or condition causing the risk | When risk cannot be adequately mitigated and activity is non-essential |

### 5.2 Treatment Plan Requirements

Each treated risk must have:

- Named treatment plan owner
- Specific controls or actions to implement
- Target completion date
- Measurable success criteria
- Residual risk re-assessment after implementation

---

## 6. Risk Register

### 6.1 Register Location

The authoritative risk register is maintained in **Drata** and synced automatically via the `drata-sync` CLI tool. A local copy is maintained in the compliance repository.

### 6.2 Current Risk Register Summary

| # | Risk | Category | Inherent | Residual | Treatment |
|---|------|----------|----------|----------|-----------|
| 1 | Unauthorized Access to Customer Data | Security | 20 (4×5) | 5 (1×5) | MFA, RLS, pool isolation, red team |
| 2 | Data Exfiltration via App Vulnerability | Security | 15 (3×5) | 5 (1×5) | RLS, WAF, SAST, input validation |
| 3 | Supply Chain Compromise | Security | 12 (3×4) | 4 (1×4) | SBOM, Dependabot, Trivy, distroless |
| 4 | Cloud Infrastructure Misconfiguration | Operational | 12 (3×4) | 4 (1×4) | IaC, org policies, drift detection |
| 5 | Denial of Service | Operational | 9 (3×3) | 4 (2×2) | WAF, auto-scaling, rate limiting |
| 6 | Insider Threat | Security | 10 (2×5) | 4 (1×4) | Least privilege, audit logging, PR review |
| 7 | Encryption Key Compromise | Security | 5 (1×5) | 5 (1×5) | Cloud KMS (HSM-backed), auto-rotation, IAM |
| 8 | Vendor/Third-Party Breach | Third-Party | 10 (2×5) | 6 (2×3) | Per-customer single-cloud, encryption, vendor monitoring |
| 9 | Data Loss / DR Failure | Operational | 10 (2×5) | 3 (1×3) | PITR, object storage versioning, multi-zone HA |
| 10 | Regulatory Non-Compliance | Compliance | 8 (2×4) | 4 (1×4) | Drata monitoring, SSP, formal policies |
| 11 | AI/ML Model Misuse / Prompt Injection | Security | 9 (3×3) | 4 (2×2) | Scoped retrieval, input validation, audit |
| 12 | CI/CD Pipeline Compromise | Security | 10 (2×5) | 4 (1×4) | WIF, branch protection, prod gates |

---

## 7. Risk Appetite

### 7.1 Risk Appetite Statement

Latent Archon maintains a **low risk appetite** for customer data security and regulatory compliance, and a **moderate risk appetite** for operational and business risks.

### 7.2 Thresholds

| Category | Maximum Acceptable Residual Score | Escalation |
|----------|----------------------------------|-----------|
| Customer data security | 6 (Low-Medium) | Risks > 6 require CEO decision |
| Regulatory compliance | 6 (Low-Medium) | Risks > 6 require immediate treatment plan |
| Operational continuity | 9 (Medium) | Risks > 9 require treatment within 30 days |
| Business/financial | 12 (Medium-High) | Risks > 12 require CEO decision |

---

## 8. Monitoring and Review

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Risk register review | Quarterly | Security Lead |
| Full risk re-assessment | Annual | CEO + Security Lead |
| New risk identification | Continuous | All personnel |
| Post-incident risk update | On occurrence | Incident Commander |
| Vulnerability-driven re-scoring | On critical CVE | Engineering |
| Drata risk register sync | Weekly (automated) | CI/CD |
| Red team results → risk update | Monthly | Engineering |

---

## 9. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| **CEO** | Approves risk appetite, accepts High/Critical residual risks, final authority on risk decisions |
| **Security Lead** | Maintains risk register, conducts assessments, reports to CEO, coordinates treatment |
| **Engineering Lead** | Implements technical controls, provides feasibility assessment for treatments |
| **All Personnel** | Report potential risks, participate in risk identification |

---

## 10. Integration with Other Policies

| Policy | Risk Integration |
|--------|-----------------|
| Incident Response (POL-IR-001) | Post-incident risk re-assessment |
| Change Management (POL-CM-001) | Change risk assessment for Significant changes |
| Vendor Risk (POL-VR-001) | Third-party risk scoring feeds risk register |
| Access Control (POL-AC-001) | Access-related risk mitigations |
| Encryption (POL-EN-001) | Cryptographic risk mitigations |

---

*Next review date: March 2027*
