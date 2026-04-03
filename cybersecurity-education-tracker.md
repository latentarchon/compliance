# Cybersecurity Education — Training & Testing Evidence Tracker

> **Document ID**: EDU-LA-001  
> **Version**: 1.0  
> **Date**: April 2026  
> **Owner**: ISSO (CEO)  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: AT-2, AT-3, AT-4, IR-2

---

## 1. Purpose

This document tracks completion of security awareness training, role-based training, and persistent testing of security competence for all Latent Archon personnel. It serves as the evidence artifact for the FedRAMP 20x Cybersecurity Education KSI theme.

---

## 2. Training Completion Log

### 2.1 Security Awareness Training (Annual)

| Name | Role | Training Module | Completion Date | Certificate/Record | Next Due |
|------|------|----------------|-----------------|-------------------|----------|
| Andrew Hendel | CEO / ISSO | Security Awareness Fundamentals | April 2026 | Drata personnel compliance | April 2027 |

### 2.2 Role-Based Training (Annual)

| Name | Role | Training Topic | Completion Date | Certificate/Record | Next Due |
|------|------|---------------|-----------------|-------------------|----------|
| Andrew Hendel | CEO / Engineer | OWASP Top 10 + Secure Go Development | April 2026 | Internal | April 2027 |
| Andrew Hendel | CEO / DevOps | Cloud Security (GCP/AWS/Azure), Terraform Security, IAM | April 2026 | Internal | April 2027 |
| Andrew Hendel | CEO / Management | Risk Management, NIST 800-53, FedRAMP 20x | April 2026 | Internal | April 2027 |

### 2.3 Incident Response Training (Annual)

| Name | Role | Exercise Type | Completion Date | Report Reference | Next Due |
|------|------|--------------|-----------------|-----------------|----------|
| Andrew Hendel | Incident Commander | Tabletop Exercise (IR-3) | Monthly (automated) | Red team reports in Drata | Continuous |

### 2.4 Rules of Behavior Acceptance (Annual + Onboarding)

| Name | Role | ROB Version | Acceptance Date | Client App | Record |
|------|------|-------------|-----------------|------------|--------|
| Andrew Hendel | CEO / ISSO | 1.0 | Pending first login | app, admin | `rob_acceptances` DB table |

---

## 3. Persistent Testing of Security Competence

### 3.1 Phishing Simulation Campaigns

| Campaign ID | Date | Type | Target | Result | Follow-Up |
|-------------|------|------|--------|--------|-----------|
| PHISH-2026-Q2 | Q2 2026 | Simulated phishing email | All personnel | Scheduled | Training remediation if clicked |

**Process**:
1. Simulated phishing emails sent semi-annually (per POL-AT-001 §3.1)
2. Results tracked: delivered, opened, clicked, reported
3. Personnel who click receive immediate remediation training
4. Aggregate results uploaded to Drata evidence library

### 3.2 Automated Security Testing Evidence

The following automated tests run on a recurring schedule and serve as persistent evidence of security competence in the organization's security operations:

| Test | Frequency | Evidence | NIST Control |
|------|-----------|----------|--------------|
| **Red team attack suite** (44 attacks, 3 suites) | Monthly (1st) | MITRE ATT&CK mapped report → Drata | IR-3, CA-8 |
| **Contingency plan test** (CP-4) | Monthly (1st) | Backup/PITR/health report → Drata | CP-4 |
| **IaC drift detection** | Weekly | Terraform plan diff | CM-3 |
| **Vulnerability scanning** (Trivy) | Every build | Scan results in CI logs | RA-5 |
| **Dependency monitoring** (Dependabot) | Continuous | Auto-PRs for vulnerable deps | RA-5 |
| **KSI evidence collection** | Weekly | Cloud config evidence → GitHub artifacts | CA-7 |
| **SCN classification** | Every PR | SIGNIFICANT/ROUTINE classification | CM-3 |
| **OSCAL SSP validation** | Every commit | Schema + oscal-cli validation | CA-2 |

### 3.3 Knowledge Verification

| Assessment | Audience | Frequency | Method | Passing Score |
|-----------|----------|-----------|--------|---------------|
| Security awareness quiz | All personnel | Annual (with training) | Online quiz | 80% |
| Incident response drill | IR team | Semi-annual (tabletop) | Scenario walkthrough | Participation required |
| Secure coding review | Engineers | Per PR | Code review checklist | Approval required |

---

## 4. New Hire Onboarding Checklist

- [ ] Security awareness training completed (within 5 business days)
- [ ] Role-based training completed (within 10 business days)
- [ ] Rules of Behavior accepted (enforced in-app on first login)
- [ ] Acceptable Use Policy acknowledged (Drata)
- [ ] NDA signed
- [ ] Background check initiated (if CJI access required)
- [ ] Added to this tracker

---

## 5. Evidence Retention

| Evidence Type | Retention Period | Storage Location |
|---------------|-----------------|------------------|
| Training completion records | 3 years minimum | Drata + this document |
| Phishing simulation results | 3 years minimum | Drata evidence library |
| Red team reports | 365 days (CI artifacts) + Drata | GitHub Actions + Drata |
| ROB acceptance records | Indefinite | `rob_acceptances` database table |
| Incident response exercise records | 3 years minimum | Drata evidence library |

---

*Next review: April 2027*
