# Latent Archon — Security Awareness & Training Policy

> **Policy ID**: POL-AT-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Security Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: AT-1, AT-2, AT-3, AT-4

---

## 1. Purpose

This policy establishes requirements for security awareness and training to ensure all personnel understand their security responsibilities and possess the skills needed to protect Latent Archon systems and customer data.

---

## 2. Scope

This policy applies to all employees, contractors, and temporary personnel with access to Latent Archon systems or data.

---

## 3. Training Requirements

### 3.1 Mandatory Training

| Training | Audience | Frequency | Delivery | Tracking |
|----------|----------|-----------|----------|----------|
| **Security Awareness** | All personnel | Annual + onboarding | Online module | Drata personnel compliance check |
| **Secure Development** | Engineers | Annual | Workshop / online | Drata + completion certificate |
| **Incident Response** | IR team members | Annual | Tabletop exercise | Exercise attendance record |
| **Phishing Awareness** | All personnel | Semi-annual | Simulated phishing campaign | Campaign results |
| **Policy Acknowledgment** | All personnel | Annual + onboarding | Drata policy acceptance | Drata assigned policies |

### 3.2 Role-Based Training

| Role | Additional Training Topics |
|------|---------------------------|
| **Engineers** | OWASP Top 10, secure coding in Go, SQL injection prevention, secrets management, container security, supply chain security |
| **DevOps / Infrastructure** | GCP security best practices, Terraform security, least-privilege IAM, network security, incident response procedures |
| **Management** | Risk management, regulatory compliance (NIST 800-53, FedRAMP), vendor risk assessment, security governance |
| **All Personnel** | Data classification, acceptable use, password/MFA hygiene, social engineering defense, reporting procedures |

---

## 4. Security Awareness Program

### 4.1 Onboarding (within first 5 business days)

New personnel must complete:

1. Read and acknowledge all applicable security policies (tracked in Drata)
2. Complete security awareness training module
3. Configure MFA on all Latent Archon accounts (Identity Platform TOTP)
4. Review the Acceptable Use Policy (POL-AU-001)
5. Review the Incident Response Policy (POL-IR-001) — know how to report
6. Background check initiation (tracked in Drata)

### 4.2 Ongoing Awareness Activities

| Activity | Frequency | Format |
|----------|-----------|--------|
| Security tips and advisories | Monthly | Email or Slack |
| CVE and threat briefings | As needed | Email summary |
| Policy update notifications | On change | Email + Drata re-acknowledgment |
| Red team results summary (sanitized) | Quarterly | Internal report |
| Security metrics dashboard | Continuous | Drata compliance dashboard |

### 4.3 Annual Refresher

All personnel must complete annual refresher training covering:

- Updates to security policies since last training
- Recent threat landscape changes relevant to Latent Archon
- Lessons learned from incidents (sanitized)
- Red team findings and remediation summary
- Compliance framework updates (NIST, FedRAMP, SOC 2)

---

## 5. Secure Development Training

### 5.1 Topics

Engineers must demonstrate competency in:

| Topic | Relevance to Latent Archon |
|-------|---------------------------|
| Input validation | All RPC endpoints validate inputs (length, type, UUID, enum) |
| SQL injection prevention | sqlc parameterized queries, PostgreSQL RLS |
| Authentication/authorization flaws | Firebase Auth, MFA enforcement, RBAC, pool isolation |
| Cryptographic best practices | FIPS 140-2 BoringCrypto, CMEK, TLS configuration |
| Secrets management | WIF (keyless auth), no SA keys, Gitleaks in CI |
| Dependency management | Dependabot, SBOM generation, vulnerability scanning |
| Container security | Distroless images, Trivy scanning, no shell access |
| AI/ML security | Prompt injection defenses, workspace-scoped retrieval |
| Secure code review practices | Security review checklist for PRs |

### 5.2 Practical Exercises

- Participate in code review of security-sensitive changes
- Review red team attack results and understand defense mechanisms
- Walk through incident response scenarios relevant to development

---

## 6. Incident Response Training

### 6.1 Tabletop Exercises

Semi-annual tabletop exercises covering scenarios such as:

- Customer data breach via application vulnerability
- Compromised CI/CD pipeline
- Insider threat / unauthorized data access
- DDoS attack against production services
- Vendor (GCP) security incident
- Ransomware / crypto mining on infrastructure

### 6.2 Participation

- All IR team members (primary and backup) must participate
- Exercises documented with findings and improvement actions
- Results feed into risk register updates

---

## 7. Training Records

### 7.1 Tracking

All training completion is tracked via:

| Record Type | System | Retention |
|-------------|--------|-----------|
| Security awareness completion | Drata (personnel compliance check: `SECURITY_TRAINING`) | Employment + 3 years |
| Policy acknowledgment | Drata (assigned policies) | Employment + 3 years |
| Secure development training | Drata (evidence library) | Employment + 3 years |
| Tabletop exercise attendance | Drata (evidence library) | 3 years |
| Phishing simulation results | Training platform / Drata | 3 years |
| Background check completion | Drata (background checks) | Employment + 7 years |

### 7.2 Non-Compliance

| Condition | Action |
|-----------|--------|
| Training not completed within 30 days of due date | Automated reminder via Drata |
| Training not completed within 60 days | Manager notification, access review |
| Training not completed within 90 days | Access suspension until training completed |
| Repeated non-compliance | Documented in personnel file, escalated to CEO |

---

## 8. Training Effectiveness

### 8.1 Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Training completion rate | > 95% within 30 days of due date | Drata compliance dashboard |
| Phishing simulation click rate | < 10% | Phishing platform reports |
| Policy acknowledgment rate | 100% within 5 days of publication | Drata assigned policies |
| Time to MFA enrollment | < 24 hours from account creation | Identity Platform logs |
| Security incident rate (human error) | Decreasing year-over-year | Incident reports |

### 8.2 Program Review

The training program is reviewed annually and updated based on:

- Training effectiveness metrics
- Incident post-mortem findings
- Changes in threat landscape
- New technologies or architecture changes
- Regulatory requirement changes
- Personnel feedback

---

## 9. Enforcement

- Training completion is a condition of continued system access
- Failure to complete required training results in progressive access restrictions
- Willful refusal to participate in security training is a policy violation subject to disciplinary action
- Training status is visible to management via Drata compliance dashboard

---

*Next review date: March 2027*
