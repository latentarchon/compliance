# Latent Archon — Incident Response Policy

> **Policy ID**: POL-IR-001  
> **Version**: 1.1  
> **Effective Date**: March 2026  
> **Owner**: Chief Executive / Security Lead  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: IR-1, IR-2, IR-3, IR-4, IR-5, IR-6, IR-6(1), IR-7, IR-8, IR-9

---

## 1. Purpose

This policy establishes the incident response framework for Latent Archon, defining roles, procedures, and communication protocols for identifying, containing, eradicating, and recovering from security incidents. Given that Latent Archon handles Controlled Unclassified Information (CUI) for government customers, rapid and structured incident response is critical.

---

## 2. Scope

This policy covers security incidents affecting:

- Latent Archon production and staging environments
- Customer data (documents, messages, workspace content)
- Authentication and identity systems
- Infrastructure (cloud environments, networking, compute)
- CI/CD pipelines and source code repositories
- Third-party integrations

---

## 3. Incident Classification

### 3.1 Severity Levels

| Severity | Definition | Examples | Response Time |
|----------|-----------|----------|---------------|
| **SEV-1 (Critical)** | Active breach, data exfiltration, or complete service outage | Unauthorized data access, credential compromise, ransomware | Immediate (< 15 min) |
| **SEV-2 (High)** | Attempted breach, partial outage, or vulnerability with known exploit | Failed auth bypass attempts, WAF rule triggers, dependency CVE with public exploit | < 1 hour |
| **SEV-3 (Medium)** | Anomalous activity, degraded service, or vulnerability without known exploit | Unusual rate limit violations, elevated error rates, dependency CVE without exploit | < 4 hours |
| **SEV-4 (Low)** | Informational, minor anomaly, policy violation | Port scan detected, single failed login from unusual location | < 24 hours |

### 3.2 Incident Categories

| Category | Description | MITRE Mapping |
|----------|-------------|---------------|
| **Authentication Bypass** | Attempt to access system without valid credentials | TA0001 Initial Access |
| **Privilege Escalation** | Attempt to gain unauthorized elevated access | TA0004 Privilege Escalation |
| **Data Exfiltration** | Unauthorized extraction of customer or system data | TA0010 Exfiltration |
| **Injection Attack** | SQL injection, prompt injection, XSS attempts | TA0002 Execution |
| **Denial of Service** | Attempt to degrade or disrupt service availability | TA0040 Impact |
| **Supply Chain** | Compromise of dependency, build tool, or CI/CD | TA0001 Initial Access |
| **Insider Threat** | Unauthorized access by authorized personnel | TA0001 Initial Access |
| **Data Integrity** | Unauthorized modification of customer data | TA0040 Impact |

---

## 4. Incident Response Team

### 4.1 Roles

| Role | Responsibility | Primary | Backup |
|------|---------------|---------|--------|
| **Incident Commander (IC)** | Overall incident coordination, decision authority | CEO/CTO | Security Lead |
| **Technical Lead** | Investigation, containment, eradication | Engineering Lead | Senior Engineer |
| **Communications Lead** | Customer notification, status updates | CEO | Operations |
| **Forensics** | Evidence collection, root cause analysis | Security Lead | Engineering Lead |

### 4.2 Contact Escalation

1. **First responder** detects incident (automated alert or manual observation)
2. **Incident Commander** is notified immediately for SEV-1/SEV-2
3. **Full team** activated for SEV-1 within 15 minutes
4. **Customer notification** initiated per Section 8 timelines

---

## 5. Detection Sources

### 5.1 Automated Detection

| Source | What It Detects | Alert Mechanism |
|--------|----------------|-----------------|
| WAF | OWASP attacks, DDoS, suspicious IPs | Cloud monitoring alert policy |
| WAF Adaptive Protection | ML-detected L7 DDoS anomalies | Cloud monitoring alert policy |
| WAF Block Spike Alert | Elevated WAF DENY event volume | Cloud monitoring alert (HIGH) |
| 5xx Error Rate Alert | 5xx/total request ratio exceeds threshold | Cloud monitoring alert (HIGH) |
| Database Auth Failure Alert | `FATAL` or `password authentication failed` in DB logs | Cloud monitoring alert (HIGH) |
| IAM Privilege Escalation Alert | `SetIamPolicy`, `CreateRole`, `UpdateRole` API calls | Cloud monitoring alert (CRITICAL) |
| KMS Key Lifecycle Alert | Key disable, destroy, or version state changes | Cloud monitoring alert (CRITICAL) |
| Secret Access Alert | Secret access calls on managed secrets | Cloud monitoring alert (CRITICAL) |
| DLP Findings | PII, credentials, or financial data detected in uploaded documents | DLP inspect template findings log |
| Audit Events (WARN level) | Auth failures, privilege escalation, deletions | Cloud logging alert policy |
| Rate Limit Violations | Brute force, API abuse (tiered: SCIM 30/min, auth 20/min, login 10/min, global 100/min) | WAF rate-based ban |
| Red Team Dashboard | Attack request volume, IAM denials, auth failures | Cloud monitoring dashboard |
| Dependabot | Vulnerable dependencies | GitHub notification + PR |
| Cloud Audit Logs | IAM changes, resource modifications, API calls | Cloud logging alert policy |
| Identity Provider | Brute force, suspicious sign-ins | Provider alerts |
| Security Email Notifications | Role escalation, auth failures, member changes, SCIM events, document deletions | Real-time email to org admins |

### 5.2 Manual Detection

- Red team attack suite execution (monthly)
- Quarterly access reviews
- Customer reports
- Employee observations

---

## 6. Incident Response Phases

### Phase 1: Detection & Triage (0–15 minutes)

1. **Acknowledge** alert or report
2. **Classify** severity (SEV-1 through SEV-4)
3. **Assign** Incident Commander
4. **Create** incident channel (Slack or equivalent)
5. **Begin** incident log (timestamped actions)

### Phase 2: Containment (15 minutes – 2 hours)

#### Immediate Containment Actions by Category

| Category | Containment Action |
|----------|-------------------|
| **Auth Bypass** | Revoke compromised tokens; disable affected user accounts via identity provider admin SDK; rotate affected secrets |
| **Privilege Escalation** | Revoke IAM grants; disable service accounts; block affected IP ranges in WAF |
| **Data Exfiltration** | Block source IP in WAF; revoke affected user sessions; enable enhanced logging |
| **Injection Attack** | Update WAF rules; deploy application patch; enable request body logging |
| **DDoS** | Adjust WAF rate limits; enable adaptive protection; contact CSP support |
| **Supply Chain** | Pin affected dependency; revert to known-good version; audit recent deployments |

#### Platform-Specific Actions

- **Container service**: Deploy previous revision (instant rollback via traffic split)
- **Database**: Enable enhanced audit logging; snapshot current state
- **WAF**: Add emergency IP block rules; adjust rate limits
- **Identity provider**: Disable affected IDP pool; revoke all sessions for affected org
- **Kill Switch**: Red team tooling includes kill-on-breach capability for immediate containment

### Phase 3: Eradication (2–24 hours)

1. **Identify** root cause via audit logs, cloud logging, and distributed traces (OpenTelemetry)
2. **Remove** attacker access (revoke all compromised credentials, tokens, sessions)
3. **Patch** vulnerability (deploy fix via standard CI/CD pipeline)
4. **Verify** fix (run targeted red team attack suite against the vulnerability)
5. **Scan** for lateral movement (review audit logs for affected timeframe across all services)

### Phase 4: Recovery (24–72 hours)

1. **Restore** normal operations (re-enable disabled services/accounts)
2. **Validate** system integrity:
   - Database: Compare checksums, verify RLS policies intact
   - Object storage: Verify object versions, check for unauthorized uploads
   - Vector Store: Verify workspace scoping, rebuild index if necessary
   - IAM: Audit all grants, verify service account permissions
3. **Monitor** enhanced logging for recurrence (minimum 72 hours)
4. **Confirm** customer data integrity

### Phase 5: Post-Incident (72 hours – 2 weeks)

1. **Incident report** drafted within 72 hours (see Section 7)
2. **Root cause analysis** (5 Whys or similar)
3. **Lessons learned** meeting with full incident team
4. **Remediation items** tracked in POA&M
5. **Policy/procedure updates** if gaps identified
6. **Red team update**: Add new attack scenario based on incident
7. **Customer debrief** (for SEV-1/SEV-2 affecting customer data)

---

## 7. Incident Documentation

### 7.1 Incident Report Template

Every SEV-1 and SEV-2 incident requires a written report containing:

1. **Summary**: One-paragraph description
2. **Timeline**: Timestamped sequence of events (detection → containment → eradication → recovery)
3. **Impact**: Affected customers, data scope, service availability
4. **Root Cause**: Technical root cause analysis
5. **Containment Actions**: What was done to stop the incident
6. **Eradication Actions**: How the vulnerability was removed
7. **Recovery Actions**: How normal operations were restored
8. **Lessons Learned**: What went well, what didn't, what to improve
9. **Action Items**: Remediation tasks with owners and deadlines

### 7.2 Evidence Preservation

- Cloud logging exports preserved for minimum 365 days
- Database audit events preserved indefinitely
- Object storage versions preserved per lifecycle policy
- Terraform state versions preserved in cloud storage
- Screenshots and screen recordings of dashboards during incident

### 7.3 Forensic Preservation Holds

On **SEV-1/SEV-2 security incidents**, a forensic preservation endpoint captures a complete database snapshot and audit trail for the affected scope:

- **Scope**: Organization-level or workspace-level preservation
- **Captures**: Database snapshot (documents, messages, members, audit events) + full audit trail
- **Access Control**: Restricted to the ops service with OIDC authentication (Cloud Scheduler / admin SA only)
- **Audit Trail**: Preservation operations are themselves audit-logged
- **Purpose**: Ensures evidence is preserved before any automated purge or account lifecycle action can destroy relevant data
- **Alignment**: Security Addendum §7.4, Privacy Policy §5 (data purge exemption)

---

## 8. Customer Notification

### 8.1 Notification Timelines

| Severity | Customer Impact | Notification Timeline |
|----------|----------------|----------------------|
| SEV-1 | Data breach confirmed | Within 24 hours |
| SEV-1 | Service outage > 4 hours | Within 2 hours |
| SEV-2 | Potential data exposure | Within 72 hours |
| SEV-2 | Service degradation > 2 hours | Within 4 hours |
| SEV-3/4 | No customer data impact | Monthly security digest |

### 8.2 Notification Content

Customer notifications include:

- Nature of the incident
- Timeframe of impact
- Data affected (or confirmation of no data impact)
- Actions taken
- Recommended customer actions (if any)
- Point of contact for questions

### 8.3 Federal Incident Reporting (US-CERT / CISA)

FedRAMP and FISMA require reporting security incidents to the Cybersecurity and Infrastructure Security Agency (CISA) via US-CERT. Latent Archon follows the **FedRAMP Incident Communications Procedure** and **NIST SP 800-61 Rev. 2**.

#### 8.3.1 Reporting Timelines

| Category | Description | US-CERT Report Deadline | FedRAMP PMO Deadline |
|----------|-------------|------------------------|---------------------|
| **CAT 1** | Unauthorized access to CUI / data exfiltration confirmed | **1 hour** from detection | **1 hour** (same report) |
| **CAT 2** | Denial of service attack (successful) | **2 hours** from detection | **2 hours** |
| **CAT 3** | Malicious code execution (malware, ransomware) | **1 hour** from detection | **1 hour** |
| **CAT 4** | Improper usage / policy violation | **1 week** | **1 week** |
| **CAT 5** | Scans, probes, attempted access (unsuccessful) | **Monthly** (aggregated) | **Monthly** |
| **CAT 6** | Investigation / unconfirmed | **1 week** | **1 week** |

#### 8.3.2 US-CERT Reporting Process

1. **Incident Commander** initiates US-CERT report at [us-cert.cisa.gov/report](https://us-cert.cisa.gov/report) or via email to `soc@us-cert.gov`
2. **Initial report** must contain:
   - Date/time of incident detection
   - Date/time of incident occurrence (if known)
   - Incident category (CAT 1-6)
   - Description of the incident
   - Affected system(s) and data types
   - Impact assessment (number of users/records potentially affected)
   - Actions taken to contain the incident
   - Point of contact for follow-up
3. **Follow-up report** within **72 hours** containing:
   - Root cause analysis (preliminary or final)
   - Full scope of affected data and users
   - Eradication and recovery actions taken
   - Indicators of Compromise (IOCs) if available
   - Corrective action plan with milestones
4. **Final report** within **30 days** containing:
   - Complete root cause analysis
   - Lessons learned
   - POA&M items with target dates
   - Updated risk assessment

#### 8.3.3 FedRAMP PMO Notification

In addition to US-CERT, the **FedRAMP PMO** must be notified:

- **Same timeline** as US-CERT for CAT 1-3 incidents
- Via email to `info@fedramp.gov` and the assigned FedRAMP reviewer
- Include the US-CERT incident ticket number
- Monthly significant change reports must reference any incidents

#### 8.3.4 Agency Customer Notification

- **Agency ISSO**: Notify the customer agency's Information System Security Officer per the timeline in Section 8.1
- **Sponsoring Agency AO**: Notify the Authorizing Official within 24 hours for CAT 1-3
- Notification content per Section 8.2, plus US-CERT ticket number

#### 8.3.5 Reporting Contacts

| Entity | Contact | Method |
|--------|---------|--------|
| US-CERT / CISA | soc@us-cert.gov | Email + web form |
| FedRAMP PMO | info@fedramp.gov | Email |
| Agency ISSO | Per customer contract | Email + phone |
| CSP Security | Per-provider security contact | Email (for inherited infra incidents) |

---

## 9. Training and Testing

### 9.1 Training

| Audience | Training | Frequency |
|----------|---------|-----------|
| All employees | Security awareness + incident identification | Annual |
| Incident response team | IR procedures + tooling | Semi-annual |
| Engineering | Secure coding + incident containment | Annual |

### 9.2 Testing

| Exercise | Description | Frequency |
|----------|-------------|-----------|
| Red team attack suite | Automated execution of 44 attack scenarios | Monthly |
| Tabletop exercise | Walk-through of incident scenario with full team | Semi-annual |
| Full simulation | End-to-end incident response drill (detection → recovery) | Annual |

---

## 10. Tools and Resources

| Tool | Purpose | Access |
|------|---------|--------|
| Cloud Logging | Log search, analysis, alerting | Cloud console |
| Cloud Monitoring | Metrics, dashboards, alert policies | Cloud console |
| WAF | WAF rules, IP blocking, rate limiting | Cloud console |
| Identity Provider Console | User management, session revocation | Provider console |
| Terraform/Terragrunt | Infrastructure state, rollback | CLI + cloud storage state |
| Red Team CLI | Attack suite execution, validation | `redteam/cmd/redteam/` |
| GitHub | Code history, deployment logs | github.com/latentarchon |

---

## 11. Metrics

| Metric | Target | Measurement |
|--------|--------|------------|
| Mean Time to Detect (MTTD) | < 15 minutes (SEV-1) | Alert timestamp → acknowledgment |
| Mean Time to Contain (MTTC) | < 1 hour (SEV-1) | Acknowledgment → containment confirmed |
| Mean Time to Resolve (MTTR) | < 24 hours (SEV-1) | Detection → normal operations restored |
| Incident report completion | < 72 hours | Incident close → report published |
| Post-incident action items closed | < 30 days | Action item created → completed |

---

## 12. Enforcement

- All employees are required to report suspected security incidents immediately
- Failure to report a known incident is a policy violation
- Intentional obstruction of incident response activities is grounds for immediate termination
- Post-incident action items are tracked with deadlines and assigned owners

---

*Next review date: March 2027*
