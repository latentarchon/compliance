# Incident Response Tabletop Exercise

> **Document ID**: IR-TTX-001
> **Parent Document**: POL-IR-001 (policies/incident-response.md), ISCP-LA-001 (contingency-plan.md)
> **Version**: 1.0
> **Date**: April 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Exercise Coordinator**: Andrew Hendel, CEO / ISSO
> **Target Cadence**: Annual (minimum), semi-annual (recommended)

---

## 1. Purpose

This document provides a structured tabletop exercise to test the organization's incident response capabilities against realistic threat scenarios targeting the Latent Archon platform. The exercise validates:

- Detection capabilities and alert response times
- Escalation and communication procedures
- Technical containment and eradication procedures
- Recovery procedures per the ISCP
- FedRAMP incident reporting obligations
- Coordination between roles

---

## 2. Exercise Format

**Type**: Facilitated tabletop discussion (no live systems affected)
**Duration**: 2–3 hours
**Participants**: All contingency team members

| Role | Participant | Exercise Role |
|------|-----------|---------------|
| Exercise Coordinator / Facilitator | CEO / ISSO | Presents injects, tracks decisions |
| Security Lead | Security Lead | Primary responder, forensic decisions |
| Operations Lead | Engineering Lead | Technical containment and recovery |
| Communications Lead | CEO | External notification decisions |
| Observer / Note-taker | (assign) | Documents timeline and decisions |

**Materials Needed**:
- This document (printed or screen-shared)
- Incident Response Policy (POL-IR-001)
- Contingency Plan (ISCP-LA-001)
- ConMon Plan (CONMON-LA-001)
- Architecture diagram (from SSP)
- Stopwatch for timed decision points

---

## 3. Scenario 1: Credential Exfiltration via Compromised Dependency

**Threat Category**: Supply chain attack (SA-12, SI-7)
**NIST CSF**: Identify → Detect → Respond → Recover
**Severity**: Critical

### Inject 1 — Detection (T+0)

> Dependabot opens a critical alert on the `backend` repo: a transitive Go dependency
> (`github.com/example/httputil v2.3.1`) has been flagged for a backdoor that exfiltrates
> environment variables to an external endpoint. The advisory was published 4 hours ago.
> Your CI pipeline ran a build using this dependency 6 hours ago.

**Discussion Questions**:
1. What is your first action upon seeing this alert?
2. How do you determine if the compromised build was deployed to staging or production?
3. What environment variables could have been exfiltrated? Which are most critical?

**Expected Actions**:
- [ ] Check deployment history: was the compromised build deployed?
- [ ] Identify affected environment variables (DB credentials, API keys, KMS key names)
- [ ] Assess blast radius: which services used the compromised dependency?

### Inject 2 — Containment (T+15 min)

> You confirm the compromised build was deployed to the `archon-ops` Cloud Run service
> in staging 5 hours ago. The service has access to Cloud SQL, GCS, KMS, and DLP APIs.
> Cloud Audit Logs show normal API patterns, but you cannot rule out exfiltration of
> the `DATABASE_URL` connection string.

**Discussion Questions**:
1. Do you take the staging service offline immediately? What's the impact?
2. How do you rotate the potentially compromised credentials?
3. Who do you notify at this point?

**Expected Actions**:
- [ ] Roll back `archon-ops` to the previous known-good revision
- [ ] Rotate database password via Secret Manager
- [ ] Rotate any API keys or tokens in environment variables
- [ ] Review Cloud Audit Logs for unusual data access patterns
- [ ] Activate incident response: notify Security Lead and CEO

### Inject 3 — Investigation (T+45 min)

> Cloud Audit Logs reveal 3 unusual `cloudsql.instances.connect` calls from an IP
> address not associated with your Cloud Run services. The calls occurred 4 hours ago,
> approximately 1 hour after the compromised build was deployed. The source IP
> geolocates to Eastern Europe.

**Discussion Questions**:
1. This confirms credential compromise. What is the FedRAMP reporting timeline?
2. How do you preserve forensic evidence?
3. What additional credentials need rotation beyond the database?

**Expected Actions**:
- [ ] Classify as confirmed security incident (Category: Unauthorized Access)
- [ ] Export Cloud Audit Logs to immutable storage (WORM bucket)
- [ ] Rotate ALL secrets: DB password, service account keys, KMS (if accessible)
- [ ] File US-CERT report within required timeline
- [ ] Notify FedRAMP PMO within 1 hour of confirmation
- [ ] Notify affected agency customers within 1 hour

### Inject 4 — Recovery (T+90 min)

> Credentials have been rotated. The attacker's IP is blocked at the firewall level.
> Database audit logs (`pgAudit`) show the attacker executed `SELECT` queries against
> the `documents` and `users` tables but no `INSERT`, `UPDATE`, or `DELETE` operations.
> 47 document records and 12 user records were potentially accessed.

**Discussion Questions**:
1. How do you determine exactly which data was accessed?
2. What are the breach notification obligations?
3. When can you declare the incident resolved?

**Expected Actions**:
- [ ] Analyze pgAudit logs for exact queries and accessed rows
- [ ] Determine if PII was in the accessed records (DLP scan results)
- [ ] Prepare breach notification for affected organizations
- [ ] Document full incident timeline for after-action report
- [ ] Update SSP if any controls need strengthening
- [ ] Add dependency pinning/verification to CI (Cosign, SLSA)

---

## 4. Scenario 2: DDoS + WAF Bypass Attempt

**Threat Category**: Availability attack + application layer exploit (SC-5, SC-7)
**NIST CSF**: Detect → Respond → Recover
**Severity**: High

### Inject 1 — Detection (T+0)

> Cloud Monitoring fires two alerts simultaneously:
> 1. Cloud Armor DENY events spike to 50,000/minute (normal: <100/minute)
> 2. 5xx error rate on `archon-app` exceeds 10% (normal: <0.1%)
>
> The WAF dashboard shows the requests are targeting `/api/v1/documents/search`
> with malformed query parameters containing SQL injection payloads.

**Discussion Questions**:
1. Is this a DDoS attack, an application attack, or both?
2. What Cloud Armor rules should be responding?
3. Why might 5xx errors be occurring if WAF is blocking?

**Expected Actions**:
- [ ] Review Cloud Armor logs for rule match patterns
- [ ] Check if WAF OWASP CRS rules are matching the SQLi payloads
- [ ] Investigate 5xx errors (legitimate traffic affected? resource exhaustion?)

### Inject 2 — Escalation (T+15 min)

> The attack shifts: the attacker starts using a botnet with 10,000 unique IP addresses.
> Rate limiting per-IP is no longer effective. Cloud Armor adaptive protection has
> triggered but some requests are getting through. The `archon-app` service is
> experiencing increased latency (p99: 12s, normal: 200ms).

**Discussion Questions**:
1. What Cloud Armor features can handle distributed attacks?
2. Should you scale up the service or reduce attack surface?
3. At what point do you involve GCP support?

**Expected Actions**:
- [ ] Enable Cloud Armor adaptive protection in block mode (if not already)
- [ ] Add geographic restrictions if attack source is identifiable
- [ ] Consider emergency maintenance page via Cloud CDN
- [ ] Open GCP support ticket (P1 if premium support)
- [ ] Monitor database connection pool (Cloud SQL) for exhaustion

### Inject 3 — Resolution (T+45 min)

> Cloud Armor adaptive protection has identified and is blocking the botnet pattern.
> Error rates return to normal. However, you notice 3 requests made it through to the
> application layer with unusual headers that don't match any WAF rule.

**Discussion Questions**:
1. How do you analyze the requests that bypassed WAF?
2. Should these be reported as a potential vulnerability?
3. What WAF rule updates are needed?

**Expected Actions**:
- [ ] Extract and analyze the 3 bypassed requests from application logs
- [ ] Determine if any resulted in unauthorized data access
- [ ] Create custom Cloud Armor rule to block the bypass pattern
- [ ] Document the WAF gap as a POA&M item
- [ ] Update Cloud Armor rule set in Terraform and apply

---

## 5. Scenario 3: Insider Threat — Unauthorized Data Access

**Threat Category**: Insider threat (AC-2, AU-6, IR-6)
**NIST CSF**: Detect → Respond
**Severity**: High

### Inject 1 — Detection (T+0)

> During the monthly IAM access review (SOP-03), you discover that a service account
> `archon-ops@archon-fed-admin-staging.iam.gserviceaccount.com` has been granted
> `roles/bigquery.admin` on the admin project. This role is not in the Terraform
> configuration. The IAM binding was added 2 weeks ago via the GCP Console.

**Discussion Questions**:
1. How do you determine who made this change?
2. Is this a misconfiguration or a deliberate unauthorized action?
3. What data could `roles/bigquery.admin` access?

**Expected Actions**:
- [ ] Query Cloud Audit Logs for `SetIamPolicy` on the project in the last 30 days
- [ ] Identify the principal who made the change
- [ ] Check BigQuery audit logs for any data access via this binding
- [ ] Verify the SSP-IaC drift checker would have caught this

### Inject 2 — Investigation (T+20 min)

> Cloud Audit Logs show the IAM change was made by a developer's personal Google account
> via the GCP Console. The developer states they needed BigQuery access to debug a
> production data pipeline issue and "forgot to go through Terraform." BigQuery
> audit logs show 5 queries against the `audit_logs` dataset.

**Discussion Questions**:
1. Is this an incident or a policy violation?
2. What controls failed to prevent this?
3. What corrective actions are needed?

**Expected Actions**:
- [ ] Revoke the unauthorized IAM binding immediately
- [ ] Run `terragrunt apply` to enforce desired state
- [ ] Review the 5 BigQuery queries for data sensitivity
- [ ] Document as a policy violation (change management)
- [ ] Implement preventive controls:
  - [ ] GCP Organization Policy to restrict Console IAM changes
  - [ ] Cloud Monitoring alert on `SetIamPolicy` events
  - [ ] Require Terraform-only IAM changes (enforce via CI)

---

## 6. Scenario 4: Ransomware / Data Destruction

**Threat Category**: Destructive attack (CP-9, CP-10, IR-4)
**NIST CSF**: Detect → Respond → Recover
**Severity**: Critical

### Inject 1 — Detection (T+0)

> At 3:00 AM, Cloud Monitoring fires multiple alerts:
> 1. Cloud SQL instance stopped responding
> 2. GCS bucket `archon-fed-ops-staging-documents` returning 404 for all objects
> 3. KMS key `archon-key` has been scheduled for destruction (24-hour pending period)
>
> All three events occurred within a 5-minute window using the `terraform-sa` service
> account's credentials.

**Discussion Questions**:
1. What is your immediate first action?
2. How do you prevent further damage?
3. What's the KMS key destruction timeline and can it be reversed?

**Expected Actions**:
- [ ] Immediately disable the `terraform-sa` service account key
- [ ] Cancel KMS key destruction (24-hour pending period allows cancellation)
- [ ] Assess Cloud SQL status (instance deleted? or just connection issue?)
- [ ] Check GCS versioning and soft-delete (objects may be recoverable)
- [ ] Activate ISCP (CEO authorization)

### Inject 2 — Assessment (T+15 min)

> Investigation reveals:
> - Cloud SQL instance was NOT deleted (attacker ran `DROP DATABASE` via SQL)
> - GCS objects were deleted but versioning is enabled (prior versions exist)
> - KMS key destruction was cancelled in time
> - The terraform-sa credentials were compromised via a leaked `.tfvars` file in
>   a developer's personal GitHub repository (discovered via Gitleaks external scan)

**Discussion Questions**:
1. Can you recover the database? How?
2. Can you recover the GCS objects? How?
3. What's the full blast radius of terraform-sa compromise?

**Expected Actions**:
- [ ] Database: Initiate PITR to timestamp before the `DROP DATABASE` (< 5 min RPO)
- [ ] GCS: Restore all objects from versioned copies
- [ ] Rotate terraform-sa credentials
- [ ] Audit all terraform-sa actions in Cloud Audit Logs for the compromise window
- [ ] Verify KMS keys are intact (encryption still functional)
- [ ] Remove the leaked `.tfvars` from the developer's personal repo

### Inject 3 — Recovery (T+60 min)

> Database PITR is complete. GCS objects are restored. All credentials are rotated.
> Services are coming back online.

**Discussion Questions**:
1. How do you verify data integrity post-recovery?
2. What are the FedRAMP/CISA reporting requirements?
3. What preventive controls would have prevented this?

**Expected Actions**:
- [ ] Run data integrity checks (row counts, checksums)
- [ ] Verify RLS enforcement on recovered database
- [ ] Verify audit logging is active
- [ ] End-to-end functional test
- [ ] File US-CERT report, notify FedRAMP PMO
- [ ] Notify affected agencies
- [ ] Implement preventive controls:
  - [ ] Gitleaks pre-push hook (already exists — verify enforcement)
  - [ ] terraform-sa: remove persistent keys, use WIF only
  - [ ] GCS: WORM retention policy prevents deletion
  - [ ] Cloud SQL: deletion protection enabled

---

## 7. Exercise Scoring

After each scenario, score the team's response:

| Criterion | Points | Score |
|-----------|--------|-------|
| **Detection** — Identified the incident within expected timeframe | 0–5 | |
| **Classification** — Correctly classified severity and type | 0–5 | |
| **Containment** — Took appropriate containment actions | 0–5 | |
| **Communication** — Followed notification procedures (internal + external) | 0–5 | |
| **Recovery** — Identified correct recovery procedures | 0–5 | |
| **Evidence Preservation** — Preserved forensic evidence | 0–5 | |
| **FedRAMP Compliance** — Met reporting timelines and obligations | 0–5 | |
| **Lessons Learned** — Identified meaningful preventive controls | 0–5 | |
| **Total** | /40 | |

### Scoring Guide

| Score | Rating | Meaning |
|-------|--------|---------|
| 35–40 | Excellent | Team is well-prepared |
| 28–34 | Good | Minor gaps identified |
| 20–27 | Adequate | Several areas need improvement |
| < 20 | Needs Improvement | Significant gaps in IR capability |

---

## 8. After-Action Report Template

Complete within 72 hours of exercise:

```
INCIDENT RESPONSE TABLETOP EXERCISE — AFTER-ACTION REPORT
═══════════════════════════════════════════════════════════

Exercise Date:        [DATE]
Participants:         [NAMES AND ROLES]
Scenarios Completed:  [1, 2, 3, 4]
Overall Score:        [X/40 per scenario]

STRENGTHS:
1. [What went well]
2. [What went well]

AREAS FOR IMPROVEMENT:
1. [Gap identified] → [Corrective action] → [Owner] → [Deadline]
2. [Gap identified] → [Corrective action] → [Owner] → [Deadline]

PLAN UPDATES REQUIRED:
- [ ] Incident Response Policy: [specific update]
- [ ] Contingency Plan: [specific update]
- [ ] ConMon SOPs: [specific update]
- [ ] SSP Controls: [specific update]

NEXT EXERCISE DATE: [DATE]
```

---

## 9. Exercise Log

| Date | Scenarios Run | Score | Key Findings | AAR Filed |
|------|--------------|-------|-------------|-----------|
| _Pending_ | | | | |

---

_End of Incident Response Tabletop Exercise_
