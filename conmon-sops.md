# Continuous Monitoring Standard Operating Procedures (SOPs)

> **Document ID**: SOP-CONMON-001
> **Parent Document**: CONMON-LA-001 (continuous-monitoring-plan.md)
> **Version**: 1.0
> **Date**: April 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Owner**: Andrew Hendel, CEO / ISSO

---

## SOP-01: Monthly Vulnerability Scan Review

**Control Mapping**: RA-5, SI-2, CA-7
**Frequency**: Monthly (1st business day)
**Responsible**: Security Lead / ISSO
**Estimated Duration**: 1–2 hours

### Procedure

1. **Collect scan results** from all automated scanners:
   ```bash
   # GitHub Security tab → each repo → Dependabot alerts
   # Repos: backend, infra, compliance, admin, app, redteam, red-infra

   # CI artifacts: check last 30 days of workflow runs
   # Backend: GoSec, govulncheck, Semgrep, Trivy
   # All repos: Dependabot
   ```

2. **Export findings to spreadsheet**:

   | Finding ID | Scanner | Repo | Severity | CVSS | Package/File | Status | Date Found |
   |-----------|---------|------|----------|------|-------------|--------|------------|
   | (auto-increment) | (tool) | (repo) | (Crit/High/Med/Low) | (score) | (location) | Open/Remediated/FP | (date) |

3. **Triage new findings**:
   - **Critical/High (CVSS ≥ 7.0)**: Create GitHub Issue, assign owner, set 30-day deadline
   - **Medium (CVSS 4.0–6.9)**: Add to POA&M, set 90-day deadline
   - **Low (CVSS < 4.0)**: Add to POA&M, set 180-day deadline
   - **False Positive**: Document justification, mark as FP in tracker

4. **Check remediation status of existing findings**:
   - Review all open items from prior months
   - Verify fixes are merged and deployed
   - Close remediated items with evidence (PR link, deploy timestamp)

5. **Generate monthly vulnerability summary**:
   ```
   Monthly Vulnerability Summary — [MONTH YEAR]
   ─────────────────────────────────────────────
   New findings:        X (Crit: X, High: X, Med: X, Low: X)
   Remediated:          X
   Still open:          X
   False positives:     X
   Overdue (past SLA):  X
   ```

6. **Upload to Drata** (automated via `cloudbuild-monthly.yaml`, verify upload succeeded):
   ```bash
   # Check Cloud Build history for monthly-exercises trigger
   gcloud builds list --project=archon-fed-admin-staging \
     --filter="substitutions._TRIGGER_NAME=monthly-exercises" \
     --limit=1
   ```

7. **Archive**: Save summary to `gs://[PROJECT]-build-artifacts/compliance-exercises/[YYYY-MM-DD]/`

### Deliverable
- Monthly vulnerability scan report (uploaded to Drata + GCS archive)
- Updated POA&M entries

---

## SOP-02: Monthly POA&M Review

**Control Mapping**: CA-5, PM-4
**Frequency**: Monthly (1st week)
**Responsible**: Security Lead / ISSO
**Estimated Duration**: 1 hour

### Procedure

1. **Open POA&M tracker** (Drata → Controls → POA&M, or local spreadsheet)

2. **For each open item**, review:
   - Is the remediation deadline approaching or past?
   - Has the assigned owner made progress?
   - Is the original risk assessment still accurate?

3. **Update status**:
   | Status | Criteria |
   |--------|----------|
   | **Open** | Not yet started or in progress |
   | **In Progress** | Fix developed, awaiting deploy or verification |
   | **Remediated** | Fix deployed, verified in production |
   | **Risk Accepted** | Documented risk acceptance with CEO approval |
   | **Deviation Requested** | FedRAMP PMO notified, awaiting response |

4. **Escalate overdue items**:
   - Items past SLA with no progress → escalate to CEO
   - Items that cannot be remediated within SLA → prepare Deviation Request for FedRAMP PMO

5. **Add new POA&M entries** from:
   - This month's vulnerability scan (SOP-01)
   - Any 3PAO or internal audit findings
   - Any incident findings

6. **Generate POA&M summary**:
   ```
   POA&M Summary — [MONTH YEAR]
   ─────────────────────────────
   Total open items:    X
   New this month:      X
   Closed this month:   X
   Overdue:             X
   Deviation requests:  X
   ```

### Deliverable
- Updated POA&M (Drata + PDF export archived to GCS)

---

## SOP-03: Monthly IAM / Access Review

**Control Mapping**: AC-2, AC-6, AC-6(5), PS-4
**Frequency**: Monthly (2nd week)
**Responsible**: Security Lead / ISSO
**Estimated Duration**: 1–2 hours

### Procedure

1. **Review GCP IAM bindings** for all projects:
   ```bash
   # For each project
   for PROJECT in archon-fed-admin-staging archon-fed-app-staging; do
     echo "=== $PROJECT ==="
     gcloud projects get-iam-policy "$PROJECT" \
       --format="table(bindings.role, bindings.members)" \
       --flatten="bindings[].members"
   done
   ```

2. **Verify service account permissions** match SSP claims:
   ```bash
   # Run the drift checker to validate terraform-sa role count
   cd compliance && go run ./cmd/check-ssp-iac-drift --json | \
     jq '.checks[] | select(.control == "AC-6")'
   ```

3. **Review application-level RBAC**:
   - Check admin panel for org/workspace membership changes
   - Verify no unauthorized role escalations in `audit_log` table
   - Review SCIM sync logs for any external identity changes

4. **Check for terminated personnel** (PS-4):
   - Cross-reference HR records with active IAM/RBAC accounts
   - Revoke access for any departures within 24 hours
   - Document revocation with timestamp

5. **Review Firebase Auth / Identity Platform**:
   ```bash
   # Check for disabled or suspicious accounts
   # Firebase Console → Authentication → Users
   # Review last sign-in dates, identify dormant accounts (>90 days)
   ```

6. **Document findings**:
   ```
   IAM Access Review — [MONTH YEAR]
   ──────────────────────────────────
   GCP IAM bindings reviewed:       X
   Service accounts reviewed:       X
   Application users reviewed:      X
   Accounts disabled/removed:       X
   Anomalies found:                 X
   Reviewer:                        [Name]
   ```

### Deliverable
- IAM access review record (screenshot + summary, uploaded to Drata)

---

## SOP-04: Weekly KSI Evidence Collection

**Control Mapping**: CA-7, FedRAMP 20x KSI
**Frequency**: Weekly (automated via GitHub Actions)
**Responsible**: Automated (verified by Security Lead monthly)
**Estimated Duration**: 5 minutes (verification only)

### Procedure

1. **Verify automated collection ran**:
   ```bash
   # Check GitHub Actions → compliance repo → KSI Evidence workflow
   # Should run weekly and produce artifacts
   ```

2. **Verify manifest integrity**:
   ```bash
   # Download latest artifact from GitHub Actions
   # Check manifest.json contains all 10 KSI evidence files
   # Verify SHA-256 checksums match
   cat manifest.json | jq '.files | length'  # Should be 10
   ```

3. **Spot-check one evidence file** each week (rotate through):
   | Week | Evidence File | What to Check |
   |------|--------------|---------------|
   | 1 | `ksi-iam-bindings.json` | Role count matches SSP |
   | 2 | `ksi-cna-firewall.json` | Firewall rules match SSP |
   | 3 | `ksi-svc-kms.json` | Key rotation period = 90 days |
   | 4 | `ksi-rec-db-backup.json` | Backup retention = 14 days |

4. **If collection failed**:
   - Check GitHub Actions logs for errors
   - Verify cloud API credentials are valid
   - Re-run manually: `go run ./cmd/ksi-evidence --provider gcp --project archon-fed-admin-staging`

### Deliverable
- Weekly KSI evidence artifacts (automated, 365-day retention in GitHub Actions)

---

## SOP-05: Weekly Infrastructure Drift Detection

**Control Mapping**: CM-3, CM-6, SA-10
**Frequency**: Weekly (automated via GitHub Actions)
**Responsible**: Automated (verified by Security Lead monthly)
**Estimated Duration**: 5 minutes (verification only)

### Procedure

1. **Verify Terragrunt drift detection ran**:
   ```bash
   # Check GitHub Actions → infra repo → Terragrunt CI workflow
   # "drift-detect" job should run on schedule
   ```

2. **Review drift results**:
   - If drift detected: investigate whether it was an authorized out-of-band change
   - If unauthorized: create incident ticket, revert via `terragrunt apply`
   - If authorized: update Terragrunt config to match and commit

3. **Verify SSP-IaC drift checker**:
   ```bash
   cd compliance
   go run ./cmd/check-ssp-iac-drift --infra-root ../infra --backend-root ../backend
   # All 26 checks should pass
   ```

4. **If SSP-IaC drift detected**:
   - Determine whether SSP or IaC is the source of truth
   - Update the out-of-date artifact
   - Re-run drift checker to confirm resolution
   - Commit and push changes

### Deliverable
- Weekly drift detection results (automated CI artifacts)

---

## SOP-06: Monthly Red Team Exercise

**Control Mapping**: CA-8, IR-3, SI-6
**Frequency**: Monthly (3rd week, automated via Cloud Build)
**Responsible**: Security Lead / ISSO
**Estimated Duration**: 2–4 hours (review)

### Procedure

1. **Verify monthly exercise ran**:
   ```bash
   gcloud builds list --project=archon-fed-admin-staging \
     --filter="substitutions._TRIGGER_NAME=monthly-exercises" \
     --limit=1
   ```

2. **Review red team report**:
   - Check attack success/failure counts
   - Identify any newly successful attacks (defense regression)
   - Compare with prior month's results

3. **For any successful attacks**:
   - Create POA&M item with severity assessment
   - Determine root cause (missing control, misconfiguration, new vulnerability)
   - Assign remediation owner and deadline

4. **Update defense metrics**:
   ```
   Red Team Monthly Summary — [MONTH YEAR]
   ─────────────────────────────────────────
   Total attacks executed:     44
   Attacks blocked:            X
   Attacks succeeded:          X
   Defense success rate:       X%
   New regressions:            X
   ```

5. **Upload report** to Drata as penetration test evidence

### Deliverable
- Monthly red team exercise report (Drata + GCS archive)

---

## SOP-07: Quarterly Contingency Plan Validation

**Control Mapping**: CP-4, CP-2
**Frequency**: Quarterly
**Responsible**: Operations Lead + Security Lead
**Estimated Duration**: 2–4 hours

### Procedure

1. **Select component recovery test** (rotate quarterly):
   | Q1 | Q2 | Q3 | Q4 |
   |----|----|----|-----|
   | Database PITR | Container rollback | Storage restore | Full IaC rebuild |

2. **Execute test using contingency-test CLI**:
   ```bash
   cd compliance/contingency-test
   go run ./cmd/contingency-test \
     --project-id archon-fed-admin-staging \
     --app-project-id archon-fed-app-staging \
     --region us-east4 \
     --db-instance archon-db \
     --documents-bucket archon-fed-ops-staging-documents \
     --kms-keyring archon --kms-key archon-key \
     --output-dir ./reports \
     --verbose
   ```

3. **Document results**:
   - Actual RPO vs. target RPO
   - Actual RTO vs. target RTO
   - Any failures or unexpected issues
   - Corrective actions required

4. **Upload report** to Drata and archive to GCS

### Deliverable
- Quarterly contingency plan test report

---

## SOP-08: Annual SSP Review and Update

**Control Mapping**: PL-2, CA-7
**Frequency**: Annual (or on significant change)
**Responsible**: Security Lead / ISSO + CEO
**Estimated Duration**: 8–16 hours

### Procedure

1. **Run full SSP-IaC drift check**:
   ```bash
   cd compliance
   go run ./cmd/check-ssp-iac-drift --infra-root ../infra --backend-root ../backend --json > annual-drift-report.json
   ```

2. **Review each SSP section** against current system:
   - System description and boundary
   - Architecture diagrams
   - Data flow descriptions
   - All 232 control narratives
   - Personnel and roles

3. **Update SSP narratives** for any changes during the year

4. **Regenerate OSCAL SSP** and validate:
   ```bash
   npm run generate:oscal
   npm run validate:oscal-schema
   ```

5. **Version the updated SSP** with change log entry

6. **Submit updated SSP** to FedRAMP PMO and agency AO

### Deliverable
- Updated SSP (all formats: markdown, OSCAL JSON)
- Change log documenting all updates

---

## Appendix A: SOP Schedule Summary

| SOP | Frequency | Day | Automated? |
|-----|-----------|-----|------------|
| SOP-01: Vuln Scan Review | Monthly | 1st business day | Manual review of automated scans |
| SOP-02: POA&M Review | Monthly | 1st week | Manual |
| SOP-03: IAM Access Review | Monthly | 2nd week | Manual + drift checker |
| SOP-04: KSI Evidence | Weekly | Automated | Automated (verify monthly) |
| SOP-05: Drift Detection | Weekly | Automated | Automated (verify monthly) |
| SOP-06: Red Team Exercise | Monthly | 3rd week | Automated (review results) |
| SOP-07: CP Validation | Quarterly | Rotating | Semi-automated |
| SOP-08: SSP Review | Annual | Anniversary | Manual |

## Appendix B: Escalation Matrix

| Severity | Response Time | Escalation Path |
|----------|--------------|-----------------|
| Critical (CVSS ≥ 9.0) | Immediate | Security Lead → CEO → FedRAMP PMO |
| High (CVSS 7.0–8.9) | 24 hours | Security Lead → CEO |
| Medium (CVSS 4.0–6.9) | 5 business days | Security Lead |
| Low (CVSS < 4.0) | 30 days | Security Lead |

## Appendix C: Tool Reference

| Tool | Command | Purpose |
|------|---------|---------|
| SSP-IaC Drift Checker | `go run ./cmd/check-ssp-iac-drift` | Validate SSP claims against IaC |
| KSI Evidence Collector | `go run ./cmd/ksi-evidence` | Collect machine-readable evidence from cloud APIs |
| SCN Classifier | `go run ./cmd/classify-scn` | Classify changes as significant/routine |
| OSCAL Generator | `npm run generate:oscal` | Generate OSCAL SSP JSON |
| OSCAL Validator | `npm run validate:oscal-schema` | Validate OSCAL SSP against schema |
| Contingency Test | `go run ./cmd/contingency-test` | Automated contingency plan testing |
| Training Tracker | `go run ./cmd/training-tracker` | Security training attestation |
| Drata Sync | `go run ./cmd/drata-sync` | Upload evidence to Drata |

---

_End of Continuous Monitoring SOPs_
