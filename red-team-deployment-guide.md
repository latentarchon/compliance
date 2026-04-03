# Red Team Infrastructure — Cost Analysis & Deployment Guide

> **Date**: March 2026  
> **Scope**: `red-infra/` Terraform + `redteam/` Go CLI  
> **Target**: Staging environment only

---

## Architecture Summary

The red team infrastructure runs in an **isolated GCP project** (`latentarchon-redteam`) completely separate from application infrastructure. It targets staging endpoints to validate security controls documented in the SSP.

| Component | Resource | Always-On? |
|-----------|----------|------------|
| Service Account | `redteam-attacker` SA | Yes (free) |
| GCS Bucket | `latentarchon-redteam-attack-logs` | Yes |
| VPC + Subnet | `redteam-vpc` / `redteam-subnet` (10.99.0.0/24) | Yes (free) |
| Firewall Rules | deny-all-ingress, allow-IAP-SSH, allow-egress | Yes (free) |
| Cloud NAT + Router | `redteam-nat` / `redteam-router` | Yes |
| Log Sinks (×4) | Audit sinks on redteam + app + admin projects | Yes (free) |
| Monitoring Dashboard | Red Team Assessment dashboard | Yes (free) |
| **Optional** Attacker VM | `e2-small` preemptible, Debian 12, 20 GB | Off by default |
| **Optional** Cloud Scheduler | Weekly cron → Cloud Run Job | Off by default |
| **Optional** Cloud Run Job | `redteam-runner` (containerized CLI) | Off by default |
| **Optional** Artifact Registry | `redteam` Docker repo | Off by default |

---

## Monthly Cost Estimate

### Base Infrastructure (always-on, `enable_attacker_vm=false`, `enable_scheduler=false`)

| Resource | Unit Cost | Monthly Est. |
|----------|-----------|-------------|
| GCS Bucket (Standard, <1 GB) | $0.02/GB | ~$0.02 |
| GCS Nearline (after 90d) | $0.01/GB | ~$0.01 |
| Cloud NAT (idle) | $0.045/hr × 730h | ~$32.85 |
| Cloud NAT data processing | $0.045/GB | ~$0.05 |
| VPC Flow Logs | $0.50/GB ingested | ~$0.50 |
| Log sink storage (audit logs) | Included in GCS | $0 |
| **Base Total** | | **~$33/mo** |

> **Note**: Cloud NAT is the dominant cost even when idle. If the attacker VM is disabled and you run the CLI externally (laptop/CI), you can **remove Cloud NAT entirely** and drop to **<$1/mo**.

### With Attacker VM (periodic use)

| Resource | Unit Cost | Monthly Est. |
|----------|-----------|-------------|
| e2-small preemptible (4h/week) | $0.0067/hr × 16h | ~$0.11 |
| 20 GB pd-standard | $0.04/GB | ~$0.80 |
| Cloud NAT (active during exercises) | $0.045/hr × 16h | ~$0.72 |
| **VM add-on** | | **~$1.63/mo** |

### With Scheduled Cloud Run Job (weekly automated runs)

| Resource | Unit Cost | Monthly Est. |
|----------|-----------|-------------|
| Cloud Run Job (4 runs × 30min, 1 vCPU, 512Mi) | $0.00002400/vCPU-s + $0.00000250/GiB-s | ~$0.18 |
| Cloud Scheduler (1 job) | $0.10/job | ~$0.10 |
| Artifact Registry (<100 MB) | $0.10/GB | ~$0.01 |
| **Scheduler add-on** | | **~$0.29/mo** |

### Cost Summary

| Configuration | Monthly Cost |
|---------------|-------------|
| Base only (no VM, no scheduler) | ~$33 |
| Base without Cloud NAT (run CLI externally) | **<$1** |
| Base + weekly Cloud Run Job | ~$33.30 |
| Base + attacker VM (4h/week) | ~$34.60 |
| Everything enabled | ~$35 |

---

## Deployment Recommendation

### Phase 1: Deploy Now (Staging Only)

**What to deploy**: Base infrastructure with `enable_attacker_vm=false` and `enable_scheduler=false`.

**Prerequisites**:
1. Create `latentarchon-redteam` GCP project (add to `org/` terraform or create via `gcloud`)
2. Create state bucket: `gsutil mb -l us-east4 gs://latentarchon-redteam-tfstate`
3. Enable APIs: `compute.googleapis.com`, `logging.googleapis.com`, `storage.googleapis.com`, `monitoring.googleapis.com`
4. Grant `gh-ci-terraform` SA viewer access on redteam project (for CI plan)

**Apply**:
```bash
cd red-infra
terraform init
terraform plan -var-file=environments/staging/terraform.tfvars
terraform apply -var-file=environments/staging/terraform.tfvars
```

**Cost optimization**: If you only run the redteam CLI from CI (GitHub Actions) or locally, the Cloud NAT is unnecessary. Add a `enable_nat` variable gated with `count` to avoid the ~$33/mo NAT cost when the attacker VM is disabled.

### Phase 2: Enable Scheduled Runs (Pre-Authorization)

Once staging is fully deployed and the redteam CLI is validated:

1. Build and push the redteam Docker image to Artifact Registry
2. Set `enable_scheduler=true` in staging tfvars
3. Re-apply — this creates the Cloud Run Job, Artifact Registry, and Cloud Scheduler
4. Weekly automated exercises generate reports in the GCS bucket

### Phase 3: Never (Production)

Red team exercises target **staging only**. This is correct because:
- Staging mirrors production configuration (same Terraform modules, same Cloud Armor rules, same RBAC)
- The redteam CLI has a **staging-only lock** that refuses production endpoints
- Running attacks against production risks real user impact
- FedRAMP requires you to **demonstrate** security testing, not that you attack production
- Document in the SSP that staging is a representative environment and findings are remediated before production deployment

---

## Why Not Terragrunt?

Red-infra is a single flat Terraform config (6 `.tf` files, 1 project, 1 environment). Terragrunt's value comes from:
- Multiple modules with cross-dependencies → red-infra has none
- Per-environment × per-project matrix → red-infra is staging-only
- Shared variables via `env.hcl` → not needed with a single tfvars

Plain Terraform with `-var-file` is simpler and appropriate here.

---

## FedRAMP Evidence Generated

The red-infra deployment supports these KSI themes:

| KSI Theme | Evidence | Source |
|-----------|----------|--------|
| KSI-IR (Incident Response) | Monthly red team exercise reports | GCS `attack-logs` bucket |
| KSI-MLA (Monitoring) | Audit log correlation (attacks ↔ WAF blocks ↔ IAM denials) | Cloud Logging sinks + dashboard |
| KSI-CNA (Cloud Native) | Firewall/WAF block validation | Cloud Armor + firewall rule testing |
| KSI-IAM (Identity) | Auth bypass/token forgery test results | Redteam CLI logs |
| CA-8 (Penetration Testing) | Full assessment reports with MITRE ATT&CK mapping | Report generator |

Red team reports are uploaded to Drata and referenced in the POA&M as evidence for CA-8, IR-3, and SI-4 controls.
