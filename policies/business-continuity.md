# Latent Archon — Business Continuity & Disaster Recovery Policy

> **Policy ID**: POL-BC-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: CP-1, CP-2, CP-4, CP-6, CP-7, CP-9, CP-10

---

> **Organizational context**: Latent Archon is a founder-led, automation-first security organization. Continuity controls are largely automated: backups, health checks, and contingency tests run continuously. The CEO/ISSO directs recovery decisions. See SOD-LA-001.

## 1. Purpose

This policy establishes requirements for maintaining the continuity of Latent Archon's services and recovering from disruptive events. It defines backup strategies, recovery objectives, and procedures to ensure customer data and service availability are protected against infrastructure failures, security incidents, natural disasters, and human error.

---

## 2. Scope

This policy applies to:

- All production and staging infrastructure on GCP
<!-- MULTI-CLOUD: Original stated GCP, AWS, or Azure. -->
- All customer data (documents, messages, embeddings, account data)
- All supporting systems (CI/CD, monitoring, DNS, load balancers)
- All personnel involved in incident response and recovery

---

## 3. Recovery Objectives

### 3.1 Service Tier Definitions

| Tier | Services | RPO | RTO | Justification |
|------|----------|-----|-----|---------------|
| **Tier 1 — Critical** | Database (PostgreSQL), Document storage, Authentication | < 5 minutes | < 1 hour | Customer data and authentication — any loss is unacceptable |
| **Tier 2 — Essential** | Container services (app API, admin API, ops), Load Balancers, WAF | 0 (stateless) | < 4 hours | Stateless services rebuilt from container images + Terraform |
| **Tier 3 — Supporting** | AI services (Vector Search + LLM), Document extraction, Task queue, Ops Service | < 24 hours | < 8 hours | AI/search features; system usable without them (degraded mode) |
| **Tier 4 — Non-critical** | Staging environments, CI/CD, monitoring dashboards, Drata sync | N/A | < 24 hours | Operational tooling; no customer impact |

### 3.2 Availability Target

- Production services: **99.9% uptime** (< 8.76 hours downtime/year)
- Excludes scheduled maintenance windows (announced 72 hours in advance)

---

## 4. Backup Strategy

### 4.1 Database (Primary Data Store)

| Feature | Configuration |
|---------|--------------|
| **Automated backups** | Daily, retained for 7 days |
| **Point-in-time recovery** | Enabled, WAL-based, < 5 minute granularity |
| **High availability** | Multi-zone (regional) deployment |
| **Failover** | Automatic failover to standby instance |
| **Encryption** | CMEK (AES-256 via cloud KMS) |
| **Cross-region backup** | Configurable (not currently enabled — single-region deployment) |

Cloud-specific service: Cloud SQL (GCP).
<!-- MULTI-CLOUD: Original also listed RDS PostgreSQL (AWS) and PostgreSQL Flexible Server (Azure). -->

### 4.2 Object Storage (Documents)

| Feature | Configuration |
|---------|--------------|
| **Object versioning** | Enabled, 365-day retention |
| **Lifecycle policies** | Old versions auto-archived after 90 days, deleted after 365 days |
| **Encryption** | CMEK (AES-256 via cloud KMS) |
| **Soft delete** | 30-day soft delete before permanent removal |
| **Redundancy** | Regional with automatic replication across zones |

Cloud-specific service: GCS (GCP).
<!-- MULTI-CLOUD: Original also listed S3 (AWS) and Blob Storage (Azure). -->

### 4.3 Infrastructure Configuration

| Asset | Backup Method | Recovery Method |
|-------|--------------|-----------------|
| **Terraform state** | Cloud storage with versioning and state locking | `terraform init` from versioned state |
| **Terragrunt configs** | Git (GitHub) | Clone and apply |
| **Application source code** | Git (GitHub) | Clone and build |
| **Container images** | Container registry (current + 5 previous) | Pull from registry |
| **Database schema** | Migration files in Git (Atlas) | Apply migrations to fresh database |
| **DNS configuration** | Terraform-managed | Terraform apply |
| **SSL certificates** | Cloud-managed certificates (auto-managed) | Auto-provisioned on new LB |

### 4.4 Backup Verification

| Activity | Frequency | Owner | Method |
|----------|-----------|-------|--------|
| Database backup restore test | Quarterly | Engineering | Restore to staging instance, verify data integrity |
| Storage version recovery test | Semi-annual | Engineering | Restore specific objects, verify checksums |
| Full infrastructure rebuild test | Annual | Engineering | `terragrunt apply` to fresh project |
| PITR recovery test | Semi-annual | Engineering | Restore to specific timestamp, verify data |

---

## 5. Disaster Recovery Procedures

### 5.1 Scenario: Database Failure

**Detection**: Health check failures on `/health` endpoint → container service unhealthy → alert

**Recovery**:
1. Verify database instance status in cloud console
2. If primary unavailable: automatic failover to HA standby (< 60 seconds)
3. If regional failure: restore from PITR backup to new instance
4. Update database connection config in container environment variables if instance name changed
5. Verify data integrity: row counts, audit event continuity, RLS enforcement
6. Resume service

**Time estimate**: Automatic failover < 1 min, PITR restore < 30 min

### 5.2 Scenario: Container Service Failure

**Detection**: Health check failures, load balancer 5xx errors, cloud monitoring alerts

**Recovery**:
1. Container platform auto-heals by replacing failed instances (automatic)
2. If deployment-related: roll back to previous revision (`gcloud run services update-traffic`)
<!-- MULTI-CLOUD: Original also included AWS ECS task definition rollback and Azure Container Apps revision revert. -->
3. If persistent: redeploy from container registry latest known-good image
4. Verify via health check and smoke test

**Time estimate**: Auto-heal < 30 seconds, rollback < 5 min

### 5.3 Scenario: Object Storage Data Loss

**Detection**: Application errors on document access, user-reported missing documents

**Recovery**:
1. List object versions using `gsutil`
<!-- MULTI-CLOUD: Original also listed aws s3api and az storage blob. -->
2. Restore specific version from versioning history
3. For bulk restore: script to restore latest non-deleted version of all objects
4. Verify document count matches database records

**Time estimate**: Single object < 1 min, bulk restore < 1 hour

### 5.4 Scenario: Vector Search Index Corruption

**Detection**: Search quality degradation, embedding retrieval errors

**Recovery**:
1. Rebuild index from source documents in database + object storage
2. Re-embed all document chunks using embedding model
3. Create new index, deploy to endpoint
4. Update index ID in container environment variables
5. Verify search quality with test queries

**Time estimate**: < 4 hours (depending on corpus size)

### 5.5 Scenario: Full Regional Failure

**Recovery**:
1. Provision new infrastructure in alternate region using Terragrunt
2. Restore database from cross-region backup (if configured) or PITR
3. Restore storage data from regional redundancy
4. Rebuild all container services from registry images
5. Update DNS records to point to new load balancer IPs
6. Re-index vector search from restored data

**Time estimate**: 4-8 hours (manual, requires DNS propagation)

---

## 6. Communication During Disruption

| Audience | Channel | Timeline |
|----------|---------|----------|
| Internal team | Slack / direct communication | Immediate |
| Affected customers | Email from designated contact | Within 1 hour of confirmed impact |
| All customers (major incident) | Status page / email | Within 4 hours |
| Regulatory (if CUI impacted) | Per incident response policy | Within 24 hours |

---

## 7. Business Continuity

### 7.1 Personnel Continuity

- All critical procedures documented in Git (infrastructure, deployment, recovery)
- Infrastructure fully codified in Git — any authorized team member can rebuild from IaC. Automation workforce handles deployment independently.
- Emergency contact list maintained and reviewed quarterly
- Remote work capability — all operations performable from any internet-connected location

### 7.2 Vendor Continuity

| Vendor | Risk | Mitigation |
|--------|------|-----------|
| **GCP** | Regional outage | Multi-zone HA (current), cross-region DR (planned) |
| **GitHub** | Service outage | Local git clones, GitHub archive export |
| **Drata** | Service outage | Compliance docs stored locally in Git |

### 7.3 Financial Continuity

- Cloud provider committed use discounts or reserved capacity for production workloads
- Business insurance covering cyber incidents and business interruption
- 6-month operating reserve maintained

---

## 8. Testing

| Test Type | Frequency | Scope | Owner |
|-----------|-----------|-------|-------|
| **Tabletop exercise** | Semi-annual | Walk through DR scenarios | CEO + Engineering |
| **Backup restore test** | Quarterly | Database + storage restore to staging | Engineering |
| **Infrastructure rebuild** | Annual | Full Terragrunt apply to test environment | Engineering |
| **Failover test** | Annual | Database HA failover | Engineering |
| **Communication test** | Semi-annual | Notification procedures | CEO / ISSO |

---

## 9. Plan Maintenance

| Trigger | Action |
|---------|--------|
| Infrastructure architecture change | Update DR procedures and time estimates |
| New service or data store added | Add to backup strategy and recovery procedures |
| DR test identifies gaps | Update procedures, create remediation tickets |
| Annual review | Full policy review, update RTOs/RPOs if needed |

---

*Next review date: March 2027*
