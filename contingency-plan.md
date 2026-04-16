# Information System Contingency Plan (ISCP)

> **Document ID**: ISCP-LA-001
> **Parent Document**: SSP-LA-001 (fedramp-ssp.md, Appendix D)
> **Version**: 1.1 — DRAFT
> **Date**: March 2026
> **System Name**: Latent Archon Document Intelligence Platform
> **Plan Owner**: Andrew Hendel, CEO
> **Last Tested**: _Pending — Q3 2026_

---

## 1. Introduction

### 1.1 Purpose

This Information System Contingency Plan (ISCP) establishes procedures to recover the Latent Archon Document Intelligence Platform following a disruption. The plan addresses service degradation, component failure, and regional disaster scenarios for a cloud-native SaaS system deployed on Google Cloud Platform.

<!-- MULTI-CLOUD: Original stated deployable on GCP, AWS, or Azure. -->

### 1.2 Applicability

This plan applies to all components within the Latent Archon authorization boundary as defined in the System Security Plan (SSP-LA-001), including container services, managed PostgreSQL database, object storage, AI/LLM services, identity platform, and supporting infrastructure on whichever cloud provider hosts the deployment.

### 1.3 Scope

The ISCP covers:
- Mission-essential functions and recovery priorities
- Roles and responsibilities for contingency operations
- Recovery procedures for five failure scenarios
- Communication plan for internal and external stakeholders
- Plan testing, training, and maintenance schedule

---

## 2. Concept of Operations

### 2.1 System Description

Latent Archon is a multi-tenant document intelligence SaaS platform deployed on GCP. The system consists of:
- **3 container services**: archon-app (user-facing), archon-admin (admin API), archon-ops (background processing)
- **Managed PostgreSQL 15**: Primary data store with RLS (Cloud SQL)
- **Object storage**: Document file storage (GCS)
- **AI services**: Vector search and LLM inference (Vertex AI)
- **Identity**: Authentication with two pools: app and admin (Identity Platform)
- **WAF**: Dual-layer — Cloudflare Edge WAF (managed rulesets, rate limiting, geo-blocking) + Cloud Armor origin WAF (OWASP CRS, origin restriction)
- **KMS**: Encryption key management (Cloud KMS)

<!-- MULTI-CLOUD: Original also listed RDS/PostgreSQL Flexible Server, S3/Blob Storage, Bedrock+OpenSearch/Azure OpenAI+AI Search, SAML federation/Azure AD, WAFv2/Front Door WAF, AWS KMS/Key Vault. -->

All infrastructure is managed via Terraform/Terragrunt, enabling reproducible deployment to any GCP region.

### 2.2 Recovery Objectives

| Service Tier | Components | RPO | RTO | Description |
|-------------|------------|-----|-----|-------------|
| **Tier 1 — Critical** | Database (PostgreSQL), Document Storage, Authentication | < 5 min | < 1 hr | Customer data and authentication — any loss is unacceptable |
| **Tier 2 — Essential** | Container APIs (app, admin, ops), Load Balancers, Cloudflare Edge WAF, Cloud Armor Origin WAF | 0 (stateless) | < 4 hr | Stateless services rebuilt from container images + Terraform; Cloudflare edge config restored via Terragrunt |
| **Tier 3 — Supporting** | AI services (Vector Search + LLM), Document extraction, Task queue, Ops Service | < 24 hr | < 8 hr | AI/search features; system usable without them (degraded mode) |
| **Tier 4 — Non-Critical** | CI/CD pipelines, Monitoring dashboards, Drata sync | N/A | < 24 hr | Operational tooling; does not affect customer service |

---

## 3. Roles and Responsibilities

### 3.1 Founder-Led Contingency Team

| Role | Person | Responsibilities |
|------|--------|------------------|
| **Contingency Plan Coordinator / ISSO** | Andrew Hendel (CEO) | Activate plan, authorize and execute recovery actions, assess security impact, notify stakeholders |
| **Automation Workforce** | Cloud Monitoring / Cloud Build | Detection, alerting, automated health checks, evidence preservation |

> Automated monitoring provides continuous detection and alerting. The CEO directs assessment, activation, recovery, and communication. As the team scales (POA-15, POA-16), responsibilities will be distributed across dedicated roles.

<details>
<summary>📍 Growth Plan: Expanded contingency team</summary>

| Role | Person | Responsibilities |
|------|--------|------------------|
| **Contingency Plan Coordinator** | CEO | Activate plan, authorize recovery actions, approve communications |
| **Security Lead / ISSO** | Security Lead (POA-15) | Assess security impact, coordinate forensics, manage incident overlap |
| **Operations Lead** | Engineering Lead (POA-16) | Execute recovery procedures, validate service restoration |
| **Communications Lead** | CEO | Notify customers, FedRAMP PMO, agency liaisons |

</details>

### 3.2 Activation Authority

The Contingency Plan Coordinator (CEO) has authority to activate the ISCP. Activation is warranted when:
- A Tier 1 or Tier 2 component is unavailable for > 30 minutes
- A regional GCP outage affects the production deployment
- A security incident requires system isolation and rebuild
- A data corruption event requires point-in-time recovery

---

## 4. Notification and Activation

### 4.1 Notification Procedures

1. **Detection**: Disruption detected via Cloud Monitoring alerts, customer reports, or manual observation
2. **Assessment**: CEO assesses scope and affected tiers within 15 minutes
3. **Activation Decision**: CEO decides whether to activate ISCP within 30 minutes of detection
4. **Team Notification**: Lean team notified via:
   - Primary: Email to engineering distribution list
   - Secondary: Slack #incident channel
   - Tertiary: Phone tree for Tier 1 failures (as team scales)
5. **Incident Log Initiation**: CEO begins incident log documenting timeline, decisions, and actions taken

### 4.2 External Notification Timeline

| Stakeholder | Notification Trigger | Timeline |
|-------------|---------------------|----------|
| Affected customer agencies | Tier 1/2 service disruption | Within 1 hour of activation |
| FedRAMP PMO | Significant service disruption affecting federal data | Within 4 hours |
| US-CERT/CISA | If disruption is caused by a security incident | Per IR policy timelines |
| GCP Support | Infrastructure-level failure | Immediately upon detection |

---

## 5. Recovery Procedures

### 5.1 Scenario 1: Cloud SQL Database Failure

**Trigger**: Database unresponsive, connection failures from all container services
**Impact**: Tier 1 — All API operations fail, authentication succeeds but data access blocked

**Recovery Steps**:

1. **Assess** (5 min): Check database instance status in cloud console. Determine if failure is instance-level or storage-level.
2. **If instance healthy but connections exhausted**: Restart container services to clear connection pools.
3. **If instance unhealthy**: Initiate point-in-time recovery (PITR) to last known-good state.
4. **Update connection**: Modify container environment variables to point to recovered instance.
5. **Validate**: Run health check queries, verify RLS enforcement, confirm audit logging.
6. **Switchover**: Update connection strings in Terragrunt config and apply.

**RPO**: < 5 minutes (PITR with WAL archiving)
**RTO**: < 1 hour

### 5.2 Scenario 2: Container Service Failure

**Trigger**: One or more container services returning 5xx errors or not responding
**Impact**: Tier 2 — Affected service unavailable, other services may continue

**Recovery Steps**:

1. **Assess** (5 min): Check container service logs for crash loops, OOM, or configuration errors.
2. **If recent deployment caused failure**: Roll back to previous revision (`gcloud run services update-traffic`).
<!-- MULTI-CLOUD: Original also included AWS ECS task definition rollback and Azure Container Apps revision revert. -->
3. **If infrastructure issue**: Redeploy from container registry using pinned image digest.
4. **If regional issue**: Deploy to alternate region using Terragrunt with updated region variable.
5. **Validate**: Health checks, end-to-end API test, audit log verification.

**RPO**: N/A (stateless services)
**RTO**: < 30 minutes (rollback), < 4 hours (regional failover)

### 5.3 Scenario 3: Object Storage Failure

**Trigger**: Document upload/download failures, 5xx from storage API
**Impact**: Tier 2 — Document access unavailable, app search may degrade

**Recovery Steps**:

1. **Assess** (5 min): Check storage bucket/container status and cloud status dashboard.
2. **If object corruption**: Restore from versioned objects.
3. **If bucket-level failure**: Cloud-native storage provides automatic regional redundancy. Wait for CSP recovery or switch to backup bucket.
4. **If regional failure**: Restore from cross-region backup (if configured) or rebuild from database metadata.
5. **Validate**: Document download test, upload test, verify object integrity checksums.

**RPO**: < 5 minutes (object versioning with 365-day retention)
**RTO**: < 4 hours

### 5.4 Scenario 4: AI / Vector Search Failure

**Trigger**: Semantic search returns errors or empty results
**Impact**: Tier 3 — AI-powered search unavailable, basic document listing still works

**Recovery Steps**:

1. **Assess** (10 min): Check vector search endpoint status, private endpoint connectivity.
2. **If index endpoint unhealthy**: Undeploy and redeploy index via Terragrunt.
3. **If index corrupted**: Rebuild from source documents by triggering re-embedding job via task queue.
4. **Enable degraded mode**: System continues to function with document listing and manual search while vector search is unavailable.
5. **Validate**: Test semantic search queries, verify result relevance, check workspace scoping.

**RPO**: Hours (time to re-embed document collection)
**RTO**: < 8 hours

### 5.5 Scenario 5: Regional Failure (Disaster Recovery)

**Trigger**: Cloud provider region experiences sustained outage
**Impact**: All tiers — Complete service disruption

**Recovery Steps**:

1. **Activate DR** (CEO authorization required): Decision to failover to alternate US region.
2. **Database recovery**: Restore database from cross-region backup to target region. Verify data integrity and RLS enforcement.
3. **Infrastructure deployment**: Update region in env.hcl and run `terragrunt run-all apply`.
4. **Application deployment**: Push container images to registry in target region. Deploy container services pointing to recovered database.
5. **DNS failover**: Update Cloudflare DNS records to point to new region's load balancer IPs.
6. **Identity**: Verify authentication works (identity services are multi-regional on all clouds).
7. **Validation**: End-to-end authentication, document upload/download, API functionality, audit logging, RLS enforcement.
8. **Notify stakeholders**: Confirm service restoration to customers and FedRAMP PMO.

**RPO**: < 5 minutes (cross-region database backup)
**RTO**: < 4 hours (IaC-driven rebuild)

---

## 6. Reconstitution

After recovery, the following reconstitution steps ensure full operational capability:

1. **Verify all Tier 1-3 services** are operational with expected performance
2. **Review audit logs** during disruption period for any security anomalies
3. **Verify data integrity** by running consistency checks on database and storage
4. **Confirm monitoring** dashboards and alert policies are active
5. **Re-enable CI/CD** pipelines if paused during recovery
6. **Conduct post-incident review** within 72 hours: timeline of events, root cause analysis, recovery effectiveness assessment, lessons learned
7. **Update ISCP** with any improvements identified during the incident
8. **File after-action report** with FedRAMP PMO if applicable

---

## 7. Plan Testing

### 7.1 Testing Schedule

| Test Type | Frequency | Description |
|-----------|-----------|-------------|
| **Tabletop Exercise** | Annual | Walk-through of all 5 scenarios with contingency team |
| **Component Recovery Test** | Quarterly | Test database PITR, container rollback, storage restore |
| **IaC Rebuild Validation** | Quarterly | Verify Terragrunt can deploy full stack from scratch |
| **Backup Verification** | Monthly | Verify database backup integrity and storage versioning (automated via `contingency-test` CLI) |
| **Automated Contingency Test** | Monthly | `contingency-test` CLI validates backup existence, PITR window, health endpoints, GCS versioning |

### 7.2 Test Documentation

Each test produces a report including:
- Test date, participants, and scenario tested
- Steps executed and outcomes
- Actual vs. expected RPO/RTO
- Issues identified and corrective actions
- Plan updates required

---

## 8. Plan Maintenance

- **Annual Review**: Full plan review and update, aligned with SSP annual review
- **Change-Triggered Update**: Plan updated when significant system changes occur (new components, architecture changes, region changes)
- **Post-Incident Update**: Plan updated within 30 days of any contingency activation
- **Training**: All contingency team members trained on plan within 30 days of assignment and annually thereafter

---

## 9. Backup Strategy Summary

| Component | Backup Method | Retention | Encryption | Location |
|-----------|--------------|-----------|------------|----------|
| PostgreSQL | Automated daily + PITR | 30 days | CMEK (AES-256) | Cross-region |
| Object Storage | Object versioning | 365 days | CMEK (AES-256) | Regional (multi-zone) |
| Terraform State | Cloud storage with versioning | Indefinite | Cloud-managed | Multi-region |
| Container Images | Container registry | Indefinite | Cloud-managed | Regional |
| Configuration | Git (GitHub) | Indefinite | GitHub encryption | GitHub US |
| Vector Indexes | Rebuilt from source | N/A (rebuild) | CMEK | Regional |

---

_End of Information System Contingency Plan_
