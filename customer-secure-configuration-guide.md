# Latent Archon — Customer Secure Configuration Guide

> **Document ID**: GUIDE-SCG-001  
> **Version**: 1.0  
> **Date**: March 2026  
> **Classification**: PUBLIC  
> **FedRAMP Control**: CM-6 (Configuration Settings)

---

## 1. Purpose

This guide provides customer agencies with security configuration recommendations for the Latent Archon Document Intelligence Platform. Following these settings ensures your organization meets FedRAMP Moderate baseline requirements when using the platform.

---

## 2. Authentication Configuration

### 2.1 Multi-Factor Authentication (MFA)

MFA is **enforced by default** for all users. TOTP (Time-Based One-Time Password) is the supported MFA method, compatible with authenticator apps (Google Authenticator, Authy, 1Password, etc.).

| Setting | Default | Recommended | How to Change |
|---------|---------|-------------|---------------|
| MFA Required | Yes (enforced) | Keep enabled | Cannot be disabled |
| TOTP Adjacent Intervals | 1 | 1 | Platform setting (contact support) |

**Customer Action**: Ensure all users enroll a TOTP authenticator during first login. Users who fail to complete MFA enrollment cannot access the platform.

### 2.2 Session Timeouts

| Setting | Default | Recommended (CJIS) | Recommended (Standard) | How to Change |
|---------|---------|---------------------|------------------------|---------------|
| Idle Timeout | 30 minutes | 15 minutes | 30 minutes | Admin API → `UpdateOrganizationSettings` |
| Absolute Timeout | 12 hours | 8 hours | 12 hours | Admin API → `UpdateOrganizationSettings` |

**Customer Action**: Agencies handling CJIS data should set idle timeout to 15 minutes or less per CJIS Security Policy §5.5.5.

### 2.3 Single Sign-On (SSO)

SAML 2.0 SSO is supported for enterprise identity providers (Okta, Azure AD, PingFederate, etc.).

| Setting | Default | Recommended |
|---------|---------|-------------|
| SSO Enabled | Off | Enable for all agencies with enterprise IdP |
| SCIM Provisioning | Off | Enable alongside SSO for automated lifecycle |
| JIT Provisioning | On (when SSO active) | Keep enabled |

**Customer Action**:
1. Configure SAML SSO via the admin dashboard (Settings → SSO Configuration)
2. Provide your IdP metadata URL, entity ID, and SSO URL
3. Upload your IdP's signing certificate
4. Enable SCIM 2.0 provisioning for automated user lifecycle management
5. Map IdP groups to Latent Archon roles for automatic role assignment

### 2.4 Password Policy

Latent Archon uses **passwordless authentication** (magic link) by default. No passwords are stored in the application.

For SSO users, password policy is governed by the customer's Identity Provider. Ensure your IdP enforces:
- Minimum 12 characters
- Complexity requirements per NIST SP 800-63B
- Breach detection / compromised password blocking

---

## 3. Access Control Configuration

### 3.1 Role-Based Access Control (RBAC)

| Role | Privileges | Recommended Assignment |
|------|-----------|----------------------|
| `master_admin` | Full org management, user management, all workspace access | 1-2 designated agency admins only |
| `admin` | User management, workspace management, document management | IT security staff |
| `editor` | Upload documents, chat, search within assigned workspaces | Analysts and content managers |
| `viewer` | Chat and search within assigned workspaces (read-only) | General staff |

**Customer Action**:
- Assign `master_admin` to no more than 2 agency personnel
- Follow least-privilege: assign `viewer` by default, escalate only as needed
- Review role assignments quarterly (documented in your agency's access review process)

### 3.2 Workspace Isolation

Workspaces provide data isolation boundaries. Documents and chat history in one workspace are invisible to users in other workspaces.

**Customer Action**:
- Create separate workspaces for different data sensitivity levels or projects
- Assign users only to workspaces they need access to
- Do not co-mingle CUI and non-CUI data in the same workspace

### 3.3 IP Allowlisting

Restrict access to your organization's network ranges.

| Setting | Default | Recommended |
|---------|---------|-------------|
| IP Allowlist Enabled | Off | Enable for all agencies |
| Allowed CIDRs | None | Your agency's egress IP ranges |

**Customer Action**:
1. Navigate to Admin Dashboard → Settings → IP Allowlist
2. Add your agency's public IP ranges (CIDR notation, e.g., `203.0.113.0/24`)
3. Enable the allowlist — all requests from outside these ranges will be blocked

---

## 4. Data Protection Configuration

### 4.1 Encryption

All data is encrypted automatically. No customer configuration is required.

| Data State | Encryption | Key Management |
|-----------|-----------|----------------|
| At rest (documents) | AES-256-GCM | Customer-Managed Encryption Keys (CMEK) via Cloud KMS |
| At rest (database) | AES-256 | CMEK via Cloud KMS |
| In transit | TLS 1.2+ | Google-managed certificates |
| In processing | Memory-only | Cleared after request completion |

### 4.2 Data Retention

| Setting | Default | Configurable | How to Change |
|---------|---------|-------------|---------------|
| Document Retention | Indefinite | Yes | Admin API → `UpdateOrganizationSettings` |
| Chat History Retention | Indefinite | Yes | Admin API → `UpdateOrganizationSettings` |
| Audit Log Retention | 365 days | No (platform minimum) | N/A |
| Closed Account Purge | 90 days | No | Automatic |

**Customer Action**: Set retention periods appropriate to your agency's records management policy.

### 4.3 Document Upload

| Setting | Value | Notes |
|---------|-------|-------|
| Max File Size | 50 MB | Per document |
| Supported Formats | PDF, DOCX, TXT, MD, CSV | Processed via Document AI OCR |
| Malware Scanning | Enabled (fail-closed) | ClamAV scans all uploads before storage |

---

## 5. Audit and Monitoring

### 5.1 Audit Logging

All user and administrative actions are logged automatically:

- Authentication events (login, logout, MFA challenges)
- Document operations (upload, download, delete)
- Chat interactions (message sent, search performed)
- Administrative actions (role changes, member additions/removals, settings changes)
- SCIM provisioning events
- SSO configuration changes

**Customer Action**:
- Review audit logs regularly via the admin dashboard
- Export audit logs to your agency SIEM if required (contact support for log forwarding configuration)

### 5.2 Security Notifications

Real-time email notifications are sent for security-relevant events:

- Repeated authentication failures
- Role escalation (user promoted to admin)
- New member added to organization
- SSO/SCIM configuration changes
- IP allowlist changes

**Customer Action**: Ensure the org `master_admin` email is monitored. Consider using a distribution group.

---

## 6. Incident Reporting

Report security incidents or vulnerabilities to:

- **Email**: security@latentarchon.com
- **Response SLA**: Acknowledgment within 1 business day, initial assessment within 72 hours

For incidents affecting CUI, Latent Archon will notify the customer agency and FedRAMP PMO per the Incident Response Policy (POL-IR-001) within the timelines specified in US-CERT Federal Incident Notification Guidelines.

---

## 7. Recommended Quarterly Review Checklist

Agencies should perform these reviews quarterly:

- [ ] **Access review**: Verify all user role assignments are still appropriate
- [ ] **Workspace membership review**: Remove users who no longer need access
- [ ] **IP allowlist review**: Update IP ranges if agency network changes
- [ ] **Session timeout review**: Confirm timeout settings match agency policy
- [ ] **SCIM sync verification**: Confirm IdP user list matches platform users
- [ ] **Audit log review**: Sample audit logs for anomalous activity
- [ ] **Data retention review**: Confirm retention settings match records policy

---

## 8. Support

| Channel | Contact | Hours |
|---------|---------|-------|
| Technical Support | support@latentarchon.com | Business hours (9am-6pm ET) |
| Security Issues | security@latentarchon.com | 24/7 monitoring |
| Documentation | https://docs.latentarchon.com | Self-service |

---

*This document is updated with each platform release. Last reviewed: March 2026.*
