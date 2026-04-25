# Latent Archon — Physical Security Policy

> **Policy ID**: POL-PE-001  
> **Version**: 1.0  
> **Effective Date**: March 2026  
> **Owner**: CEO / ISSO  
> **Review Cycle**: Annual  
> **NIST 800-53 Controls**: PE-1, PE-2, PE-3, PE-6, MA-1, MA-5

---

> **Organizational context**: Latent Archon is a founder-led, automation-first security organization. Physical security controls are fully inherited from the FedRAMP-authorized cloud service provider (GCP). See SOD-LA-001 for the automation-first security architecture.
<!-- MULTI-CLOUD: Original also listed AWS and Azure. -->

## 1. Purpose

This policy defines physical and environmental security requirements for Latent Archon. As a cloud-native organization with all infrastructure hosted on a FedRAMP High authorized cloud provider (GCP), physical security is primarily an inherited control from the CSP's data centers.
<!-- MULTI-CLOUD: Original stated GCP, AWS, or Azure. --> This policy documents the inheritance model, supplementary controls for personnel devices, and administrative requirements.

---

## 2. Scope

This policy applies to:

- Cloud provider data centers hosting Latent Archon infrastructure (inherited controls)
- Personnel work locations (home offices, co-working spaces)
- Personnel devices used to access Latent Archon systems
- Any physical media that may contain Latent Archon or customer data

---

## 3. Inherited Physical Security Controls (Cloud Providers)

### 3.1 CSP FedRAMP High Authorization

All Latent Archon infrastructure is hosted in US regions on GCP (FedRAMP High authorized).
<!-- MULTI-CLOUD: Original stated GCP, AWS, or Azure with single cloud per customer. --> The CSP's FedRAMP High authorization means the following physical security controls are fully inherited:

| NIST Control | Control Name | CSP Implementation |
|-------------|-------------|-------------------|
| PE-2 | Physical Access Authorizations | Multi-layer access: perimeter security, building access, data center floor, server cages |
| PE-3 | Physical Access Control | Biometric + badge authentication, man-traps, vehicle barriers |
| PE-4 | Access Control for Transmission | Cabled infrastructure within secured facility |
| PE-5 | Access Control for Output Devices | No customer access to physical infrastructure |
| PE-6 | Monitoring Physical Access | 24/7 CCTV, security operations center, intrusion detection |
| PE-8 | Visitor Access Records | Visitor logs, escort requirements, background checks |
| PE-9 | Power Equipment and Cabling | Redundant power (UPS + generators), protected cabling |
| PE-10 | Emergency Shutoff | Facility-level emergency power controls |
| PE-11 | Emergency Power | N+1 UPS systems, diesel generators with multi-day fuel |
| PE-12 | Emergency Lighting | Emergency lighting throughout facilities |
| PE-13 | Fire Protection | Advanced fire detection and suppression (dry-pipe, pre-action) |
| PE-14 | Environmental Controls | Precision HVAC, humidity control, water detection |
| PE-15 | Water Damage Protection | Raised floors, water sensors, leak detection |
| PE-16 | Delivery and Removal | Controlled shipping/receiving, asset tracking |
| PE-17 | Alternate Work Site | GCP maintains multiple data center locations |
| PE-18 | Location of Information System Components | Components housed within secured data center floors |

### 3.2 CSP Compliance Documentation

Each cloud provider's physical security posture is verified by:

- **FedRAMP High** P-ATO (Joint Authorization Board)
- **SOC 2 Type II** reports (available under NDA)
- **ISO 27001** certification
- **ISO 27017** (cloud security)
- **ISO 27018** (PII protection in cloud)
- **CSA STAR** Level 2 certification

Latent Archon reviews each CSP's FedRAMP marketplace listing and compliance status as part of vendor risk management (per POL-VR-001). See [cloud supplements](../cloud/) for per-provider details.

---

## 4. Supplementary Controls — Personnel Environments

### 4.1 Work Location Requirements

Since Latent Archon personnel work remotely, the following requirements apply to any location where company systems are accessed:

| Requirement | Details |
|-------------|---------|
| **Screen privacy** | Position screens to prevent shoulder surfing; use privacy screens if in public or shared spaces |
| **Unattended devices** | Lock screen when stepping away (< 5 min auto-lock required) |
| **Conversations** | Do not discuss customer data or security details where others may overhear |
| **Printed materials** | Avoid printing customer data; if printed, shred when no longer needed |
| **Secure storage** | Store any physical devices with company access in a locked location when not in use |

### 4.2 Personnel Device Security

| Requirement | Standard |
|-------------|----------|
| Full-disk encryption | Required (FileVault, BitLocker, or LUKS) |
| Screen lock timeout | ≤ 5 minutes |
| OS updates | Applied within 14 days of release; critical patches within 48 hours |
| Firewall | Enabled |
| Antivirus / endpoint protection | Required on Windows; recommended on macOS/Linux |
| Browser | Current version of Chrome, Firefox, Edge, or Safari |
| MFA on all company accounts | Required (TOTP or IdP-provided MFA) |
| Google Workspace Endpoint Verification | Required on all devices accessing corporate Google services |

**Endpoint Verification and Context-Aware Access**: Google Workspace Endpoint Verification is deployed on all personnel devices. It reports device encryption status (FileVault/BitLocker), OS version, screen lock configuration, and password status. Context-Aware Access uses this data to enforce device posture requirements at the access layer — devices that do not meet requirements (missing disk encryption, outdated OS, no screen lock) are denied access to all Google services until remediated. This is self-enforcing: non-compliant devices cannot access corporate systems. No MDM is deployed — the combination of Context-Aware Access (blocks non-compliant devices) and DLP rules (prevent downloading from Google Drive) eliminates both the access risk and the data-at-rest risk on endpoints.

### 4.3 Device Loss or Theft

If a device with access to Latent Archon systems is lost or stolen:

1. **Report immediately** to CEO / ISSO
2. **Suspend Google Workspace account**: Immediately suspend the user's Workspace account via Admin Console, which terminates all active Google sessions and blocks sign-in
3. **Revoke sessions**: All active sessions terminated via identity provider (Firebase/Identity Platform)
4. **Revoke tokens**: GitHub PATs, any API keys revoked
5. **Assess exposure**: Determine what data/systems were accessible. Note: CUI is not stored on personnel devices — it resides behind VPC Service Controls and is accessed only through the application. Google Workspace DLP rules prevent downloading files from Google Drive. The primary local exposure is source code in git repositories.
6. **Monitor**: Watch for unauthorized access in audit logs for 30 days
7. **Document**: Log incident per Incident Response Policy

---

## 5. Media Handling

### 5.1 Digital Media

| Requirement | Details |
|-------------|---------|
| Encryption | All removable media containing company data must be encrypted |
| Prohibited transfers | Customer data must **never** be copied to USB drives or removable media |
| Cloud-only | All company data stored in approved cloud services (GCP, GitHub) |

### 5.2 Media Disposal

| Media Type | Disposal Method |
|-----------|-----------------|
| Printed customer data | Cross-cut shred |
| Removable storage with company data | Cryptographic erasure + physical destruction |
| Decommissioned laptops | Full disk wipe (NIST 800-88 Clear) before disposal/donation |
| Cloud resources | Managed by CSP (cryptographic erasure on disk retirement) |

---

## 6. Maintenance

### 6.1 Infrastructure Maintenance (Inherited)

All infrastructure maintenance is performed by the cloud provider and inherited under their FedRAMP High authorization:

- Hardware maintenance by authorized CSP personnel only
- Failed drives cryptographically erased and physically destroyed
- Maintenance logs maintained by CSP per FedRAMP requirements
- No Latent Archon personnel have physical access to infrastructure

### 6.2 Personnel Device Maintenance

- Personnel are responsible for maintaining their own devices per Section 4.2
- Company may provide IT support for security configuration
- Third-party repair of devices requires removal of company data/accounts first
- CEO / ISSO may audit device compliance at any time

---

## 7. Monitoring

| Activity | Frequency | Owner |
|----------|-----------|-------|
| CSP FedRAMP status check | Quarterly | CEO / ISSO |
| CSP SOC 2 report review | Annual (on availability) | CEO / ISSO |
| Device compliance audit | Semi-annual | CEO / ISSO |
| Endpoint Verification device status review | Monthly | CEO / ISSO |
| Google Workspace security audit (audit-workspace-security.sh) | Monthly | CEO / ISSO |
| Policy acknowledgment | Annual | All personnel (via compliance repository) |
| Incident review (device loss) | On occurrence | CEO / ISSO |

---

## 8. Enforcement

- Failure to secure personal devices per Section 4.2 may result in access suspension until remediated
- Loss of an unsecured device (no encryption, no screen lock) is a moderate policy violation
- Unauthorized transfer of customer data to physical media is a severe policy violation
- All physical security exceptions require written approval from CEO

---

*Next review date: March 2027*
