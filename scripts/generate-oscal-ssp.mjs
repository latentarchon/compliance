#!/usr/bin/env node
/**
 * generate-oscal-ssp.mjs
 *
 * Generates a valid OSCAL v1.1.3 System Security Plan (SSP) in JSON format
 * from the Latent Archon compliance source data.
 *
 * Usage:
 *   node scripts/generate-oscal-ssp.mjs [--output oscal/ssp.json]
 *
 * The output can be validated with:
 *   oscal-cli validate oscal/ssp.json
 *   # or via Docker:
 *   docker run --rm -v "$(pwd):/data" ghcr.io/metaschema-framework/oscal-cli:latest validate /data/oscal/ssp.json
 */

import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { randomUUID } from 'crypto';

const ROOT = join(import.meta.dirname, '..');
const DEFAULT_OUTPUT = join(ROOT, 'oscal', 'ssp.json');

// Parse CLI args
const args = process.argv.slice(2);
let outputPath = DEFAULT_OUTPUT;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--output' && args[i + 1]) outputPath = args[++i];
}

// ---------------------------------------------------------------------------
// Stable UUIDs — these should remain constant across regenerations so that
// external references to this SSP remain valid. Generated once, hardcoded.
// ---------------------------------------------------------------------------
const UUID = {
  ssp:                'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
  partyOrg:           'b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e',
  partyOwner:         'c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f',
  roleSystemOwner:    'system-owner',
  roleISSOfficer:     'information-system-security-officer',
  roleAO:             'authorizing-official',
  componentApp:       'd4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80',
  componentGCP:       'e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8091',
  componentChatAPI:   'f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f809102',
  componentAdminAPI:  'a7b8c9d0-e1f2-4a3b-4c5d-6e7f80910213',
  componentOps:       'b8c9d0e1-f2a3-4b4c-5d6e-7f8091021324',
  componentDB:        'c9d0e1f2-a3b4-4c5d-6e7f-809102132435',
  componentGCS:       'd0e1f2a3-b4c5-4d6e-7f80-910213243546',
  componentWAF:       'e1f2a3b4-c5d6-4e7f-8091-021324354657',
  componentKMS:       'f2a3b4c5-d6e7-4f80-9102-132435465768',
  componentIdP:       'a3b4c5d6-e7f8-4091-0213-243546576879',
  componentVectorAI:  'b4c5d6e7-f809-4102-1324-35465768798a',
  componentCICD:      'c5d6e7f8-0910-4213-2435-4657687989ab',
  componentClamAV:    'd6e7f809-1021-4324-3546-57687989abbc',
  leveragedGCP:       'e7f80910-2132-4435-4657-687989abbbcd',
};

// ---------------------------------------------------------------------------
// Parse controls from Appendix A markdown
// ---------------------------------------------------------------------------
function parseControls(mdPath) {
  const content = readFileSync(mdPath, 'utf-8');
  const controls = [];
  // Match ### AC-1: Title patterns
  const controlRegex = /^### ([A-Z]{2}-\d+(?:\(\d+\))?): (.+)$/gm;
  let match;
  while ((match = controlRegex.exec(content)) !== null) {
    const controlId = match[1].toLowerCase().replace(/\((\d+)\)/, '.$1');
    const title = match[2].trim();
    const startIdx = match.index + match[0].length;

    // Find the next control heading or end of file
    const nextMatch = controlRegex.exec(content);
    const endIdx = nextMatch ? nextMatch.index : content.length;
    // Reset regex lastIndex to allow next iteration to find this match
    if (nextMatch) controlRegex.lastIndex = match.index + match[0].length;

    const block = content.substring(startIdx, endIdx);

    // Extract responsibility
    const respMatch = block.match(/\*\*Responsibility\*\*:\s*(.+)/);
    const responsibility = respMatch ? respMatch[1].trim() : 'CSP';

    // Extract status
    const statusMatch = block.match(/\*\*Status\*\*:\s*(.+)/);
    const status = statusMatch ? statusMatch[1].trim() : 'Implemented';

    // Extract implementation narrative (everything after **Implementation**:)
    const implMatch = block.match(/\*\*Implementation\*\*:?\s*([\s\S]*?)(?=\*\*Customer Responsibility\*\*|### [A-Z]{2}-|---|\n## [A-Z]|$)/);
    const narrative = implMatch
      ? implMatch[1].trim().replace(/\*\*/g, '').replace(/\n{3,}/g, '\n\n')
      : '';

    controls.push({ controlId, title, responsibility, status, narrative });
  }
  return controls;
}

// Re-parse with a simpler approach since regex state is tricky
function parseControlsSimple(mdPath) {
  const content = readFileSync(mdPath, 'utf-8');
  const lines = content.split('\n');
  const controls = [];
  let current = null;
  let collectingNarrative = false;
  let narrativeLines = [];

  for (const line of lines) {
    const headingMatch = line.match(/^### ([A-Z]{2}-\d+(?:\(\d+\))?): (.+)$/);
    if (headingMatch) {
      // Save previous control
      if (current) {
        current.narrative = narrativeLines.join('\n').trim().replace(/\*\*/g, '');
        controls.push(current);
      }
      const rawId = headingMatch[1];
      const controlId = rawId.toLowerCase().replace(/\((\d+)\)/, '.$1');
      current = {
        controlId,
        title: headingMatch[2].trim(),
        responsibility: 'CSP',
        status: 'implemented',
        narrative: '',
      };
      collectingNarrative = false;
      narrativeLines = [];
      continue;
    }

    if (!current) continue;

    const respMatch = line.match(/\*\*Responsibility\*\*:\s*(.+)/);
    if (respMatch) {
      const r = respMatch[1].trim().toLowerCase();
      if (r.includes('inherited')) current.responsibility = 'inherited';
      else if (r.includes('shared')) current.responsibility = 'shared';
      else if (r.includes('customer')) current.responsibility = 'customer-configured';
      else current.responsibility = 'sp-system-specific';
      continue;
    }

    const statusMatch = line.match(/\*\*Status\*\*:\s*(.+)/);
    if (statusMatch) {
      const s = statusMatch[1].trim().toLowerCase();
      if (s.includes('partial')) current.status = 'partial';
      else if (s.includes('planned')) current.status = 'planned';
      else if (s.includes('alternative')) current.status = 'alternative';
      else if (s.includes('not applicable') || s.includes('n/a')) current.status = 'not-applicable';
      else current.status = 'implemented';
      continue;
    }

    if (line.startsWith('**Implementation**')) {
      collectingNarrative = true;
      const afterColon = line.replace(/^\*\*Implementation\*\*:?\s*/, '');
      if (afterColon) narrativeLines.push(afterColon);
      continue;
    }

    if (line.startsWith('**Customer Responsibility**')) {
      collectingNarrative = false;
      continue;
    }

    if (collectingNarrative && line.trim()) {
      narrativeLines.push(line);
    }
  }

  // Save last control
  if (current) {
    current.narrative = narrativeLines.join('\n').trim().replace(/\*\*/g, '');
    controls.push(current);
  }

  return controls;
}

// ---------------------------------------------------------------------------
// Build the OSCAL SSP JSON
// ---------------------------------------------------------------------------
function buildSSP(controls) {
  const now = new Date().toISOString();

  return {
    'system-security-plan': {
      uuid: UUID.ssp,
      metadata: {
        title: 'Latent Archon Document Intelligence Platform — System Security Plan',
        'last-modified': now,
        version: '1.0.0',
        'oscal-version': '1.1.3',
        props: [
          {
            name: 'marking',
            value: 'CUI',
          },
        ],
        roles: [
          {
            id: UUID.roleSystemOwner,
            title: 'System Owner',
          },
          {
            id: UUID.roleISSOfficer,
            title: 'Information System Security Officer',
          },
          {
            id: UUID.roleAO,
            title: 'Authorizing Official',
          },
        ],
        parties: [
          {
            uuid: UUID.partyOrg,
            type: 'organization',
            name: 'Latent Archon, LLC',
            'email-addresses': ['ajhendel@latentarchon.com'],
            links: [
              { href: 'https://latentarchon.com', rel: 'homepage' },
            ],
          },
          {
            uuid: UUID.partyOwner,
            type: 'person',
            name: 'Andrew Hendel',
            props: [
              { name: 'job-title', value: 'Chief Executive Officer' },
            ],
            'email-addresses': ['ajhendel@latentarchon.com'],
            'member-of-organizations': [UUID.partyOrg],
          },
        ],
        'responsible-parties': [
          {
            'role-id': UUID.roleSystemOwner,
            'party-uuids': [UUID.partyOwner],
          },
        ],
      },

      'import-profile': {
        href: 'https://raw.githubusercontent.com/GSA/fedramp-automation/refs/heads/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json',
      },

      'system-characteristics': {
        'system-ids': [
          {
            'identifier-type': 'http://ietf.org/rfc/rfc4122',
            id: 'LA-DIP-MODERATE-2026',
          },
        ],
        'system-name': 'Latent Archon Document Intelligence Platform',
        'system-name-short': 'LA-DIP',
        description: 'Latent Archon is a multi-tenant document intelligence platform purpose-built for U.S. government agencies handling Controlled Unclassified Information (CUI). The platform provides document management with malware scanning, AI-powered semantic search using Retrieval-Augmented Generation (RAG), interactive conversation over uploaded documents using Google Gemini LLMs, workspace-level data isolation enforced through PostgreSQL Row-Level Security (RLS), and enterprise SSO/SCIM integration.',
        props: [
          { name: 'cloud-service-model', value: 'saas' },
          { name: 'cloud-deployment-model', value: 'public-cloud' },
          { name: 'identity-assurance-level', value: '2' },
          { name: 'authenticator-assurance-level', value: '2' },
          { name: 'federation-assurance-level', value: '2' },
        ],
        'security-sensitivity-level': 'moderate',
        'system-information': {
          'information-types': [
            {
              uuid: randomUUID(),
              title: 'Customer Documents (CUI)',
              description: 'Customer-uploaded documents including Controlled Unclassified Information per 32 CFR 2002.',
              'categorizations': [
                { system: 'https://doi.org/10.6028/NIST.SP.800-60v2r1', 'information-type-ids': ['D.14'] },
              ],
              'confidentiality-impact': { base: 'moderate' },
              'integrity-impact': { base: 'moderate' },
              'availability-impact': { base: 'moderate' },
            },
            {
              uuid: randomUUID(),
              title: 'Conversation Messages / AI Responses',
              description: 'User conversation messages and AI-generated responses from RAG pipeline.',
              'categorizations': [
                { system: 'https://doi.org/10.6028/NIST.SP.800-60v2r1', 'information-type-ids': ['D.14'] },
              ],
              'confidentiality-impact': { base: 'moderate' },
              'integrity-impact': { base: 'moderate' },
              'availability-impact': { base: 'low' },
            },
            {
              uuid: randomUUID(),
              title: 'User Account Data (PII)',
              description: 'User identity information managed by Firebase Identity Platform.',
              'categorizations': [
                { system: 'https://doi.org/10.6028/NIST.SP.800-60v2r1', 'information-type-ids': ['D.8'] },
              ],
              'confidentiality-impact': { base: 'moderate' },
              'integrity-impact': { base: 'moderate' },
              'availability-impact': { base: 'low' },
            },
            {
              uuid: randomUUID(),
              title: 'Audit Logs',
              description: 'Application and infrastructure audit event records.',
              'categorizations': [
                { system: 'https://doi.org/10.6028/NIST.SP.800-60v2r1', 'information-type-ids': ['D.3.5'] },
              ],
              'confidentiality-impact': { base: 'moderate' },
              'integrity-impact': { base: 'moderate' },
              'availability-impact': { base: 'low' },
            },
          ],
        },
        'security-impact-level': {
          'security-objective-confidentiality': 'moderate',
          'security-objective-integrity': 'moderate',
          'security-objective-availability': 'moderate',
        },
        status: {
          state: 'under-development',
          remarks: 'System is in pre-authorization status. Infrastructure-as-code validated in staging. Production deployment pending authorization boundary finalization and 3PAO engagement.',
        },
        'authorization-boundary': {
          description: 'The authorization boundary encompasses all components required to deliver the Latent Archon SaaS offering: application code (Go backend, React SPAs), GCP infrastructure (Cloud Run, Cloud SQL, Cloud Storage, Vertex AI, Cloud Armor, Cloud KMS, Identity Platform), CI/CD pipelines (GitHub Actions with Workload Identity Federation), administrative interfaces, and supporting services (ClamAV malware scanning, Document AI OCR). The system uses a two-project architecture for blast-radius isolation: App Project (archon-fed-app-prod) for user-facing services and Admin Project (archon-fed-admin-prod) for administrative, processing, and data storage services.',
        },
        'network-architecture': {
          description: 'All inbound traffic flows through Cloud Armor WAF and Global HTTPS Load Balancer. No services have public IP addresses. Internal communication uses VPC-native networking with Cloud SQL via VPC peering, Vertex AI via Private Service Connect, and Cloud Run serverless containers. Egress firewall is deny-all by default with FQDN-based allowlist for GCP APIs only.',
        },
        'data-flow': {
          description: 'Document upload: Browser → Cloud Armor → HTTPS LB → Admin API (auth, MFA, RBAC, malware scan) → Cloud Storage (CMEK) → Cloud Tasks → Ops Service (OCR, chunking, embedding) → Vertex AI Vector Search. App query: Browser → Cloud Armor → HTTPS LB → App API (auth, MFA, workspace check) → Vector Search (semantic query) → Gemini LLM (streaming response) → Client. All data at rest encrypted with AES-256 (CMEK via Cloud KMS). All data in transit encrypted with TLS 1.2+.',
        },
      },

      'system-implementation': {
        'leveraged-authorizations': [
          {
            uuid: UUID.leveragedGCP,
            title: 'Google Cloud Platform',
            props: [
              { name: 'implementation-point', value: 'external' },
            ],
            links: [
              { href: '#' + UUID.componentGCP, rel: 'uses-service' },
            ],
            'party-uuid': UUID.partyOrg,
            'date-authorized': '2018-05-18',
          },
        ],
        users: [
          {
            uuid: randomUUID(),
            title: 'Customer End User',
            description: 'Agency staff using conversation/search functionality via the app SPA.',
            props: [
              { name: 'type', value: 'external' },
              { name: 'privilege-level', value: 'non-privileged' },
            ],
            'role-ids': ['viewer', 'editor'],
            'authorized-privileges': [
              {
                title: 'Conversation and Search',
                description: 'Access to conversation interface and document search within assigned workspaces.',
                'functions-performed': ['document-search', 'conversation', 'view-documents'],
              },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Customer Org Admin',
            description: 'Agency administrator managing organization settings, users, and workspaces.',
            props: [
              { name: 'type', value: 'external' },
              { name: 'privilege-level', value: 'privileged' },
            ],
            'role-ids': ['master_admin', 'admin'],
            'authorized-privileges': [
              {
                title: 'Organization Management',
                description: 'Create/manage workspaces, invite/remove members, upload documents, configure SSO/SCIM, manage IP allowlists.',
                'functions-performed': ['user-management', 'workspace-management', 'document-management', 'settings-management'],
              },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Engineer',
            description: 'Platform developer deploying via CI/CD. No direct production data access.',
            props: [
              { name: 'type', value: 'internal' },
              { name: 'privilege-level', value: 'privileged' },
            ],
            'role-ids': ['developer'],
            'authorized-privileges': [
              {
                title: 'CI/CD Deployment',
                description: 'Deploy application containers and infrastructure changes via GitHub Actions with Workload Identity Federation (keyless).',
                'functions-performed': ['code-deployment', 'infrastructure-management'],
              },
            ],
          },
        ],
        components: [
          {
            uuid: UUID.componentApp,
            type: 'this-system',
            title: 'Latent Archon Application',
            description: 'The complete Latent Archon Document Intelligence Platform including Go backend services, React SPAs, and supporting infrastructure.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentGCP,
            type: 'leveraged-system',
            title: 'Google Cloud Platform',
            description: 'FedRAMP High authorized cloud infrastructure providing compute, storage, networking, identity, AI/ML, and security services.',
            props: [
              { name: 'leveraged-authorization-uuid', value: UUID.leveragedGCP },
            ],
            status: { state: 'operational' },
          },
          {
            uuid: UUID.componentChatAPI,
            type: 'service',
            title: 'App API (archon-app)',
            description: 'Cloud Run service handling user-facing API: conversation, search, auth, streaming responses.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentAdminAPI,
            type: 'service',
            title: 'Admin API (archon-admin)',
            description: 'Cloud Run service handling admin API: org management, document ingestion, settings, member management.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentOps,
            type: 'service',
            title: 'Ops Service (archon-ops)',
            description: 'Cloud Run service handling background processing: document processing, embeddings, cron jobs.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentDB,
            type: 'service',
            title: 'Cloud SQL PostgreSQL 15',
            description: 'Primary relational data store with Row-Level Security (RLS), encrypted at rest with CMEK via Cloud KMS. Private IP only, VPC peering.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentGCS,
            type: 'service',
            title: 'Cloud Storage',
            description: 'Object storage for customer documents. AES-256-GCM + CMEK, workspace-scoped paths, versioning with 365-day retention.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentWAF,
            type: 'service',
            title: 'Cloud Armor WAF',
            description: 'Web Application Firewall with OWASP CRS v3.3, rate limiting, bot blocking, HTTP method enforcement, per-tenant IP allowlisting.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentKMS,
            type: 'service',
            title: 'Cloud KMS',
            description: 'Customer-Managed Encryption Keys (CMEK) for Cloud SQL and GCS. AES-256 with 365-day automatic rotation. FIPS 140-2 Level 3.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentIdP,
            type: 'service',
            title: 'Identity Platform',
            description: 'Firebase Identity Platform providing multi-tenant authentication with TOTP MFA, magic link (passwordless), SAML SSO, and SCIM 2.0.',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentVectorAI,
            type: 'service',
            title: 'Vertex AI',
            description: 'AI/ML services: Vector Search (PSC endpoint, workspace-scoped), Gemini LLM (RAG response generation), embedding API (gemini-embedding-2-preview).',
            status: { state: 'under-development' },
          },
          {
            uuid: UUID.componentCICD,
            type: 'service',
            title: 'CI/CD Pipeline',
            description: 'GitHub Actions with Workload Identity Federation (keyless, zero secrets). Includes: build, test, Trivy scan, SBOM generation, deploy to Cloud Run.',
            status: { state: 'operational' },
          },
          {
            uuid: UUID.componentClamAV,
            type: 'service',
            title: 'ClamAV Malware Scanner',
            description: 'Internal-only Cloud Run service providing REST API for document malware scanning. Fail-closed in production.',
            status: { state: 'under-development' },
          },
        ],
      },

      'control-implementation': {
        description: 'This section describes how each NIST SP 800-53 Rev. 5 Moderate baseline control is implemented within the Latent Archon system. Controls are either directly implemented by Latent Archon (CSP), inherited from the GCP FedRAMP High authorization, shared between Latent Archon and the customer agency, or the responsibility of the customer.',
        'implemented-requirements': controls.map(ctrl => ({
          uuid: randomUUID(),
          'control-id': ctrl.controlId,
          props: [
            {
              name: 'implementation-status',
              value: ctrl.status,
            },
          ],
          'responsible-roles': [
            {
              'role-id': ctrl.responsibility === 'inherited'
                ? 'leveraged-system'
                : ctrl.responsibility === 'customer-configured'
                ? 'customer'
                : UUID.roleSystemOwner,
            },
          ],
          statements: [
            {
              'statement-id': `${ctrl.controlId}_smt`,
              uuid: randomUUID(),
              'by-components': [
                {
                  'component-uuid': ctrl.responsibility === 'inherited'
                    ? UUID.componentGCP
                    : UUID.componentApp,
                  uuid: randomUUID(),
                  description: ctrl.narrative || `Implementation of ${ctrl.controlId}: ${ctrl.title}`,
                  'implementation-status': {
                    state: ctrl.status,
                  },
                },
              ],
            },
          ],
        })),
      },

      'back-matter': {
        resources: [
          {
            uuid: randomUUID(),
            title: 'FedRAMP Rev5 Moderate Baseline',
            rlinks: [
              {
                href: 'https://raw.githubusercontent.com/GSA/fedramp-automation/refs/heads/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json',
                'media-type': 'application/json',
              },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Access Control Policy (POL-AC-001)',
            description: 'Access control policy document.',
            rlinks: [
              { href: './policies/access-control.md', 'media-type': 'text/markdown' },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Incident Response Policy (POL-IR-001)',
            description: 'Incident response policy and procedures.',
            rlinks: [
              { href: './policies/incident-response.md', 'media-type': 'text/markdown' },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Configuration Management Plan',
            description: 'Configuration management plan document.',
            rlinks: [
              { href: './configuration-management-plan.md', 'media-type': 'text/markdown' },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Contingency Plan',
            description: 'Information system contingency plan (ISCP).',
            rlinks: [
              { href: './contingency-plan.md', 'media-type': 'text/markdown' },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Continuous Monitoring Plan',
            description: 'Continuous monitoring strategy and procedures.',
            rlinks: [
              { href: './continuous-monitoring-plan.md', 'media-type': 'text/markdown' },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Supply Chain Risk Management Plan',
            description: 'Supply chain risk management plan (SCRMP).',
            rlinks: [
              { href: './supply-chain-risk-management-plan.md', 'media-type': 'text/markdown' },
            ],
          },
          {
            uuid: randomUUID(),
            title: 'Latent Archon Privacy Impact Assessment',
            description: 'Privacy impact assessment (PIA).',
            rlinks: [
              { href: './privacy-impact-assessment.md', 'media-type': 'text/markdown' },
            ],
          },
        ],
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  console.log('Parsing controls from Appendix A...');
  const controlsPath = join(ROOT, 'fedramp-ssp-appendix-a-controls.md');
  const controls = parseControlsSimple(controlsPath);
  console.log(`  Found ${controls.length} controls`);

  console.log('Building OSCAL SSP JSON...');
  const ssp = buildSSP(controls);

  const implReqs = ssp['system-security-plan']['control-implementation']['implemented-requirements'];
  const statusCounts = {};
  for (const req of implReqs) {
    const s = req.props[0].value;
    statusCounts[s] = (statusCounts[s] || 0) + 1;
  }
  console.log('  Control status breakdown:');
  for (const [status, count] of Object.entries(statusCounts)) {
    console.log(`    ${status}: ${count}`);
  }

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(ssp, null, 2) + '\n');
  console.log(`\nOSCAL SSP written to: ${outputPath}`);
  console.log('\nValidate with:');
  console.log('  docker run --rm -v "$(pwd):/data" ghcr.io/metaschema-framework/oscal-cli:latest validate /data/oscal/ssp.json');
}

main();
