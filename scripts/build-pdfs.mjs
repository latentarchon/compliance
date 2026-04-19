import { mdToPdf } from 'md-to-pdf';
import { readdir, mkdir } from 'fs/promises';
import { join, basename } from 'path';
import { existsSync } from 'fs';

// PUBLIC — safe to host on the marketing site (latentarchon.com/docs/)
const PUBLIC_DOCS = [
  'security-whitepaper.md',
  'policies/access-control.md',
  'policies/change-management.md',
  'policies/incident-response.md',
  'policies/vendor-risk.md',
  'policies/information-security.md',
  'policies/encryption.md',
  'policies/data-classification.md',
  'policies/business-continuity.md',
  'policies/risk-management.md',
  'policies/acceptable-use.md',
  'policies/security-awareness-training.md',
  'policies/physical-security.md',
  'policies/vulnerability-scanning.md',
];

// INTERNAL — shared only with agency sponsors, 3PAO, and FedRAMP PMO under NDA
const INTERNAL_DOCS = [
  'ssp-lite-nist-800-53.md',
  'fedramp-ssp.md',
  'fedramp-ssp-appendix-a-controls.md',
  'contingency-plan.md',
  'configuration-management-plan.md',
  'continuous-monitoring-plan.md',
  'supply-chain-risk-management-plan.md',
  'privacy-impact-assessment.md',
];

const ALL_DOCS = [
  ...PUBLIC_DOCS.map(d => ({ doc: d, tier: 'public' })),
  ...INTERNAL_DOCS.map(d => ({ doc: d, tier: 'internal' })),
];

const DIST = join(import.meta.dirname, '..', 'dist');
const DIST_PUBLIC = join(DIST, 'public');
const DIST_INTERNAL = join(DIST, 'internal');
const ROOT = join(import.meta.dirname, '..');

const pdfOptions = {
  pdf_options: {
    format: 'Letter',
    margin: { top: '0.75in', bottom: '0.75in', left: '0.75in', right: '0.75in' },
    printBackground: true,
  },
  css: `
    body { font-family: 'Inter', 'Helvetica Neue', Arial, sans-serif; font-size: 11px; color: #1e293b; line-height: 1.6; }
    h1 { font-size: 22px; border-bottom: 2px solid #0891b2; padding-bottom: 6px; margin-top: 28px; }
    h2 { font-size: 16px; color: #0f172a; margin-top: 24px; }
    h3 { font-size: 13px; color: #334155; margin-top: 18px; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 10px; }
    th, td { border: 1px solid #cbd5e1; padding: 6px 8px; text-align: left; }
    th { background: #f1f5f9; font-weight: 600; }
    code { background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 10px; }
    pre { background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 4px; font-size: 9px; }
    blockquote { border-left: 3px solid #0891b2; margin-left: 0; padding-left: 12px; color: #475569; }
    a { color: #0891b2; }
    @page { @bottom-center { content: "Latent Archon — Company Confidential"; font-size: 8px; color: #94a3b8; } }
  `,
};

async function main() {
  for (const dir of [DIST_PUBLIC, DIST_INTERNAL]) {
    if (!existsSync(dir)) await mkdir(dir, { recursive: true });
  }

  for (const { doc, tier } of ALL_DOCS) {
    const src = join(ROOT, doc);
    if (!existsSync(src)) {
      console.warn(`⚠  Skipping ${doc} (not found)`);
      continue;
    }
    const outName = basename(doc, '.md') + '.pdf';
    const destDir = tier === 'public' ? DIST_PUBLIC : DIST_INTERNAL;
    const dest = join(destDir, outName);
    console.log(`📄 [${tier}] ${doc} → dist/${tier}/${outName}`);
    try {
      await mdToPdf({ path: src }, { ...pdfOptions, dest });
    } catch (err) {
      console.error(`❌ Failed: ${doc}`, err.message);
    }
  }
  console.log(`\n✅ Public PDFs → dist/public/ (${PUBLIC_DOCS.length} docs)`);
  console.log(`🔒 Internal PDFs → dist/internal/ (${INTERNAL_DOCS.length} docs)`);
}

main();
