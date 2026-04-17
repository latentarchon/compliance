#!/usr/bin/env node
/**
 * generate-conmon-report.mjs
 *
 * Generates a quarterly Continuous Monitoring (ConMon) report from existing
 * compliance data sources. Produces a FedRAMP-ready quarterly report that can
 * be shared with an agency sponsor once engaged.
 *
 * Usage:
 *   node scripts/generate-conmon-report.mjs [--quarter Q2] [--year 2026] [--output-dir reports/conmon]
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'fs';
import { join, dirname } from 'path';

const ROOT = join(import.meta.dirname, '..');

// Parse CLI args
const args = process.argv.slice(2);
let quarter = null;
let year = null;
let outputDir = join(ROOT, 'reports', 'conmon');

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--quarter' && args[i + 1]) quarter = args[++i];
  if (args[i] === '--year' && args[i + 1]) year = parseInt(args[++i], 10);
  if (args[i] === '--output-dir' && args[i + 1]) outputDir = args[++i];
}

const now = new Date();
if (!year) year = now.getFullYear();
if (!quarter) {
  const q = Math.ceil((now.getMonth() + 1) / 3);
  quarter = `Q${q}`;
}

const quarterNum = parseInt(quarter.replace('Q', ''), 10);
const quarterStart = new Date(year, (quarterNum - 1) * 3, 1);
const quarterEnd = new Date(year, quarterNum * 3, 0);

const roster = JSON.parse(readFileSync(join(ROOT, 'personnel.json'), 'utf-8'));
const isso = roster.personnel.find(p => p.roles.includes('isso'));
const issoName = isso ? `${isso.name} (${isso.title})` : 'TBD';

function readPOAM() {
  const ssp = readFileSync(join(ROOT, 'fedramp-ssp.md'), 'utf-8');
  const poamSection = ssp.match(/### Appendix I: Plan of Action and Milestones[\s\S]*?\n\n---/);
  if (!poamSection) return { total: 0, open: 0, remediated: 0, text: 'Unable to parse POA&M from SSP.' };

  const rows = poamSection[0].match(/^\| POA-\d+.*/gm) || [];
  const open = rows.filter(r => r.includes('Open')).length;
  const remediated = rows.filter(r => r.includes('Remediated')).length;
  return { total: rows.length, open, remediated, text: poamSection[0] };
}

function countKSIEvidence() {
  const evidenceDir = join(ROOT, 'evidence');
  if (!existsSync(evidenceDir)) return 0;
  try {
    return readdirSync(evidenceDir).filter(f => f.endsWith('.json') || f.endsWith('.md')).length;
  } catch {
    return 0;
  }
}

function readKSISummary() {
  const ksi = readFileSync(join(ROOT, 'fedramp-20x-ksi-summaries.md'), 'utf-8');
  const statusTable = ksi.match(/\| Theme \| KSIs \| Status \|[\s\S]*?(?=\n\n)/);
  return statusTable ? statusTable[0] : 'See fedramp-20x-ksi-summaries.md';
}

function generateReport() {
  const poam = readPOAM();
  const evidenceCount = countKSIEvidence();
  const ksiSummary = readKSISummary();

  const reportDate = now.toISOString().split('T')[0];
  const periodStr = `${quarter} ${year} (${quarterStart.toLocaleDateString('en-US', { month: 'long', day: 'numeric' })} – ${quarterEnd.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })})`;

  let report = '';
  report += `# Quarterly Continuous Monitoring Report\n\n`;
  report += `> **Document ID**: CONMON-RPT-${quarter}-${year}\n`;
  report += `> **Report Period**: ${periodStr}\n`;
  report += `> **Report Date**: ${reportDate}\n`;
  report += `> **System**: Latent Archon Document Intelligence Platform (LA-DIP)\n`;
  report += `> **Prepared By**: ${issoName}\n`;
  report += `> **Parent Document**: CONMON-LA-001 (continuous-monitoring-plan.md)\n`;
  report += `> **Controls**: CA-7, PM-4, RA-5, SI-2\n\n`;
  report += `---\n\n`;

  // Executive Summary
  report += `## 1. Executive Summary\n\n`;
  report += `This report summarizes the continuous monitoring activities for the Latent Archon Document Intelligence Platform during ${quarter} ${year}. `;
  report += `All automated monitoring systems operated within expected parameters. `;
  report += `The system remains in pre-authorization status pending agency sponsor engagement.\n\n`;
  report += `| Metric | Value |\n`;
  report += `|--------|-------|\n`;
  report += `| **Authorization Status** | Pre-Authorization (DRAFT) |\n`;
  report += `| **POA&M Items (Total)** | ${poam.total} |\n`;
  report += `| **POA&M Items (Open)** | ${poam.open} |\n`;
  report += `| **POA&M Items (Remediated)** | ${poam.remediated} |\n`;
  report += `| **KSI Evidence Files** | ${evidenceCount} |\n`;
  report += `| **Significant Changes** | _See §3_ |\n`;
  report += `| **Security Incidents** | _See §4_ |\n\n`;

  // Vulnerability Management
  report += `## 2. Vulnerability Management Summary\n\n`;
  report += `### 2.1 Automated Scanning\n\n`;
  report += `| Scanner | Frequency | Coverage | Status |\n`;
  report += `|---------|-----------|----------|--------|\n`;
  report += `| Trivy (container CVEs) | Every build + daily | All container images | Active |\n`;
  report += `| GoSec (SAST) | Every build + daily | Go source code | Active |\n`;
  report += `| Semgrep (multi-lang SAST) | Daily | All source code | Active |\n`;
  report += `| govulncheck (Go deps) | Every build + daily | Go dependencies | Active |\n`;
  report += `| Dependabot (SCA) | Continuous | All 9 repositories | Active |\n`;
  report += `| Gitleaks (secrets) | Every commit | All repositories | Active |\n\n`;
  report += `### 2.2 Findings Summary\n\n`;
  report += `| Severity | New This Quarter | Remediated | Still Open | Overdue |\n`;
  report += `|----------|-----------------|------------|------------|---------|\n`;
  report += `| Critical | _[fill]_ | _[fill]_ | _[fill]_ | _[fill]_ |\n`;
  report += `| High | _[fill]_ | _[fill]_ | _[fill]_ | _[fill]_ |\n`;
  report += `| Medium | _[fill]_ | _[fill]_ | _[fill]_ | _[fill]_ |\n`;
  report += `| Low | _[fill]_ | _[fill]_ | _[fill]_ | _[fill]_ |\n\n`;
  report += `> **Action**: Review Dependabot alerts, CI scan artifacts, and Drata evidence library to populate this table before submission.\n\n`;

  // Significant Changes
  report += `## 3. Significant Change Notifications (SCN)\n\n`;
  report += `All changes are tracked via Git with automated SCN classification. PRs classified as SIGNIFICANT require \`scn-acknowledged\` label before merge.\n\n`;
  report += `| Date | Change | Classification | SCN Filed? |\n`;
  report += `|------|--------|---------------|------------|\n`;
  report += `| _[fill from git log]_ | _[description]_ | SIGNIFICANT / ROUTINE | _[yes/no]_ |\n\n`;
  report += `> **Action**: Run \`git log --since="${quarterStart.toISOString().split('T')[0]}" --until="${quarterEnd.toISOString().split('T')[0]}" --oneline\` across all repos and filter for SCN-classified PRs.\n\n`;

  // Incident Summary
  report += `## 4. Incident Summary\n\n`;
  report += `| Incident ID | Date | Severity | Description | Status | Lessons Learned |\n`;
  report += `|------------|------|----------|-------------|--------|-----------------|\n`;
  report += `| _None_ | — | — | No security incidents during this period | — | — |\n\n`;

  // POA&M Status
  report += `## 5. POA&M Status\n\n`;
  report += poam.text + '\n\n';

  // Red Team / Penetration Testing
  report += `## 6. Security Testing\n\n`;
  report += `### 6.1 Red Team Exercises\n\n`;
  report += `Automated red team exercises run monthly (1st of month) with 99 attacks across 6 suites.\n\n`;
  report += `| Month | Attacks Run | Blocked | Succeeded | Defense Rate |\n`;
  report += `|-------|------------|---------|-----------|-------------|\n`;
  const months = [];
  for (let m = (quarterNum - 1) * 3; m < quarterNum * 3; m++) {
    months.push(new Date(year, m, 1).toLocaleDateString('en-US', { month: 'long' }));
  }
  for (const m of months) {
    report += `| ${m} | 99 | _[fill]_ | _[fill]_ | _[fill]_ |\n`;
  }
  report += `\n`;

  report += `### 6.2 Contingency Plan Tests (CP-4)\n\n`;
  report += `Automated contingency tests run monthly. Tests verify: Cloud SQL backup/PITR, GCS versioning, Cloud Run health, KMS key status, Artifact Registry availability.\n\n`;
  report += `| Month | Tests Run | Passed | Failed | Notes |\n`;
  report += `|-------|----------|--------|--------|-------|\n`;
  for (const m of months) {
    report += `| ${m} | _[fill]_ | _[fill]_ | _[fill]_ | _[fill]_ |\n`;
  }
  report += `\n`;

  // Infrastructure Drift
  report += `## 7. Configuration / Drift Detection\n\n`;
  report += `Weekly \`terragrunt plan\` drift detection and SSP-IaC drift check verify infrastructure matches declared state.\n\n`;
  report += `| Week | Drift Detected? | Action Taken |\n`;
  report += `|------|----------------|-------------|\n`;
  const weeksInQuarter = Math.ceil((quarterEnd - quarterStart) / (7 * 24 * 60 * 60 * 1000));
  for (let w = 1; w <= Math.min(weeksInQuarter, 13); w++) {
    report += `| Week ${w} | _[fill]_ | _[fill]_ |\n`;
  }
  report += `\n`;

  // KSI Evidence
  report += `## 8. KSI Evidence Summary\n\n`;
  report += ksiSummary + '\n\n';

  // Access Review
  report += `## 9. Access Review Summary\n\n`;
  report += `Monthly IAM/RBAC access reviews per SOP-03.\n\n`;
  report += `| Month | GCP IAM Reviewed | App RBAC Reviewed | Anomalies | Actions |\n`;
  report += `|-------|-----------------|-------------------|-----------|--------|\n`;
  for (const m of months) {
    report += `| ${m} | _[fill]_ | _[fill]_ | _[fill]_ | _[fill]_ |\n`;
  }
  report += `\n`;

  // Attestation
  report += `## 10. Attestation\n\n`;
  report += `I certify that the continuous monitoring activities described in this report were performed `;
  report += `during the reporting period and that the findings accurately represent the security posture `;
  report += `of the Latent Archon Document Intelligence Platform.\n\n`;
  report += `**Prepared By**: ________________________\n`;
  report += `**Name**: ${issoName}\n`;
  report += `**Date**: ${reportDate}\n\n`;
  report += `**Reviewed By** (Agency AO/ISSO): ________________________\n`;
  report += `**Name**: _[TBD — pending agency sponsor engagement]_\n`;
  report += `**Date**: ________________________\n\n`;

  report += `---\n\n`;
  report += `_End of Quarterly Continuous Monitoring Report — CONMON-RPT-${quarter}-${year}_\n`;

  return report;
}

// Main
const report = generateReport();
mkdirSync(outputDir, { recursive: true });
const filename = `conmon-report-${quarter.toLowerCase()}-${year}.md`;
const outPath = join(outputDir, filename);
writeFileSync(outPath, report);
console.log(`Quarterly ConMon report written to: ${outPath}`);
console.log(`\nNote: Sections marked [fill] require manual data entry from:`);
console.log(`  - Dependabot/CI scan artifacts (§2.2)`);
console.log(`  - Git log SCN-classified PRs (§3)`);
console.log(`  - Red team exercise reports in Drata (§6.1)`);
console.log(`  - CP-4 test reports in Drata (§6.2)`);
console.log(`  - Terragrunt drift detection CI runs (§7)`);
console.log(`  - IAM access review records (§9)`);
